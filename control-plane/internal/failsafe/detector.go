// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: DDoS flood detector (control-plane/internal/failsafe/detector.go).
//              Runs multiple detection algorithms in parallel against the
//              rolling XDP stats. Each algorithm votes independently; any
//              vote triggers the circuit breaker (OR logic).
//
//              Algorithms:
//                1. AbsoluteThreshold: pps or bps exceeds static limit
//                2. RateOfChange:      sudden spike > N× the rolling baseline
//                3. SYNRatio:          SYN:ACK ratio anomaly (SYN flood)
//                4. PacketDropRatio:   drop rate > M% of total RX
//                5. ErrorSpike:        parse error rate anomaly
//
//              Sliding window: 5-sample exponential moving average (EMA)
//              prevents single-sample spikes from triggering false positives.
// =============================================================================

package failsafe

import (
	"fmt"
	"math"
	"time"

	"github.com/ft-1/falx-v2/control-plane/pkg/bpfmaps"
)

// ─── Detection Result ─────────────────────────────────────────────────────────
type DetectionResult struct {
	Triggered  bool
	Algorithm  string
	Reason     string
	CurrentPPS uint64
	CurrentBPS uint64
	Confidence float64 // 0.0 - 1.0
}

// ─── Stats Sample ─────────────────────────────────────────────────────────────
type StatsSample struct {
	At         time.Time
	Stats      bpfmaps.XdpStats
	DeltaPPS   uint64  // Packets in the last interval
	DeltaBPS   uint64  // Bits in the last interval
	IntervalMs float64 // Actual interval duration
}

// ─── Detector Config ──────────────────────────────────────────────────────────
type DetectorConfig struct {
	// Algorithm 1: Absolute thresholds
	PPSThreshold uint64  // packets/sec hard limit
	BPSThreshold uint64  // bits/sec hard limit

	// Algorithm 2: Rate-of-change spike detection
	SpikeMultiplier float64 // trip if current_pps > baseline_pps * N
	BaselineWindow  int     // Number of samples for EMA baseline (default: 10)

	// Algorithm 3: SYN ratio (ratio of drops to rx — proxy for SYN flood)
	// Real SYN tracking would need a separate BPF map; this is an approximation
	DropRatioThreshold float64 // trip if dropped/rx_packets > threshold (0.0–1.0)

	// Algorithm 4: Error spike
	ParseErrorRateThreshold float64 // trip if parse_errors/rx_packets > threshold

	// Hysteresis: require N consecutive violations before tripping
	ConsecutiveViolations int

	// Hysteresis: require M consecutive clean samples before closing
	ConsecutiveClean int
}

func DefaultDetectorConfig() DetectorConfig {
	return DetectorConfig{
		PPSThreshold:            1_000_000,    // 1 Mpps
		BPSThreshold:            10_000_000_000, // 10 Gbps
		SpikeMultiplier:         5.0,          // 5× baseline = spike
		BaselineWindow:          10,
		DropRatioThreshold:      0.90,         // >90% drop rate = flood
		ParseErrorRateThreshold: 0.05,         // >5% parse errors = malformed flood
		ConsecutiveViolations:   3,
		ConsecutiveClean:        5,
	}
}

// ─── Detector ─────────────────────────────────────────────────────────────────
type Detector struct {
	cfg DetectorConfig

	// EMA baseline state
	emaPPS     float64
	emaBPS     float64
	emaAlpha   float64 // EMA smoothing factor: 2/(N+1)
	sampleCount int

	// Previous sample for delta computation
	prevStats   *bpfmaps.XdpStats
	prevAt      time.Time

	// Consecutive state counters
	cleanCount     int
}

func NewDetector(cfg DetectorConfig) *Detector {
	alpha := 2.0 / (float64(cfg.BaselineWindow) + 1.0)
	return &Detector{
		cfg:      cfg,
		emaAlpha: alpha,
	}
}

// UpdateThresholds hot-swaps the pps/bps thresholds used by checkAbsolute.
// Called from the engine's override path (applyOverride) which runs on the
// engine's single polling goroutine — same goroutine as Analyze, so no lock
// is needed here. EMA baseline state is preserved across the swap.
func (d *Detector) UpdateThresholds(pps, bps uint64) {
	d.cfg.PPSThreshold = pps
	d.cfg.BPSThreshold = bps
}

// ─── Sample Processing ────────────────────────────────────────────────────────

// Analyze processes one stats snapshot and returns all triggered detections.
// Called by the engine polling loop every tick.
func (d *Detector) Analyze(stats bpfmaps.XdpStats) []DetectionResult {
	now := time.Now()

	// ── Compute delta since last sample ──────────────────────────────────
	sample := d.buildSample(stats, now)
	d.prevStats = &stats
	d.prevAt    = now
	d.sampleCount++

	// Not enough history for rate-of-change algorithms
	if d.sampleCount < 2 {
		d.updateEMA(sample)
		return nil
	}

	var results []DetectionResult

	// ── Algorithm 1: Absolute Threshold ────────────────────────────────────
	if r := d.checkAbsolute(sample); r.Triggered {
		results = append(results, r)
	}

	// ── Algorithm 2: Rate-of-Change Spike ──────────────────────────────────
	if d.sampleCount >= d.cfg.BaselineWindow {
		if r := d.checkSpike(sample); r.Triggered {
			results = append(results, r)
		}
	}

	// ── Algorithm 3: Drop Ratio ─────────────────────────────────────────────
	if r := d.checkDropRatio(stats); r.Triggered {
		results = append(results, r)
	}

	// ── Algorithm 4: Parse Error Rate ──────────────────────────────────────
	if r := d.checkParseErrors(stats); r.Triggered {
		results = append(results, r)
	}

	// Update EMA after running algorithms (so baseline reflects prior samples)
	d.updateEMA(sample)

	return results
}

// ─── Algorithm 1: Absolute Threshold ─────────────────────────────────────────
func (d *Detector) checkAbsolute(s StatsSample) DetectionResult {
	pps := s.DeltaPPS
	bps := s.DeltaBPS

	if pps > d.cfg.PPSThreshold {
		return DetectionResult{
			Triggered:  true,
			Algorithm:  "absolute_pps",
			Reason:     fmt.Sprintf("pps=%d exceeds threshold=%d", pps, d.cfg.PPSThreshold),
			CurrentPPS: pps,
			CurrentBPS: bps,
			Confidence: math.Min(float64(pps)/float64(d.cfg.PPSThreshold), 1.0),
		}
	}
	if bps > d.cfg.BPSThreshold {
		return DetectionResult{
			Triggered:  true,
			Algorithm:  "absolute_bps",
			Reason:     fmt.Sprintf("bps=%d exceeds threshold=%d", bps, d.cfg.BPSThreshold),
			CurrentPPS: pps,
			CurrentBPS: bps,
			Confidence: math.Min(float64(bps)/float64(d.cfg.BPSThreshold), 1.0),
		}
	}
	return DetectionResult{Triggered: false}
}

// ─── Algorithm 2: Rate-of-Change Spike Detection ─────────────────────────────
func (d *Detector) checkSpike(s StatsSample) DetectionResult {
	if d.emaPPS < 1.0 {
		return DetectionResult{Triggered: false} // No baseline yet
	}

	ratio := float64(s.DeltaPPS) / d.emaPPS
	if ratio > d.cfg.SpikeMultiplier {
		return DetectionResult{
			Triggered:  true,
			Algorithm:  "rate_spike",
			Reason: fmt.Sprintf(
				"pps=%d is %.1fx above EMA baseline=%.0f (threshold=%.1fx)",
				s.DeltaPPS, ratio, d.emaPPS, d.cfg.SpikeMultiplier,
			),
			CurrentPPS: s.DeltaPPS,
			CurrentBPS: s.DeltaBPS,
			Confidence: math.Min((ratio-1.0)/(d.cfg.SpikeMultiplier-1.0), 1.0),
		}
	}
	return DetectionResult{Triggered: false}
}

// ─── Algorithm 3: Drop Ratio ──────────────────────────────────────────────────
func (d *Detector) checkDropRatio(stats bpfmaps.XdpStats) DetectionResult {
	if stats.RxPackets == 0 {
		return DetectionResult{Triggered: false}
	}
	totalDrops := stats.Dropped + stats.RateLimited + stats.FailsafeDrops
	ratio       := float64(totalDrops) / float64(stats.RxPackets)

	if ratio > d.cfg.DropRatioThreshold {
		return DetectionResult{
			Triggered:  true,
			Algorithm:  "drop_ratio",
			Reason: fmt.Sprintf(
				"drop_ratio=%.1f%% exceeds threshold=%.1f%% (drops=%d rx=%d)",
				ratio*100, d.cfg.DropRatioThreshold*100, totalDrops, stats.RxPackets,
			),
			CurrentPPS: 0,
			CurrentBPS: 0,
			Confidence: math.Min(ratio/d.cfg.DropRatioThreshold, 1.0),
		}
	}
	return DetectionResult{Triggered: false}
}

// ─── Algorithm 4: Parse Error Rate ───────────────────────────────────────────
// A high parse error rate indicates malformed packet floods (e.g. random bytes
// crafted to evade signature-based detection at the expense of valid headers).
func (d *Detector) checkParseErrors(stats bpfmaps.XdpStats) DetectionResult {
	if stats.RxPackets == 0 {
		return DetectionResult{Triggered: false}
	}
	errRate := float64(stats.ParseErrors) / float64(stats.RxPackets)

	if errRate > d.cfg.ParseErrorRateThreshold {
		return DetectionResult{
			Triggered:  true,
			Algorithm:  "parse_error_spike",
			Reason: fmt.Sprintf(
				"parse_error_rate=%.2f%% exceeds threshold=%.2f%%",
				errRate*100, d.cfg.ParseErrorRateThreshold*100,
			),
			Confidence: math.Min(errRate/d.cfg.ParseErrorRateThreshold, 1.0),
		}
	}
	return DetectionResult{Triggered: false}
}

// ─── EMA Update ───────────────────────────────────────────────────────────────
func (d *Detector) updateEMA(s StatsSample) {
	if d.sampleCount <= 1 {
		d.emaPPS = float64(s.DeltaPPS)
		d.emaBPS = float64(s.DeltaBPS)
	} else {
		d.emaPPS = d.emaAlpha*float64(s.DeltaPPS) + (1-d.emaAlpha)*d.emaPPS
		d.emaBPS = d.emaAlpha*float64(s.DeltaBPS) + (1-d.emaAlpha)*d.emaBPS
	}
}

// ─── Delta Builder ────────────────────────────────────────────────────────────
func (d *Detector) buildSample(stats bpfmaps.XdpStats, now time.Time) StatsSample {
	s := StatsSample{At: now, Stats: stats}

	if d.prevStats != nil && !d.prevAt.IsZero() {
		intervalSec := now.Sub(d.prevAt).Seconds()
		if intervalSec > 0 {
			// Packets and bytes SINCE last sample (delta of cumulative counters)
			deltaPkts := stats.RxPackets - d.prevStats.RxPackets
			deltaBytes := stats.RxBytes - d.prevStats.RxBytes

			s.DeltaPPS   = uint64(float64(deltaPkts)  / intervalSec)
			s.DeltaBPS   = uint64(float64(deltaBytes*8) / intervalSec)
			s.IntervalMs = intervalSec * 1000
		}
	}
	return s
}

// ─── Baseline Stats ───────────────────────────────────────────────────────────
type DetectorBaseline struct {
	EMAPPS      float64
	EMABPS      float64
	SampleCount int
}

func (d *Detector) Baseline() DetectorBaseline {
	return DetectorBaseline{
		EMAPPS:      d.emaPPS,
		EMABPS:      d.emaBPS,
		SampleCount: d.sampleCount,
	}
}
