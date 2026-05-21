//go:build linux
// +build linux

// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Zero-allocation control-plane primitives (control/failsafe.go).
//
//   This file provides six independent subsystems:
//
//   0. KernelVersionGuard — enforces Linux ≥ 5.6 before any BPF object loads.
//      BPF-to-BPF subprograms (#[inline(never)] in Rust/Aya) require 5.6+.
//      BPF_MAP_TYPE_BLOOM_FILTER requires 5.16+. CheckKernelVersion() must be
//      called as the first operation in falxd main() before any BPF syscall.
//
//   1. SPSCRing — Single-Producer Single-Consumer lock-free ring buffer.
//      [F3-C] Added `dropped cacheLinePadded` counter: each rejected Push()
//      call (ring full) atomically increments dropped, giving the consumer
//      goroutine exact visibility into back-pressure events at flood rates.
//
//   2. ThresholdSynchronizer — Atomic BPF map updater for SIGHUP hot-reload.
//
//   3. ELFVerifier — ECDSA/P-256 anti-tamper check for the compiled eBPF ELF.
//
//   4. GeoIPReader — Zero-allocation MaxMind MMDB IPv4 country-code lookup.
//
//   5. AmnestySweeeper — Async goroutine that purges expired BPF map entries.
//      Runs every 60 s. Scans BLOCKLIST_V4 (removes entries whose expire_at
//      has passed) and COOLING_TRACKER (removes entries idle for > 7.5 days).
//      Prevents LRU eviction thrashing during multi-day volumetric floods.
//      [F2-A] maxMMDBNodes = 1<<28 ceiling: nodeCount values above this limit
//        are rejected at Open() time, eliminating malicious B-tree offset
//        wrap-around via uint32 overflow in treeSize = nodeCount × bytesPerNode.
//      [F2-A] All B-tree size arithmetic uses uint64 before conversion.
//      [F2-B] buildISOTable and readRecord use uint64 for dataPos computation,
//        eliminating the uint32 overflow vector in `dataBase + 16 + idx`.
//        Also fixes a pre-existing off-by-16 bug: data record file offset is
//        `dataBase + idx`, not `dataBase + 16 + idx`.
//      [F2-C] decodeISOInMap caps entryCount at maxMMDBMapEntries = 64,
//        eliminating runaway startup loops on crafted MMDB with 16M-entry maps.
// =============================================================================

package control

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"

	"github.com/ft-1/falx-v2/control-plane/pkg/bpfmaps"
)

// ═══════════════════════════════════════════════════════════════════════════════
// § 0 — KERNEL VERSION GUARD [F1-C]
// ═══════════════════════════════════════════════════════════════════════════════
//
// CheckKernelVersion MUST be called before any BPF object is loaded into the
// kernel. It enforces a hard minimum version boundary by reading /proc/version.
//
// Rationale:
//   - Linux < 5.6:  BPF-to-BPF subprogram calls (apply_cooling_ban marked
//                   #[inline(never)]) are unsupported — program load fails.
//   - Linux < 5.16: BPF_MAP_TYPE_BLOOM_FILTER is unavailable — map creation
//                   fails silently, leaving BLOOM_FILTER in a broken state.
//
// The caller (falxd main) should call:
//   if err := control.CheckKernelVersion(control.MinKernelVersion); err != nil {
//       log.Fatal(err)
//   }

// kernelVersion represents a Linux kernel major.minor version pair.
type kernelVersion struct{ Major, Minor int }

// MinKernelVersion is the absolute minimum for FALX-V2 Phase-11.
// BPF_MAP_TYPE_BLOOM_FILTER (5.16) is the binding constraint.
var MinKernelVersion = kernelVersion{Major: 5, Minor: 16}

// BPFSubprogramVersion is the minimum for BPF-to-BPF calls (#[inline(never)]).
var BPFSubprogramVersion = kernelVersion{Major: 5, Minor: 6}

// CheckKernelVersion reads /proc/version and returns a non-nil error if the
// running Linux kernel version is older than required. It performs a safe abort:
// callers must treat any non-nil return as a fatal startup error.
func CheckKernelVersion(required kernelVersion) error {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return fmt.Errorf("CheckKernelVersion: read /proc/version: %w", err)
	}

	// /proc/version format: "Linux version 6.8.0-51-generic (buildd@...) ..."
	var major, minor int
	n, _ := fmt.Sscanf(string(data), "Linux version %d.%d", &major, &minor)
	if n < 2 {
		return fmt.Errorf("CheckKernelVersion: cannot parse kernel version from %q",
			truncate(string(data), 80))
	}

	if major < required.Major || (major == required.Major && minor < required.Minor) {
		return fmt.Errorf(
			"kernel %d.%d is below FALX-V2 Phase-11 minimum %d.%d "+
				"(BPF subprograms require ≥ 5.6; BPF_MAP_TYPE_BLOOM_FILTER requires ≥ 5.16)",
			major, minor, required.Major, required.Minor,
		)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ═══════════════════════════════════════════════════════════════════════════════
// § 1 — SPSC RING BUFFER
// ═══════════════════════════════════════════════════════════════════════════════

// RingCapacity is the number of slots in the ring. Must be a power of two.
// 16 384 slots × 128 bytes/slot = 2 MB — fits inside a typical L2 cache.
const (
	RingCapacity = 1 << 14 // 16 384
	ringMask     = RingCapacity - 1
)

// SpscMeta is a fixed-size, pointer-free snapshot of a parsed packet.
// All fields are scalar types or fixed-size byte arrays — no pointers.
// The GC never scans the [RingCapacity]SpscMeta array (invisible to GC).
// Layout: 128 bytes (two 64-byte cache lines).
type SpscMeta struct {
	SrcIP      [16]byte
	DstIP      [16]byte
	FlowID     uint64
	PktLen     uint32
	SrcPort    uint16
	DstPort    uint16
	TCPFlags   uint16
	Protocol   uint8
	IsIPv6     bool
	PayloadLen uint8
	_pad       [11]byte
	Payload    [64]byte
}

// cacheLinePadded wraps an atomic.Uint64 in an exclusive 64-byte cache line,
// preventing false sharing between the producer CPU (head) and consumer CPU (tail).
type cacheLinePadded struct {
	atomic.Uint64
	_ [56]byte // pad to 64 bytes: 8 (Uint64) + 56 = 64
}

// SPSCRing is a lock-free ring buffer with single-producer, single-consumer
// semantics. Push must be called from exactly one goroutine; Pop from exactly
// one (different) goroutine.
//
// Cache layout:
//   head    [64 bytes] — producer-owned
//   tail    [64 bytes] — consumer-owned
//   dropped [64 bytes] — producer-owned; [F3-C] counts full-ring drop events
//   slots   [2 MB]     — ring data
type SPSCRing struct {
	head    cacheLinePadded // written by producer, read by consumer
	tail    cacheLinePadded // written by consumer, read by producer
	dropped cacheLinePadded // [F3-C] written by producer on full-ring push failure
	slots   [RingCapacity]SpscMeta
}

// NewSPSCRing allocates a ring buffer. Only allocation in the ring's lifetime.
func NewSPSCRing() *SPSCRing { return new(SPSCRing) }

// Push inserts m into the ring. Returns false without blocking if the ring is
// full. [F3-C] On failure, atomically increments the dropped counter.
// Must be called from a single producer goroutine only.
func (r *SPSCRing) Push(m SpscMeta) bool {
	head := r.head.Load()
	if head-r.tail.Load() >= RingCapacity {
		// [F3-C] Ring is full. Count the drop so the consumer goroutine can
		// observe back-pressure without spinning or blocking.
		r.dropped.Add(1)
		return false
	}
	r.slots[head&ringMask] = m
	r.head.Store(head + 1)
	return true
}

// Pop removes and returns the oldest entry. Returns (zero, false) without
// blocking if the ring is empty. Must be called from a single consumer only.
func (r *SPSCRing) Pop() (SpscMeta, bool) {
	tail := r.tail.Load()
	if r.head.Load() == tail {
		return SpscMeta{}, false
	}
	m := r.slots[tail&ringMask]
	r.tail.Store(tail + 1)
	return m, true
}

// Len returns the approximate number of occupied slots.
func (r *SPSCRing) Len() int {
	head := r.head.Load()
	tail := r.tail.Load()
	if head >= tail {
		return int(head - tail)
	}
	return 0
}

// IsFull returns true if no slots are available.
func (r *SPSCRing) IsFull() bool {
	return r.head.Load()-r.tail.Load() >= RingCapacity
}

// DroppedCount returns the total number of Push calls rejected due to ring full.
// [F3-C] Read by the consumer goroutine or monitoring path to quantify
// back-pressure without requiring any mutex or channel overhead.
func (r *SPSCRing) DroppedCount() uint64 {
	return r.dropped.Load()
}

// FromAfxdpMeta converts an AF_XDP bridge PacketMeta into a pointer-free
// SpscMeta suitable for ring insertion.
func FromAfxdpMeta(src interface {
	GetSrcIP() []byte
	GetDstIP() []byte
	GetFlowID() uint64
	GetPktLen() uint32
	GetSrcPort() uint16
	GetDstPort() uint16
	GetTCPFlags() uint16
	GetProtocol() uint8
	GetIsIPv6() bool
	GetPayload() []byte
}) (SpscMeta, bool) {
	if src == nil {
		return SpscMeta{}, false
	}
	var m SpscMeta
	copy(m.SrcIP[:], src.GetSrcIP())
	copy(m.DstIP[:], src.GetDstIP())
	m.FlowID   = src.GetFlowID()
	m.PktLen   = src.GetPktLen()
	m.SrcPort  = src.GetSrcPort()
	m.DstPort  = src.GetDstPort()
	m.TCPFlags = src.GetTCPFlags()
	m.Protocol = src.GetProtocol()
	m.IsIPv6   = src.GetIsIPv6()
	n := copy(m.Payload[:], src.GetPayload())
	m.PayloadLen = uint8(n)
	return m, true
}

// ═══════════════════════════════════════════════════════════════════════════════
// § 2 — THRESHOLD SYNCHRONIZER (SyncFailsafeThresholds + SIGHUP watcher)
// ═══════════════════════════════════════════════════════════════════════════════

type thresholdSnapshot struct {
	PPS uint64
	BPS uint64
}

// ThresholdSynchronizer manages the SIGHUP-triggered BPF map update lifecycle.
// Zero value is invalid; use NewThresholdSynchronizer.
type ThresholdSynchronizer struct {
	snap atomic.Value // stores thresholdSnapshot
	mgr  *bpfmaps.Manager
	log  *zap.Logger
}

// NewThresholdSynchronizer constructs a synchronizer and performs an immediate
// eager sync to the kernel.
func NewThresholdSynchronizer(
	mgr *bpfmaps.Manager,
	initialPPS, initialBPS uint64,
	log *zap.Logger,
) (*ThresholdSynchronizer, error) {
	ts := &ThresholdSynchronizer{mgr: mgr, log: log}
	ts.snap.Store(thresholdSnapshot{PPS: initialPPS, BPS: initialBPS})
	if err := ts.SyncNow(); err != nil {
		return nil, fmt.Errorf("initial failsafe threshold sync: %w", err)
	}
	return ts, nil
}

// UpdateLocal atomically replaces the in-process threshold values.
func (ts *ThresholdSynchronizer) UpdateLocal(pps, bps uint64) {
	ts.snap.Store(thresholdSnapshot{PPS: pps, BPS: bps})
}

// SyncNow performs the atomic BPF map write with the current snapshot.
func (ts *ThresholdSynchronizer) SyncNow() error {
	s := ts.snap.Load().(thresholdSnapshot)
	if err := ts.mgr.UpdateFailsafeThresholds(s.PPS, s.BPS); err != nil {
		ts.log.Error("SyncFailsafeThresholds BPF write failed",
			zap.Uint64("pps", s.PPS),
			zap.Uint64("bps", s.BPS),
			zap.Error(err),
		)
		return fmt.Errorf("sync failsafe thresholds: %w", err)
	}
	ts.log.Info("Failsafe thresholds synced to kernel via BPF map",
		zap.Uint64("pps_threshold", s.PPS),
		zap.Uint64("bps_threshold", s.BPS),
	)
	return nil
}

// Watch starts a goroutine that calls SyncNow() on every SIGHUP signal.
// The goroutine exits when ctx is cancelled.
func (ts *ThresholdSynchronizer) Watch(ctx context.Context) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)

	go func() {
		defer signal.Stop(sigCh)
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigCh:
				ts.log.Info("SIGHUP received — syncing failsafe thresholds to kernel")
				if err := ts.SyncNow(); err != nil {
					ts.log.Error("SIGHUP threshold sync failed — kernel thresholds unchanged",
						zap.Error(err),
					)
				}
			}
		}
	}()
}

// SyncFailsafeThresholds is a standalone helper for tests and CLI tools.
func SyncFailsafeThresholds(
	mgr *bpfmaps.Manager,
	pps, bps uint64,
	log *zap.Logger,
) error {
	if err := mgr.UpdateFailsafeThresholds(pps, bps); err != nil {
		log.Error("SyncFailsafeThresholds failed",
			zap.Uint64("pps", pps), zap.Uint64("bps", bps), zap.Error(err))
		return fmt.Errorf("SyncFailsafeThresholds: %w", err)
	}
	log.Info("Failsafe thresholds written to BPF map",
		zap.Uint64("pps", pps), zap.Uint64("bps", bps))
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// § 3 — ELF OBJECT ANTI-TAMPER VERIFIER (ECDSA/P-256)
// ═══════════════════════════════════════════════════════════════════════════════

// embeddedPublicKeyHex is the hex-encoded DER SubjectPublicKeyInfo for the
// ECDSA P-256 signing public key. Replace with the output of:
//   openssl ec -in falx-signing.key -pubout -outform DER -out falx-signing.pub
//   xxd -p falx-signing.pub | tr -d '\n'
//
// !!DEVELOPMENT PLACEHOLDER — REPLACE BEFORE PRODUCTION DEPLOYMENT!!
const embeddedPublicKeyHex = "" +
	"3059301306072a8648ce3d020106082a8648ce3d03010703420004" +
	"b3a3f0c3e4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5" +
	"d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1"

type ecdsaSignature struct {
	R, S *big.Int
}

// ELFVerifier verifies the ECDSA-P256 signature of a compiled eBPF ELF object.
// Zero value is invalid; use NewELFVerifier.
type ELFVerifier struct {
	pubKey *ecdsa.PublicKey
	log    *zap.Logger
}

// NewELFVerifier parses the embedded P-256 public key and returns an ELFVerifier
// ready for use.
func NewELFVerifier(log *zap.Logger) (*ELFVerifier, error) {
	pubDER, err := hexDecode(embeddedPublicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("ELFVerifier: decode embedded public key hex: %w", err)
	}

	rawKey, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return nil, fmt.Errorf("ELFVerifier: parse PKIX public key: %w", err)
	}

	ecKey, ok := rawKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("ELFVerifier: embedded key is not an ECDSA key")
	}
	if ecKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("ELFVerifier: expected P-256 curve, got %s", ecKey.Params().Name)
	}

	return &ELFVerifier{pubKey: ecKey, log: log}, nil
}

// Verify reads elfPath and elfPath+".sig", computes SHA-256 over the ELF binary,
// and verifies the DER-encoded ECDSA signature. Fail-closed: callers MUST NOT
// load the ELF object if Verify returns a non-nil error.
func (v *ELFVerifier) Verify(elfPath string) error {
	elfData, err := os.ReadFile(elfPath)
	if err != nil {
		return fmt.Errorf("ELFVerifier.Verify: read ELF %q: %w", elfPath, err)
	}

	digest := sha256.Sum256(elfData)

	sigPath := elfPath + ".sig"
	sigDER, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("ELFVerifier.Verify: read signature %q: %w", sigPath, err)
	}

	var sig ecdsaSignature
	if rest, err := asn1.Unmarshal(sigDER, &sig); err != nil {
		return fmt.Errorf("ELFVerifier.Verify: parse DER signature: %w", err)
	} else if len(rest) != 0 {
		return fmt.Errorf("ELFVerifier.Verify: trailing bytes in signature file (%d bytes)", len(rest))
	}
	if sig.R == nil || sig.S == nil {
		return fmt.Errorf("ELFVerifier.Verify: signature R or S is nil")
	}

	if !ecdsa.Verify(v.pubKey, digest[:], sig.R, sig.S) {
		v.log.Error("ELF signature verification FAILED — refusing to load BPF object",
			zap.String("elf",    elfPath),
			zap.String("sig",    sigPath),
			zap.String("digest", fmt.Sprintf("%x", digest)),
		)
		return fmt.Errorf("ELFVerifier.Verify: invalid ECDSA signature for %q", filepath.Base(elfPath))
	}

	v.log.Info("ELF signature verified",
		zap.String("elf",    elfPath),
		zap.String("digest", fmt.Sprintf("sha256:%x", digest[:8])),
	)
	return nil
}

func hexDecode(h string) ([]byte, error) {
	if len(h)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex string")
	}
	b := make([]byte, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		hi, lo := fromHexNibble(h[i]), fromHexNibble(h[i+1])
		if hi > 15 || lo > 15 {
			return nil, fmt.Errorf("invalid hex character at offset %d", i)
		}
		b[i/2] = hi<<4 | lo
	}
	return b, nil
}

func fromHexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0xFF
}

// ═══════════════════════════════════════════════════════════════════════════════
// § 4 — GEOIP ZERO-ALLOCATION LOOKUP ENGINE (MaxMind MMDB)
// ═══════════════════════════════════════════════════════════════════════════════
//
// Security hardening applied in this implementation:
//
// [F2-A] maxMMDBNodes ceiling:
//   A malicious MMDB can encode nodeCount = 2^32−1 (max uint32). With
//   bytesPerNode = 8 (record_size=32), treeSize = (2^32−1)×8 overflows uint32
//   silently to a small number, making r.dataBase point deep into the mmap'd
//   file and allowing arbitrary data-section reads.
//   Fix: reject any nodeCount > maxMMDBNodes (= 1<<28 = 268M nodes) at Open()
//   time. Then perform ALL size arithmetic in uint64 and validate the result
//   fits in uint32 and within the actual file size before storing in r.dataBase.
//
// [F2-B] uint64 dataPos arithmetic in buildISOTable and readRecord:
//   `dataBase + idx` where both are uint32 can overflow for nodeCount near
//   uint32::MAX. All intermediate computations now use uint64.
//   Also fixes a pre-existing off-by-16 bug: the data record's file byte offset
//   is `r.dataBase + idx`, not `r.dataBase + 16 + idx`. (r.dataBase already
//   accounts for the 16-byte data-section separator in its value.)
//
// [F2-C] maxMMDBMapEntries cap in decodeISOInMap:
//   The MMDB data format encodes map sizes as 24-bit values, allowing up to
//   16 777 215 key-value pairs in a single map entry. A crafted MMDB with a
//   16M-entry country sub-map would loop for seconds at startup.
//   Fix: cap entryCount at maxMMDBMapEntries = 64 before entering the loop.

// maxMMDBNodes is the hard ceiling on MMDB nodeCount values. Any MMDB with
// more than 268M nodes is rejected at Open() time to prevent uint32 overflow
// in treeSize = nodeCount × bytesPerNode.
const maxMMDBNodes = uint32(1 << 28) // 268 435 456 nodes maximum

// maxMMDBMapEntries caps the iteration count in decodeISOInMap to prevent
// runaway startup loops on crafted MMDB databases with enormous map entries.
const maxMMDBMapEntries = 64

var mmdbMetaSep = []byte{
	0xAB, 0xCD, 0xEF,
	'M', 'a', 'x', 'M', 'i', 'n', 'd', '.', 'c', 'o', 'm',
}

type mmdbMeta struct {
	NodeCount  uint32
	RecordSize uint32
	IPVersion  uint32
}

// isoEntry stores a 2-byte ISO 3166-1 alpha-2 country code.
// Fixed-size array keeps isoTable pointer-free (GC-invisible).
type isoEntry = [2]byte

// GeoIPReader provides zero-allocation IPv4 country-code lookups.
type GeoIPReader struct {
	raw          []byte
	nodeCount    uint32
	recordSize   uint32
	bytesPerNode uint32
	dataBase     uint32   // byte offset of data section start (after 16-byte separator)
	isoTable     []isoEntry
	log          *zap.Logger
}

// OpenGeoIP opens and mmaps the MMDB file at dbPath, parses its metadata,
// validates nodeCount against maxMMDBNodes, and builds the ISO-code lookup table.
func OpenGeoIP(dbPath string, log *zap.Logger) (*GeoIPReader, error) {
	f, err := os.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("GeoIPReader.Open: %w", err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("GeoIPReader.Open: stat: %w", err)
	}
	size := int(fi.Size())
	if size < len(mmdbMetaSep)+1 {
		return nil, fmt.Errorf("GeoIPReader.Open: file too small (%d bytes)", size)
	}

	raw, err := syscall.Mmap(
		int(f.Fd()),
		0, size,
		syscall.PROT_READ,
		syscall.MAP_SHARED,
	)
	if err != nil {
		return nil, fmt.Errorf("GeoIPReader.Open: mmap: %w", err)
	}

	r := &GeoIPReader{raw: raw, log: log}

	meta, err := parseMeta(raw)
	if err != nil {
		_ = syscall.Munmap(raw)
		return nil, fmt.Errorf("GeoIPReader.Open: parse metadata: %w", err)
	}
	if meta.IPVersion != 4 && meta.IPVersion != 6 {
		_ = syscall.Munmap(raw)
		return nil, fmt.Errorf("GeoIPReader.Open: unsupported ip_version %d", meta.IPVersion)
	}
	if meta.RecordSize != 24 && meta.RecordSize != 28 && meta.RecordSize != 32 {
		_ = syscall.Munmap(raw)
		return nil, fmt.Errorf("GeoIPReader.Open: unsupported record_size %d", meta.RecordSize)
	}

	// [F2-A] Hard ceiling: reject maliciously large nodeCount values before any
	// arithmetic. Without this check, nodeCount near 2^32 causes uint32 overflow
	// in treeSize, making r.dataBase point to an arbitrary file location.
	if meta.NodeCount > maxMMDBNodes {
		_ = syscall.Munmap(raw)
		return nil, fmt.Errorf(
			"GeoIPReader.Open: nodeCount %d exceeds maximum allowed %d — refusing potentially malicious MMDB",
			meta.NodeCount, maxMMDBNodes,
		)
	}

	r.nodeCount    = meta.NodeCount
	r.recordSize   = meta.RecordSize
	r.bytesPerNode = (meta.RecordSize*2 + 7) / 8

	// [F2-A] Compute treeSize and dataBase in uint64 to detect overflow before
	// converting back to uint32. maxMMDBNodes = 1<<28, bytesPerNode ≤ 8:
	// max treeSize64 = (1<<28) * 8 = 1<<31 < 1<<32 (fits in uint32 safely).
	// dataBase64 = treeSize64 + 16 ≤ 1<<31 + 16, also fits.
	treeSize64 := uint64(r.nodeCount) * uint64(r.bytesPerNode)
	dataBase64 := treeSize64 + 16 // +16: skip the 16-byte data section separator

	if dataBase64 > uint64(len(raw)) {
		_ = syscall.Munmap(raw)
		return nil, fmt.Errorf(
			"GeoIPReader.Open: computed dataBase (%d) exceeds file size (%d)",
			dataBase64, len(raw),
		)
	}
	if dataBase64 > uint64(^uint32(0)) {
		_ = syscall.Munmap(raw)
		return nil, fmt.Errorf("GeoIPReader.Open: dataBase %d overflows uint32", dataBase64)
	}
	r.dataBase = uint32(dataBase64)

	if err := r.buildISOTable(); err != nil {
		_ = syscall.Munmap(raw)
		return nil, fmt.Errorf("GeoIPReader.Open: build ISO table: %w", err)
	}

	log.Info("GeoIPReader ready",
		zap.String("db",          dbPath),
		zap.Uint32("nodes",       r.nodeCount),
		zap.Uint32("record_bits", r.recordSize),
		zap.Int("iso_entries",    len(r.isoTable)),
	)
	return r, nil
}

// Close unmaps the MMDB file. Call only at daemon shutdown.
func (r *GeoIPReader) Close() error {
	if r.raw != nil {
		if err := syscall.Munmap(r.raw); err != nil {
			return fmt.Errorf("GeoIPReader.Close: munmap: %w", err)
		}
		r.raw = nil
	}
	return nil
}

// LookupIPv4 returns the ISO 3166-1 alpha-2 country code for the given IPv4
// address (big-endian / host byte order). ZERO heap allocations after Open().
func (r *GeoIPReader) LookupIPv4(ip uint32) (iso isoEntry, ok bool) {
	leaf := r.traverseTree(ip)

	if leaf <= r.nodeCount+15 {
		return isoEntry{}, false
	}

	idx := leaf - r.nodeCount - 16
	if idx >= uint32(len(r.isoTable)) {
		return isoEntry{}, false
	}

	entry := r.isoTable[idx]
	if entry == (isoEntry{}) {
		return isoEntry{}, false
	}
	return entry, true
}

// traverseTree walks the MMDB binary search tree for a 32-bit IPv4 address.
// Traverses bits MSB→LSB. Zero heap allocations.
func (r *GeoIPReader) traverseTree(ip uint32) uint32 {
	node := uint32(0)
	for bit := 31; bit >= 0; bit-- {
		direction := (ip >> uint(bit)) & 1
		node = r.readRecord(node, direction)
		if node >= r.nodeCount {
			return node
		}
	}
	return node
}

// readRecord extracts the left (direction=0) or right (direction=1) record
// value for the given B-tree node. Uses raw pointer arithmetic on the mmap'd
// byte slice.
//
// [F2-A] Bounds check uses uint64 arithmetic to prevent `node * bytesPerNode`
// uint32 overflow on crafted nodeCount values that pass the maxMMDBNodes check
// but are still large enough to cause overflow when multiplied by bytesPerNode.
// (maxMMDBNodes * maxBytesPerNode = 1<<28 * 8 = 1<<31, which fits in uint32,
// but we use uint64 defensively throughout the computation chain.)
func (r *GeoIPReader) readRecord(node, direction uint32) uint32 {
	// [F2-A] uint64 arithmetic for bounds guard.
	base64 := uint64(node) * uint64(r.bytesPerNode)
	if base64+uint64(r.bytesPerNode) > uint64(r.dataBase) {
		return r.nodeCount // sentinel: "no data"
	}
	base := uint32(base64) // safe: validated above
	raw  := r.raw

	switch r.recordSize {
	case 24:
		// Node: [left_hi, left_mid, left_lo, right_hi, right_mid, right_lo]
		p := unsafe.Pointer(&raw[base])
		if direction == 0 {
			return uint32(*(*uint8)(p))<<16 |
				uint32(*(*uint8)(unsafe.Add(p, 1)))<<8 |
				uint32(*(*uint8)(unsafe.Add(p, 2)))
		}
		return uint32(*(*uint8)(unsafe.Add(p, 3)))<<16 |
			uint32(*(*uint8)(unsafe.Add(p, 4)))<<8 |
			uint32(*(*uint8)(unsafe.Add(p, 5)))

	case 28:
		// 7-byte nibble-packed layout:
		//   Bytes 0-2: bits 27-4 of left record
		//   Byte  3:   high nibble = bits 3-0 of left; low nibble = bits 27-24 of right
		//   Bytes 4-6: bits 23-0 of right record
		p   := unsafe.Pointer(&raw[base])
		mid := uint32(*(*uint8)(unsafe.Add(p, 3)))
		if direction == 0 {
			return (mid&0xF0)<<20 |
				uint32(*(*uint8)(p))<<16 |
				uint32(*(*uint8)(unsafe.Add(p, 1)))<<8 |
				uint32(*(*uint8)(unsafe.Add(p, 2)))
		}
		return (mid&0x0F)<<24 |
			uint32(*(*uint8)(unsafe.Add(p, 4)))<<16 |
			uint32(*(*uint8)(unsafe.Add(p, 5)))<<8 |
			uint32(*(*uint8)(unsafe.Add(p, 6)))

	case 32:
		p := unsafe.Pointer(&raw[base])
		if direction == 0 {
			return binary.BigEndian.Uint32(
				(*[4]byte)(unsafe.Slice((*byte)(p), 4))[:],
			)
		}
		p4 := unsafe.Add(p, 4)
		return binary.BigEndian.Uint32(
			(*[4]byte)(unsafe.Slice((*byte)(p4), 4))[:],
		)
	}

	return r.nodeCount
}

// buildISOTable performs an iterative B-tree DFS at startup to enumerate all
// reachable leaf values, decode their MMDB data records, and build the flat
// isoTable slice indexed by (leafValue − nodeCount − 16).
//
// [F2-B] All intermediate index and offset arithmetic uses uint64 to eliminate
// overflow for nodeCount values close to maxMMDBNodes.
//
// Bug fix: the data record file offset is `r.dataBase + idx` (not
// `r.dataBase + 16 + idx`). r.dataBase already includes the 16-byte separator
// offset (dataBase = nodeCount * bytesPerNode + 16). The extra +16 in the
// previous implementation would have landed 16 bytes past the correct record.
func (r *GeoIPReader) buildISOTable() error {
	type frame struct{ node uint32 }

	visitedNodes := make(map[uint32]struct{}, r.nodeCount/4)
	leafSet      := make(map[uint32]struct{}, 4096)
	stack        := make([]frame, 0, 64)
	stack         = append(stack, frame{0})

	for len(stack) > 0 {
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if _, seen := visitedNodes[top.node]; seen {
			continue
		}
		visitedNodes[top.node] = struct{}{}

		for dir := uint32(0); dir <= 1; dir++ {
			child := r.readRecord(top.node, dir)
			if child >= r.nodeCount {
				if child >= r.nodeCount+16 {
					leafSet[child] = struct{}{}
				}
			} else {
				stack = append(stack, frame{child})
			}
		}
	}

	if len(leafSet) == 0 {
		r.isoTable = nil
		return nil
	}

	// [F2-B] Compute maxIdx in uint64 to prevent overflow.
	var maxIdx64 uint64
	for leaf := range leafSet {
		// leafSet only contains leaves >= nodeCount+16, so this subtraction is safe.
		idx64 := uint64(leaf) - uint64(r.nodeCount) - 16
		if idx64 > maxIdx64 {
			maxIdx64 = idx64
		}
	}
	if maxIdx64 > uint64(^uint32(0)) {
		return fmt.Errorf("GeoIPReader: ISO table index %d overflows uint32", maxIdx64)
	}
	maxIdx := uint32(maxIdx64)

	r.isoTable = make([]isoEntry, maxIdx+1)

	for leaf := range leafSet {
		idx64 := uint64(leaf) - uint64(r.nodeCount) - 16

		// [F2-B] dataPos uses uint64 arithmetic.
		// Correct formula: r.dataBase + idx
		// (r.dataBase = nodeCount*bytesPerNode + 16 = start of data section;
		//  idx = leaf - nodeCount - 16 = byte offset within data section)
		dataPos64 := uint64(r.dataBase) + idx64
		if dataPos64 >= uint64(len(r.raw)) {
			continue
		}

		idx := uint32(idx64)
		if idx >= uint32(len(r.isoTable)) {
			continue
		}
		r.isoTable[idx] = r.decodeISOCode(int(dataPos64))
	}

	return nil
}

// decodeISOCode navigates the MMDB data record at pos to extract the
// country.iso_code UTF-8 string value. Returns a zero [2]byte if not found.
// Called only during buildISOTable() at startup — allocations acceptable.
func (r *GeoIPReader) decodeISOCode(pos int) isoEntry {
	data := r.raw
	n    := len(data)

	dtype, mapSize, adv := mmdbCtrl(data, pos)
	if dtype != mmdbTypeMap || adv == 0 {
		return isoEntry{}
	}
	pos += adv

	for i := 0; i < mapSize && pos < n; i++ {
		kdtype, klen, kadv := mmdbCtrl(data, pos)
		pos += kadv
		if kdtype != mmdbTypeUTF8 || pos+klen > n {
			return isoEntry{}
		}
		key := data[pos : pos+klen]
		pos += klen

		vdtype, vsize, vadv := mmdbCtrl(data, pos)
		pos += vadv

		if mmdbBytesEqual(key, "country") && vdtype == mmdbTypeMap {
			return r.decodeISOInMap(pos, vsize)
		}

		pos = r.skipMMDBValue(pos, vdtype, vsize)
	}
	return isoEntry{}
}

// decodeISOInMap searches a decoded map for an "iso_code" UTF-8 string field.
//
// [F2-C] entryCount is capped at maxMMDBMapEntries = 64 before entering the
// loop to prevent runaway iteration on crafted MMDB databases encoding a
// country sub-map with up to 16 777 215 entries (the MMDB 24-bit size limit).
func (r *GeoIPReader) decodeISOInMap(pos, entryCount int) isoEntry {
	// [F2-C] Hard cap: a real country record has at most a handful of fields.
	// Iterating more than 64 entries on a legitimate MMDB is impossible.
	if entryCount > maxMMDBMapEntries {
		entryCount = maxMMDBMapEntries
	}

	data := r.raw
	n    := len(data)

	for i := 0; i < entryCount && pos < n; i++ {
		kdtype, klen, kadv := mmdbCtrl(data, pos)
		pos += kadv
		if kdtype != mmdbTypeUTF8 || pos+klen > n {
			return isoEntry{}
		}
		key := data[pos : pos+klen]
		pos += klen

		vdtype, vsize, vadv := mmdbCtrl(data, pos)
		pos += vadv

		if mmdbBytesEqual(key, "iso_code") && vdtype == mmdbTypeUTF8 && vsize >= 2 {
			if pos+2 <= n {
				var iso isoEntry
				iso[0] = data[pos]
				iso[1] = data[pos+1]
				return iso
			}
		}

		pos = r.skipMMDBValue(pos, vdtype, vsize)
	}
	return isoEntry{}
}

// skipMMDBValue advances pos past the MMDB data value of (dtype, size).
func (r *GeoIPReader) skipMMDBValue(pos, dtype, size int) int {
	data := r.raw
	n    := len(data)

	switch dtype {
	case mmdbTypeUTF8, mmdbTypeBytes:
		return pos + size
	case mmdbTypeUint16, mmdbTypeUint32, mmdbTypeUint64, mmdbTypeUint128,
		mmdbTypeInt32, mmdbTypeDouble, mmdbTypeFloat:
		return pos + size
	case mmdbTypeBool:
		return pos
	case mmdbTypeMap:
		for i := 0; i < size && pos < n; i++ {
			_, klen, kadv := mmdbCtrl(data, pos)
			pos += kadv + klen
			vdtype, vsize, vadv := mmdbCtrl(data, pos)
			pos += vadv
			pos = r.skipMMDBValue(pos, vdtype, vsize)
		}
		return pos
	case mmdbTypeArray:
		for i := 0; i < size && pos < n; i++ {
			vdtype, vsize, vadv := mmdbCtrl(data, pos)
			pos += vadv
			pos = r.skipMMDBValue(pos, vdtype, vsize)
		}
		return pos
	case mmdbTypePointer:
		return pos + size
	}
	return pos
}

// ─── MMDB Data Encoding Constants ────────────────────────────────────────────

const (
	mmdbTypePointer  = 1
	mmdbTypeUTF8     = 2
	mmdbTypeDouble   = 3
	mmdbTypeBytes    = 4
	mmdbTypeUint16   = 5
	mmdbTypeUint32   = 6
	mmdbTypeMap      = 7
	mmdbTypeInt32    = 8
	mmdbTypeUint64   = 9
	mmdbTypeUint128  = 10
	mmdbTypeArray    = 11
	mmdbTypeBool     = 14
	mmdbTypeFloat    = 15
)

// mmdbCtrl reads an MMDB data control byte sequence and returns
// (dataType, size, bytesConsumed).
func mmdbCtrl(data []byte, pos int) (dtype, size, adv int) {
	n := len(data)
	if pos >= n {
		return -1, 0, 0
	}

	b   := int(data[pos])
	adv  = 1
	pos++

	dtype = b >> 5
	if dtype == 0 {
		if pos >= n {
			return -1, 0, 0
		}
		dtype = int(data[pos]) + 7
		adv++
		pos++
	}

	rawSz := b & 0x1F
	switch {
	case rawSz < 29:
		size = rawSz
	case rawSz == 29:
		if pos >= n {
			return -1, 0, 0
		}
		size = int(data[pos]) + 29
		adv++
	case rawSz == 30:
		if pos+1 >= n {
			return -1, 0, 0
		}
		size = (int(data[pos])<<8 | int(data[pos+1])) + 285
		adv += 2
	case rawSz == 31:
		if pos+2 >= n {
			return -1, 0, 0
		}
		size = (int(data[pos])<<16 | int(data[pos+1])<<8 | int(data[pos+2])) + 65821
		adv += 3
	}
	return dtype, size, adv
}

// mmdbBytesEqual compares a byte slice to a string without allocation.
func mmdbBytesEqual(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	bstr := *(*string)(unsafe.Pointer(&b))
	return bstr == s
}

// ─── MMDB Metadata Parser ────────────────────────────────────────────────────

func parseMeta(raw []byte) (mmdbMeta, error) {
	idx := bytes.LastIndex(raw, mmdbMetaSep)
	if idx < 0 {
		return mmdbMeta{}, fmt.Errorf("metadata separator not found — not a valid MMDB file")
	}

	metaStart := idx + len(mmdbMetaSep)
	if metaStart >= len(raw) {
		return mmdbMeta{}, fmt.Errorf("metadata separator at end of file with no metadata following")
	}

	return decodeMetaRecord(raw, metaStart)
}

func decodeMetaRecord(raw []byte, pos int) (mmdbMeta, error) {
	var meta mmdbMeta
	n := len(raw)

	dtype, mapSize, adv := mmdbCtrl(raw, pos)
	if dtype != mmdbTypeMap {
		return meta, fmt.Errorf("expected metadata map (type 7), got type %d", dtype)
	}
	pos += adv

	for i := 0; i < mapSize && pos < n; i++ {
		kdtype, klen, kadv := mmdbCtrl(raw, pos)
		pos += kadv
		if kdtype != mmdbTypeUTF8 || pos+klen > n {
			return meta, fmt.Errorf("unexpected key type %d in metadata", kdtype)
		}
		key := raw[pos : pos+klen]
		pos += klen

		vdtype, vsize, vadv := mmdbCtrl(raw, pos)
		valPos := pos + vadv
		pos = valPos

		switch {
		case mmdbBytesEqual(key, "node_count") && (vdtype == mmdbTypeUint32 || vdtype == mmdbTypeUint16):
			meta.NodeCount = uint32(readBigEndianN(raw, valPos, vsize))
		case mmdbBytesEqual(key, "record_size") && (vdtype == mmdbTypeUint32 || vdtype == mmdbTypeUint16):
			meta.RecordSize = uint32(readBigEndianN(raw, valPos, vsize))
		case mmdbBytesEqual(key, "ip_version") && (vdtype == mmdbTypeUint32 || vdtype == mmdbTypeUint16):
			meta.IPVersion = uint32(readBigEndianN(raw, valPos, vsize))
		}

		pos += vsize
	}

	if meta.NodeCount == 0 {
		return meta, fmt.Errorf("metadata missing or zero node_count")
	}
	if meta.RecordSize == 0 {
		return meta, fmt.Errorf("metadata missing or zero record_size")
	}
	return meta, nil
}

func readBigEndianN(data []byte, pos, n int) uint64 {
	var v uint64
	for i := 0; i < n && pos+i < len(data); i++ {
		v = (v << 8) | uint64(data[pos+i])
	}
	return v
}

// ═══════════════════════════════════════════════════════════════════════════════
// § 5 — AMNESTY SWEEPER (Asynchronous BPF Map Garbage Collector)
// ═══════════════════════════════════════════════════════════════════════════════
//
// AmnestySweeeper runs every 60 seconds and purges two BPF LRU hash maps:
//
//   BLOCKLIST_V4    — removes entries whose expire_at (Unix seconds) has passed.
//                     Permanent entries (expire_at == 0) are never touched.
//
//   COOLING_TRACKER — removes entries whose last_ban_at_ns (CLOCK_MONOTONIC ns)
//                     is older than maxCoolingBanNs (10 × 2^16 s ≈ 7.5 days).
//                     An entry that old cannot produce a valid future ban window.
//
// Design invariants:
//   - Two-pass per map: collect stale keys → delete. Never modifies a map while
//     iterating (ebpf-go's MapIterator uses GET_NEXT_KEY, which is undefined
//     during concurrent deletes; the collect-then-delete pattern is safe).
//   - Monotonic clock (CLOCK_MONOTONIC via syscall.ClockGettime) is used for
//     COOLING_TRACKER because BPF's bpf_ktime_get_ns() returns CLOCK_MONOTONIC
//     nanoseconds, not Unix epoch. Wall clock (time.Now().Unix()) is used for
//     BLOCKLIST_V4 because XDP writes expire_at as Unix seconds.
//   - SweepStats are written under a mutex; Stats() provides a snapshot without
//     blocking the sweep goroutine.
//   - Context-cancellable: exits cleanly when ctx is done.

// sweepBlockEntry mirrors the BPF BlockEntry layout (repr(C), 16 bytes).
// ABI: MUST match ebpf-kern/src/types.rs BlockEntry exactly.
type sweepBlockEntry struct {
	ExpireAt    uint64
	Action      uint8
	RuleID      uint8
	ThreatScore uint8
	Pad         uint8
	Reason      uint32
}

// sweepCoolingEntry mirrors the BPF CoolingEntry layout (Option B, 16 bytes).
// ABI: MUST match ebpf-kern/src/types.rs CoolingEntry (no bpf_spin_lock).
type sweepCoolingEntry struct {
	RepeatCount uint32
	Pad         uint32
	LastBanAtNs uint64
}

// maxCoolingBanNs is the maximum ban duration at r=MAX_COOLING_SHIFT (16):
//   T_ban = 10 × 2^16 = 655 360 s, expressed in nanoseconds.
// A COOLING_TRACKER entry older than this is definitively stale.
const maxCoolingBanNs = uint64(655_360) * 1_000_000_000

// SweepStats captures cumulative metrics across all sweep passes.
type SweepStats struct {
	BlocklistPurged  uint64        // total BLOCKLIST_V4 entries deleted
	CoolingPurged    uint64        // total COOLING_TRACKER entries deleted
	SweepErrors      uint64        // iterator or delete errors (non-fatal)
	TotalSweeps      uint64        // completed passes
	LastSweepAt      time.Time     // wall clock of most recent sweep start
	LastSweepElapsed time.Duration // duration of most recent sweep
}

// AmnestySweeeper periodically reclaims expired BPF LRU map slots, preventing
// the kernel LRU from thrashing hot entries during multi-day volumetric attacks.
type AmnestySweeeper struct {
	blocklistV4    *ebpf.Map
	coolingTracker *ebpf.Map
	interval       time.Duration
	mu             sync.Mutex
	stats          SweepStats
	log            *zap.Logger
}

// NewAmnestySweeeper constructs a sweeper targeting the two given BPF maps.
// Call Start(ctx) once to launch the background goroutine.
// Recommended interval: 60 * time.Second.
func NewAmnestySweeeper(
	blocklistV4, coolingTracker *ebpf.Map,
	interval time.Duration,
	log *zap.Logger,
) *AmnestySweeeper {
	return &AmnestySweeeper{
		blocklistV4:    blocklistV4,
		coolingTracker: coolingTracker,
		interval:       interval,
		log:            log,
	}
}

// Start launches the sweep goroutine. Returns immediately.
// The goroutine exits when ctx is cancelled. Call exactly once.
func (s *AmnestySweeeper) Start(ctx context.Context) {
	go s.run(ctx)
}

func (s *AmnestySweeeper) run(ctx context.Context) {
	s.log.Info("AmnestySweeeper started", zap.Duration("interval", s.interval))
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.sweep()
		case <-ctx.Done():
			s.log.Info("AmnestySweeeper stopped")
			return
		}
	}
}

// sweep performs one full garbage-collection pass over both maps.
func (s *AmnestySweeeper) sweep() {
	start := time.Now()
	nowS  := uint64(start.Unix())

	// Read CLOCK_MONOTONIC for the cooling tracker comparison.
	// bpf_ktime_get_ns() returns CLOCK_MONOTONIC nanoseconds, so we must use
	// the same clock — not Unix wall clock — for last_ban_at_ns comparisons.
	nowNs := monotonicNs()

	blPurged, blErrs := s.sweepBlocklist(nowS)
	clPurged, clErrs := s.sweepCooling(nowNs)
	elapsed := time.Since(start)

	s.log.Info("AmnestySweeeper pass",
		zap.Uint64("blocklist_purged", blPurged),
		zap.Uint64("cooling_purged",   clPurged),
		zap.Uint64("errors",           blErrs+clErrs),
		zap.Duration("elapsed",        elapsed),
	)

	s.mu.Lock()
	s.stats.BlocklistPurged  += blPurged
	s.stats.CoolingPurged    += clPurged
	s.stats.SweepErrors      += blErrs + clErrs
	s.stats.TotalSweeps++
	s.stats.LastSweepAt      = start
	s.stats.LastSweepElapsed = elapsed
	s.mu.Unlock()
}

// sweepBlocklist collects and deletes BLOCKLIST_V4 entries past their TTL.
// Returns (purged count, error count).
func (s *AmnestySweeeper) sweepBlocklist(nowS uint64) (uint64, uint64) {
	var (
		key   uint32
		val   sweepBlockEntry
		stale []uint32
		errs  uint64
	)

	iter := s.blocklistV4.Iterate()
	for iter.Next(&key, &val) {
		// expire_at == 0 → permanent block; never purge.
		if val.ExpireAt != 0 && val.ExpireAt <= nowS {
			stale = append(stale, key)
		}
	}
	if err := iter.Err(); err != nil {
		s.log.Warn("BLOCKLIST_V4 iterate error", zap.Error(err))
		errs++
	}

	var purged uint64
	for _, k := range stale {
		if err := s.blocklistV4.Delete(k); err == nil {
			purged++
		} else {
			errs++
		}
	}
	return purged, errs
}

// sweepCooling collects and deletes COOLING_TRACKER entries older than the
// maximum possible ban window (maxCoolingBanNs ≈ 7.5 days in CLOCK_MONOTONIC ns).
// Returns (purged count, error count).
func (s *AmnestySweeeper) sweepCooling(nowNs uint64) (uint64, uint64) {
	var (
		key   uint32
		val   sweepCoolingEntry
		stale []uint32
		errs  uint64
	)

	iter := s.coolingTracker.Iterate()
	for iter.Next(&key, &val) {
		// Guard against clock skew / fresh zero-valued entries.
		if val.LastBanAtNs > 0 &&
			nowNs > val.LastBanAtNs &&
			nowNs-val.LastBanAtNs > maxCoolingBanNs {
			stale = append(stale, key)
		}
	}
	if err := iter.Err(); err != nil {
		s.log.Warn("COOLING_TRACKER iterate error", zap.Error(err))
		errs++
	}

	var purged uint64
	for _, k := range stale {
		if err := s.coolingTracker.Delete(k); err == nil {
			purged++
		} else {
			errs++
		}
	}
	return purged, errs
}

// Stats returns a point-in-time snapshot of cumulative sweep statistics.
func (s *AmnestySweeeper) Stats() SweepStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// monotonicNs returns the current CLOCK_MONOTONIC time in nanoseconds.
// This matches the clock used by the BPF helper bpf_ktime_get_ns(), making
// it correct for comparing against last_ban_at_ns values in COOLING_TRACKER.
// Uses golang.org/x/sys/unix (already a transitive dep of cilium/ebpf).
func monotonicNs() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		// Extremely unlikely on Linux; fall back to wall-clock nanoseconds.
		// The sweep will be conservative (may retain entries slightly longer).
		return uint64(time.Now().UnixNano())
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}
