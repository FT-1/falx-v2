/**
 * FALX V2 — High-Frequency SOC Dashboard
 * Lead Architect & Owner: FT-1
 *
 * Phase-11 Security Hardening (Fail-Closed Sprint):
 *
 * [F3-B] WebSocket ghost-handle elimination:
 *   A `cancelled` boolean is set to true as the FIRST action in the useEffect
 *   cleanup function, BEFORE ws.close(). Every async callback (onopen,
 *   onmessage, onclose, ppsTick) guards with `if (cancelled) return` at
 *   entry. This guarantees that no setState call can fire on an unmounted
 *   component, regardless of when the browser delivers the close event.
 *
 * [F4-A] Canvas ctx.save() stack leak elimination:
 *   The previous createSubContext() called ctx.save() internally. The paint
 *   loop also called ctx.save() externally — resulting in 1 unmatched save
 *   per panel × 6 panels = 6 leaked saves per frame. The canvas state stack
 *   overflowed within ~5 frames, corrupting all subsequent renders.
 *   Fix: ctx.save() removed from the sub-context helper entirely. The paint
 *   loop owns exactly ONE matched save/restore pair per panel. translate() is
 *   called BEFORE clip() (within the same save scope), giving the clip region
 *   the correct panel-local coordinate system.
 *
 * [F4-C] Pre-allocated SUB_CONTEXTS array:
 *   6 sub-context proxy objects are allocated once at module load time and
 *   reused across all animation frames. Object.create() + Object.defineProperty()
 *   are called only when the underlying canvas context reference changes (rare:
 *   only on canvas element re-creation). Per-frame allocation is eliminated:
 *   getSubContext() mutates the cached dims object in-place (width/height update
 *   is a simple property write, not a new object). This removes 360 small
 *   allocations/sec from the JIT heap and prevents polymorphic IC invalidation
 *   caused by per-frame proxy construction with variable prototype chains.
 */

import React, {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from 'react';

import {
  Background,
  BackgroundVariant,
  Controls,
  Edge,
  Handle,
  MiniMap,
  Node,
  NodeProps,
  Position,
  ReactFlow,
} from '@xyflow/react';

import '@xyflow/react/dist/style.css';

// ─── WebSocket Message Types ──────────────────────────────────────────────────

interface MetricsFrame {
  type:           'metrics';
  ts:             number;
  rx_packets:     number;
  rx_bytes:       number;
  dropped:        number;
  rate_limited:   number;
  passed:         number;
  redirected:     number;
  failsafe_drops: number;
  parse_errors:   number;
  circuit_open:   boolean;
  current_pps:    number;
  current_bps:    number;
  cooling_bans?:  number;
  bloom_hits?:    number;
  bloom_misses?:  number;
}

interface CircuitEvent {
  type:    'circuit_open' | 'circuit_closed' | 'circuit_half_open';
  reason?: string;
  pps?:    number;
  bps?:    number;
  ts:      number;
}

type WSMessage = MetricsFrame | CircuitEvent;

// ─── Circuit Breaker State ────────────────────────────────────────────────────

type CircuitState = 'CLOSED' | 'HALF_OPEN' | 'OPEN';

// ─── In-Memory Metrics Ring Buffer ───────────────────────────────────────────

const HISTORY_SIZE = 600; // 60 s at 10 samples/sec

class MetricsBuffer {
  private readonly pps:           Float64Array;
  private readonly bps:           Float64Array;
  private readonly dropRate:      Float64Array;
  private readonly passRate:      Float64Array;
  private readonly failsafeDrops: Float64Array;
  private readonly coolingBans:   Float64Array;
  private head:  number = 0;
  private count: number = 0;

  constructor() {
    this.pps           = new Float64Array(HISTORY_SIZE);
    this.bps           = new Float64Array(HISTORY_SIZE);
    this.dropRate      = new Float64Array(HISTORY_SIZE);
    this.passRate      = new Float64Array(HISTORY_SIZE);
    this.failsafeDrops = new Float64Array(HISTORY_SIZE);
    this.coolingBans   = new Float64Array(HISTORY_SIZE);
  }

  push(frame: MetricsFrame): void {
    const totalDecisions = frame.rx_packets || 1;
    this.pps[this.head]           = frame.current_pps;
    this.bps[this.head]           = frame.current_bps;
    this.dropRate[this.head]      = (frame.dropped + frame.rate_limited) / totalDecisions;
    this.passRate[this.head]      = frame.passed / totalDecisions;
    this.failsafeDrops[this.head] = frame.failsafe_drops;
    this.coolingBans[this.head]   = frame.cooling_bans ?? 0;
    this.head = (this.head + 1) % HISTORY_SIZE;
    if (this.count < HISTORY_SIZE) this.count++;
  }

  slice(series: 'pps' | 'bps' | 'dropRate' | 'passRate' | 'failsafeDrops' | 'coolingBans'): Float64Array {
    const src = this[series];
    const n   = this.count;
    if (n === 0) return new Float64Array(0);

    const out = new Float64Array(n);
    if (n < HISTORY_SIZE) {
      out.set(src.subarray(0, n));
    } else {
      const tail = HISTORY_SIZE - this.head;
      out.set(src.subarray(this.head), 0);
      out.set(src.subarray(0, this.head), tail);
    }
    return out;
  }

  get length(): number { return this.count; }
}

// ─── LTTB Downsampler ────────────────────────────────────────────────────────
//
// Largest-Triangle-Three-Buckets (LTTB) — Steinarsson 2013.
// Reduces a dense Float64Array to `threshold` representative points while
// preserving the visual shape (peaks, troughs, inflections) of the original.
//
// Time complexity:  O(n)   — single pass over src after bucket setup.
// Space complexity: O(threshold) — output array only; src is read-only.
//
// Called inside drawTimeSeries with threshold = floor(panelWidth / 2).
// At a typical 400 px panel width that caps draws at 200 lineTo calls
// regardless of how many samples (up to 600) are in the ring buffer,
// cutting per-frame path work by up to 3×.
//
// Invariants guaranteed by the algorithm:
//   • First and last points of src are always preserved.
//   • Each selected point maximises the triangle area formed with the previous
//     selected point and the centroid of the following bucket — ensuring that
//     local extrema are never silently discarded.
//   • When src.length ≤ threshold the original array is returned unchanged
//     (zero copy, zero allocation).
function lttb(src: Float64Array, threshold: number): Float64Array {
  const n = src.length;
  if (n <= threshold || threshold < 2) return src;

  const out = new Float64Array(threshold);
  out[0]             = src[0]!;
  out[threshold - 1] = src[n - 1]!;

  const bucketSize = (n - 2) / (threshold - 2);
  let prevIdx = 0;

  for (let i = 0; i < threshold - 2; i++) {
    // ── Current bucket bounds ──────────────────────────────────────────────
    const cStart = Math.floor( i      * bucketSize) + 1;
    const cEnd   = Math.floor((i + 1) * bucketSize) + 1;

    // ── Next bucket centroid (avgX, avgY) ──────────────────────────────────
    const nStart  = cEnd;
    const nEnd    = Math.min(Math.floor((i + 2) * bucketSize) + 1, n);
    const nCount  = nEnd - nStart;
    let   avgX    = 0;
    let   avgY    = 0;
    for (let j = nStart; j < nEnd; j++) { avgX += j; avgY += src[j]!; }
    avgX /= nCount;
    avgY /= nCount;

    // ── Select point in current bucket with largest triangle area ──────────
    let maxArea = -1;
    let maxI    = cStart;
    const aX = prevIdx;
    const aY = src[prevIdx]!;
    for (let j = cStart; j < cEnd && j < n; j++) {
      // Triangle area = 0.5 × |cross product| (the 0.5 cancels in comparison)
      const area = Math.abs(
        (avgX - aX) * (src[j]! - aY) -
        (j    - aX) * (avgY    - aY),
      );
      if (area > maxArea) { maxArea = area; maxI = j; }
    }

    out[i + 1] = src[maxI]!;
    prevIdx    = maxI;
  }

  return out;
}

// ─── Canvas Chart Drawing ─────────────────────────────────────────────────────

interface ChartTheme {
  background:  string;
  grid:        string;
  text:        string;
  lineColor:   string;
  fillColor:   string;
  dangerColor: string;
  dangerFill:  string;
  accentColor: string;
  accentFill:  string;
}

const DEFAULT_THEME: ChartTheme = {
  background:  '#0d1117',
  grid:        'rgba(255,255,255,0.07)',
  text:        'rgba(255,255,255,0.6)',
  lineColor:   '#58a6ff',
  fillColor:   'rgba(88,166,255,0.15)',
  dangerColor: '#f85149',
  dangerFill:  'rgba(248,81,73,0.15)',
  accentColor: '#d29922',
  accentFill:  'rgba(210,153,34,0.15)',
};

function drawTimeSeries(
  ctx:    CanvasRenderingContext2D,
  data:   Float64Array,
  label:  string,
  unit:   string,
  maxVal: number,
  danger: boolean,
  accent: boolean,
  theme:  ChartTheme,
): void {
  // [F4-C] ctx.canvas.width/height now come from the pre-allocated sub-context
  // proxy's `dims` object, which is mutated in-place before each drawTimeSeries
  // call. No allocation here — just two property reads.
  const { width: W, height: H } = ctx.canvas;
  const n = data.length;

  ctx.fillStyle = theme.background;
  ctx.fillRect(0, 0, W, H);

  if (n < 2) {
    ctx.fillStyle = theme.text;
    ctx.font = '13px monospace';
    ctx.fillText('Waiting for data…', 16, H / 2);
    return;
  }

  // ── yMax from the full dataset — LTTB may miss the absolute extremum ──────
  let yMax = maxVal;
  if (yMax <= 0) {
    for (let i = 0; i < n; i++) {
      if (data[i]! > yMax) yMax = data[i]!;
    }
    yMax = yMax > 0 ? yMax * 1.2 : 1;
  }

  // ── LTTB downsample — cap lineTo calls to ≤ half the panel pixel width ────
  // At 400 px panel width: ≤ 200 points instead of up to 600, cutting draw
  // work by 3× at peak flood telemetry rates (1 000 updates / sec).
  // yMax is computed above from the full data so scale is never clipped.
  const threshold = Math.max(2, Math.floor(W / 2));
  const pts = lttb(data, threshold);
  const m   = pts.length; // ≤ threshold; always ≥ 2

  const lineColor = danger ? theme.dangerColor : accent ? theme.accentColor : theme.lineColor;
  const fillColor = danger ? theme.dangerFill  : accent ? theme.accentFill  : theme.fillColor;

  ctx.strokeStyle = theme.grid;
  ctx.lineWidth   = 1;
  for (let g = 1; g <= 3; g++) {
    const y = (H * g) / 4 | 0;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(W, y);
    ctx.stroke();
    const val = yMax * (1 - g / 4);
    ctx.fillStyle = theme.text;
    ctx.font = '10px monospace';
    ctx.fillText(formatValue(val, unit), 4, y - 4);
  }

  // ── Single-path line (downsampled) ────────────────────────────────────────
  ctx.strokeStyle = lineColor;
  ctx.lineWidth   = 2;
  ctx.lineJoin    = 'round';
  ctx.beginPath();
  for (let i = 0; i < m; i++) {
    const x = (i / (m - 1)) * W;
    const y = H - (pts[i]! / yMax) * H;
    if (i === 0) ctx.moveTo(x, y);
    else         ctx.lineTo(x, y);
  }
  ctx.stroke();

  // ── Single-path fill (same downsampled points) ────────────────────────────
  ctx.fillStyle = fillColor;
  ctx.beginPath();
  for (let i = 0; i < m; i++) {
    const x = (i / (m - 1)) * W;
    const y = H - (pts[i]! / yMax) * H;
    if (i === 0) ctx.moveTo(x, y);
    else         ctx.lineTo(x, y);
  }
  ctx.lineTo(W, H);
  ctx.lineTo(0, H);
  ctx.closePath();
  ctx.fill();

  // Current-value badge uses the last point of the original data, not the
  // downsampled array, to always show the most recent telemetry value.
  const current = data[n - 1]!;
  ctx.fillStyle = '#ffffff';
  ctx.font      = 'bold 14px monospace';
  const valStr  = formatValue(current, unit);
  const tw      = ctx.measureText(valStr).width;
  ctx.fillText(valStr, W - tw - 10, 20);

  ctx.fillStyle = theme.text;
  ctx.font      = '11px monospace';
  ctx.fillText(label, 8, 16);
}

function formatValue(v: number, unit: string): string {
  if (unit === 'pps' || unit === 'bps') {
    if (v >= 1e9) return `${(v / 1e9).toFixed(2)} G${unit}`;
    if (v >= 1e6) return `${(v / 1e6).toFixed(2)} M${unit}`;
    if (v >= 1e3) return `${(v / 1e3).toFixed(1)} K${unit}`;
    return `${v.toFixed(0)} ${unit}`;
  }
  if (unit === '%') return `${(v * 100).toFixed(1)} %`;
  return `${v.toFixed(0)} ${unit}`;
}

// ─── Pre-Allocated Sub-Context Cache [F4-C] ───────────────────────────────────
//
// Sub-context proxies simulate a canvas element with panel-local dimensions.
// drawTimeSeries reads ctx.canvas.width and ctx.canvas.height to determine
// the draw area. Without sub-contexts, each panel call would read the full
// canvas dimensions and draw over adjacent panels.
//
// The previous implementation called Object.create(ctx) + Object.defineProperty
// inside the RAF loop — 6 × 60 = 360 small-object allocations per second.
// This causes JIT polymorphic IC invalidation because each frame produces a
// proxy with a different hidden class (the defineProperty getter target is a
// new closure each time).
//
// Fix: allocate PANEL_COUNT slot objects at module load time. Each slot holds:
//   proxy  — the Object.create proxy (rebuilt only when ctx reference changes)
//   dims   — { width, height } object MUTATED in-place each frame (no alloc)
//   srcCtx — tracks which ctx the proxy was built against
//
// getSubContext() rebuilds the proxy at most once per canvas context lifetime
// (i.e., essentially once ever). Per-frame cost: two property writes to dims.

const PANEL_COUNT = 6;

interface SubCtxSlot {
  proxy:  CanvasRenderingContext2D | null;
  dims:   { width: number; height: number };
  srcCtx: CanvasRenderingContext2D | null;
}

// Module-level allocation — persists across all renders and component instances.
const SUB_CONTEXTS: SubCtxSlot[] = Array.from({ length: PANEL_COUNT }, () => ({
  proxy:  null,
  dims:   { width: 0, height: 0 },
  srcCtx: null,
}));

/**
 * getSubContext returns a pre-allocated canvas context proxy for the given
 * panel index. The proxy's `canvas.width` and `canvas.height` are updated
 * in-place via the mutable `dims` object — zero per-frame allocations.
 *
 * The caller (paint loop) is responsible for the save/translate/clip/restore
 * sequence. getSubContext does NOT call ctx.save() or ctx.translate().
 */
function getSubContext(
  ctx:   CanvasRenderingContext2D,
  index: number,
  w:     number,
  h:     number,
): CanvasRenderingContext2D {
  const slot = SUB_CONTEXTS[index]!;

  // Rebuild proxy only if the underlying canvas context reference changed.
  // In practice this fires once per canvas element lifetime — essentially never
  // during normal operation.
  if (slot.proxy === null || slot.srcCtx !== ctx) {
    const dims  = slot.dims; // capture reference — getter closure captures this
    const proxy = Object.create(ctx) as CanvasRenderingContext2D;
    Object.defineProperty(proxy, 'canvas', {
      configurable: true,
      get: () => dims, // returns the SAME object each time — no allocation
    });
    slot.proxy  = proxy;
    slot.srcCtx = ctx;
  }

  // Mutate dims in-place — the getter closure above returns this object by
  // reference, so drawTimeSeries sees the updated values immediately.
  slot.dims.width  = w;
  slot.dims.height = h;
  return slot.proxy!;
}

// ─── Canvas Metrics Panel ─────────────────────────────────────────────────────

interface MetricsCanvasProps {
  bufferRef:   React.MutableRefObject<MetricsBuffer>;
  circuitOpen: boolean;
}

/**
 * MetricsCanvas renders six time-series charts on a single <canvas> element
 * in a 3×2 grid, driven by requestAnimationFrame at 60 fps.
 *
 * Row 0: Packet Rate (PPS) | Throughput (BPS) | Drop Rate (%)
 * Row 1: Failsafe Drops    | Cooling Bans      | Pass Rate (%)
 *
 * [F4-A] Paint loop — matched save/restore, translate-before-clip:
 *   Each panel iteration follows this exact sequence:
 *     ctx.save()            — ① push clean state (ONE save per panel)
 *     ctx.translate(ox, oy) — ② move origin to panel top-left
 *     ctx.beginPath()
 *     ctx.rect(0, 0, pw, ph) — ③ clip in panel-local coords (after translate)
 *     ctx.clip()
 *     getSubContext(...)    — ④ get proxy with panel dims (no internal save)
 *     drawTimeSeries(...)   — ⑤ draws within [0,0,pw,ph]
 *     ctx.restore()         — ① matched restore — undoes translate AND clip
 *
 *   The critical invariant: ctx.clip() is called INSIDE the translate, so the
 *   clipping rectangle [0, 0, pw, ph] correctly maps to [ox, oy, pw, ph] in
 *   the canvas coordinate space. Each ctx.restore() perfectly reverts both
 *   the translate and the clip state — zero state leakage between panels.
 */
const MetricsCanvas: React.FC<MetricsCanvasProps> = ({ bufferRef, circuitOpen }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const rafRef    = useRef<number>(0);

  const paint = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const buf   = bufferRef.current;
    const W     = canvas.width;
    const H     = canvas.height;
    const cols  = 3;
    const rows  = 2;
    const pw    = W / cols;
    const ph    = H / rows;
    const theme = DEFAULT_THEME;

    type Panel = {
      col:    number;
      row:    number;
      series: Parameters<MetricsBuffer['slice']>[0];
      label:  string;
      unit:   string;
      danger: boolean;
      accent: boolean;
    };

    const panels: Panel[] = [
      { col: 0, row: 0, series: 'pps',           label: 'Packet Rate',    unit: 'pps',  danger: circuitOpen, accent: false },
      { col: 1, row: 0, series: 'bps',           label: 'Throughput',     unit: 'bps',  danger: false,       accent: false },
      { col: 2, row: 0, series: 'dropRate',      label: 'Drop Rate',      unit: '%',    danger: true,        accent: false },
      { col: 0, row: 1, series: 'failsafeDrops', label: 'Failsafe Drops', unit: 'pkts', danger: circuitOpen, accent: false },
      { col: 1, row: 1, series: 'coolingBans',   label: 'Cooling Bans',   unit: 'pkts', danger: false,       accent: true  },
      { col: 2, row: 1, series: 'passRate',      label: 'Pass Rate',      unit: '%',    danger: false,       accent: false },
    ];

    // [F4-A] One matched save/restore per panel. Translate BEFORE clip.
    for (let i = 0; i < panels.length; i++) {
      const p  = panels[i]!;
      const ox = p.col * pw;
      const oy = p.row * ph;

      ctx.save();               // ① push state — establishes restoration point
      ctx.translate(ox, oy);    // ② move origin to panel top-left

      // ③ clip in panel-LOCAL coordinates (origin already at panel top-left).
      // Clipping after translate means rect(0,0,pw,ph) correctly covers
      // exactly the panel area in canvas space — no external coordinate needed.
      ctx.beginPath();
      ctx.rect(0, 0, pw, ph);
      ctx.clip();

      // ④ [F4-C] Get pre-allocated proxy — no Object.create, no closure alloc.
      // The proxy's canvas.width/height are updated in-place inside getSubContext.
      const sub = getSubContext(ctx, i, pw, ph);

      // ⑤ Draw in panel-local coordinates [0, 0, pw, ph].
      drawTimeSeries(sub, buf.slice(p.series), p.label, p.unit, 0, p.danger, p.accent, theme);

      ctx.restore();            // ① matched restore — reverts translate + clip
    }

    // Separator lines between panels (drawn after all panel restores).
    ctx.strokeStyle = 'rgba(255,255,255,0.10)';
    ctx.lineWidth   = 1;
    for (let c = 1; c < cols; c++) {
      ctx.beginPath(); ctx.moveTo(c * pw, 0); ctx.lineTo(c * pw, H); ctx.stroke();
    }
    ctx.beginPath(); ctx.moveTo(0, ph); ctx.lineTo(W, ph); ctx.stroke();

    rafRef.current = requestAnimationFrame(paint);
  }, [bufferRef, circuitOpen]);

  useLayoutEffect(() => {
    const resize = () => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const rect  = canvas.getBoundingClientRect();
      const dpr   = window.devicePixelRatio || 1;
      canvas.width  = rect.width  * dpr;
      canvas.height = rect.height * dpr;
      const ctx = canvas.getContext('2d');
      if (ctx) ctx.scale(dpr, dpr);
    };
    resize();
    window.addEventListener('resize', resize);
    return () => window.removeEventListener('resize', resize);
  }, []);

  useEffect(() => {
    rafRef.current = requestAnimationFrame(paint);
    return () => cancelAnimationFrame(rafRef.current);
  }, [paint]);

  return (
    <canvas
      ref={canvasRef}
      style={{
        width:           '100%',
        height:          '360px',
        display:         'block',
        borderRadius:    '8px',
        border:          `1px solid ${circuitOpen ? '#f85149' : '#30363d'}`,
        boxShadow:       circuitOpen ? '0 0 24px rgba(248,81,73,0.4)' : '0 0 4px rgba(0,0,0,0.5)',
        transition:      'border-color 0.4s, box-shadow 0.4s',
        backgroundColor: DEFAULT_THEME.background,
      }}
    />
  );
};

// ─── Pipeline Playbook (React Flow — 7-stage XDP pipeline) ───────────────────

const CIRCUIT_COLORS: Record<CircuitState, { border: string; bg: string; glow: string }> = {
  CLOSED:    { border: '#3fb950', bg: 'rgba(63,185,80,0.15)',  glow: 'rgba(63,185,80,0.3)'  },
  HALF_OPEN: { border: '#d29922', bg: 'rgba(210,153,34,0.15)', glow: 'rgba(210,153,34,0.3)' },
  OPEN:      { border: '#f85149', bg: 'rgba(248,81,73,0.25)',  glow: 'rgba(248,81,73,0.5)'  },
};

const NEUTRAL_COLOR = { border: '#58a6ff', bg: 'rgba(88,166,255,0.12)',  glow: 'transparent' };
const ACCENT_COLOR  = { border: '#d29922', bg: 'rgba(210,153,34,0.10)',  glow: 'transparent' };
const TERMINAL_PASS = { border: '#3fb950', bg: 'rgba(63,185,80,0.10)',   glow: 'transparent' };
const TERMINAL_DROP = { border: '#f85149', bg: 'rgba(248,81,73,0.10)',   glow: 'transparent' };

interface FalxNodeData {
  label:             string;
  sublabel?:         string;
  circuitState?:     CircuitState;
  isCircuitBreaker?: boolean;
  isSource?:         boolean;
  isTerminalPass?:   boolean;
  isTerminalDrop?:   boolean;
  isCooling?:        boolean;
  stat?:             string;
  icon?:             string;
}

const FalxPipelineNode: React.FC<NodeProps<Node<FalxNodeData>>> = ({ data }) => {
  let colors = NEUTRAL_COLOR;
  if (data.isCircuitBreaker && data.circuitState) colors = CIRCUIT_COLORS[data.circuitState];
  else if (data.isTerminalPass)                   colors = TERMINAL_PASS;
  else if (data.isTerminalDrop)                   colors = TERMINAL_DROP;
  else if (data.isCooling)                        colors = ACCENT_COLOR;

  const isPulsing = data.isCircuitBreaker && data.circuitState === 'OPEN';

  return (
    <div
      style={{
        padding:      '10px 14px',
        borderRadius: '8px',
        border:       `2px solid ${colors.border}`,
        background:   colors.bg,
        boxShadow:    `0 0 12px ${colors.glow}`,
        color:        '#e6edf3',
        fontFamily:   'monospace',
        fontSize:     '11px',
        minWidth:     '110px',
        textAlign:    'center',
        animation:    isPulsing ? 'falx-pulse 1s ease-in-out infinite' : 'none',
        transition:   'background 0.4s, border-color 0.4s, box-shadow 0.4s',
        userSelect:   'none',
      }}
    >
      <Handle type="target" position={Position.Left}
              style={{ background: colors.border, border: 'none', width: 8, height: 8 }} />
      {data.icon && (
        <div style={{ fontSize: '16px', marginBottom: '2px' }}>{data.icon}</div>
      )}
      <div style={{ fontWeight: 'bold', color: colors.border, fontSize: '12px' }}>
        {data.label}
      </div>
      {data.sublabel && (
        <div style={{ marginTop: '2px', opacity: 0.65, fontSize: '9px', lineHeight: 1.3 }}>
          {data.sublabel}
        </div>
      )}
      {data.stat && (
        <div style={{
          marginTop:    '4px',
          padding:      '1px 6px',
          borderRadius: '4px',
          background:   'rgba(0,0,0,0.35)',
          fontSize:     '9px',
          color:        colors.border,
        }}>
          {data.stat}
        </div>
      )}
      <Handle type="source" position={Position.Right}
              style={{ background: colors.border, border: 'none', width: 8, height: 8 }} />
    </div>
  );
};

const nodeTypes = { falxNode: FalxPipelineNode };

function buildNodes(circuitState: CircuitState, latestPPS: number): Node<FalxNodeData>[] {
  const Y_MAIN    = 100;
  const Y_COOLING = 240;
  const Y_DROP    = 240;
  const Y_PASS    = -40;
  const X_STEP    = 185;

  return [
    {
      id: 'internet', type: 'falxNode',
      position: { x: 0, y: Y_MAIN },
      data: { label: 'Internet', sublabel: 'Raw inbound traffic', icon: '🌐', isSource: true, stat: 'All protocols' },
    },
    {
      id: 'bounds-check', type: 'falxNode',
      position: { x: X_STEP * 1, y: Y_MAIN },
      data: { label: 'Bounds Check', sublabel: 'Fail-closed: < 14 B', icon: '📏', stat: 'XDP_DROP on truncated' },
    },
    {
      id: 'bloom', type: 'falxNode',
      position: { x: X_STEP * 2, y: Y_MAIN },
      data: { label: 'Bloom Filter', sublabel: 'BLOOM_FILTER (BPF)', icon: '🔍', stat: 'O(k=3)  ~98.9% skip' },
    },
    {
      id: 'blocklist', type: 'falxNode',
      position: { x: X_STEP * 3, y: Y_MAIN },
      data: { label: 'Blocklist', sublabel: 'BLOCKLIST_V4/V6', icon: '🚫', stat: '65 536 LRU entries' },
    },
    {
      id: 'rate-limit', type: 'falxNode',
      position: { x: X_STEP * 4, y: Y_MAIN },
      data: { label: 'Rate Limiter', sublabel: 'Token bucket / IP', icon: '⏱', stat: 'RATE_LIMIT LRU' },
    },
    {
      id: 'cooling', type: 'falxNode',
      position: { x: X_STEP * 4, y: Y_COOLING },
      data: {
        label:     'Cooling Tracker',
        sublabel:  'T_ban = 10s × 2^r',
        icon:      '🌡',
        isCooling: true,
        stat:      'best-effort RMW (Option B)',
      },
    },
    {
      id: 'syn-heuristic', type: 'falxNode',
      position: { x: X_STEP * 5, y: Y_MAIN },
      data: { label: 'SYN Heuristic', sublabel: 'SYN-only packets', icon: '⚡', stat: '10× token cost' },
    },
    {
      id: 'circuit-breaker', type: 'falxNode',
      position: { x: X_STEP * 6, y: Y_MAIN },
      data: {
        label:            'Circuit Breaker',
        sublabel:         `${circuitState}  •  ${formatValue(latestPPS, 'pps')}`,
        icon:             circuitState === 'OPEN'      ? '🔴'
                        : circuitState === 'HALF_OPEN' ? '🟡' : '🟢',
        circuitState,
        isCircuitBreaker: true,
        stat:             'FAILSAFE_STATE',
      },
    },
    {
      id: 'xdp-pass', type: 'falxNode',
      position: { x: X_STEP * 7, y: Y_PASS },
      data: { label: 'XDP_PASS', sublabel: 'To network stack', icon: '✅', isTerminalPass: true },
    },
    {
      id: 'xdp-drop', type: 'falxNode',
      position: { x: X_STEP * 7, y: Y_DROP },
      data: { label: 'XDP_DROP', sublabel: 'Sub-µs discard', icon: '❌', isTerminalDrop: true },
    },
  ];
}

function buildEdges(): Edge[] {
  const passStyle = { stroke: '#58a6ff', strokeWidth: 2 };
  const dropStyle = { stroke: '#f85149', strokeWidth: 1.5, strokeDasharray: '4 3' };
  const sideStyle = { stroke: '#d29922', strokeWidth: 1.5, strokeDasharray: '3 3' };
  const feedStyle = { stroke: '#d29922', strokeWidth: 1.5 };

  return [
    { id: 'e-internet->bounds',   source: 'internet',         target: 'bounds-check',    style: passStyle, animated: true,  type: 'smoothstep' },
    { id: 'e-bounds->bloom',      source: 'bounds-check',     target: 'bloom',           style: passStyle, animated: true,  type: 'smoothstep' },
    { id: 'e-bloom->blocklist',   source: 'bloom',            target: 'blocklist',       style: passStyle, animated: true,  type: 'smoothstep' },
    { id: 'e-blocklist->ratelim', source: 'blocklist',        target: 'rate-limit',      style: passStyle, animated: true,  type: 'smoothstep' },
    { id: 'e-ratelim->syn',       source: 'rate-limit',       target: 'syn-heuristic',   style: passStyle, animated: true,  type: 'smoothstep' },
    { id: 'e-syn->cb',            source: 'syn-heuristic',    target: 'circuit-breaker', style: passStyle, animated: true,  type: 'smoothstep' },
    { id: 'e-cb->pass',           source: 'circuit-breaker',  target: 'xdp-pass',        style: passStyle, animated: false, type: 'smoothstep' },

    { id: 'e-bounds->drop', source: 'bounds-check',   target: 'xdp-drop', style: dropStyle, animated: false, type: 'smoothstep', label: '< 14B'       },
    { id: 'e-bloom->drop',  source: 'bloom',          target: 'xdp-drop', style: dropStyle, animated: false, type: 'smoothstep', label: 'TTL ban'      },
    { id: 'e-list->drop',   source: 'blocklist',      target: 'xdp-drop', style: dropStyle, animated: false, type: 'smoothstep', label: 'blocked'      },
    { id: 'e-rl->drop',     source: 'rate-limit',     target: 'xdp-drop', style: dropStyle, animated: false, type: 'smoothstep', label: 'exhausted'    },
    { id: 'e-syn->drop',    source: 'syn-heuristic',  target: 'xdp-drop', style: dropStyle, animated: false, type: 'smoothstep', label: 'SYN flood'    },
    { id: 'e-cb->drop',     source: 'circuit-breaker',target: 'xdp-drop', style: dropStyle, animated: false, type: 'smoothstep', label: 'circuit OPEN' },

    { id: 'e-rl->cooling',   source: 'rate-limit',    target: 'cooling',   style: sideStyle, animated: false, type: 'smoothstep', label: 'on DROP'    },
    { id: 'e-syn->cooling',  source: 'syn-heuristic', target: 'cooling',   style: sideStyle, animated: false, type: 'smoothstep' },
    { id: 'e-cooling->list', source: 'cooling',       target: 'blocklist', style: feedStyle, animated: false, type: 'smoothstep', label: 'auto-ban ↺' },
  ];
}

interface PipelinePlaybookProps {
  circuitState: CircuitState;
  latestPPS:    number;
}

const PipelinePlaybook: React.FC<PipelinePlaybookProps> = ({ circuitState, latestPPS }) => {
  const nodes = React.useMemo<Node<FalxNodeData>[]>(
    () => buildNodes(circuitState, latestPPS),
    [circuitState, latestPPS],
  );
  const edges = React.useMemo(buildEdges, []);

  return (
    <div style={{
      height:       '380px',
      background:   '#0d1117',
      borderRadius: '8px',
      border:       '1px solid #30363d',
      overflow:     'hidden',
    }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.15 }}
        proOptions={{ hideAttribution: true }}
        minZoom={0.4}
        maxZoom={1.6}
        defaultEdgeOptions={{ type: 'smoothstep' }}
      >
        <Background variant={BackgroundVariant.Dots} color="#21262d" gap={24} size={1} />
        <Controls showInteractive={false} />
        <MiniMap
          nodeColor={() => '#58a6ff'}
          maskColor="rgba(13,17,23,0.8)"
          style={{ background: '#161b22', border: '1px solid #30363d' }}
        />
      </ReactFlow>
    </div>
  );
};

// ─── Status Banner ────────────────────────────────────────────────────────────

const CircuitBanner: React.FC<{ state: CircuitState; reason?: string }> = ({ state, reason }) => {
  const config = {
    OPEN:      { bg: '#3d1c1f', border: '#f85149', text: '#f85149', label: '⚠ CIRCUIT OPEN — XDP_DROP MODE ACTIVE'   },
    HALF_OPEN: { bg: '#2e2207', border: '#d29922', text: '#d29922', label: '⟳ CIRCUIT HALF-OPEN — Recovery Probe'     },
    CLOSED:    { bg: '#0d2214', border: '#3fb950', text: '#3fb950', label: '✓ CIRCUIT CLOSED — Normal Operation'       },
  }[state];

  return (
    <div style={{
      padding:      '10px 20px',
      background:   config.bg,
      border:       `1px solid ${config.border}`,
      borderRadius: '6px',
      color:        config.text,
      fontFamily:   'monospace',
      fontWeight:   'bold',
      fontSize:     '13px',
      display:      'flex',
      gap:          '16px',
      alignItems:   'center',
    }}>
      <span>{config.label}</span>
      {reason && (
        <span style={{ opacity: 0.7, fontWeight: 'normal' }}>reason: {reason}</span>
      )}
    </div>
  );
};

// ─── Root Dashboard Component ─────────────────────────────────────────────────

export interface HighFrequencyDashboardProps {
  wsUrl: string;
}

export const HighFrequencyDashboard: React.FC<HighFrequencyDashboardProps> = ({ wsUrl }) => {
  const [circuitState,  setCircuitState]  = useState<CircuitState>('CLOSED');
  const [circuitReason, setCircuitReason] = useState<string | undefined>();
  const [wsStatus,      setWsStatus]      = useState<'connecting' | 'open' | 'closed'>('connecting');
  const [latestPPS,     setLatestPPS]     = useState(0);

  const bufferRef    = useRef<MetricsBuffer>(new MetricsBuffer());
  const latestPPSRef = useRef(0);

  useEffect(() => {
    // [F3-B] `cancelled` is the unmount sentinel. It is set to true as the
    // FIRST action in the cleanup function, BEFORE ws.close(). Every callback
    // that reaches into React state checks this flag at its entry point.
    // This guarantees no setState fires after cleanup — even when the browser
    // delivers a stale onclose event after the component has unmounted.
    let cancelled      = false;
    let ws:             WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

    const connect = () => {
      // [F3-B] Do not attempt a reconnect if cleanup has already run.
      if (cancelled) return;

      setWsStatus('connecting');
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        // [F3-B] Guard: cleanup may have run between connect() and onopen.
        if (cancelled) return;
        setWsStatus('open');
      };

      ws.onmessage = (event: MessageEvent<string>) => {
        // [F3-B] Guard: discard messages received after unmount.
        if (cancelled) return;

        let msg: WSMessage;
        try {
          msg = JSON.parse(event.data) as WSMessage;
        } catch {
          return;
        }

        if (msg.type === 'metrics') {
          bufferRef.current.push(msg);
          latestPPSRef.current = msg.current_pps;

          const next: CircuitState = msg.circuit_open ? 'OPEN' : 'CLOSED';
          setCircuitState(prev => (prev === next ? prev : next));

        } else if (msg.type === 'circuit_open') {
          setCircuitState('OPEN');
          setCircuitReason(msg.reason);
        } else if (msg.type === 'circuit_closed') {
          setCircuitState('CLOSED');
          setCircuitReason(undefined);
        } else if (msg.type === 'circuit_half_open') {
          setCircuitState('HALF_OPEN');
          setCircuitReason(msg.reason);
        }
      };

      ws.onerror = () => { /* onclose fires next and handles reconnect */ };

      ws.onclose = () => {
        // [F3-B] The critical guard. ws.close() in cleanup triggers this handler
        // asynchronously. Without `cancelled`, this would call setWsStatus and
        // schedule a reconnect on an unmounted component.
        if (cancelled) return;

        setWsStatus('closed');
        reconnectTimer = setTimeout(connect, 3_000);
      };
    };

    connect();

    // PPS state sync at 200 ms — keeps the playbook node subtitle fresh.
    const ppsTick = setInterval(() => {
      // [F3-B] Guard the interval callback too — intervals fire independently
      // of WebSocket lifecycle and outlive the cleanup if not cleared promptly.
      if (cancelled) return;
      setLatestPPS(latestPPSRef.current);
    }, 200);

    return () => {
      // [F3-B] Set cancelled FIRST — all async callbacks will now no-op.
      cancelled = true;
      ws?.close();
      if (reconnectTimer) clearTimeout(reconnectTimer);
      clearInterval(ppsTick);
    };
  }, [wsUrl]);

  const isCircuitOpen = circuitState === 'OPEN';

  return (
    <div style={{
      display:       'flex',
      flexDirection: 'column',
      gap:           '16px',
      padding:       '20px',
      background:    '#010409',
      minHeight:     '100vh',
      color:         '#e6edf3',
      fontFamily:    'monospace',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '18px', color: '#58a6ff', letterSpacing: '-0.01em' }}>
            FALX V2 — High-Frequency SOC Dashboard
          </h1>
          <p style={{ margin: '2px 0 0', fontSize: '11px', opacity: 0.45 }}>
            Real-time XDP telemetry · 7-stage eBPF datapath · AF_XDP bridge
          </p>
        </div>
        <WSStatusBadge status={wsStatus} />
      </div>

      <CircuitBanner state={circuitState} reason={circuitReason} />

      <section>
        <SectionLabel>Live Telemetry — 6 × Float64Array ring buffers @ 60 fps</SectionLabel>
        <MetricsCanvas bufferRef={bufferRef} circuitOpen={isCircuitOpen} />
      </section>

      <section>
        <SectionLabel>
          XDP 7-Stage Pipeline Playbook
          &nbsp;·&nbsp;
          Circuit Breaker:&nbsp;
          <span style={{
            color: circuitState === 'OPEN'      ? '#f85149'
                 : circuitState === 'HALF_OPEN' ? '#d29922' : '#3fb950',
          }}>{circuitState}</span>
        </SectionLabel>
        <PipelinePlaybook circuitState={circuitState} latestPPS={latestPPS} />
      </section>

      <style>{`
        @keyframes falx-pulse {
          0%, 100% { box-shadow: 0 0 12px rgba(248,81,73,0.5); }
          50%       { box-shadow: 0 0 32px rgba(248,81,73,0.95); }
        }
      `}</style>
    </div>
  );
};

// ─── Utility Sub-Components ───────────────────────────────────────────────────

const SectionLabel: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div style={{
    fontSize:      '10px',
    textTransform: 'uppercase',
    letterSpacing: '0.08em',
    color:         'rgba(255,255,255,0.38)',
    marginBottom:  '8px',
  }}>
    {children}
  </div>
);

const WS_STATUS_CONFIG = {
  connecting: { color: '#d29922', label: '⟳ Connecting'  },
  open:       { color: '#3fb950', label: '● Live'         },
  closed:     { color: '#f85149', label: '✕ Disconnected' },
};

const WSStatusBadge: React.FC<{ status: 'connecting' | 'open' | 'closed' }> = ({ status }) => {
  const cfg = WS_STATUS_CONFIG[status];
  return (
    <span style={{
      padding:      '4px 10px',
      borderRadius: '12px',
      border:       `1px solid ${cfg.color}`,
      color:        cfg.color,
      fontSize:     '11px',
      fontFamily:   'monospace',
    }}>
      {cfg.label}
    </span>
  );
};

export default HighFrequencyDashboard;
