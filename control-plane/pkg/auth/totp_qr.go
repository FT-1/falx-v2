// =============================================================================
// Project: FALX V2
// Description: Inline QR code SVG generator (control-plane/pkg/auth/totp_qr.go).
//              Zero external dependencies — stdlib only.
//              Implements ISO 18004 byte mode, EC level M, versions 1-10.
//              Covers otpauth:// URIs up to 216 bytes.
//
//              Public surface: qrDataURI(uri string) string
//              Returns a data:image/svg+xml;base64,... string ready for <img src>.
// =============================================================================

package auth

import (
	"encoding/base64"
	"fmt"
	"math"
	"strings"
)

// ── GF(256) tables for Reed-Solomon ──────────────────────────────────────────

var qrExp [512]byte
var qrLog [256]byte

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		qrExp[i] = byte(x)
		qrLog[x] = byte(i)
		x <<= 1
		if x >= 256 {
			x ^= 0x11d // primitive polynomial x^8+x^4+x^3+x^2+1
		}
	}
	for i := 255; i < 512; i++ {
		qrExp[i] = qrExp[i-255]
	}
}

func qrMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return qrExp[int(qrLog[a])+int(qrLog[b])]
}

// qrRS computes n Reed-Solomon error-correction codewords for data.
func qrRS(data []byte, n int) []byte {
	// Build generator polynomial
	g := []byte{1}
	for i := 0; i < n; i++ {
		t := make([]byte, len(g)+1)
		for j, c := range g {
			t[j] ^= c
			t[j+1] ^= qrMul(c, qrExp[i])
		}
		g = t
	}
	msg := make([]byte, len(data)+n)
	copy(msg, data)
	for i := 0; i < len(data); i++ {
		if c := msg[i]; c != 0 {
			for j := 1; j <= n; j++ {
				msg[i+j] ^= qrMul(c, g[j])
			}
		}
	}
	return msg[len(data):]
}

// ── Version / block structure table (EC level M only) ────────────────────────

type qrVer struct {
	dataBytes, ecPerBlock int
	g1n, g1d             int // group-1 block count and data bytes per block
	g2n, g2d             int // group-2 (0 = no second group)
}

var qrVersions = [10]qrVer{
	{16, 10, 1, 16, 0, 0},   // v1
	{28, 16, 1, 28, 0, 0},   // v2
	{44, 26, 1, 44, 0, 0},   // v3
	{64, 18, 2, 32, 0, 0},   // v4
	{86, 24, 2, 43, 0, 0},   // v5
	{108, 16, 4, 27, 0, 0},  // v6
	{124, 18, 4, 31, 0, 0},  // v7
	{154, 22, 2, 38, 2, 39}, // v8
	{182, 22, 3, 36, 2, 37}, // v9
	{216, 26, 4, 43, 1, 44}, // v10
}

// ── Alignment pattern centre coordinates per version ─────────────────────────

var qrAlignPos = [10][]int{
	{},
	{6, 18},
	{6, 22},
	{6, 26},
	{6, 30},
	{6, 34},
	{6, 22, 38},
	{6, 24, 42},
	{6, 26, 46},
	{6, 28, 50},
}

// ── Format info 15-bit words for EC=M, masks 0-7 (BCH + XOR 0x5412) ─────────
// Verified: FI[m] = BCH(00_m) ^ 0x5412 where generator = x^10+x^8+x^5+x^4+x^2+x+1

var qrFmtInfo = [8]uint16{0x5412, 0x5125, 0x5E7C, 0x5B4B, 0x45F9, 0x40CE, 0x4F97, 0x4AA0}

// ── Remainder bits appended after data codewords (v1-v10) ────────────────────

var qrRemBits = [10]int{0, 7, 7, 7, 7, 7, 0, 0, 0, 0}

// ── Encoding ─────────────────────────────────────────────────────────────────

func qrEncode(text string) (version int, codewords []byte, err error) {
	data := []byte(text) // Go strings are already UTF-8

	vi := -1
	for i, v := range qrVersions {
		if v.dataBytes >= len(data) {
			vi = i
			break
		}
	}
	if vi < 0 {
		return 0, nil, fmt.Errorf("qr: text too long (%d bytes, max 216)", len(data))
	}

	v := qrVersions[vi]
	version = vi + 1

	// Bit stream
	bits := make([]byte, 0, v.dataBytes*8+20)
	push := func(val uint, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, byte((val>>uint(i))&1))
		}
	}

	push(0b0100, 4) // byte mode indicator
	if version <= 9 {
		push(uint(len(data)), 8)
	} else {
		push(uint(len(data)), 16)
	}
	for _, b := range data {
		push(uint(b), 8)
	}

	cap := v.dataBytes * 8
	for i := 0; i < 4 && len(bits) < cap; i++ {
		bits = append(bits, 0)
	}
	for len(bits)%8 != 0 {
		bits = append(bits, 0)
	}
	pads, pi := [2]byte{0xEC, 0x11}, 0
	for len(bits) < cap {
		push(uint(pads[pi%2]), 8)
		pi++
	}

	rawData := make([]byte, v.dataBytes)
	for i := range rawData {
		var b byte
		for j := 0; j < 8; j++ {
			b = (b << 1) | bits[i*8+j]
		}
		rawData[i] = b
	}

	// Reed-Solomon blocks
	type blk struct{ d, ec []byte }
	var blocks []blk
	pos := 0
	addBlocks := func(count, size int) {
		for i := 0; i < count; i++ {
			d := rawData[pos : pos+size]
			blocks = append(blocks, blk{d: d, ec: qrRS(d, v.ecPerBlock)})
			pos += size
		}
	}
	addBlocks(v.g1n, v.g1d)
	if v.g2n > 0 {
		addBlocks(v.g2n, v.g2d)
	}

	// Interleave data then EC
	maxD := v.g1d
	if v.g2d > maxD {
		maxD = v.g2d
	}
	out := make([]byte, 0, v.dataBytes+v.ecPerBlock*len(blocks))
	for i := 0; i < maxD; i++ {
		for _, b := range blocks {
			if i < len(b.d) {
				out = append(out, b.d[i])
			}
		}
	}
	for i := 0; i < v.ecPerBlock; i++ {
		for _, b := range blocks {
			out = append(out, b.ec[i])
		}
	}
	return version, out, nil
}

// ── Matrix construction ───────────────────────────────────────────────────────

func qrBuildMatrix(version int, codewords []byte) (mod, fn [][]byte, N int) {
	N = version*4 + 17
	mod = make([][]byte, N)
	fn = make([][]byte, N)
	for i := range mod {
		mod[i] = make([]byte, N)
		fn[i] = make([]byte, N)
	}

	put := func(r, c int, v, f byte) {
		if r < 0 || r >= N || c < 0 || c >= N {
			return
		}
		mod[r][c] = v
		if f != 0 {
			fn[r][c] = 1
		}
	}

	// Finder patterns (7×7 core + 1-cell separator)
	finder := func(tr, tc int) {
		for r := -1; r <= 7; r++ {
			for c := -1; c <= 7; c++ {
				var v byte
				if !(r < 0 || r > 6 || c < 0 || c > 6) {
					if r == 0 || r == 6 || c == 0 || c == 6 {
						v = 1
					} else if r >= 2 && r <= 4 && c >= 2 && c <= 4 {
						v = 1
					}
				}
				put(tr+r, tc+c, v, 1)
			}
		}
	}
	finder(0, 0)
	finder(0, N-7)
	finder(N-7, 0)

	// Timing strips
	for i := 0; i < N; i++ {
		v := byte(1)
		if i%2 != 0 {
			v = 0
		}
		put(6, i, v, 1)
		put(i, 6, v, 1)
	}

	// Dark module
	put(N-8, 8, 1, 1)

	// Alignment patterns (skip cells that overlap finder/timing)
	for _, r := range qrAlignPos[version-1] {
		for _, c := range qrAlignPos[version-1] {
			if fn[r][c] != 0 {
				continue
			}
			for dr := -2; dr <= 2; dr++ {
				for dc := -2; dc <= 2; dc++ {
					var v byte
					if dr == 0 && dc == 0 {
						v = 1
					} else if dr == -2 || dr == 2 || dc == -2 || dc == 2 {
						v = 1
					}
					put(r+dr, c+dc, v, 1)
				}
			}
		}
	}

	// Format info placeholder cells (marked functional; values written after masking)
	fmtCells := [][2]int{
		// Copy 1: horizontal at row 8, then vertical at col 8
		{8, 0}, {8, 1}, {8, 2}, {8, 3}, {8, 4}, {8, 5}, {8, 7}, {8, 8},
		{7, 8}, {5, 8}, {4, 8}, {3, 8}, {2, 8}, {1, 8}, {0, 8},
		// Copy 2: vertical at col 8 (rows N-1..N-7) = bits 0-6;
		//         horizontal at row 8 (cols N-8..N-1) = bits 7-14.
		// Note: dark module lives at {N-8, 8} (already set above) — NOT a format cell.
		//       Bit 7 of copy 2 goes to {8, N-8}, which IS a format cell and must be
		//       listed here so the data-placement zigzag skips it.
		{N - 1, 8}, {N - 2, 8}, {N - 3, 8}, {N - 4, 8}, {N - 5, 8}, {N - 6, 8}, {N - 7, 8},
		{8, N - 8}, {8, N - 7}, {8, N - 6}, {8, N - 5}, {8, N - 4}, {8, N - 3}, {8, N - 2}, {8, N - 1},
	}
	for _, p := range fmtCells {
		put(p[0], p[1], 0, 1)
	}

	// Data placement — zigzag scan from bottom-right
	bits := make([]byte, 0, len(codewords)*8+8)
	for _, b := range codewords {
		for i := 7; i >= 0; i-- {
			bits = append(bits, (b>>uint(i))&1)
		}
	}
	for i := 0; i < qrRemBits[version-1]; i++ {
		bits = append(bits, 0)
	}

	bi, upward := 0, true
	for right := N - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5 // skip timing column
		}
		for row := 0; row < N; row++ {
			r := row
			if upward {
				r = N - 1 - row
			}
			for dc := 0; dc < 2; dc++ {
				c := right - dc
				if fn[r][c] == 0 {
					if bi < len(bits) {
						mod[r][c] = bits[bi]
						bi++
					}
				}
			}
		}
		upward = !upward
	}
	return mod, fn, N
}

// ── Masking ───────────────────────────────────────────────────────────────────

type qrMaskFn func(r, c int) bool

var qrMasks = [8]qrMaskFn{
	func(r, c int) bool { return (r+c)%2 == 0 },
	func(r, c int) bool { return r%2 == 0 },
	func(r, c int) bool { return c%3 == 0 },
	func(r, c int) bool { return (r+c)%3 == 0 },
	func(r, c int) bool { return (r/2+c/3)%2 == 0 },
	func(r, c int) bool { return r*c%2+r*c%3 == 0 },
	func(r, c int) bool { return (r*c%2+r*c%3)%2 == 0 },
	func(r, c int) bool { return ((r+c)%2+r*c%3)%2 == 0 },
}

func qrApplyMask(mod, fn [][]byte, N, m int) [][]byte {
	out := make([][]byte, N)
	for i := range out {
		out[i] = make([]byte, N)
		copy(out[i], mod[i])
	}
	for r := 0; r < N; r++ {
		for c := 0; c < N; c++ {
			if fn[r][c] == 0 && qrMasks[m](r, c) {
				out[r][c] ^= 1
			}
		}
	}
	return out
}

// ── Format info writing ───────────────────────────────────────────────────────

// Format info positions — copy 1 (bit i → C1[i]) and copy 2 (bit i → C2[i]).
// Bits are indexed from 0 (LSB) to 14 (MSB).
func qrWriteFormat(mod [][]byte, N, mask int) {
	bits := qrFmtInfo[mask]

	// Copy 1: adjacent to the top-left finder pattern.
	c1 := [15][2]int{
		{8, 0}, {8, 1}, {8, 2}, {8, 3}, {8, 4}, {8, 5}, {8, 7}, {8, 8},
		{7, 8}, {5, 8}, {4, 8}, {3, 8}, {2, 8}, {1, 8}, {0, 8},
	}
	// Copy 2: adjacent to the top-right and bottom-left finder patterns.
	// ISO 18004 §7.9: bits 0-6 go in column 8 (rows N-1..N-7);
	//                 bits 7-14 go in row 8 (cols N-8..N-1).
	// The dark module at {N-8, 8} is always 1 and is NOT a format-info cell;
	// it is set once in qrBuildMatrix and must not be written here.
	c2 := [15][2]int{
		{N - 1, 8}, {N - 2, 8}, {N - 3, 8}, {N - 4, 8}, {N - 5, 8}, {N - 6, 8}, {N - 7, 8},
		{8, N - 8}, // bit 7 — row 8, column N-8 (NOT the dark-module cell {N-8,8})
		{8, N - 7}, {8, N - 6}, {8, N - 5}, {8, N - 4}, {8, N - 3}, {8, N - 2}, {8, N - 1},
	}

	for i := 0; i < 15; i++ {
		v := byte((bits >> uint(i)) & 1)
		mod[c1[i][0]][c1[i][1]] = v
		mod[c2[i][0]][c2[i][1]] = v
	}
}

// ── Penalty scoring (all 4 rules) ─────────────────────────────────────────────

var qrP3a = [11]byte{1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0}
var qrP3b = [11]byte{0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1}

func qrPenalty(mod [][]byte, N int) int {
	score := 0

	// Rule 1: 5+ consecutive same-colour modules
	for r := 0; r < N; r++ {
		run := 1
		for c := 1; c < N; c++ {
			if mod[r][c] == mod[r][c-1] {
				run++
				if run == 5 {
					score += 3
				} else if run > 5 {
					score++
				}
			} else {
				run = 1
			}
		}
	}
	for c := 0; c < N; c++ {
		run := 1
		for r := 1; r < N; r++ {
			if mod[r][c] == mod[r-1][c] {
				run++
				if run == 5 {
					score += 3
				} else if run > 5 {
					score++
				}
			} else {
				run = 1
			}
		}
	}

	// Rule 2: 2×2 same-colour blocks
	for r := 0; r < N-1; r++ {
		for c := 0; c < N-1; c++ {
			v := mod[r][c]
			if v == mod[r+1][c] && v == mod[r][c+1] && v == mod[r+1][c+1] {
				score += 3
			}
		}
	}

	// Rule 3: finder-like 1:1:3:1:1 patterns
	for r := 0; r < N; r++ {
		for c := 0; c <= N-11; c++ {
			mA, mB := true, true
			for k := 0; k < 11; k++ {
				if mod[r][c+k] != qrP3a[k] {
					mA = false
				}
				if mod[r][c+k] != qrP3b[k] {
					mB = false
				}
			}
			if mA || mB {
				score += 40
			}
		}
	}
	for c := 0; c < N; c++ {
		for r := 0; r <= N-11; r++ {
			mA, mB := true, true
			for k := 0; k < 11; k++ {
				if mod[r+k][c] != qrP3a[k] {
					mA = false
				}
				if mod[r+k][c] != qrP3b[k] {
					mB = false
				}
			}
			if mA || mB {
				score += 40
			}
		}
	}

	// Rule 4: dark module ratio deviation from 50%
	dark := 0
	for _, row := range mod {
		for _, v := range row {
			if v == 1 {
				dark++
			}
		}
	}
	pct := float64(dark) * 100 / float64(N*N)
	lo := math.Floor(pct/5) * 5
	hi := math.Ceil(pct/5) * 5
	loD := math.Abs(lo-50) / 5 * 10
	hiD := math.Abs(hi-50) / 5 * 10
	if loD < hiD {
		score += int(loD)
	} else {
		score += int(hiD)
	}
	return score
}

// ── SVG rendering ─────────────────────────────────────────────────────────────

func qrSVG(text string) (string, error) {
	version, codewords, err := qrEncode(text)
	if err != nil {
		return "", err
	}

	base, fn, N := qrBuildMatrix(version, codewords)

	// Evaluate all 8 masks; keep the one with the lowest penalty score.
	var best [][]byte
	bestScore := math.MaxInt32
	for m := 0; m < 8; m++ {
		masked := qrApplyMask(base, fn, N, m)
		qrWriteFormat(masked, N, m)
		if sc := qrPenalty(masked, N); sc < bestScore {
			bestScore = sc
			best = masked
		}
	}

	// Build SVG.
	// 4-module quiet zone on all sides; each module = 1 SVG unit.
	// The viewBox makes it resolution-independent — CSS controls display size.
	const margin = 4
	size := N + margin*2

	var sb strings.Builder
	// width/height on the root SVG element set the intrinsic size so that
	// browsers / Android WebViews scale the image correctly when it is
	// embedded as a data:image/svg+xml;base64 src in an <img> tag even
	// without explicit CSS dimensions.  4 px per module keeps edges crisp.
	fmt.Fprintf(&sb,
		`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %[1]d %[1]d" width="%[2]d" height="%[2]d" shape-rendering="crispEdges">`,
		size, size*4)
	fmt.Fprintf(&sb, `<rect width="%d" height="%d" fill="#fff"/>`, size, size)

	// Emit all dark modules as a single <path> (one command per module).
	// M x,y h1 v1 h-1 z = a 1×1 filled square at (x, y).
	sb.WriteString(`<path fill="#000" d="`)
	for r := 0; r < N; r++ {
		for c := 0; c < N; c++ {
			if best[r][c] == 1 {
				fmt.Fprintf(&sb, "M%d,%dh1v1h-1z", c+margin, r+margin)
			}
		}
	}
	sb.WriteString(`"/>`)
	sb.WriteString(`</svg>`)

	return sb.String(), nil
}

// ── Public entry point ────────────────────────────────────────────────────────

// qrDataURI encodes text as a QR code and returns a data:image/svg+xml;base64,...
// URI suitable for use as an <img> src attribute.
// On encoder error (text > 216 bytes) returns an empty string.
func qrDataURI(text string) string {
	svg, err := qrSVG(text)
	if err != nil {
		return ""
	}
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svg))
}
