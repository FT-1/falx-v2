// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: IPC frame I/O + socket auth (control-plane/internal/ipc/framing.go).
//              Low-level read/write of binary frames over Unix domain sockets.
//              SO_PEERCRED credential extraction for connection authentication.
// =============================================================================

//go:build linux
// +build linux

package ipc

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ─── Frame Reader ─────────────────────────────────────────────────────────────
// readFrame reads one complete frame from a Unix connection.
// Blocks until the full frame is received or an error occurs.
func readFrame(r io.Reader) (*Frame, error) {
	// Read fixed-size header
	var rawHdr [HeaderSize]byte
	if _, err := io.ReadFull(r, rawHdr[:]); err != nil {
		return nil, fmt.Errorf("header read: %w", err)
	}

	hdr, err := UnmarshalHeader(rawHdr)
	if err != nil {
		return nil, fmt.Errorf("header parse: %w", err)
	}

	// Read payload
	var payload []byte
	if hdr.Len > 0 {
		payload = make([]byte, hdr.Len)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("payload read (%d bytes): %w", hdr.Len, err)
		}
	}

	return &Frame{Header: hdr, Payload: payload}, nil
}

// ─── Frame Writer ─────────────────────────────────────────────────────────────
// writeFrame writes one complete frame to a Unix connection atomically.
func writeFrame(w io.Writer, frame *Frame) error {
	hBytes := frame.Header.Marshal()

	// Write header + payload in a single writev-style call
	// using a temporary combined buffer to avoid partial writes
	buf := make([]byte, HeaderSize+len(frame.Payload))
	copy(buf[:HeaderSize], hBytes[:])
	copy(buf[HeaderSize:], frame.Payload)

	_, err := w.Write(buf)
	return err
}

// ─── SO_PEERCRED Authentication ───────────────────────────────────────────────
// getPeerCred retrieves the UID and PID of the connecting process.
// Only available on Linux — uses SO_PEERCRED getsockopt.
func getPeerCred(uc *net.UnixConn) (uid uint32, pid int32, err error) {
	raw, e := uc.SyscallConn()
	if e != nil {
		return 0, 0, fmt.Errorf("SyscallConn: %w", e)
	}

	var cred *syscall.Ucred
	var credErr error

	ctrlErr := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(
			int(fd),
			syscall.SOL_SOCKET,
			syscall.SO_PEERCRED,
		)
	})

	if ctrlErr != nil {
		return 0, 0, fmt.Errorf("control: %w", ctrlErr)
	}
	if credErr != nil {
		return 0, 0, fmt.Errorf("SO_PEERCRED: %w", credErr)
	}

	return cred.Uid, cred.Pid, nil
}

// ─── Per-connection Rate Limiter ──────────────────────────────────────────────
// Limits MapUpdateReq messages per second from a single AI connection.
type connRateLimiter struct {
	mu         sync.Mutex
	tokens     float64
	capacity   float64
	refillRate float64
	lastRefill time.Time
	dropped    atomic.Int64
}

func newConnRateLimiter(rps int64) *connRateLimiter {
	return &connRateLimiter{
		tokens:     float64(rps),
		capacity:   float64(rps),
		refillRate: float64(rps),
		lastRefill: time.Now(),
	}
}

func (rl *connRateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now     := time.Now()
	elapsed := now.Sub(rl.lastRefill).Seconds()
	rl.tokens = min(rl.tokens+elapsed*rl.refillRate, rl.capacity)
	rl.lastRefill = now

	if rl.tokens < 1 {
		rl.dropped.Add(1)
		return false
	}
	rl.tokens--
	return true
}
