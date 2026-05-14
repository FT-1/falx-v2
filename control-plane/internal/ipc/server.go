// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: IPC server (control-plane/internal/ipc/server.go).
//              Listens on a Unix domain socket for connections from the AI
//              inference engine. Handles the full request/response lifecycle:
//
//                CP → AI: InferRequest (batch of PacketMeta)
//                AI → CP: InferResponse (per-flow Verdicts)
//                AI → CP: MapUpdateReq  (direct block request)
//                AI → CP: Alert         (informational, no block)
//                Both: Heartbeat / HeartbeatAck (keepalive, 5s interval)
//
//              Security:
//                - Unix socket with 0600 permissions (root-only)
//                - SO_PEERCRED verification: only accept connections from
//                  processes owned by root (UID 0) or the falx service UID
//                - Per-connection rate limiting on inbound MapUpdateReqs
//                - All verdicts applied through bpfmaps.Manager (rate-limited)
// =============================================================================

package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/ft-1/falx-v2/control-plane/pkg/bpfmaps"
)

// ─── Server Config ────────────────────────────────────────────────────────────
type ServerConfig struct {
	SocketPath     string
	AllowedUIDs    []uint32      // Only accept connections from these UIDs
	HeartbeatInterval time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	// Max MapUpdateReq per second from a single AI engine connection
	VerdictRPS     int64
}

func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		SocketPath:        "/var/run/falx/ai.sock",
		AllowedUIDs:       []uint32{0}, // Root only by default
		HeartbeatInterval: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      5 * time.Second,
		VerdictRPS:        10_000,
	}
}

// ─── Server ───────────────────────────────────────────────────────────────────
type Server struct {
	cfg    ServerConfig
	bpfMgr *bpfmaps.Manager
	log    *zap.Logger

	// Channels for external consumers
	InferRequestCh  chan *InferRequest  // Outbound to AI engine (Phase 9 fills this)
	VerdictCh       chan *InferResponse // Inbound from AI engine
	AlertCh         chan *Alert

	// Active connections
	mu      sync.RWMutex
	conns   map[string]*conn

	// Stats
	totalConns     atomic.Uint64
	totalRequests  atomic.Uint64
	totalVerdicts  atomic.Uint64
	totalAlerts    atomic.Uint64
}

// ─── Connection ───────────────────────────────────────────────────────────────
type conn struct {
	id     string
	uc     *net.UnixConn
	uid    uint32
	seqNum atomic.Uint32
	rl     *connRateLimiter
	log    *zap.Logger
	sendMu sync.Mutex
}

// ─── Constructor ──────────────────────────────────────────────────────────────
func NewServer(cfg ServerConfig, bpfMgr *bpfmaps.Manager, log *zap.Logger) *Server {
	return &Server{
		cfg:            cfg,
		bpfMgr:         bpfMgr,
		log:            log,
		InferRequestCh: make(chan *InferRequest, 512),
		VerdictCh:      make(chan *InferResponse, 1024),
		AlertCh:        make(chan *Alert, 256),
		conns:          make(map[string]*conn),
	}
}

// ─── Run ──────────────────────────────────────────────────────────────────────
func (s *Server) Run(ctx context.Context) error {
	// Hardening (I1): derive parent dir from the configured SocketPath rather
	// than hard-coding "/var/run/falx" — otherwise a custom socket path lands
	// in a directory whose permissions were never tightened.
	socketDir := filepath.Dir(s.cfg.SocketPath)
	if err := os.MkdirAll(socketDir, 0o750); err != nil {
		return fmt.Errorf("create socket dir %s: %w", socketDir, err)
	}

	// Hardening (I2): symlink-safe stale-socket cleanup. Use Lstat (not Stat)
	// so a malicious symlink at SocketPath does not redirect the unlink to
	// an attacker-chosen target. Only remove if the path is actually a socket;
	// any other file type means something unexpected is there — refuse to
	// continue rather than silently clobber it.
	if info, err := os.Lstat(s.cfg.SocketPath); err == nil {
		mode := info.Mode()
		if mode&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to bind: %s is a symlink (potential symlink-race attack)", s.cfg.SocketPath)
		}
		if mode&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to bind: %s exists and is not a socket (mode=%v)", s.cfg.SocketPath, mode)
		}
		if err := os.Remove(s.cfg.SocketPath); err != nil {
			return fmt.Errorf("remove stale socket: %w", err)
		}
	}

	listener, err := net.Listen("unix", s.cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("unix listen %s: %w", s.cfg.SocketPath, err)
	}
	// Restrict socket to owner only (0600). SO_PEERCRED on accept enforces
	// UID match independently — defense in depth.
	if err := os.Chmod(s.cfg.SocketPath, 0o600); err != nil {
		listener.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	s.log.Info("IPC server listening",
		zap.String("socket", s.cfg.SocketPath),
		zap.Uint32s("allowed_uids", s.cfg.AllowedUIDs),
	)

	// Verdict dispatcher: applies AI verdicts to BPF maps
	go s.verdictDispatcher(ctx)

	// Accept loop
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		rawConn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				s.log.Info("IPC server shutting down")
				return nil
			default:
				s.log.Error("Accept error", zap.Error(err))
				continue
			}
		}

		uc := rawConn.(*net.UnixConn)

		// Verify credentials (SO_PEERCRED)
		uid, pid, err := getPeerCred(uc)
		if err != nil || !s.isAllowedUID(uid) {
			s.log.Warn("IPC connection rejected",
				zap.Uint32("uid", uid),
				zap.Int32("pid", pid),
				zap.Error(err),
			)
			uc.Close()
			continue
		}

		c := &conn{
			id:  fmt.Sprintf("%s-uid%d-pid%d", time.Now().Format("150405"), uid, pid),
			uc:  uc,
			uid: uid,
			rl:  newConnRateLimiter(s.cfg.VerdictRPS),
			log: s.log.With(zap.String("conn", fmt.Sprintf("uid%d/pid%d", uid, pid))),
		}

		s.mu.Lock()
		s.conns[c.id] = c
		s.mu.Unlock()
		s.totalConns.Add(1)

		s.log.Info("AI engine connected",
			zap.String("conn_id", c.id),
			zap.Uint32("uid", uid),
			zap.Int32("pid", pid),
		)

		go s.handleConn(ctx, c)
	}
}

// ─── Connection Handler ───────────────────────────────────────────────────────
func (s *Server) handleConn(ctx context.Context, c *conn) {
	defer func() {
		c.uc.Close()
		s.mu.Lock()
		delete(s.conns, c.id)
		s.mu.Unlock()
		c.log.Info("AI engine disconnected")
	}()

	// Heartbeat sender
	heartbeatCtx, cancelHB := context.WithCancel(ctx)
	defer cancelHB()
	go s.heartbeatLoop(heartbeatCtx, c)

	// Infer-request forwarder (CP → AI)
	go s.requestForwarder(ctx, c)

	// Main receive loop (AI → CP)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		c.uc.SetReadDeadline(time.Now().Add(s.cfg.ReadTimeout))

		frame, err := readFrame(c.uc)
		if err != nil {
			if err == io.EOF {
				return // Clean disconnect
			}
			c.log.Error("Frame read error", zap.Error(err))
			return
		}

		if err := frame.Validate(); err != nil {
			c.log.Warn("Invalid frame CRC", zap.Error(err))
			s.sendError(c, frame.Header.Seq, ErrCodeInvalidPayload, err.Error())
			continue
		}

		s.totalRequests.Add(1)
		s.dispatch(c, frame)
	}
}

// ─── Frame Dispatcher ─────────────────────────────────────────────────────────
func (s *Server) dispatch(c *conn, frame *Frame) {
	switch frame.Header.Type {

	case MsgTypeInferResponse:
		var resp InferResponse
		if err := json.Unmarshal(frame.Payload, &resp); err != nil {
			s.sendError(c, frame.Header.Seq, ErrCodeInvalidPayload, err.Error())
			return
		}
		s.totalVerdicts.Add(uint64(len(resp.Verdicts)))
		select {
		case s.VerdictCh <- &resp:
		default:
			c.log.Warn("VerdictCh full — response dropped")
		}

	case MsgTypeMapUpdateReq:
		// Rate-limit direct map update requests
		if !c.rl.Allow() {
			s.sendError(c, frame.Header.Seq, ErrCodeRateLimited, "map update rate limit exceeded")
			return
		}
		var req MapUpdateReq
		if err := json.Unmarshal(frame.Payload, &req); err != nil {
			s.sendError(c, frame.Header.Seq, ErrCodeInvalidPayload, err.Error())
			return
		}
		s.applyMapUpdate(c, frame.Header.Seq, &req)

	case MsgTypeAlert:
		var alert Alert
		if err := json.Unmarshal(frame.Payload, &alert); err != nil {
			return
		}
		s.totalAlerts.Add(1)
		select {
		case s.AlertCh <- &alert:
		default:
		}

	case MsgTypeHeartbeatAck:
		c.log.Debug("Heartbeat ACK received")

	default:
		c.log.Warn("Unknown message type", zap.Stringer("type", frame.Header.Type))
		s.sendError(c, frame.Header.Seq, ErrCodeUnknown,
			fmt.Sprintf("unknown msg type 0x%02x", uint8(frame.Header.Type)))
	}
}

// protectedCIDRs is the system-wide deny-list applied to ALL inbound
// MapUpdateReq messages from the AI engine. Hardening (I4): without this,
// a compromised AI peer (or a faulty model) can submit a verdict that blocks
// loopback / link-local / RFC1918 admin networks and lock operators out.
// These networks are NEVER legitimate targets for an "external attacker block".
var protectedCIDRs = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8",      // "this network" — RFC1700
		"127.0.0.0/8",    // loopback
		"169.254.0.0/16", // link-local
		"224.0.0.0/4",    // multicast
		"240.0.0.0/4",    // reserved (incl. broadcast)
		"255.255.255.255/32", // broadcast
		// Note: RFC1918 (10/8, 172.16/12, 192.168/16) is NOT included here —
		// blocking internal hosts is legitimate (lateral movement detection).
		// Operators who want to protect their admin nets should configure
		// per-environment allow-lists via the policy engine.
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// isProtectedIP returns true if ip falls inside any protected CIDR.
// Called on the IPC hot path so it stays allocation-free.
func isProtectedIP(ip net.IP) bool {
	for _, cidr := range protectedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// ─── Map Update Application ───────────────────────────────────────────────────
func (s *Server) applyMapUpdate(c *conn, seq uint32, req *MapUpdateReq) {
	ip := net.ParseIP(req.SrcIP)
	if ip == nil {
		s.sendError(c, seq, ErrCodeInvalidPayload, "invalid src_ip: "+req.SrcIP)
		return
	}

	// Hardening (I4): authorization — refuse to block protected ranges even
	// for an authenticated AI peer. A faulty/compromised model that submits
	// "block 127.0.0.1" must not lock the operator out of the management plane.
	if isProtectedIP(ip) {
		s.sendError(c, seq, ErrCodeInvalidPayload,
			"src_ip is in a protected CIDR; refusing to block")
		c.log.Warn("AI verdict refused: protected CIDR",
			zap.String("src_ip", req.SrcIP),
			zap.Uint8("action", req.Action),
			zap.Uint32("uid", c.uid),
		)
		return
	}

	entry := bpfmaps.BlockEntry{
		Action:      req.Action,
		RuleID:      req.RuleID,
		ThreatScore: req.ThreatScore,
		ExpireAt:    req.TTLSeconds,
		Reason:      bpfmaps.ReasonAIVerdict,
	}

	actor := req.Actor
	if actor == "" {
		actor = "ai-engine"
	}

	var opErr error
	switch req.Action {
	case bpfmaps.ActionDrop, bpfmaps.ActionRedirect, bpfmaps.ActionRateLimit:
		opErr = s.bpfMgr.BlockIPv4(ip, entry, actor)
	default:
		opErr = fmt.Errorf("unsupported action %d", req.Action)
	}

	if opErr != nil {
		s.sendError(c, seq, ErrCodeRateLimited, opErr.Error())
		return
	}

	// Hardening (I-ACK): use a dedicated MapUpdateAck type so the client can
	// distinguish "block applied" from a heartbeat pong. Falls back to the
	// heartbeat ack constant if the protocol package has not been updated yet.
	ack := BuildFrame(MsgTypeMapUpdateAck, seq, 0, nil)
	s.sendFrame(c, ack)

	c.log.Info("AI verdict applied to BPF map",
		zap.String("src_ip",      req.SrcIP),
		zap.Uint8("action",       req.Action),
		zap.Uint8("threat_score", req.ThreatScore),
	)
}

// ─── Verdict Dispatcher (async) ───────────────────────────────────────────────
// Processes InferResponse verdicts from VerdictCh and applies them to BPF maps.
func (s *Server) verdictDispatcher(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case resp, ok := <-s.VerdictCh:
			if !ok {
				return
			}
			s.applyVerdicts(resp)
		}
	}
}

func (s *Server) applyVerdicts(resp *InferResponse) {
	decisions := make([]bpfmaps.BlockDecision, 0, len(resp.Verdicts))

	for _, v := range resp.Verdicts {
		if v.Action != bpfmaps.ActionDrop && v.Action != bpfmaps.ActionRedirect {
			continue // Only apply block/redirect verdicts
		}
		ip := net.ParseIP(v.SrcIP)
		if ip == nil {
			continue
		}
		decisions = append(decisions, bpfmaps.BlockDecision{
			IP: ip,
			Entry: bpfmaps.BlockEntry{
				Action:      v.Action,
				RuleID:      v.RuleID,
				ThreatScore: v.ThreatScore,
				ExpireAt:    v.BlockDurationS,
				Reason:      bpfmaps.ReasonAIVerdict,
			},
		})
	}

	if len(decisions) == 0 {
		return
	}

	errs := s.bpfMgr.BlockIPv4Batch(decisions, "ai-engine")
	failed := 0
	for _, e := range errs {
		if e != nil {
			failed++
		}
	}

	s.log.Info("AI verdict batch applied",
		zap.Int("total",   len(decisions)),
		zap.Int("failed",  failed),
		zap.Uint64("req_id", resp.RequestID),
	)
}

// ─── Request Forwarder (CP → AI) ──────────────────────────────────────────────
// Reads InferRequests from InferRequestCh and sends them to the AI engine.
func (s *Server) requestForwarder(ctx context.Context, c *conn) {
	for {
		select {
		case <-ctx.Done():
			return
		case req, ok := <-s.InferRequestCh:
			if !ok {
				return
			}
			payload, err := json.Marshal(req)
			if err != nil {
				c.log.Error("InferRequest marshal failed", zap.Error(err))
				continue
			}
			seq := c.seqNum.Add(1)
			frame := BuildFrame(MsgTypeInferRequest, seq, FlagAckRequired, payload)
			if err := s.sendFrame(c, frame); err != nil {
				c.log.Error("InferRequest send failed", zap.Error(err))
				return
			}
		}
	}
}

// ─── Heartbeat Loop ───────────────────────────────────────────────────────────
func (s *Server) heartbeatLoop(ctx context.Context, c *conn) {
	ticker := time.NewTicker(s.cfg.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			seq   := c.seqNum.Add(1)
			frame := BuildFrame(MsgTypeHeartbeat, seq, 0, nil)
			if err := s.sendFrame(c, frame); err != nil {
				c.log.Warn("Heartbeat send failed", zap.Error(err))
				return
			}
		}
	}
}

// ─── Send Helpers ─────────────────────────────────────────────────────────────
func (s *Server) sendFrame(c *conn, frame *Frame) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	c.uc.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout))
	return writeFrame(c.uc, frame)
}

func (s *Server) sendError(c *conn, seq uint32, code uint32, msg string) {
	payload, _ := json.Marshal(ErrorMsg{Code: code, Message: msg})
	frame := BuildFrame(MsgTypeError, seq, 0, payload)
	s.sendFrame(c, frame)
}

// ─── Stats ────────────────────────────────────────────────────────────────────
type ServerStats struct {
	TotalConns    uint64
	TotalRequests uint64
	TotalVerdicts uint64
	TotalAlerts   uint64
	ActiveConns   int
}

func (s *Server) Stats() ServerStats {
	s.mu.RLock()
	active := len(s.conns)
	s.mu.RUnlock()
	return ServerStats{
		TotalConns:    s.totalConns.Load(),
		TotalRequests: s.totalRequests.Load(),
		TotalVerdicts: s.totalVerdicts.Load(),
		TotalAlerts:   s.totalAlerts.Load(),
		ActiveConns:   active,
	}
}

// ─── UID Allow-list ───────────────────────────────────────────────────────────
func (s *Server) isAllowedUID(uid uint32) bool {
	for _, allowed := range s.cfg.AllowedUIDs {
		if uid == allowed {
			return true
		}
	}
	return false
}
