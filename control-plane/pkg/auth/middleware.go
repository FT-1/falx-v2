// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Auth middleware (control-plane/internal/auth/middleware.go).
//              HTTP middleware chain for the FALX API:
//
//                1. RequireAuth: Extract Bearer token, validate JWT, touch session
//                2. RequirePermission: Check RBAC permission on the route
//                3. RequireRole: Check minimum role level
//                4. RateLimit: Per-IP rate limiting (separate from login RL)
//                5. AuditLog: Record all sensitive API calls
//
//              Context keys: claims are stored in request context under
//              ctxKeyClaims and retrieved by handlers.
// =============================================================================

package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// ─── Context Keys ─────────────────────────────────────────────────────────────
type contextKey string

const (
	ctxKeyClaims contextKey = "falx_claims"
	ctxKeyUserID contextKey = "falx_user_id"
)

// ─── API Error Response ───────────────────────────────────────────────────────
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeAPIError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(APIError{Code: code, Message: message})
}

// ─── Middleware: RequireAuth ───────────────────────────────────────────────────
// Validates the Bearer JWT in the Authorization header.
// Injects claims into request context on success.
func (s *Service) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r)
		if token == "" {
			writeAPIError(w, http.StatusUnauthorized, "missing_token",
				"Authorization header with Bearer token required")
			return
		}

		claims, err := s.ValidateRequest(token)
		if err != nil {
			switch err {
			case ErrInactivityTimeout:
				writeAPIError(w, http.StatusUnauthorized, "session_expired",
					"Session expired due to inactivity — please log in again")
			case ErrSessionRevoked:
				writeAPIError(w, http.StatusUnauthorized, "session_revoked",
					"Session has been revoked")
			default:
				writeAPIError(w, http.StatusUnauthorized, "invalid_token",
					"Invalid or expired token")
			}
			return
		}

		// Inject claims into context
		ctx := context.WithValue(r.Context(), ctxKeyClaims, claims)
		ctx  = context.WithValue(ctx, ctxKeyUserID, claims.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ─── Middleware: RequirePermission ─────────────────────────────────────────────
// Checks that the authenticated user's role includes the required permission.
func (s *Service) RequirePermission(perm Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if claims == nil {
				writeAPIError(w, http.StatusUnauthorized, "missing_claims",
					"Authentication required")
				return
			}

			// Build a temporary User for permission check
			dummy := &User{Role: claims.Role}
			if !dummy.HasPermission(perm) {
				writeAPIError(w, http.StatusForbidden, "insufficient_permission",
					"Your role does not have permission: "+string(perm))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ─── Middleware: RequireRole ───────────────────────────────────────────────────
// Checks that the authenticated user has at least the minimum role level.
func (s *Service) RequireRole(minRole Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if claims == nil {
				writeAPIError(w, http.StatusUnauthorized, "missing_claims", "")
				return
			}
			if claims.Role.Level() < minRole.Level() {
				writeAPIError(w, http.StatusForbidden, "insufficient_role",
					"Minimum required role: "+string(minRole))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ─── Middleware: SecurityHeaders ──────────────────────────────────────────────
// Adds security-related response headers to every response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options",     "nosniff")
		h.Set("X-Frame-Options",            "DENY")
		h.Set("X-XSS-Protection",           "1; mode=block")
		h.Set("Referrer-Policy",            "strict-origin-when-cross-origin")
		// The SOC dashboard ships as a single self-contained HTML file at
		// /etc/falx/dashboard/index.html — ~82 KB with all CSS inside one
		// <style> block and all JS inside one <script> block. A strict
		// `default-src 'self'` CSP blocks both, which is why the page rendered
		// as raw unstyled HTML in the browser. 'unsafe-inline' for style-src
		// and script-src is the minimum loosening required; img-src 'data:'
		// permits inline base64 icons; ws:/wss: in connect-src is needed for
		// the dashboard's WebSocket subscription to /ws. frame-ancestors 'none'
		// is the modern equivalent of the X-Frame-Options=DENY above.
		// Long-term option (out of scope here): per-request nonce in
		// <style nonce=...>/<script nonce=...>, served through an html/template
		// pipeline so the static file can drop 'unsafe-inline'.
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"script-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; "+
				"connect-src 'self' ws: wss:; "+
				"frame-ancestors 'none'; "+
				"base-uri 'self'")
		h.Set("Strict-Transport-Security",  "max-age=63072000; includeSubDomains")
		h.Set("Cache-Control",              "no-store")
		h.Del("Server")
		next.ServeHTTP(w, r)
	})
}

// ─── Middleware: RequestLogger ────────────────────────────────────────────────
func RequestLogger(log *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw    := &responseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)
			log.Info("API request",
				zap.String("method",   r.Method),
				zap.String("path",     r.URL.Path),
				zap.Int("status",      rw.status),
				zap.Duration("latency",time.Since(start)),
				zap.String("ip",       realIP(r)),
			)
		})
	}
}

// ─── Middleware: CORS ─────────────────────────────────────────────────────────
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	originSet := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		originSet[o] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if _, ok := originSet[origin]; ok {
				w.Header().Set("Access-Control-Allow-Origin",  origin)
				w.Header().Set("Vary",                         "Origin")
			}
			w.Header().Set("Access-Control-Allow-Methods",    "GET,POST,PUT,PATCH,DELETE,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers",    "Authorization,Content-Type")
			w.Header().Set("Access-Control-Allow-Credentials","true")
			w.Header().Set("Access-Control-Max-Age",          "3600")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ─── Context Helpers ──────────────────────────────────────────────────────────
func ClaimsFromContext(ctx context.Context) *TokenClaims {
	v := ctx.Value(ctxKeyClaims)
	if v == nil {
		return nil
	}
	c, _ := v.(*TokenClaims)
	return c
}

func UserIDFromContext(ctx context.Context) string {
	v := ctx.Value(ctxKeyUserID)
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

// ─── Bearer Token Extraction ──────────────────────────────────────────────────
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		// Also check cookie (for browser-based SOC dashboard)
		if c, err := r.Cookie("falx_access_token"); err == nil {
			return c.Value
		}
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return parts[1]
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func realIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	return r.RemoteAddr
}
