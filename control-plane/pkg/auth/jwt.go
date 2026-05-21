// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: JWT manager (control-plane/internal/auth/jwt.go).
//              Implements RS256-signed JWT tokens (asymmetric).
//              Using RS256 (not HS256) because:
//                - Services can verify tokens using the public key only
//                - Private key stays in the auth service exclusively
//                - Cannot forge tokens even with read access to other services
//
//              Token TTLs:
//                Access token:  15 minutes (short-lived, stateless)
//                Refresh token: 7 days (stored in DB, rotated on use)
//
//              Inactivity Timeout:
//                Enforced at SESSION level (not JWT level).
//                Each API request slides the session.LastActivityAt.
//                Middleware rejects requests if now - LastActivityAt > 25 min.
// =============================================================================

package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ─── Config ───────────────────────────────────────────────────────────────────
type JWTConfig struct {
	// Paths to PEM-encoded RSA keys (generated on first start if absent)
	PrivateKeyPath string
	PublicKeyPath  string

	// Token lifetimes
	AccessTokenTTL  time.Duration // default: 15 min
	RefreshTokenTTL time.Duration // default: 7 days
	InactivityTimeout time.Duration // default: 25 min
	Issuer          string
}

func DefaultJWTConfig() JWTConfig {
	return JWTConfig{
		PrivateKeyPath:    "/etc/falx/keys/jwt_private.pem",
		PublicKeyPath:     "/etc/falx/keys/jwt_public.pem",
		AccessTokenTTL:    15 * time.Minute,
		RefreshTokenTTL:   7 * 24 * time.Hour,
		InactivityTimeout: 25 * time.Minute,
		Issuer:            "falx-v2",
	}
}

// ─── JWT Manager ──────────────────────────────────────────────────────────────
type JWTManager struct {
	cfg        JWTConfig
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// ─── Constructor ──────────────────────────────────────────────────────────────
func NewJWTManager(cfg JWTConfig) (*JWTManager, error) {
	m := &JWTManager{cfg: cfg}

	if err := m.loadOrGenerateKeys(); err != nil {
		return nil, fmt.Errorf("JWT key init: %w", err)
	}
	return m, nil
}

// ─── Key Management ───────────────────────────────────────────────────────────
func (m *JWTManager) loadOrGenerateKeys() error {
	// Try to load existing keys
	privPEM, privErr := os.ReadFile(m.cfg.PrivateKeyPath)
	pubPEM, pubErr   := os.ReadFile(m.cfg.PublicKeyPath)

	if privErr == nil && pubErr == nil {
		return m.parseKeys(privPEM, pubPEM)
	}

	// Generate new 4096-bit RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("RSA key generation: %w", err)
	}

	// Encode and save
	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privBlock  := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}
	pubBytes, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	pubBlock     := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}

	keyDir := filepath.Dir(m.cfg.PrivateKeyPath)
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return fmt.Errorf("key dir %s: %w", keyDir, err)
	}
	if err := os.WriteFile(m.cfg.PrivateKeyPath,
		pem.EncodeToMemory(privBlock), 0o600); err != nil {
		return fmt.Errorf("save private key: %w", err)
	}
	if err := os.WriteFile(m.cfg.PublicKeyPath,
		pem.EncodeToMemory(pubBlock), 0o644); err != nil {
		return fmt.Errorf("save public key: %w", err)
	}

	m.privateKey = privateKey
	m.publicKey  = &privateKey.PublicKey
	return nil
}

func (m *JWTManager) parseKeys(privPEM, pubPEM []byte) error {
	block, _ := pem.Decode(privPEM)
	if block == nil {
		return errors.New("invalid private key PEM")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	block, _ = pem.Decode(pubPEM)
	if block == nil {
		return errors.New("invalid public key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return errors.New("public key is not RSA")
	}

	m.privateKey = priv
	m.publicKey  = rsaPub
	return nil
}

// ─── Internal Claims (extends jwt.RegisteredClaims) ──────────────────────────
type falxClaims struct {
	jwt.RegisteredClaims
	Username    string       `json:"username"`
	Role        Role         `json:"role"`
	SessionID   string       `json:"sid"`
	TokenType   string       `json:"type"`
	TFAVerified bool         `json:"tfa_ok"`
	Scope       string       `json:"scope"`
	Permissions []Permission `json:"perms"`
}

// ─── Access Token ─────────────────────────────────────────────────────────────
// scope must be ScopePreAuth or ScopeSession (defined in models.go).
func (m *JWTManager) GenerateAccessToken(user *User, sessionID string, tfaVerified bool, scope string) (string, time.Time, error) {
	now    := time.Now()
	expiry := now.Add(m.cfg.AccessTokenTTL)

	claims := falxClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			Issuer:    m.cfg.Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiry),
			NotBefore: jwt.NewNumericDate(now),
		},
		Username:    user.Username,
		Role:        user.Role,
		SessionID:   sessionID,
		TokenType:   "access",
		TFAVerified: tfaVerified,
		Scope:       scope,
		Permissions: RolePermissions[user.Role],
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(m.privateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign access token: %w", err)
	}
	return signed, expiry, nil
}

// ─── Refresh Token ────────────────────────────────────────────────────────────
// Refresh tokens are opaque random bytes (not JWT).
// Stored hashed in the DB; the raw token is returned once and never stored in clear.
func (m *JWTManager) GenerateRefreshToken() (raw string, hashed string, err error) {
	b := make([]byte, 48) // 384 bits of entropy
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("refresh token entropy: %w", err)
	}

	urlSafeEncode := func(b []byte) string {
		const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		out := make([]byte, len(b))
		for i, v := range b {
			out[i] = chars[v%64]
		}
		return string(out)
	}

	raw = urlSafeEncode(b)

	// Hash using Argon2id for storage
	hashed, err = HashPassword(raw)
	if err != nil {
		return "", "", fmt.Errorf("hash refresh token: %w", err)
	}
	return raw, hashed, nil
}

// ─── Verify Access Token ──────────────────────────────────────────────────────
func (m *JWTManager) VerifyAccessToken(tokenStr string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenStr,
		&falxClaims{},
		func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return m.publicKey, nil
		},
		jwt.WithIssuer(m.cfg.Issuer),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*falxClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}
	if claims.TokenType != "access" {
		return nil, errors.New("wrong token type: expected access")
	}

	return &TokenClaims{
		UserID:      claims.Subject,
		Username:    claims.Username,
		Role:        claims.Role,
		SessionID:   claims.SessionID,
		IssuedAt:    claims.IssuedAt.Unix(),
		ExpiresAt:   claims.ExpiresAt.Unix(),
		TokenType:   claims.TokenType,
		TFAVerified: claims.TFAVerified,
		Scope:       claims.Scope,
		Permissions: claims.Permissions,
	}, nil
}

// ─── Public Key (PEM) for external services ───────────────────────────────────
func (m *JWTManager) PublicKeyPEM() ([]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(m.publicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}), nil
}

// ─── Token TTLs ───────────────────────────────────────────────────────────────
func (m *JWTManager) AccessTokenTTL()    time.Duration { return m.cfg.AccessTokenTTL }
func (m *JWTManager) RefreshTokenTTL()   time.Duration { return m.cfg.RefreshTokenTTL }
func (m *JWTManager) InactivityTimeout() time.Duration { return m.cfg.InactivityTimeout }
