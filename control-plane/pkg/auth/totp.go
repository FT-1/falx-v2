// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: TOTP 2FA (control-plane/internal/auth/totp.go).
//              RFC 6238 Time-based One-Time Password implementation.
//              Compatible with Google Authenticator, Authy, 1Password, etc.
//
//              Security properties:
//                - HMAC-SHA1 (standard TOTP) with 30-second window
//                - ±1 window tolerance for clock drift
//                - Used-code replay prevention via in-memory cache
//                - 8 single-use backup codes (Argon2id hashed)
//                - QR code provisioning URI generation
// =============================================================================

package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ─── TOTP Config ──────────────────────────────────────────────────────────────
const (
	totpDigits    = 6
	totpPeriod    = 30 // seconds
	totpWindow    = 1  // ± windows for clock drift
	totpIssuer    = "FALX-V2"
)

// ─── Secret Generation ────────────────────────────────────────────────────────
// GenerateTOTPSecret creates a new random 20-byte (160-bit) TOTP secret.
// Returns the secret encoded in Base32 (the standard for TOTP secrets).
func GenerateTOTPSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate TOTP secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// ─── OTP Generation ───────────────────────────────────────────────────────────
// GenerateTOTP computes the TOTP code for a given secret and Unix timestamp.
// Used for testing and server-side validation.
func GenerateTOTP(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("invalid TOTP secret: %w", err)
	}

	counter := uint64(math.Floor(float64(t.Unix()) / totpPeriod))
	code, err := hotp(key, counter, totpDigits)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", totpDigits, code), nil
}

// ─── OTP Verification ─────────────────────────────────────────────────────────
// totpCache prevents replay attacks by tracking recently-used codes.
var (
	totpCacheMu sync.Mutex
	totpCache   = make(map[string]int64) // "secret:code" → unix timestamp
)

// VerifyTOTPCode checks a code with ±1 window tolerance and replay prevention.
func VerifyTOTPCode(secret, code string) bool {
	if len(code) != totpDigits {
		return false
	}

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.ToUpper(secret))
	if err != nil {
		return false
	}

	now := time.Now().Unix()
	step := int64(totpPeriod)

	// Check current window ± tolerance
	for delta := -int64(totpWindow); delta <= int64(totpWindow); delta++ {
		counter := uint64((now + delta*step) / step)
		expected, err := hotp(key, counter, totpDigits)
		if err != nil {
			continue
		}
		expectedStr := fmt.Sprintf("%0*d", totpDigits, expected)

		if hmac.Equal([]byte(code), []byte(expectedStr)) {
			// Replay prevention: mark this (secret+counter) as used
			cacheKey := fmt.Sprintf("%s:%d", secret, counter)
			totpCacheMu.Lock()
			if _, used := totpCache[cacheKey]; used {
				totpCacheMu.Unlock()
				return false // Replay detected
			}
			totpCache[cacheKey] = now
			// Purge old cache entries (>2 windows old)
			cutoff := now - int64(totpWindow+1)*step
			for k, ts := range totpCache {
				if ts < cutoff {
					delete(totpCache, k)
				}
			}
			totpCacheMu.Unlock()
			return true
		}
	}
	return false
}

// ─── HOTP core (RFC 4226) ─────────────────────────────────────────────────────
func hotp(key []byte, counter uint64, digits int) (uint32, error) {
	// Convert counter to big-endian 8-byte
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)

	// HMAC-SHA1
	mac := hmac.New(sha1.New, key)
	if _, err := mac.Write(msg); err != nil {
		return 0, err
	}
	h := mac.Sum(nil)

	// Dynamic truncation (RFC 4226 §5.3)
	offset := h[len(h)-1] & 0x0F
	code := (uint32(h[offset]&0x7F) << 24) |
		(uint32(h[offset+1]) << 16) |
		(uint32(h[offset+2]) << 8) |
		uint32(h[offset+3])

	mod := uint32(math.Pow10(digits))
	return code % mod, nil
}

// ─── Provisioning URI ─────────────────────────────────────────────────────────
// GenerateProvisioningURI creates an otpauth:// URI for QR code generation.
// Uses net/url so label components and parameter values are correctly
// percent-encoded per RFC 3986 — prevents any character in the username or
// issuer from breaking the URI structure.
func GenerateProvisioningURI(secret, username string) string {
	// Label: "Issuer:Account" — each component percent-encoded independently
	// so the colon separator is preserved as a literal.
	label := url.PathEscape(totpIssuer) + ":" + url.PathEscape(username)

	params := url.Values{}
	params.Set("secret", secret)
	params.Set("issuer", totpIssuer)
	params.Set("algorithm", "SHA1")
	params.Set("digits", fmt.Sprintf("%d", totpDigits))
	params.Set("period", fmt.Sprintf("%d", totpPeriod))

	return "otpauth://totp/" + label + "?" + params.Encode()
}

// ─── Backup Codes ─────────────────────────────────────────────────────────────
const backupCodeCount = 8

// GenerateBackupCodes creates 8 random plaintext backup codes.
// Hashing is intentionally NOT done here — call HashBackupCodes at confirm
// time so the wizard opens instantly instead of blocking for 8× Argon2id.
func GenerateBackupCodes() ([]string, error) {
	plain   := make([]string, backupCodeCount)
	charset := "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // No O/0/1/I ambiguity
	for i := range plain {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		code := make([]byte, 8)
		for j, v := range b {
			code[j] = charset[v%byte(len(charset))]
		}
		plain[i] = fmt.Sprintf("%s-%s", string(code[:4]), string(code[4:]))
	}
	return plain, nil
}

// HashBackupCodes Argon2id-hashes plaintext backup codes for storage.
// Called at confirm-time (after the user scans the QR code), not at begin-time.
// Uses HashBackupCode — NOT HashPassword — to avoid user-password length policy.
func HashBackupCodes(plain []string) ([]string, error) {
	hashed := make([]string, len(plain))
	for i, code := range plain {
		h, err := HashBackupCode(code)
		if err != nil {
			return nil, err
		}
		hashed[i] = h
	}
	return hashed, nil
}

// ─── TOTP Enrollment ──────────────────────────────────────────────────────────
type TOTPEnrollment struct {
	Secret          string   `json:"secret"`
	ProvisioningURI string   `json:"provisioning_uri"`
	BackupCodes     []string `json:"backup_codes"` // Show once, never again
	QRDataURI       string   `json:"qr_data_uri"`  // data:image/svg+xml;base64,…
	// Identity context — returned to the wizard so the UI can confirm which
	// account and role are being secured before the user scans the QR code.
	Username        string   `json:"username"`
	Role            string   `json:"role"`
}

// BeginTOTPEnrollment starts the TOTP setup for a user.
// role is the user's current RBAC role string (e.g. "super_admin") — included
// in the enrollment response for wizard context display only, NOT in the URI.
// Returns enrollment data only — backup codes are NOT hashed here.
// Call HashBackupCodes on the returned BackupCodes at confirm-time.
func BeginTOTPEnrollment(username, role string) (*TOTPEnrollment, error) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		return nil, err
	}

	plain, err := GenerateBackupCodes()
	if err != nil {
		return nil, err
	}

	uri := GenerateProvisioningURI(secret, username)
	return &TOTPEnrollment{
		Secret:          secret,
		ProvisioningURI: uri,
		BackupCodes:     plain,
		QRDataURI:       qrDataURI(uri),
		Username:        username,
		Role:            role,
	}, nil
}
