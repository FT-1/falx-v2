// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Password hashing (control-plane/internal/auth/password.go).
//              Uses Argon2id (RFC 9106) — the winner of the Password Hashing
//              Competition. Memory-hard and resistant to GPU/ASIC attacks.
//
//              Parameters (OWASP recommended for 2024):
//                Memory:      64 MiB (65536 KiB)
//                Iterations:  3
//                Parallelism: 2
//                Salt:        16 bytes (crypto/rand)
//                Key length:  32 bytes
//
//              Format stored in DB:
//                $argon2id$v=19$m=65536,t=3,p=2$<salt_b64>$<hash_b64>
// =============================================================================

package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ─── Argon2id Parameters ──────────────────────────────────────────────────────
type argon2Params struct {
	memory      uint32 // KiB
	iterations  uint32
	parallelism uint8
	saltLen     uint32
	keyLen      uint32
}

var defaultArgon2Params = argon2Params{
	memory:      64 * 1024, // 64 MiB
	iterations:  3,
	parallelism: 2,
	saltLen:     16,
	keyLen:      32,
}

// ─── Hash ─────────────────────────────────────────────────────────────────────
// HashPassword derives an Argon2id hash from a plaintext password.
// Returns a self-describing encoded string safe for storage.
func HashPassword(password string) (string, error) {
	if len(password) < 12 {
		return "", errors.New("password must be at least 12 characters")
	}
	if len(password) > 128 {
		return "", errors.New("password exceeds maximum length")
	}

	p := defaultArgon2Params

	// Cryptographically secure random salt
	salt := make([]byte, p.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("salt generation: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		p.iterations,
		p.memory,
		p.parallelism,
		p.keyLen,
	)

	// Encode in PHC string format
	b64salt := base64.RawStdEncoding.EncodeToString(salt)
	b64hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		p.memory, p.iterations, p.parallelism,
		b64salt, b64hash,
	)
	return encoded, nil
}

// ─── Verify ───────────────────────────────────────────────────────────────────
// VerifyPassword checks a plaintext password against a stored Argon2id hash.
// Uses constant-time comparison to prevent timing attacks.
func VerifyPassword(password, encoded string) (bool, error) {
	// Parse the encoded hash
	p, salt, hash, err := decodeHash(encoded)
	if err != nil {
		return false, fmt.Errorf("decode hash: %w", err)
	}

	// Re-derive the key with the stored parameters
	comparison := argon2.IDKey(
		[]byte(password),
		salt,
		p.iterations,
		p.memory,
		p.parallelism,
		p.keyLen,
	)

	// Constant-time comparison — prevents timing side-channel leaks
	if subtle.ConstantTimeCompare(hash, comparison) == 1 {
		return true, nil
	}
	return false, nil
}

// ─── Decode ───────────────────────────────────────────────────────────────────
func decodeHash(encoded string) (argon2Params, []byte, []byte, error) {
	var p argon2Params

	parts := strings.Split(encoded, "$")
	// Format: "" "argon2id" "v=19" "m=...,t=...,p=..." "salt" "hash"
	if len(parts) != 6 {
		return p, nil, nil, errors.New("invalid hash format: wrong field count")
	}
	if parts[1] != "argon2id" {
		return p, nil, nil, fmt.Errorf("unsupported algorithm: %s", parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return p, nil, nil, fmt.Errorf("version parse: %w", err)
	}
	if version != argon2.Version {
		return p, nil, nil, fmt.Errorf("incompatible argon2 version: %d", version)
	}

	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d",
		&p.memory, &p.iterations, &p.parallelism); err != nil {
		return p, nil, nil, fmt.Errorf("params parse: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return p, nil, nil, fmt.Errorf("salt decode: %w", err)
	}
	p.saltLen = uint32(len(salt))

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return p, nil, nil, fmt.Errorf("hash decode: %w", err)
	}
	p.keyLen = uint32(len(hash))

	return p, salt, hash, nil
}

// ─── Password Validation ──────────────────────────────────────────────────────
type PasswordError struct {
	Field   string
	Message string
}

func (e *PasswordError) Error() string {
	return e.Message
}

// ValidatePasswordStrength enforces the password policy.
// Policy: min 12 chars, at least 1 uppercase, 1 lowercase, 1 digit, 1 special.
func ValidatePasswordStrength(password string) error {
	if len(password) < 12 {
		return &PasswordError{"password", "must be at least 12 characters"}
	}
	if len(password) > 128 {
		return &PasswordError{"password", "must not exceed 128 characters"}
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range password {
		switch {
		case c >= 'A' && c <= 'Z': hasUpper   = true
		case c >= 'a' && c <= 'z': hasLower   = true
		case c >= '0' && c <= '9': hasDigit   = true
		default:                   hasSpecial = true
		}
	}

	if !hasUpper {
		return &PasswordError{"password", "must contain at least one uppercase letter"}
	}
	if !hasLower {
		return &PasswordError{"password", "must contain at least one lowercase letter"}
	}
	if !hasDigit {
		return &PasswordError{"password", "must contain at least one digit"}
	}
	if !hasSpecial {
		return &PasswordError{"password", "must contain at least one special character"}
	}
	return nil
}
