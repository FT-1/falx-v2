// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Auth crypto tests (control-plane/internal/auth/crypto_test.go).
//              Tests for Argon2id hashing, TOTP, and password policy.
// =============================================================================

package auth

import (
	"strings"
	"testing"
	"time"
)

// ─── Argon2id Tests ───────────────────────────────────────────────────────────

func TestHashPassword_Roundtrip(t *testing.T) {
	passwords := []string{
		"CorrectHorse#Battery9!",
		"P@ssw0rd!SecureEnough",
		"12CharMinimum!",
		strings.Repeat("a", 128), // Max length
	}

	for _, pw := range passwords {
		hash, err := HashPassword(pw)
		if err != nil {
			t.Fatalf("HashPassword(%q): %v", pw, err)
		}

		// Hash must start with Argon2id identifier
		if !strings.HasPrefix(hash, "$argon2id$") {
			t.Errorf("hash format wrong: %s", hash[:20])
		}

		// Verification must succeed
		ok, err := VerifyPassword(pw, hash)
		if err != nil {
			t.Fatalf("VerifyPassword: %v", err)
		}
		if !ok {
			t.Errorf("password %q should verify against its own hash", pw)
		}

		// Wrong password must fail
		ok, _ = VerifyPassword(pw+"_wrong", hash)
		if ok {
			t.Errorf("wrong password should not verify")
		}
	}
}

func TestHashPassword_UniqueHashes(t *testing.T) {
	// Same password hashed twice must produce different hashes (different salt)
	pw := "SamePassword123!"
	h1, _ := HashPassword(pw)
	h2, _ := HashPassword(pw)

	if h1 == h2 {
		t.Error("two hashes of same password must differ (random salt)")
	}

	// Both must verify correctly
	ok1, _ := VerifyPassword(pw, h1)
	ok2, _ := VerifyPassword(pw, h2)
	if !ok1 || !ok2 {
		t.Error("both hashes should verify correctly")
	}
}

func TestHashPassword_TooShort(t *testing.T) {
	_, err := HashPassword("short")
	if err == nil {
		t.Error("expected error for password shorter than 12 chars")
	}
}

func TestHashPassword_TooLong(t *testing.T) {
	_, err := HashPassword(strings.Repeat("a", 129))
	if err == nil {
		t.Error("expected error for password longer than 128 chars")
	}
}

func TestVerifyPassword_InvalidHash(t *testing.T) {
	_, err := VerifyPassword("anypassword", "not-a-valid-hash")
	if err == nil {
		t.Error("expected error for invalid hash format")
	}
}

func TestVerifyPassword_TimingSafe(t *testing.T) {
	// Verify that wrong password doesn't short-circuit timing
	// (We can't measure nanoseconds in unit tests, but we can ensure
	//  no panic or early return on wrong password)
	hash, _ := HashPassword("RealPassword123!")

	cases := []string{
		"WrongPassword123!",
		"",
		strings.Repeat("x", 128),
	}
	for _, pw := range cases {
		ok, err := VerifyPassword(pw, hash)
		if err != nil {
			t.Errorf("VerifyPassword(%q): unexpected error: %v", pw, err)
		}
		if ok {
			t.Errorf("VerifyPassword(%q): should not match", pw)
		}
	}
}

// ─── Password Strength Tests ──────────────────────────────────────────────────

func TestPasswordStrength(t *testing.T) {
	cases := []struct {
		pw      string
		wantErr bool
		desc    string
	}{
		{"ValidP@ss1234!", false, "strong password"},
		{"short1A!", true, "too short (<12)"},
		{"alllowercase123!", true, "no uppercase"},
		{"ALLUPPERCASE123!", true, "no lowercase"},
		{"NoNumbersHere!!", true, "no digits"},
		{"NoSpecialChars123", true, "no special chars"},
		{strings.Repeat("a", 129), true, "too long"},
		{"Correct#Horse7Battery!", false, "long strong password"},
	}

	for _, tc := range cases {
		err := ValidatePasswordStrength(tc.pw)
		if tc.wantErr && err == nil {
			t.Errorf("%s: expected error, got nil", tc.desc)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s: unexpected error: %v", tc.desc, err)
		}
	}
}

// ─── TOTP Tests ───────────────────────────────────────────────────────────────

func TestTOTPSecretGeneration(t *testing.T) {
	s1, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if len(s1) < 16 {
		t.Errorf("secret too short: %d chars", len(s1))
	}

	// Two secrets must differ
	s2, _ := GenerateTOTPSecret()
	if s1 == s2 {
		t.Error("two generated secrets must differ")
	}
}

func TestTOTPCodeGeneration(t *testing.T) {
	secret, _ := GenerateTOTPSecret()

	// Generate a code for current time
	code, err := GenerateTOTP(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}
	if len(code) != 6 {
		t.Errorf("TOTP code must be 6 digits, got %d: %s", len(code), code)
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			t.Errorf("TOTP code must be digits only, got: %s", code)
		}
	}
}

func TestTOTPVerification_CurrentWindow(t *testing.T) {
	secret, _ := GenerateTOTPSecret()

	// Generate and verify within current window
	code, _ := GenerateTOTP(secret, time.Now())
	if !VerifyTOTPCode(secret, code) {
		t.Error("current window code should verify")
	}
}

func TestTOTPVerification_PreviousWindow(t *testing.T) {
	secret, _ := GenerateTOTPSecret()

	// Code from 30 seconds ago (within ±1 window tolerance)
	past := time.Now().Add(-30 * time.Second)
	code, _ := GenerateTOTP(secret, past)
	if !VerifyTOTPCode(secret, code) {
		t.Error("previous window code should verify (±1 tolerance)")
	}
}

func TestTOTPVerification_TooOld(t *testing.T) {
	secret, _ := GenerateTOTPSecret()

	// Code from 2 minutes ago (outside ±1 window)
	old := time.Now().Add(-120 * time.Second)
	code, _ := GenerateTOTP(secret, old)
	if VerifyTOTPCode(secret, code) {
		t.Error("expired code should not verify")
	}
}

func TestTOTPVerification_ReplayPrevention(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	code, _   := GenerateTOTP(secret, time.Now())

	// First use: should succeed
	if !VerifyTOTPCode(secret, code) {
		t.Fatal("first verification should succeed")
	}

	// Second use of same code: must fail (replay prevention)
	if VerifyTOTPCode(secret, code) {
		t.Error("replay of same TOTP code should fail")
	}
}

func TestTOTPVerification_WrongCode(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	if VerifyTOTPCode(secret, "000000") {
		// Extremely unlikely but possible. Try another.
		if VerifyTOTPCode(secret, "999999") {
			t.Error("random codes should not verify (extremely unlikely to pass)")
		}
	}
}

func TestTOTPProvisioningURI(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	uri    := GenerateProvisioningURI(secret, "alice")

	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Errorf("provisioning URI must start with otpauth://totp/, got: %s", uri[:30])
	}
	if !strings.Contains(uri, secret) {
		t.Error("provisioning URI must contain the secret")
	}
	if !strings.Contains(uri, "alice") {
		t.Error("provisioning URI must contain the username")
	}
	if !strings.Contains(uri, "FALX-V2") {
		t.Error("provisioning URI must contain the issuer")
	}
}

func TestBackupCodesGeneration(t *testing.T) {
	plain, hashed, err := GenerateBackupCodes()
	if err != nil {
		t.Fatalf("GenerateBackupCodes: %v", err)
	}
	if len(plain) != backupCodeCount {
		t.Errorf("expected %d backup codes, got %d", backupCodeCount, len(plain))
	}
	if len(hashed) != backupCodeCount {
		t.Errorf("expected %d hashed codes, got %d", backupCodeCount, len(hashed))
	}

	// Each plain code must verify against its hash
	for i, code := range plain {
		ok, err := VerifyPassword(code, hashed[i])
		if err != nil {
			t.Errorf("code[%d] verify error: %v", i, err)
		}
		if !ok {
			t.Errorf("code[%d] should verify against its hash", i)
		}
	}

	// All codes must be unique
	seen := make(map[string]bool)
	for _, code := range plain {
		if seen[code] {
			t.Errorf("duplicate backup code: %s", code)
		}
		seen[code] = true
	}
}

// ─── Benchmarks ───────────────────────────────────────────────────────────────

func BenchmarkHashPassword(b *testing.B) {
	pw := "BenchmarkPassword123!"
	b.ResetTimer()
	// Argon2id is intentionally slow — benchmark shows real-world cost
	for i := 0; i < b.N; i++ {
		HashPassword(pw)
	}
}

func BenchmarkVerifyPassword(b *testing.B) {
	pw   := "BenchmarkPassword123!"
	hash, _ := HashPassword(pw)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyPassword(pw, hash)
	}
}

func BenchmarkGenerateTOTP(b *testing.B) {
	secret, _ := GenerateTOTPSecret()
	now := time.Now()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		GenerateTOTP(secret, now)
	}
}

func BenchmarkVerifyTOTP(b *testing.B) {
	secret, _ := GenerateTOTPSecret()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Each iteration uses a slightly different time to avoid replay cache
		code, _ := GenerateTOTP(secret, time.Now().Add(time.Duration(i)*time.Hour*24))
		VerifyTOTPCode(secret, code)
	}
}
