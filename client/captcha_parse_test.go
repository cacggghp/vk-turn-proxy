package main

import "testing"

// TestParseVkCaptchaError_NewFormatWithoutCaptchaSid reproduces issue #182.
//
// VK started returning a captcha-required error (error_code 14) at the
// calls.getAnonymousToken step in a NEW shape that only carries:
//
//	error_code, error_msg, is_enabled_captcha, redirect_uri
//
// and notably NO captcha_sid and NO captcha_img. The previous parser
// rejected this payload with "missing captcha_sid in captcha error data"
// and returned nil, so the auth loop never reached the captcha solver and
// just fell through to the next client_id.
//
// After the fix, ParseVkCaptchaError must return a non-nil *VkCaptchaError
// with RedirectURI + SessionToken populated so both the auto solver and the
// manual (browser) solver can run.
func TestParseVkCaptchaError_NewFormatWithoutCaptchaSid(t *testing.T) {
	t.Parallel()

	// Shape taken verbatim from the issue #182 log (session_token truncated
	// for readability but structurally identical to the real payload).
	errData := map[string]interface{}{
		"error_code":         float64(14),
		"error_msg":          "Captcha need",
		"is_enabled_captcha": true,
		"redirect_uri":       "https://id.vk.ru/not_robot_captcha?domain=vk.com&session_token=eyJhbGciOiJBMjU2R0NNS1ci.payload.signature&variant=popup&blank=1",
		"captcha_stid":       "some-stid", // unrelated field, must be ignored
	}

	got := ParseVkCaptchaError(errData)
	if got == nil {
		t.Fatal("expected non-nil VkCaptchaError for new captcha format, got nil")
	}

	if got.ErrorCode != 14 {
		t.Fatalf("ErrorCode = %d, want 14", got.ErrorCode)
	}
	if got.ErrorMsg != "Captcha need" {
		t.Fatalf("ErrorMsg = %q, want %q", got.ErrorMsg, "Captcha need")
	}
	if got.RedirectURI == "" {
		t.Fatal("RedirectURI is empty, expected the not_robot_captcha URL")
	}
	if got.SessionToken == "" {
		t.Fatal("SessionToken is empty, expected it to be parsed from redirect_uri query")
	}
	if got.SessionToken != "eyJhbGciOiJBMjU2R0NNS1ci.payload.signature" {
		t.Fatalf("SessionToken = %q, want the session_token query value", got.SessionToken)
	}
	// captcha_sid / captcha_img are absent in the new format and must default
	// to empty strings (NOT cause the parser to bail out).
	if got.CaptchaSid != "" {
		t.Fatalf("CaptchaSid = %q, want empty (not present in new format)", got.CaptchaSid)
	}
	if got.CaptchaImg != "" {
		t.Fatalf("CaptchaImg = %q, want empty (not present in new format)", got.CaptchaImg)
	}

	if !got.IsCaptchaError() {
		t.Fatal("IsCaptchaError() = false, want true (new flow is solvable via redirect_uri + session_token)")
	}
}

// TestParseVkCaptchaError_LegacyFormatStillWorks ensures the legacy captcha
// payload (captcha_sid + captcha_img, no redirect_uri) still parses so the
// manual HTTP captcha path keeps working.
func TestParseVkCaptchaError_LegacyFormatStillWorks(t *testing.T) {
	t.Parallel()

	errData := map[string]interface{}{
		"error_code":  float64(14),
		"error_msg":   "Captcha need",
		"captcha_sid": "1234567890",
		"captcha_img": "https://api.vk.com/captcha.php?sid=1234567890&s=1",
	}

	got := ParseVkCaptchaError(errData)
	if got == nil {
		t.Fatal("expected non-nil VkCaptchaError for legacy captcha format, got nil")
	}
	if got.CaptchaSid != "1234567890" {
		t.Fatalf("CaptchaSid = %q, want 1234567890", got.CaptchaSid)
	}
	if got.CaptchaImg == "" {
		t.Fatal("CaptchaImg is empty, expected the captcha image URL")
	}
	if got.RedirectURI != "" {
		t.Fatalf("RedirectURI = %q, want empty in legacy flow", got.RedirectURI)
	}
}

// TestParseVkCaptchaError_NumericCaptchaSid covers the case where VK returns
// captcha_sid as a JSON number (unmarshalled into float64).
func TestParseVkCaptchaError_NumericCaptchaSid(t *testing.T) {
	t.Parallel()

	errData := map[string]interface{}{
		"error_code":  float64(14),
		"error_msg":   "Captcha need",
		"captcha_sid": float64(9876543210),
		"captcha_img": "https://api.vk.com/captcha.php?sid=9876543210",
	}

	got := ParseVkCaptchaError(errData)
	if got == nil {
		t.Fatal("expected non-nil VkCaptchaError, got nil")
	}
	if got.CaptchaSid != "9876543210" {
		t.Fatalf("CaptchaSid = %q, want 9876543210", got.CaptchaSid)
	}
}

// TestParseVkCaptchaError_UnsolvableReturnsNil verifies that when none of the
// solvable fields are present, the parser returns nil so the caller surfaces
// the raw VK error instead of pretending it can solve a captcha it cannot.
func TestParseVkCaptchaError_UnsolvableReturnsNil(t *testing.T) {
	t.Parallel()

	errData := map[string]interface{}{
		"error_code": float64(14),
		"error_msg":  "Captcha need",
		// no redirect_uri, no captcha_sid, no captcha_img
	}

	if got := ParseVkCaptchaError(errData); got != nil {
		t.Fatalf("expected nil for unsolvable captcha payload, got %+v", got)
	}
}

// TestParseVkCaptchaError_MissingErrorCodeReturnsNil verifies the parser still
// rejects payloads that don't even identify as a VK API error object.
func TestParseVkCaptchaError_MissingErrorCodeReturnsNil(t *testing.T) {
	t.Parallel()

	errData := map[string]interface{}{
		"error_msg":    "Captcha need",
		"redirect_uri": "https://id.vk.ru/not_robot_captcha?session_token=x",
	}

	if got := ParseVkCaptchaError(errData); got != nil {
		t.Fatalf("expected nil when error_code is missing, got %+v", got)
	}
}
