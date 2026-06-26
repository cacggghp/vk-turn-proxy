package clientcore

import "testing"

func TestCaptchaSolveModeForAttempt(t *testing.T) {
	t.Parallel()

	t.Run("default flow", func(t *testing.T) {
		t.Parallel()

		mode, ok := captchaSolveModeForAttempt(0, false, true)
		if !ok || mode != captchaSolveModeAuto {
			t.Fatalf("expected first attempt to use auto captcha, got mode=%v ok=%v", mode, ok)
		}

		mode, ok = captchaSolveModeForAttempt(1, false, true)
		if !ok || mode != captchaSolveModeSliderPOC {
			t.Fatalf("expected second attempt to use slider POC, got mode=%v ok=%v", mode, ok)
		}

		mode, ok = captchaSolveModeForAttempt(2, false, true)
		if !ok || mode != captchaSolveModeManual {
			t.Fatalf("expected third attempt to use manual captcha, got mode=%v ok=%v", mode, ok)
		}

		if _, ok = captchaSolveModeForAttempt(3, false, true); ok {
			t.Fatal("expected no fourth captcha attempt in default flow")
		}
	})

	t.Run("manual only flow", func(t *testing.T) {
		t.Parallel()

		mode, ok := captchaSolveModeForAttempt(0, true, true)
		if !ok || mode != captchaSolveModeManual {
			t.Fatalf("expected manual mode on first attempt, got mode=%v ok=%v", mode, ok)
		}

		if _, ok = captchaSolveModeForAttempt(1, true, true); ok {
			t.Fatal("expected only one manual captcha attempt when manual mode is forced")
		}
	})

	t.Run("flow without slider poc", func(t *testing.T) {
		t.Parallel()

		mode, ok := captchaSolveModeForAttempt(0, false, false)
		if !ok || mode != captchaSolveModeAuto {
			t.Fatalf("expected auto captcha first, got mode=%v ok=%v", mode, ok)
		}

		mode, ok = captchaSolveModeForAttempt(1, false, false)
		if !ok || mode != captchaSolveModeManual {
			t.Fatalf("expected manual captcha second when slider POC is disabled, got mode=%v ok=%v", mode, ok)
		}

		if _, ok = captchaSolveModeForAttempt(2, false, false); ok {
			t.Fatal("expected only two attempts when slider POC is disabled")
		}
	})
}

func TestParseVkCaptchaErrorSupportsSmartCaptchaRedirectOnly(t *testing.T) {
	t.Parallel()

	captchaErr := ParseVkCaptchaError(map[string]interface{}{
		"error_code":         float64(14),
		"error_msg":          "Captcha need",
		"is_enabled_captcha": true,
		"redirect_uri":       "https://id.vk.ru/not_robot_captcha?domain=vk.com&session_token=session-123&variant=popup&blank=1",
	})

	if captchaErr == nil {
		t.Fatal("expected captcha error to parse")
		return
	}
	if !captchaErr.IsCaptchaError() {
		t.Fatal("expected parsed error to be recognized as captcha")
	}
	if captchaErr.SessionToken != "session-123" {
		t.Fatalf("expected session token from redirect_uri, got %q", captchaErr.SessionToken)
	}
	if captchaErr.CaptchaSid != "" {
		t.Fatalf("expected missing captcha_sid to stay empty, got %q", captchaErr.CaptchaSid)
	}
}

func TestParseVkCaptchaErrorSupportsLegacyImageCaptcha(t *testing.T) {
	t.Parallel()

	captchaErr := ParseVkCaptchaError(map[string]interface{}{
		"error_code":  float64(14),
		"error_msg":   "Captcha need",
		"captcha_sid": float64(12345),
		"captcha_img": "https://api.vk.ru/captcha.php?sid=12345",
	})

	if captchaErr == nil {
		t.Fatal("expected legacy captcha error to parse")
		return
	}
	if !captchaErr.IsCaptchaError() {
		t.Fatal("expected legacy captcha error to be recognized as captcha")
	}
	if captchaErr.CaptchaSid != "12345" {
		t.Fatalf("expected numeric captcha_sid to parse, got %q", captchaErr.CaptchaSid)
	}
}
