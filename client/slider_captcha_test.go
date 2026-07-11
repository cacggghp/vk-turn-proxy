package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/jpeg"
	"reflect"
	"testing"
)

func TestParseSliderSteps(t *testing.T) {
	t.Parallel()

	size, swaps, attempts, err := parseSliderSteps([]int{5, 0, 1, 2, 3, 7})
	if err != nil {
		t.Fatalf("parseSliderSteps returned error: %v", err)
	}

	if size != 5 {
		t.Fatalf("expected size 5, got %d", size)
	}
	if attempts != 7 {
		t.Fatalf("expected attempts 7, got %d", attempts)
	}
	expected := []int{0, 1, 2, 3}
	if !reflect.DeepEqual(swaps, expected) {
		t.Fatalf("expected swaps %v, got %v", expected, swaps)
	}
}

func TestParseCaptchaSettingsResponseSupportsJSONStringMap(t *testing.T) {
	t.Parallel()

	resp := map[string]interface{}{
		"response": map[string]interface{}{
			"show_captcha_type": "checkbox",
			"captcha_settings":  `{"slider":"slider-token","sound":"sound-token"}`,
		},
	}

	settings, err := parseCaptchaSettingsResponse(resp)
	if err != nil {
		t.Fatalf("parseCaptchaSettingsResponse returned error: %v", err)
	}

	if settings.ShowCaptchaType != "checkbox" {
		t.Fatalf("expected show_captcha_type checkbox, got %q", settings.ShowCaptchaType)
	}
	if settings.SettingsByType["slider"] != "slider-token" {
		t.Fatalf("expected slider settings token, got %q", settings.SettingsByType["slider"])
	}
	if settings.SettingsByType["sound"] != "sound-token" {
		t.Fatalf("expected sound settings token, got %q", settings.SettingsByType["sound"])
	}
}

func TestParseCaptchaBootstrapHTML(t *testing.T) {
	t.Parallel()

	html := `
<script>
window.init = {"data":{"show_captcha_type":"checkbox","captcha_settings":[{"type":"slider","settings":"slider-token"},{"type":"sound","settings":"sound-token"}]}};
window.lang = {};
</script>
<script>
const powInput = "abc123";
const difficulty = 3;
</script>`

	bootstrap, err := parseCaptchaBootstrapHTML(html)
	if err != nil {
		t.Fatalf("parseCaptchaBootstrapHTML returned error: %v", err)
	}

	if bootstrap.PowInput != "abc123" {
		t.Fatalf("expected pow input abc123, got %q", bootstrap.PowInput)
	}
	if bootstrap.Difficulty != 3 {
		t.Fatalf("expected difficulty 3, got %d", bootstrap.Difficulty)
	}
	if bootstrap.Settings == nil {
		t.Fatal("expected bootstrap settings")
	}
	if bootstrap.Settings.ShowCaptchaType != "checkbox" {
		t.Fatalf("expected show_captcha_type checkbox, got %q", bootstrap.Settings.ShowCaptchaType)
	}
	if bootstrap.Settings.SettingsByType["slider"] != "slider-token" {
		t.Fatalf("expected slider token, got %q", bootstrap.Settings.SettingsByType["slider"])
	}
}

func TestRenderSliderCandidateMatchesSwapLayout(t *testing.T) {
	t.Parallel()

	src := image.NewRGBA(image.Rect(0, 0, 20, 20))
	fillRect(src, image.Rect(0, 0, 10, 10), color.RGBA{R: 255, A: 255})
	fillRect(src, image.Rect(10, 0, 20, 10), color.RGBA{G: 255, A: 255})
	fillRect(src, image.Rect(0, 10, 10, 20), color.RGBA{B: 255, A: 255})
	fillRect(src, image.Rect(10, 10, 20, 20), color.RGBA{R: 255, G: 255, A: 255})

	mapping, err := buildSliderTileMapping(2, []int{0, 1})
	if err != nil {
		t.Fatalf("buildSliderTileMapping returned error: %v", err)
	}

	rendered, err := renderSliderCandidate(src, 2, mapping)
	if err != nil {
		t.Fatalf("renderSliderCandidate returned error: %v", err)
	}

	assertPixelEquals(t, rendered.At(2, 2), color.RGBA{G: 255, A: 255})
	assertPixelEquals(t, rendered.At(12, 2), color.RGBA{R: 255, A: 255})
	assertPixelEquals(t, rendered.At(2, 12), color.RGBA{B: 255, A: 255})
	assertPixelEquals(t, rendered.At(12, 12), color.RGBA{R: 255, G: 255, A: 255})
}

func TestRankSliderCandidatesPrefersMostCoherentImage(t *testing.T) {
	t.Parallel()

	src := image.NewRGBA(image.Rect(0, 0, 30, 30))
	for y := 0; y < 30; y++ {
		for x := 0; x < 30; x++ {
			src.Set(x, y, color.RGBA{
				R: uint8(x * 5),
				G: uint8(y * 5),
				B: uint8((x + y) * 3),
				A: 255,
			})
		}
	}

	candidates, err := rankSliderCandidates(src, 3, []int{0, 1, 0, 1})
	if err != nil {
		t.Fatalf("rankSliderCandidates returned error: %v", err)
	}

	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(candidates))
	}
	if candidates[0].Index != 2 {
		t.Fatalf("expected solved candidate to rank first, got candidate %d", candidates[0].Index)
	}
}

func TestEncodeSliderAnswer(t *testing.T) {
	t.Parallel()

	encoded, err := encodeSliderAnswer([]int{9, 10, 2})
	if err != nil {
		t.Fatalf("encodeSliderAnswer returned error: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("failed to decode answer: %v", err)
	}

	var payload struct {
		Value []int `json:"value"`
	}
	if err := json.Unmarshal(decoded, &payload); err != nil {
		t.Fatalf("failed to unmarshal answer payload: %v", err)
	}

	expected := []int{9, 10, 2}
	if !reflect.DeepEqual(payload.Value, expected) {
		t.Fatalf("expected payload %v, got %v", expected, payload.Value)
	}
}

func TestTrySliderCaptchaCandidates(t *testing.T) {
	t.Parallel()

	candidates := []sliderCandidate{
		{Index: 1, ActiveSteps: []int{0, 1}, Score: 10},
		{Index: 2, ActiveSteps: []int{0, 1, 0, 1}, Score: 20},
	}

	t.Run("success on first candidate", func(t *testing.T) {
		token, err := trySliderCaptchaCandidates(candidates, 2, func(candidate sliderCandidate) (*captchaCheckResult, error) {
			if candidate.Index != 1 {
				t.Fatalf("unexpected candidate index %d", candidate.Index)
			}
			return &captchaCheckResult{Status: "OK", SuccessToken: "token-1"}, nil
		})
		if err != nil {
			t.Fatalf("trySliderCaptchaCandidates returned error: %v", err)
		}
		if token != "token-1" {
			t.Fatalf("expected token-1, got %s", token)
		}
	})

	t.Run("success on later candidate", func(t *testing.T) {
		calls := 0
		token, err := trySliderCaptchaCandidates(candidates, 2, func(candidate sliderCandidate) (*captchaCheckResult, error) {
			calls++
			if candidate.Index == 1 {
				return &captchaCheckResult{Status: "BOT"}, nil
			}
			return &captchaCheckResult{Status: "OK", SuccessToken: "token-2"}, nil
		})
		if err != nil {
			t.Fatalf("trySliderCaptchaCandidates returned error: %v", err)
		}
		if calls != 2 {
			t.Fatalf("expected 2 calls, got %d", calls)
		}
		if token != "token-2" {
			t.Fatalf("expected token-2, got %s", token)
		}
	})

	t.Run("exhausted candidates", func(t *testing.T) {
		_, err := trySliderCaptchaCandidates(candidates, 1, func(candidate sliderCandidate) (*captchaCheckResult, error) {
			return &captchaCheckResult{Status: "BOT"}, nil
		})
		if err == nil {
			t.Fatal("expected error after exhausting ranked candidates")
		}
	})
}

func TestParseSliderCaptchaContentResponse(t *testing.T) {
	t.Parallel()

	src := image.NewRGBA(image.Rect(0, 0, 20, 20))
	fillRect(src, src.Bounds(), color.RGBA{R: 12, G: 34, B: 56, A: 255})

	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, src, nil); err != nil {
		t.Fatalf("failed to encode jpeg fixture: %v", err)
	}

	resp := map[string]interface{}{
		"response": map[string]interface{}{
			"status":    "OK",
			"extension": "jpeg",
			"image":     base64.StdEncoding.EncodeToString(buf.Bytes()),
			"steps":     []interface{}{float64(5), float64(0), float64(1), float64(2), float64(3), float64(6)},
		},
	}

	content, err := parseSliderCaptchaContentResponse(resp)
	if err != nil {
		t.Fatalf("parseSliderCaptchaContentResponse returned error: %v", err)
	}

	if content.Size != 5 {
		t.Fatalf("expected size 5, got %d", content.Size)
	}
	if content.Attempts != 6 {
		t.Fatalf("expected attempts 6, got %d", content.Attempts)
	}
	if len(content.Steps) != 4 {
		t.Fatalf("expected 4 swap entries, got %d", len(content.Steps))
	}
}

func fillRect(img *image.RGBA, rect image.Rectangle, c color.Color) {
	for y := rect.Min.Y; y < rect.Max.Y; y++ {
		for x := rect.Min.X; x < rect.Max.X; x++ {
			img.Set(x, y, c)
		}
	}
}

func assertPixelEquals(t *testing.T, actual color.Color, expected color.RGBA) {
	t.Helper()

	ar, ag, ab, aa := actual.RGBA()
	if ar != uint32(expected.R)*0x101 || ag != uint32(expected.G)*0x101 || ab != uint32(expected.B)*0x101 || aa != uint32(expected.A)*0x101 {
		t.Fatalf("expected pixel %+v, got rgba(%d,%d,%d,%d)", expected, ar, ag, ab, aa)
	}
}
