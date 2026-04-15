package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	_ "image/jpeg"
	"io"
	"log"
	neturl "net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
)

const (
	captchaDebugInfo      = "1d3e9babfd3a74f4588bf90cf5c30d3e8e89a0e2a4544da8de8bbf4d78a32f5c"
	sliderCaptchaType     = "slider"
	defaultSliderAttempts = 4
)

type captchaNotRobotSession struct {
	ctx          context.Context
	sessionToken string
	hash         string
	streamID     int
	client       tlsclient.HttpClient
	profile      Profile
	browserFp    string
}

type captchaSettingsResponse struct {
	ShowCaptchaType string
	SettingsByType  map[string]string
}

type captchaCheckResult struct {
	Status          string
	SuccessToken    string
	ShowCaptchaType string
}

type sliderCaptchaContent struct {
	Image    image.Image
	Size     int
	Steps    []int
	Attempts int
}

type sliderCandidate struct {
	Index       int
	ActiveSteps []int
	Score       int64
}

type captchaBootstrap struct {
	PowInput   string
	Difficulty int
	Settings   *captchaSettingsResponse
}

func newCaptchaNotRobotSession(
	ctx context.Context,
	sessionToken string,
	hash string,
	streamID int,
	client tlsclient.HttpClient,
	profile Profile,
) *captchaNotRobotSession {
	return &captchaNotRobotSession{
		ctx:          ctx,
		sessionToken: sessionToken,
		hash:         hash,
		streamID:     streamID,
		client:       client,
		profile:      profile,
		browserFp:    generateBrowserFp(profile),
	}
}

func (s *captchaNotRobotSession) baseValues() neturl.Values {
	values := neturl.Values{}
	values.Set("session_token", s.sessionToken)
	values.Set("domain", "vk.com")
	values.Set("adFp", "")
	values.Set("access_token", "")
	return values
}

func (s *captchaNotRobotSession) request(method string, values neturl.Values) (map[string]interface{}, error) {
	reqURL := "https://api.vk.ru/method/" + method + "?v=5.131"

	req, err := fhttp.NewRequestWithContext(s.ctx, "POST", reqURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}

	httpResp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = httpResp.Body.Close()
	}()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *captchaNotRobotSession) requestSettings() (*captchaSettingsResponse, error) {
	resp, err := s.request("captchaNotRobot.settings", s.baseValues())
	if err != nil {
		return nil, fmt.Errorf("settings failed: %w", err)
	}
	return parseCaptchaSettingsResponse(resp)
}

func (s *captchaNotRobotSession) requestComponentDone() error {
	values := s.baseValues()
	values.Set("browser_fp", s.browserFp)
	values.Set("device", buildCaptchaDeviceJSON(s.profile))

	resp, err := s.request("captchaNotRobot.componentDone", values)
	if err != nil {
		return fmt.Errorf("componentDone failed: %w", err)
	}

	respObj, ok := resp["response"].(map[string]interface{})
	if ok {
		if status, _ := respObj["status"].(string); status != "" && status != "OK" {
			return fmt.Errorf("componentDone status: %s", status)
		}
	}

	return nil
}

func (s *captchaNotRobotSession) requestCheckboxCheck() (*captchaCheckResult, error) {
	return s.requestCheck(generateSliderCursor(0, 1), base64.StdEncoding.EncodeToString([]byte("{}")))
}

func (s *captchaNotRobotSession) requestSliderContent(sliderSettings string) (*sliderCaptchaContent, error) {
	values := s.baseValues()
	if sliderSettings != "" {
		values.Set("captcha_settings", sliderSettings)
	}

	resp, err := s.request("captchaNotRobot.getContent", values)
	if err != nil {
		return nil, fmt.Errorf("getContent failed: %w", err)
	}
	return parseSliderCaptchaContentResponse(resp)
}

func (s *captchaNotRobotSession) requestSliderCheck(activeSteps []int, candidateIndex int, candidateCount int) (*captchaCheckResult, error) {
	answer, err := encodeSliderAnswer(activeSteps)
	if err != nil {
		return nil, err
	}

	return s.requestCheck(generateSliderCursor(candidateIndex, candidateCount), answer)
}

func (s *captchaNotRobotSession) requestCheck(cursor string, answer string) (*captchaCheckResult, error) {
	values := s.baseValues()
	values.Set("accelerometer", "[]")
	values.Set("gyroscope", "[]")
	values.Set("motion", "[]")
	values.Set("cursor", cursor)
	values.Set("taps", "[]")
	values.Set("connectionRtt", "[]")
	values.Set("connectionDownlink", "[]")
	values.Set("browser_fp", s.browserFp)
	values.Set("hash", s.hash)
	values.Set("answer", answer)
	values.Set("debug_info", captchaDebugInfo)

	resp, err := s.request("captchaNotRobot.check", values)
	if err != nil {
		return nil, fmt.Errorf("check failed: %w", err)
	}
	return parseCaptchaCheckResult(resp)
}

func (s *captchaNotRobotSession) requestEndSession() {
	log.Printf("[STREAM %d] [Captcha] Step 4/4: endSession", s.streamID)
	if _, err := s.request("captchaNotRobot.endSession", s.baseValues()); err != nil {
		log.Printf("[STREAM %d] [Captcha] Warning: endSession failed: %v", s.streamID, err)
	}
}

func callCaptchaNotRobotWithSliderPOC(
	ctx context.Context,
	sessionToken string,
	hash string,
	streamID int,
	client tlsclient.HttpClient,
	profile Profile,
	initialSettings *captchaSettingsResponse,
) (string, error) {
	session := newCaptchaNotRobotSession(ctx, sessionToken, hash, streamID, client, profile)

	log.Printf("[STREAM %d] [Captcha] Step 1/4: settings", streamID)
	settingsResp, err := session.requestSettings()
	if err != nil {
		return "", err
	}
	settingsResp = mergeCaptchaSettings(settingsResp, initialSettings)

	time.Sleep(200 * time.Millisecond)

	log.Printf("[STREAM %d] [Captcha] Step 2/4: componentDone", streamID)
	if err := session.requestComponentDone(); err != nil {
		return "", err
	}

	time.Sleep(200 * time.Millisecond)

	log.Printf("[STREAM %d] [Captcha] Step 3/4: check", streamID)
	initialCheck, err := session.requestCheckboxCheck()
	if err != nil {
		return "", err
	}
	if initialCheck.Status == "OK" {
		if initialCheck.SuccessToken == "" {
			return "", fmt.Errorf("success_token not found")
		}
		session.requestEndSession()
		return initialCheck.SuccessToken, nil
	}

	sliderSettings, hasSlider := settingsResp.SettingsByType[sliderCaptchaType]
	log.Printf(
		"[STREAM %d] [Captcha] Checkbox-style check returned status=%s (settings show_type=%q, check show_type=%q, available_types=%s)",
		streamID,
		initialCheck.Status,
		settingsResp.ShowCaptchaType,
		initialCheck.ShowCaptchaType,
		describeCaptchaTypes(settingsResp.SettingsByType),
	)

	if !hasSlider {
		log.Printf(
			"[STREAM %d] [Captcha] Slider settings not found in settings response. Trying getContent without captcha_settings...",
			streamID,
		)
	} else {
		log.Printf("[STREAM %d] [Captcha] Trying experimental slider solver...", streamID)
	}

	sliderContent, err := session.requestSliderContent(sliderSettings)
	if err != nil {
		log.Printf(
			"[STREAM %d] [Captcha] Slider getContent failed (status: %v). Trying to solve as a checkbox instead...",
			streamID,
			err,
		)
		// Fallback: maybe it's just a checkbox that needs a human-like check
		time.Sleep(300 * time.Millisecond)
		finalCheck, err2 := session.requestCheckboxCheck()
		if err2 == nil && finalCheck.Status == "OK" {
			if finalCheck.SuccessToken == "" {
				return "", fmt.Errorf("success_token not found in fallback check")
			}
			log.Printf("[STREAM %d] [Captcha] Fallback checkbox check succeeded!", streamID)
			session.requestEndSession()
			return finalCheck.SuccessToken, nil
		}
		return "", fmt.Errorf("check status: %s (slider getContent failed: %w)", initialCheck.Status, err)
	}

	candidates, err := rankSliderCandidates(sliderContent.Image, sliderContent.Size, sliderContent.Steps)
	if err != nil {
		return "", err
	}

	log.Printf(
		"[STREAM %d] [Captcha] Ranked %d slider positions locally; submitting top %d based on attempt budget %d",
		streamID,
		len(candidates),
		minInt(sliderContent.Attempts, len(candidates)),
		sliderContent.Attempts,
	)

	successToken, err := trySliderCaptchaCandidates(candidates, sliderContent.Attempts, func(candidate sliderCandidate) (*captchaCheckResult, error) {
		log.Printf(
			"[STREAM %d] [Captcha] Slider guess position=%d score=%d",
			streamID,
			candidate.Index,
			candidate.Score,
		)
		return session.requestSliderCheck(candidate.ActiveSteps, candidate.Index, len(candidates))
	})
	if err != nil {
		return "", err
	}

	session.requestEndSession()
	return successToken, nil
}

func buildCaptchaDeviceJSON(profile Profile) string {
	return fmt.Sprintf(
		`{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1040,"innerWidth":1920,"innerHeight":969,"devicePixelRatio":1,"language":"en-US","languages":["en-US"],"webdriver":false,"hardwareConcurrency":8,"deviceMemory":8,"connectionEffectiveType":"4g","notificationsPermission":"default","userAgent":"%s","platform":"Win32"}`,
		profile.UserAgent,
	)
}

func parseCaptchaSettingsResponse(resp map[string]interface{}) (*captchaSettingsResponse, error) {
	respObj, ok := resp["response"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid settings response: %v", resp)
	}

	settings := &captchaSettingsResponse{
		SettingsByType: make(map[string]string),
	}
	settings.ShowCaptchaType, _ = respObj["show_captcha_type"].(string)

	rawSettings, ok := expandCaptchaSettings(respObj["captcha_settings"])
	if !ok {
		return settings, nil
	}

	for _, rawItem := range rawSettings {
		item, ok := rawItem.(map[string]interface{})
		if !ok {
			continue
		}

		captchaType, _ := item["type"].(string)
		if captchaType == "" {
			continue
		}

		normalized, err := normalizeCaptchaSettings(item["settings"])
		if err != nil {
			return nil, fmt.Errorf("invalid captcha_settings for %s: %w", captchaType, err)
		}

		settings.SettingsByType[captchaType] = normalized
	}

	return settings, nil
}

func parseCaptchaBootstrapHTML(html string) (*captchaBootstrap, error) {
	powInputRe := regexp.MustCompile(`const\s+powInput\s*=\s*"([^"]+)"`)
	powInputMatch := powInputRe.FindStringSubmatch(html)
	if len(powInputMatch) < 2 {
		return nil, fmt.Errorf("powInput not found in captcha HTML")
	}

	difficulty := 2
	for _, expr := range []*regexp.Regexp{
		regexp.MustCompile(`startsWith\('0'\.repeat\((\d+)\)\)`),
		regexp.MustCompile(`const\s+difficulty\s*=\s*(\d+)`),
	} {
		if match := expr.FindStringSubmatch(html); len(match) >= 2 {
			if parsed, err := strconv.Atoi(match[1]); err == nil {
				difficulty = parsed
				break
			}
		}
	}

	settings, err := parseCaptchaSettingsFromHTML(html)
	if err != nil {
		return nil, err
	}

	return &captchaBootstrap{
		PowInput:   powInputMatch[1],
		Difficulty: difficulty,
		Settings:   settings,
	}, nil
}

func parseCaptchaSettingsFromHTML(html string) (*captchaSettingsResponse, error) {
	initRe := regexp.MustCompile(`(?s)window\.init\s*=\s*(\{.*?})\s*;\s*window\.lang`)
	initMatch := initRe.FindStringSubmatch(html)
	if len(initMatch) < 2 {
		return &captchaSettingsResponse{SettingsByType: make(map[string]string)}, nil
	}

	var initPayload struct {
		Data struct {
			ShowCaptchaType string      `json:"show_captcha_type"`
			CaptchaSettings interface{} `json:"captcha_settings"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(initMatch[1]), &initPayload); err != nil {
		return nil, fmt.Errorf("parse window.init captcha data: %w", err)
	}

	return parseCaptchaSettingsResponse(map[string]interface{}{
		"response": map[string]interface{}{
			"show_captcha_type": initPayload.Data.ShowCaptchaType,
			"captcha_settings":  initPayload.Data.CaptchaSettings,
		},
	})
}

func mergeCaptchaSettings(primary *captchaSettingsResponse, fallback *captchaSettingsResponse) *captchaSettingsResponse {
	if primary == nil {
		return cloneCaptchaSettings(fallback)
	}
	if primary.SettingsByType == nil {
		primary.SettingsByType = make(map[string]string)
	}
	if fallback == nil {
		return primary
	}
	if primary.ShowCaptchaType == "" {
		primary.ShowCaptchaType = fallback.ShowCaptchaType
	}
	for captchaType, settings := range fallback.SettingsByType {
		if _, exists := primary.SettingsByType[captchaType]; !exists {
			primary.SettingsByType[captchaType] = settings
		}
	}
	return primary
}

func cloneCaptchaSettings(src *captchaSettingsResponse) *captchaSettingsResponse {
	if src == nil {
		return nil
	}

	cloned := &captchaSettingsResponse{
		ShowCaptchaType: src.ShowCaptchaType,
		SettingsByType:  make(map[string]string, len(src.SettingsByType)),
	}
	for captchaType, settings := range src.SettingsByType {
		cloned.SettingsByType[captchaType] = settings
	}
	return cloned
}

func expandCaptchaSettings(raw interface{}) ([]interface{}, bool) {
	switch value := raw.(type) {
	case nil:
		return nil, false
	case []interface{}:
		return value, true
	case map[string]interface{}:
		items := make([]interface{}, 0, len(value))
		for captchaType, settings := range value {
			items = append(items, map[string]interface{}{
				"type":     captchaType,
				"settings": settings,
			})
		}
		return items, true
	case string:
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return nil, false
		}

		var items []interface{}
		if err := json.Unmarshal([]byte(trimmed), &items); err == nil {
			return items, true
		}

		var mapping map[string]interface{}
		if err := json.Unmarshal([]byte(trimmed), &mapping); err == nil {
			return expandCaptchaSettings(mapping)
		}
	}

	return nil, false
}

func normalizeCaptchaSettings(raw interface{}) (string, error) {
	switch value := raw.(type) {
	case nil:
		return "", nil
	case string:
		return value, nil
	default:
		data, err := json.Marshal(value)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
}

func parseCaptchaCheckResult(resp map[string]interface{}) (*captchaCheckResult, error) {
	respObj, ok := resp["response"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid check response: %v", resp)
	}

	result := &captchaCheckResult{}
	result.Status, _ = respObj["status"].(string)
	result.SuccessToken, _ = respObj["success_token"].(string)
	result.ShowCaptchaType, _ = respObj["show_captcha_type"].(string)
	if result.Status == "" {
		return nil, fmt.Errorf("check status missing: %v", resp)
	}

	return result, nil
}

func parseSliderCaptchaContentResponse(resp map[string]interface{}) (*sliderCaptchaContent, error) {
	respObj, ok := resp["response"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid slider content response: %v", resp)
	}

	status, _ := respObj["status"].(string)
	if status != "OK" {
		return nil, fmt.Errorf("slider getContent status: %s", status)
	}

	extension, _ := respObj["extension"].(string)
	extension = strings.ToLower(extension)
	if extension != "jpeg" && extension != "jpg" {
		return nil, fmt.Errorf("unsupported slider image format: %s", extension)
	}

	rawImage, _ := respObj["image"].(string)
	if rawImage == "" {
		return nil, fmt.Errorf("slider image missing")
	}

	rawSteps, ok := respObj["steps"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("slider steps missing")
	}

	steps, err := parseIntSlice(rawSteps)
	if err != nil {
		return nil, err
	}

	size, swaps, attempts, err := parseSliderSteps(steps)
	if err != nil {
		return nil, err
	}

	img, err := decodeSliderImage(rawImage)
	if err != nil {
		return nil, err
	}

	return &sliderCaptchaContent{
		Image:    img,
		Size:     size,
		Steps:    swaps,
		Attempts: attempts,
	}, nil
}

func parseIntSlice(raw []interface{}) ([]int, error) {
	values := make([]int, 0, len(raw))
	for _, item := range raw {
		number, err := parseIntValue(item)
		if err != nil {
			return nil, err
		}
		values = append(values, number)
	}
	return values, nil
}

func parseIntValue(raw interface{}) (int, error) {
	switch value := raw.(type) {
	case float64:
		return int(value), nil
	case int:
		return value, nil
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return 0, fmt.Errorf("invalid numeric value: %v", raw)
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("invalid numeric value: %v", raw)
	}
}

func parseSliderSteps(steps []int) (int, []int, int, error) {
	if len(steps) < 3 {
		return 0, nil, 0, fmt.Errorf("slider steps payload too short")
	}

	size := steps[0]
	if size <= 0 {
		return 0, nil, 0, fmt.Errorf("invalid slider size: %d", size)
	}

	remaining := append([]int(nil), steps[1:]...)
	attempts := defaultSliderAttempts
	if len(remaining)%2 != 0 {
		attempts = remaining[len(remaining)-1]
		remaining = remaining[:len(remaining)-1]
	}
	if attempts <= 0 {
		attempts = defaultSliderAttempts
	}
	if len(remaining) == 0 || len(remaining)%2 != 0 {
		return 0, nil, 0, fmt.Errorf("invalid slider swap payload")
	}

	return size, remaining, attempts, nil
}

func decodeSliderImage(rawImage string) (image.Image, error) {
	decoded, err := base64.StdEncoding.DecodeString(rawImage)
	if err != nil {
		return nil, fmt.Errorf("decode slider image: %w", err)
	}

	img, _, err := image.Decode(bytes.NewReader(decoded))
	if err != nil {
		return nil, fmt.Errorf("decode slider image: %w", err)
	}

	return img, nil
}

func encodeSliderAnswer(activeSteps []int) (string, error) {
	payload := struct {
		Value []int `json:"value"`
	}{
		Value: activeSteps,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(data), nil
}

func buildSliderActiveSteps(swaps []int, candidateIndex int) []int {
	if candidateIndex <= 0 {
		return []int{}
	}

	end := candidateIndex * 2
	if end > len(swaps) {
		end = len(swaps)
	}

	return append([]int(nil), swaps[:end]...)
}

func buildSliderTileMapping(gridSize int, activeSteps []int) ([]int, error) {
	tileCount := gridSize * gridSize
	if tileCount <= 0 {
		return nil, fmt.Errorf("invalid slider tile count: %d", tileCount)
	}
	if len(activeSteps)%2 != 0 {
		return nil, fmt.Errorf("invalid active steps length: %d", len(activeSteps))
	}

	mapping := make([]int, tileCount)
	for i := range mapping {
		mapping[i] = i
	}

	for idx := 0; idx < len(activeSteps); idx += 2 {
		left := activeSteps[idx]
		right := activeSteps[idx+1]
		if left < 0 || right < 0 || left >= tileCount || right >= tileCount {
			return nil, fmt.Errorf("slider step out of range: %d,%d", left, right)
		}
		mapping[left], mapping[right] = mapping[right], mapping[left]
	}

	return mapping, nil
}

func rankSliderCandidates(img image.Image, gridSize int, swaps []int) ([]sliderCandidate, error) {
	candidateCount := len(swaps) / 2
	if candidateCount == 0 {
		return nil, fmt.Errorf("slider has no candidates")
	}

	candidates := make([]sliderCandidate, 0, candidateCount)
	for idx := 1; idx <= candidateCount; idx++ {
		activeSteps := buildSliderActiveSteps(swaps, idx)
		mapping, err := buildSliderTileMapping(gridSize, activeSteps)
		if err != nil {
			return nil, err
		}

		score, err := scoreSliderCandidate(img, gridSize, mapping)
		if err != nil {
			return nil, err
		}

		candidates = append(candidates, sliderCandidate{
			Index:       idx,
			ActiveSteps: activeSteps,
			Score:       score,
		})
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Score == candidates[j].Score {
			return candidates[i].Index < candidates[j].Index
		}
		return candidates[i].Score < candidates[j].Score
	})

	return candidates, nil
}

func scoreSliderCandidate(img image.Image, gridSize int, mapping []int) (int64, error) {
	rendered, err := renderSliderCandidate(img, gridSize, mapping)
	if err != nil {
		return 0, err
	}

	return scoreRenderedSliderImage(rendered, gridSize), nil
}

func renderSliderCandidate(img image.Image, gridSize int, mapping []int) (*image.RGBA, error) {
	if gridSize <= 0 {
		return nil, fmt.Errorf("invalid grid size: %d", gridSize)
	}

	tileCount := gridSize * gridSize
	if len(mapping) != tileCount {
		return nil, fmt.Errorf("unexpected tile mapping length: %d", len(mapping))
	}

	bounds := img.Bounds()
	rendered := image.NewRGBA(bounds)
	for dstIndex, srcIndex := range mapping {
		srcRect := sliderTileRect(bounds, gridSize, srcIndex)
		dstRect := sliderTileRect(bounds, gridSize, dstIndex)
		copyScaledTile(rendered, dstRect, img, srcRect)
	}

	return rendered, nil
}

func scoreRenderedSliderImage(img image.Image, gridSize int) int64 {
	bounds := img.Bounds()
	var score int64

	for row := 0; row < gridSize; row++ {
		for col := 0; col < gridSize-1; col++ {
			leftRect := sliderTileRect(bounds, gridSize, row*gridSize+col)
			rightRect := sliderTileRect(bounds, gridSize, row*gridSize+col+1)
			height := minInt(leftRect.Dy(), rightRect.Dy())
			for offset := 0; offset < height; offset++ {
				score += pixelDiff(
					img.At(leftRect.Max.X-1, leftRect.Min.Y+offset),
					img.At(rightRect.Min.X, rightRect.Min.Y+offset),
				)
			}
		}
	}

	for row := 0; row < gridSize-1; row++ {
		for col := 0; col < gridSize; col++ {
			topRect := sliderTileRect(bounds, gridSize, row*gridSize+col)
			bottomRect := sliderTileRect(bounds, gridSize, (row+1)*gridSize+col)
			width := minInt(topRect.Dx(), bottomRect.Dx())
			for offset := 0; offset < width; offset++ {
				score += pixelDiff(
					img.At(topRect.Min.X+offset, topRect.Max.Y-1),
					img.At(bottomRect.Min.X+offset, bottomRect.Min.Y),
				)
			}
		}
	}

	return score
}

func sliderTileRect(bounds image.Rectangle, gridSize int, index int) image.Rectangle {
	row := index / gridSize
	col := index % gridSize

	x0 := bounds.Min.X + col*bounds.Dx()/gridSize
	x1 := bounds.Min.X + (col+1)*bounds.Dx()/gridSize
	y0 := bounds.Min.Y + row*bounds.Dy()/gridSize
	y1 := bounds.Min.Y + (row+1)*bounds.Dy()/gridSize

	return image.Rect(x0, y0, x1, y1)
}

func copyScaledTile(dst *image.RGBA, dstRect image.Rectangle, src image.Image, srcRect image.Rectangle) {
	if dstRect.Empty() || srcRect.Empty() {
		return
	}

	dstWidth := dstRect.Dx()
	dstHeight := dstRect.Dy()
	srcWidth := srcRect.Dx()
	srcHeight := srcRect.Dy()

	for y := 0; y < dstHeight; y++ {
		sy := srcRect.Min.Y + y*srcHeight/dstHeight
		for x := 0; x < dstWidth; x++ {
			sx := srcRect.Min.X + x*srcWidth/dstWidth
			dst.Set(dstRect.Min.X+x, dstRect.Min.Y+y, src.At(sx, sy))
		}
	}
}

func pixelDiff(left color.Color, right color.Color) int64 {
	lr, lg, lb, _ := left.RGBA()
	rr, rg, rb, _ := right.RGBA()

	return absDiff(lr, rr) + absDiff(lg, rg) + absDiff(lb, rb)
}

func absDiff(left uint32, right uint32) int64 {
	if left > right {
		return int64(left - right)
	}
	return int64(right - left)
}

func generateSliderCursor(candidateIndex int, candidateCount int) string {
	return buildSliderCursor(candidateIndex, candidateCount, time.Now().Add(-220*time.Millisecond).UnixMilli())
}

func buildSliderCursor(candidateIndex int, candidateCount int, startTime int64) string {
	if candidateCount <= 0 {
		return "[]"
	}

	type cursorPoint struct {
		X int   `json:"x"`
		Y int   `json:"y"`
		T int64 `json:"t"`
	}

	startX := 140
	endX := startX + 620*candidateIndex/candidateCount
	startY := 430

	points := make([]cursorPoint, 0, 12)
	for step := 0; step < 12; step++ {
		x := startX + (endX-startX)*step/11
		y := startY + ((step % 3) - 1)
		points = append(points, cursorPoint{
			X: x,
			Y: y,
			T: startTime + int64(step*18),
		})
	}

	data, err := json.Marshal(points)
	if err != nil {
		return "[]"
	}
	return string(data)
}

func trySliderCaptchaCandidates(
	candidates []sliderCandidate,
	maxAttempts int,
	check func(candidate sliderCandidate) (*captchaCheckResult, error),
) (string, error) {
	if len(candidates) == 0 {
		return "", fmt.Errorf("slider has no ranked candidates")
	}

	limit := minInt(maxAttempts, len(candidates))
	if limit <= 0 {
		return "", fmt.Errorf("slider has no attempts available")
	}

	for idx := 0; idx < limit; idx++ {
		result, err := check(candidates[idx])
		if err != nil {
			return "", err
		}

		switch result.Status {
		case "OK":
			if result.SuccessToken == "" {
				return "", fmt.Errorf("success_token not found")
			}
			return result.SuccessToken, nil
		case "ERROR_LIMIT":
			return "", fmt.Errorf("slider check status: %s", result.Status)
		default:
			continue
		}
	}

	return "", fmt.Errorf("slider guesses exhausted")
}

func minInt(left int, right int) int {
	if left < right {
		return left
	}
	return right
}

func describeCaptchaTypes(settingsByType map[string]string) string {
	if len(settingsByType) == 0 {
		return "none"
	}

	types := make([]string, 0, len(settingsByType))
	for captchaType := range settingsByType {
		types = append(types, captchaType)
	}
	sort.Strings(types)
	return strings.Join(types, ",")
}
