package clientcore

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	_ "image/jpeg" // register JPEG decoder
	"log"
	"math"
	mathrand "math/rand"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type sliderPuzzleV2 struct {
	Image    image.Image
	Size     int
	Swaps    []int
	Attempts int
}

type sliderGuessV2 struct {
	Index         int
	Swaps         []int
	Score         int64
	ScoreRGB      int64
	ScoreLuma     int64
	ScoreText     float64
	ConsensusRank int
}

func (s *captchaV2Session) solveSliderCaptcha(
	sessionToken string,
	browserFP string,
	hash string,
	settings string,
	debugInfo string,
) (string, error) {
	values := [][2]string{
		{"session_token", sessionToken},
		{"domain", "vk.com"},
		{"adFp", ""},
		{"access_token", ""},
		{"captcha_settings", settings},
	}

	resp, err := s.captchaRequest("captchaNotRobot.getContent", values)
	if err != nil {
		return "", fmt.Errorf("slider getContent failed: %w", err)
	}
	puzzle, err := parseSliderPuzzleV2(resp)
	if err != nil {
		return "", err
	}
	log.Printf("v2 slider puzzle decoded: grid=%d attempts=%d swaps=%d", puzzle.Size, puzzle.Attempts, len(puzzle.Swaps))

	guesses, err := rankSliderGuessesV2(puzzle.Image, puzzle.Size, puzzle.Swaps)
	if err != nil {
		return "", err
	}

	limit := puzzle.Attempts
	if limit > len(guesses) {
		limit = len(guesses)
	}
	if limit <= 0 {
		return "", errors.New("slider has no attempts available")
	}
	log.Printf("v2 slider guesses ranked: total=%d limit=%d", len(guesses), limit)

	deviceJSON := captchaV2DeviceInfo
	if s.savedProfile != nil && strings.TrimSpace(s.savedProfile.DeviceJSON) != "" {
		deviceJSON = s.savedProfile.DeviceJSON
	}
	if _, err := s.captchaRequest("captchaNotRobot.componentDone", [][2]string{
		{"session_token", sessionToken},
		{"domain", "vk.com"},
		{"adFp", ""},
		{"access_token", ""},
		{"browser_fp", browserFP},
		{"device", deviceJSON},
	}); err != nil {
		return "", fmt.Errorf("captcha componentDone failed: %w", err)
	}

	for i := 0; i < limit; i++ {
		log.Printf("v2 slider attempt %d/%d (guess #%d)", i+1, limit, guesses[i].Index)
		answerData, err := json.Marshal(struct {
			Value []int `json:"value"`
		}{Value: guesses[i].Swaps})
		if err != nil {
			return "", err
		}
		check, err := s.performCaptchaCheck(
			sessionToken,
			browserFP,
			hash,
			string(answerData),
			buildSliderCursorV2(guesses[i].Index, len(guesses)),
			debugInfo,
		)
		if err != nil {
			return "", err
		}
		if strings.EqualFold(check.Status, "ok") {
			if check.SuccessToken == "" {
				return "", errors.New("captcha success token not found")
			}
			log.Printf("v2 slider accepted on attempt %d", i+1)
			return check.SuccessToken, nil
		}
		if strings.EqualFold(check.Status, "error_limit") {
			return "", errCaptchaV2RateLimit
		}
	}
	return "", errors.New("slider guesses exhausted")
}

func parseSliderPuzzleV2(raw map[string]any) (*sliderPuzzleV2, error) {
	resp, ok := raw["response"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid slider content response: %v", raw)
	}
	status := captchaV2StringifyAny(resp["status"])
	if !strings.EqualFold(status, "ok") {
		return nil, fmt.Errorf("slider getContent status: %s", status)
	}
	rawImage := captchaV2StringifyAny(resp["image"])
	if rawImage == "" {
		return nil, errors.New("slider image missing")
	}
	rawSteps, ok := resp["steps"].([]any)
	if !ok {
		return nil, errors.New("slider steps missing")
	}
	steps := make([]int, 0, len(rawSteps))
	for _, item := range rawSteps {
		switch v := item.(type) {
		case float64:
			steps = append(steps, int(v))
		case int:
			steps = append(steps, v)
		case string:
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return nil, fmt.Errorf("invalid numeric value: %v", item)
			}
			steps = append(steps, n)
		default:
			return nil, fmt.Errorf("invalid numeric value: %v", item)
		}
	}
	size, swaps, attempts, err := splitSliderStepsV2(steps)
	if err != nil {
		return nil, err
	}
	data, err := base64.StdEncoding.DecodeString(rawImage)
	if err != nil {
		return nil, fmt.Errorf("decode slider image: %w", err)
	}
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decode slider image: %w", err)
	}
	return &sliderPuzzleV2{Image: img, Size: size, Swaps: swaps, Attempts: attempts}, nil
}

func splitSliderStepsV2(steps []int) (int, []int, int, error) {
	if len(steps) < 3 {
		return 0, nil, 0, errors.New("slider steps payload too short")
	}
	size := steps[0]
	if size <= 0 {
		return 0, nil, 0, fmt.Errorf("invalid slider size: %d", size)
	}
	tail := append([]int(nil), steps[1:]...)
	attempts := 4
	if len(tail)%2 != 0 {
		attempts = tail[len(tail)-1]
		tail = tail[:len(tail)-1]
		log.Printf("v2 slider payload had odd-length tail; fallback attempts=%d", attempts)
	}
	if attempts <= 0 {
		attempts = 4
	}
	if len(tail) == 0 || len(tail)%2 != 0 {
		return 0, nil, 0, errors.New("invalid slider swap payload")
	}
	return size, tail, attempts, nil
}

func rankSliderGuessesV2(img image.Image, gridSize int, swaps []int) ([]sliderGuessV2, error) {
	candidateCount := len(swaps) / 2
	if candidateCount == 0 {
		return nil, errors.New("slider has no candidates")
	}

	guesses := make([]sliderGuessV2, candidateCount)
	for idx := 1; idx <= candidateCount; idx++ {
		active := activeSwapsForIndexV2(swaps, idx)
		mapping, err := applySliderSwapsV2(gridSize, active)
		if err != nil {
			return nil, err
		}
		guesses[idx-1] = sliderGuessV2{Index: idx, Swaps: active}
		guesses[idx-1].ScoreLuma = seamScoreLumaV2(img, gridSize, mapping)
	}

	lumaOrder := append([]sliderGuessV2(nil), guesses...)
	sort.SliceStable(lumaOrder, func(i, j int) bool {
		if lumaOrder[i].ScoreLuma == lumaOrder[j].ScoreLuma {
			return lumaOrder[i].Index < lumaOrder[j].Index
		}
		return lumaOrder[i].ScoreLuma < lumaOrder[j].ScoreLuma
	})
	lumaRank := make(map[int]int, candidateCount)
	for rank, g := range lumaOrder {
		lumaRank[g.Index] = rank
	}

	stage2Count := candidateCount
	if stage2Count > 12 {
		stage2Count = 12
	}
	stage2Set := make(map[int]struct{}, stage2Count)
	for i := 0; i < stage2Count; i++ {
		stage2Set[lumaOrder[i].Index] = struct{}{}
	}

	type stage2Result struct {
		index int
		rgb   int64
		text  float64
		err   error
	}
	jobs := make([]int, 0, stage2Count)
	for idx := range stage2Set {
		jobs = append(jobs, idx)
	}
	jobCh := make(chan int, len(jobs))
	resCh := make(chan stage2Result, len(jobs))

	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	if workers > len(jobs) {
		workers = len(jobs)
	}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobCh {
				mapping, err := applySliderSwapsV2(gridSize, guesses[index-1].Swaps)
				if err != nil {
					resCh <- stage2Result{index: index, err: err}
					continue
				}
				rgb, text := seamScoreRGBTextV2(img, gridSize, mapping)
				resCh <- stage2Result{index: index, rgb: rgb, text: text}
			}
		}()
	}
	for _, idx := range jobs {
		jobCh <- idx
	}
	close(jobCh)
	wg.Wait()
	close(resCh)
	for r := range resCh {
		if r.err != nil {
			return nil, r.err
		}
		g := &guesses[r.index-1]
		g.ScoreRGB = r.rgb
		g.ScoreText = r.text
	}

	stage2 := make([]sliderGuessV2, 0, stage2Count)
	for _, g := range guesses {
		if _, ok := stage2Set[g.Index]; ok {
			stage2 = append(stage2, g)
		}
	}

	rgbOrder := append([]sliderGuessV2(nil), stage2...)
	sort.SliceStable(rgbOrder, func(i, j int) bool {
		if rgbOrder[i].ScoreRGB == rgbOrder[j].ScoreRGB {
			return rgbOrder[i].Index < rgbOrder[j].Index
		}
		return rgbOrder[i].ScoreRGB < rgbOrder[j].ScoreRGB
	})
	rgbRank := make(map[int]int, len(rgbOrder))
	for rank, g := range rgbOrder {
		rgbRank[g.Index] = rank
	}

	textOrder := append([]sliderGuessV2(nil), stage2...)
	sort.SliceStable(textOrder, func(i, j int) bool {
		if textOrder[i].ScoreText == textOrder[j].ScoreText {
			return textOrder[i].Index < textOrder[j].Index
		}
		return textOrder[i].ScoreText < textOrder[j].ScoreText
	})
	textRank := make(map[int]int, len(textOrder))
	for rank, g := range textOrder {
		textRank[g.Index] = rank
	}

	for i := range guesses {
		g := &guesses[i]
		g.ConsensusRank = lumaRank[g.Index]
		if _, ok := stage2Set[g.Index]; ok {
			g.ConsensusRank += rgbRank[g.Index] + textRank[g.Index]
		} else {
			g.ConsensusRank += candidateCount
		}
		g.Score = int64(g.ConsensusRank)
	}

	sort.SliceStable(guesses, func(i, j int) bool {
		if guesses[i].ConsensusRank == guesses[j].ConsensusRank {
			if guesses[i].ScoreLuma == guesses[j].ScoreLuma {
				return guesses[i].Index < guesses[j].Index
			}
			return guesses[i].ScoreLuma < guesses[j].ScoreLuma
		}
		return guesses[i].ConsensusRank < guesses[j].ConsensusRank
	})
	return guesses, nil
}

func activeSwapsForIndexV2(swaps []int, index int) []int {
	if index <= 0 {
		return []int{}
	}
	end := index * 2
	if end > len(swaps) {
		end = len(swaps)
	}
	return append([]int(nil), swaps[:end]...)
}

func applySliderSwapsV2(gridSize int, swaps []int) ([]int, error) {
	tileCount := gridSize * gridSize
	if tileCount <= 0 {
		return nil, fmt.Errorf("invalid slider tile count: %d", tileCount)
	}
	if len(swaps)%2 != 0 {
		return nil, fmt.Errorf("invalid slider swaps length: %d", len(swaps))
	}
	mapping := make([]int, tileCount)
	for i := range mapping {
		mapping[i] = i
	}
	for i := 0; i < len(swaps); i += 2 {
		left := swaps[i]
		right := swaps[i+1]
		if left < 0 || right < 0 || left >= tileCount || right >= tileCount {
			return nil, fmt.Errorf("slider step out of range: %d,%d", left, right)
		}
		mapping[left], mapping[right] = mapping[right], mapping[left]
	}
	return mapping, nil
}

func seamScoreLumaV2(img image.Image, gridSize int, mapping []int) int64 {
	bounds := img.Bounds()
	var score int64
	for row := 0; row < gridSize; row++ {
		for col := 0; col < gridSize-1; col++ {
			leftIdx := row*gridSize + col
			rightIdx := leftIdx + 1
			leftDst := sliderTileRect(bounds, gridSize, leftIdx)
			rightDst := sliderTileRect(bounds, gridSize, rightIdx)
			leftSrc := sliderTileRect(bounds, gridSize, mapping[leftIdx])
			rightSrc := sliderTileRect(bounds, gridSize, mapping[rightIdx])
			h := leftDst.Dy()
			if rightDst.Dy() < h {
				h = rightDst.Dy()
			}
			for y := 0; y < h; y++ {
				yy := leftDst.Min.Y + y
				a := sampleLumaMappedV2(img, leftDst, leftSrc, leftDst.Max.X-1, yy)
				b := sampleLumaMappedV2(img, rightDst, rightSrc, rightDst.Min.X, yy)
				score += int64(absIntV2(int(a) - int(b)))
			}
		}
	}
	for row := 0; row < gridSize-1; row++ {
		for col := 0; col < gridSize; col++ {
			topIdx := row*gridSize + col
			bottomIdx := (row+1)*gridSize + col
			topDst := sliderTileRect(bounds, gridSize, topIdx)
			bottomDst := sliderTileRect(bounds, gridSize, bottomIdx)
			topSrc := sliderTileRect(bounds, gridSize, mapping[topIdx])
			bottomSrc := sliderTileRect(bounds, gridSize, mapping[bottomIdx])
			w := topDst.Dx()
			if bottomDst.Dx() < w {
				w = bottomDst.Dx()
			}
			for x := 0; x < w; x++ {
				xx := topDst.Min.X + x
				a := sampleLumaMappedV2(img, topDst, topSrc, xx, topDst.Max.Y-1)
				b := sampleLumaMappedV2(img, bottomDst, bottomSrc, xx, bottomDst.Min.Y)
				score += int64(absIntV2(int(a) - int(b)))
			}
		}
	}
	return score
}

func seamScoreRGBTextV2(img image.Image, gridSize int, mapping []int) (int64, float64) {
	bounds := img.Bounds()
	height := float64(bounds.Dy())
	textCenters := []float64{
		float64(bounds.Min.Y) + 0.2*height,
		float64(bounds.Min.Y) + 0.5*height,
		float64(bounds.Min.Y) + 0.8*height,
	}
	sigma := height * 0.14
	if sigma < 1.0 {
		sigma = 1.0
	}
	weight := func(y int) float64 {
		yf := float64(y)
		best := absFloatV2(yf - textCenters[0])
		for i := 1; i < len(textCenters); i++ {
			d := absFloatV2(yf - textCenters[i])
			if d < best {
				best = d
			}
		}
		return 1 + 3*math.Exp(-(best*best)/(2*sigma*sigma))
	}

	var rgbScore int64
	var textScore float64
	for row := 0; row < gridSize; row++ {
		for col := 0; col < gridSize-1; col++ {
			leftIdx := row*gridSize + col
			rightIdx := leftIdx + 1
			leftDst := sliderTileRect(bounds, gridSize, leftIdx)
			rightDst := sliderTileRect(bounds, gridSize, rightIdx)
			leftSrc := sliderTileRect(bounds, gridSize, mapping[leftIdx])
			rightSrc := sliderTileRect(bounds, gridSize, mapping[rightIdx])
			h := leftDst.Dy()
			if rightDst.Dy() < h {
				h = rightDst.Dy()
			}
			for y := 0; y < h; y++ {
				yy := leftDst.Min.Y + y
				l := sampleColorMappedV2(img, leftDst, leftSrc, leftDst.Max.X-1, yy)
				r := sampleColorMappedV2(img, rightDst, rightSrc, rightDst.Min.X, yy)
				rgbScore += pixelDiff(l, r)
				_, _, lb, _ := l.RGBA()
				_, _, rb, _ := r.RGBA()
				textScore += weight(yy) * float64(absIntV2(int(lb>>8)-int(rb>>8)))
			}
		}
	}
	for row := 0; row < gridSize-1; row++ {
		for col := 0; col < gridSize; col++ {
			topIdx := row*gridSize + col
			bottomIdx := (row+1)*gridSize + col
			topDst := sliderTileRect(bounds, gridSize, topIdx)
			bottomDst := sliderTileRect(bounds, gridSize, bottomIdx)
			topSrc := sliderTileRect(bounds, gridSize, mapping[topIdx])
			bottomSrc := sliderTileRect(bounds, gridSize, mapping[bottomIdx])
			w := topDst.Dx()
			if bottomDst.Dx() < w {
				w = bottomDst.Dx()
			}
			for x := 0; x < w; x++ {
				xx := topDst.Min.X + x
				t := sampleColorMappedV2(img, topDst, topSrc, xx, topDst.Max.Y-1)
				b := sampleColorMappedV2(img, bottomDst, bottomSrc, xx, bottomDst.Min.Y)
				rgbScore += pixelDiff(t, b)
				_, _, tb, _ := t.RGBA()
				_, _, bb, _ := b.RGBA()
				textScore += 0.65 * float64(absIntV2(int(tb>>8)-int(bb>>8)))
			}
		}
	}
	return rgbScore, textScore
}

func sampleColorMappedV2(img image.Image, dstRect image.Rectangle, srcRect image.Rectangle, dstX int, dstY int) color.Color {
	dx := dstRect.Dx()
	if dx < 1 {
		dx = 1
	}
	dy := dstRect.Dy()
	if dy < 1 {
		dy = 1
	}
	sx := srcRect.Min.X + (dstX-dstRect.Min.X)*srcRect.Dx()/dx
	sy := srcRect.Min.Y + (dstY-dstRect.Min.Y)*srcRect.Dy()/dy
	return img.At(sx, sy)
}

func sampleLumaMappedV2(img image.Image, dstRect image.Rectangle, srcRect image.Rectangle, dstX int, dstY int) uint8 {
	c := sampleColorMappedV2(img, dstRect, srcRect, dstX, dstY)
	r, g, b, _ := c.RGBA()
	y := (299*(r>>8) + 587*(g>>8) + 114*(b>>8)) / 1000
	return uint8(y)
}

func absFloatV2(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

func absIntV2(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func buildSliderCursorV2(candidateIndex int, candidateCount int) string {
	if candidateCount <= 0 {
		return "[]"
	}
	if candidateIndex < 1 {
		candidateIndex = 1
	}
	if candidateIndex > candidateCount {
		candidateIndex = candidateCount
	}

	type cursorPoint struct {
		X int `json:"x"`
		Y int `json:"y"`
	}

	startX := 570 + mathrand.Intn(40)
	startY := 875 + mathrand.Intn(30)

	denom := candidateCount - 1
	if denom < 1 {
		denom = 1
	}
	baseTargetX := 734 + (937-734)*(candidateIndex-1)/denom
	targetX := baseTargetX + mathrand.Intn(10) - 5
	targetY := 655 + mathrand.Intn(14)

	points := make([]cursorPoint, 0, 28)

	for i := 0; i < 1+mathrand.Intn(3); i++ {
		points = append(points, cursorPoint{
			X: startX + mathrand.Intn(5) - 2,
			Y: startY + mathrand.Intn(5) - 2,
		})
	}

	transitSteps := 2 + mathrand.Intn(3)
	arcOffX := mathrand.Intn(60) - 30
	arcOffY := -(mathrand.Intn(30) + 10)
	for i := 1; i <= transitSteps; i++ {
		t := float64(i) / float64(transitSteps+1)
		cx := float64(startX+targetX)/2 + float64(arcOffX)
		cy := float64(startY+targetY)/2 + float64(arcOffY)
		bx := (1-t)*(1-t)*float64(startX) + 2*t*(1-t)*cx + t*t*float64(targetX)
		by := (1-t)*(1-t)*float64(startY) + 2*t*(1-t)*cy + t*t*float64(targetY)
		jitter := int((1-t)*8) + 2
		points = append(points, cursorPoint{
			X: int(math.Round(bx)) + mathrand.Intn(jitter*2+1) - jitter,
			Y: int(math.Round(by)) + mathrand.Intn(jitter*2+1) - jitter,
		})
	}

	approachSteps := 4 + mathrand.Intn(4)
	prev := points[len(points)-1]
	for i := 1; i <= approachSteps; i++ {
		t := float64(i) / float64(approachSteps)
		ax := prev.X + int(math.Round(t*float64(targetX-prev.X))) + mathrand.Intn(5) - 2
		ay := prev.Y + int(math.Round(t*float64(targetY-prev.Y))) + mathrand.Intn(5) - 2
		points = append(points, cursorPoint{X: ax, Y: ay})
	}

	settleCount := 3 + mathrand.Intn(5)
	for i := 0; i < settleCount; i++ {
		points = append(points, cursorPoint{
			X: targetX + mathrand.Intn(7) - 3,
			Y: targetY + mathrand.Intn(7) - 3,
		})
	}

	data, err := json.Marshal(points)
	if err != nil {
		return "[]"
	}
	return string(data)
}
