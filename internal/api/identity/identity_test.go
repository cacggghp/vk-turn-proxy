package identity

import (
	"strings"
	"testing"
)

func TestGetRandomProfile(t *testing.T) {
	prof := GetRandomProfile()

	if prof.UserAgent == "" {
		t.Error("Expected GetRandomProfile to return a non-empty UserAgent")
	}

	// Make sure it returns at least one of the major browser keywords
	hasKeyword := strings.Contains(prof.UserAgent, "Mozilla") ||
		strings.Contains(prof.UserAgent, "Chrome") ||
		strings.Contains(prof.UserAgent, "Safari")
	if !hasKeyword {
		t.Errorf("Returned UserAgent does not look like a realistic browser string: %s", prof.UserAgent)
	}

	// Verify randomness by calling it multiple times (small chance of getting the same randomly but statistically unlikely to be identical 50 times)
	distinct := make(map[string]bool)
	for i := 0; i < 50; i++ {
		distinct[GetRandomProfile().UserAgent] = true
	}
	if len(distinct) < 2 {
		t.Error("Expected GetRandomProfile to return varied results, but it consistently returned the same value")
	}
}

func TestGenerateName(t *testing.T) {
	name := GenerateName()

	if name == "" {
		t.Error("Expected GenerateName to return a non-empty string")
	}

	// Verify randomness
	distinct := make(map[string]bool)
	for i := 0; i < 50; i++ {
		distinct[GenerateName()] = true
	}
	if len(distinct) < 2 {
		t.Error("Expected GenerateName to return varied results")
	}

	// Test female suffix logic (a or я -> adds 'а' to last name)
	// We can't strictly assert this without intercepting the random generator, 
	// but we can check if it output valid letters (no numbers, etc).
	if strings.ContainsAny(name, "0123456789") {
		t.Errorf("Generated name contains numbers: %s", name)
	}
}
