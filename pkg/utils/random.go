package utils

import (
	"crypto/rand"
	"encoding/hex"
)

// GenerateRandomHex generates a random hex string of length n*2.
// Example: n=16 -> returns 32 chars hex string.
func GenerateRandomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateRandomHexOrPanic is useful for tests or initialization where error handling is hard.
func GenerateRandomHexOrPanic(n int) string {
	s, err := GenerateRandomHex(n)
	if err != nil {
		// Fallback for extreme cases (e.g. OS entropy exhausted)
		// Returning a fixed string is better than crashing in some contexts,
		// but for security tokens, we should panic.
		panic("failed to generate random hex: " + err.Error())
	}
	return s
}
