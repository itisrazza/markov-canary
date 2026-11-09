package canary

import (
	"crypto/rand"
	"fmt"
)

const (
	alphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	// 64 characters, so mapping a random byte with a modulo is unbiased.
	urlSafe = alphanumeric + "-_"
)

func randomString(alphabet string, length int) string {
	random := make([]byte, length)
	rand.Read(random)
	for index, value := range random {
		random[index] = alphabet[int(value)%len(alphabet)]
	}
	return string(random)
}

// RandomID returns an alphanumeric identifier for fake response objects.
// It uses a 62 character alphabet, so it is slightly biased; do not use it for keys.
func RandomID(length int) string {
	return randomString(alphanumeric, length)
}

// GenerateKey mimics the shape of the provider's real keys closely enough to
// be picked up by secret scanners.
func GenerateKey(provider Provider) (string, error) {
	switch provider {
	case OpenAI:
		return "sk-proj-" + randomString(urlSafe, 74) + "T3BlbkFJ" + randomString(urlSafe, 74), nil
	case Anthropic:
		return "sk-ant-api03-" + randomString(urlSafe, 93) + "AA", nil
	}
	return "", fmt.Errorf("generate key: %w", UnknownProviderError{Name: string(provider)})
}
