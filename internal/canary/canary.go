package canary

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

type Provider string

const (
	OpenAI    Provider = "openai"
	Anthropic Provider = "anthropic"
)

type UnknownProviderError struct {
	Name string
}

func (e UnknownProviderError) Error() string {
	return fmt.Sprintf("unknown provider %q (expected %q or %q)", e.Name, OpenAI, Anthropic)
}

func ParseProvider(name string) (Provider, error) {
	switch Provider(name) {
	case OpenAI, Anthropic:
		return Provider(name), nil
	}
	return "", UnknownProviderError{Name: name}
}

type Kind string

const (
	// KindLeak is an issued canary key being used: wherever it was planted has leaked.
	KindLeak Kind = "leak"
	// KindFlag is a key we never issued being tried against the server.
	KindFlag Kind = "flag"
)

type Token struct {
	ID        int64
	Provider  Provider
	Key       string
	Label     string
	CreatedAt time.Time
}

type Detection struct {
	ID           int64
	OccurredAt   time.Time
	Kind         Kind
	Token        *Token
	Provider     Provider
	KeyHash      string
	KeyPrefix    string
	RemoteAddr   string
	ForwardedFor string
	UserAgent    string
	Method       string
	Path         string
	Body         string
}

func HashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

const keyPrefixLength = 16

// KeyPrefix is what gets stored for keys we did not issue, so that a real
// key sent here by mistake is never kept in full.
func KeyPrefix(key string) string {
	if len(key) <= keyPrefixLength {
		return key
	}
	return key[:keyPrefixLength]
}
