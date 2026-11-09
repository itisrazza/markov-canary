package canary_test

import (
	"errors"
	"regexp"
	"testing"

	"github.com/itisrazza/markov-canary/internal/canary"
)

func TestGenerateKeyLooksLikeTheProviders(t *testing.T) {
	cases := []struct {
		provider canary.Provider
		shape    *regexp.Regexp
	}{
		{canary.OpenAI, regexp.MustCompile(`^sk-proj-[A-Za-z0-9_-]{74}T3BlbkFJ[A-Za-z0-9_-]{74}$`)},
		{canary.Anthropic, regexp.MustCompile(`^sk-ant-api03-[A-Za-z0-9_-]{93}AA$`)},
	}
	for _, testCase := range cases {
		t.Run(string(testCase.provider), func(t *testing.T) {
			first, err := canary.GenerateKey(testCase.provider)
			if err != nil {
				t.Fatal(err)
			}
			second, err := canary.GenerateKey(testCase.provider)
			if err != nil {
				t.Fatal(err)
			}
			if !testCase.shape.MatchString(first) {
				t.Errorf("key %q does not match %s", first, testCase.shape)
			}
			if first == second {
				t.Errorf("two generated keys are identical: %q", first)
			}
		})
	}
}

func TestParseProvider(t *testing.T) {
	cases := []struct {
		name    string
		want    canary.Provider
		wantErr bool
	}{
		{name: "openai", want: canary.OpenAI},
		{name: "anthropic", want: canary.Anthropic},
		{name: "OpenAI", wantErr: true},
		{name: "", wantErr: true},
	}
	for _, testCase := range cases {
		got, err := canary.ParseProvider(testCase.name)
		var unknown canary.UnknownProviderError
		if errors.As(err, &unknown) != testCase.wantErr || got != testCase.want {
			t.Errorf("ParseProvider(%q) = %q, %v; want %q, error %t",
				testCase.name, got, err, testCase.want, testCase.wantErr)
		}
	}
}

func TestKeyPrefixNeverExposesALongKey(t *testing.T) {
	cases := map[string]string{
		"short":                        "short",
		"sk-ant-api03-abcdefghijklmno": "sk-ant-api03-abc",
	}
	for key, want := range cases {
		if got := canary.KeyPrefix(key); got != want {
			t.Errorf("KeyPrefix(%q) = %q, want %q", key, got, want)
		}
	}
}
