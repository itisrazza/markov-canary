package markov_test

import (
	"errors"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/itisrazza/markov-canary/internal/markov"
)

func TestNewRejectsTinyCorpus(t *testing.T) {
	for _, corpus := range []string{"", "one", "one two"} {
		_, err := markov.New(corpus)
		var tooSmall markov.CorpusTooSmallError
		if !errors.As(err, &tooSmall) {
			t.Errorf("New(%q) error = %v, want CorpusTooSmallError", corpus, err)
		}
	}
}

func TestWordsOnlyYieldsCorpusWords(t *testing.T) {
	cases := map[string]string{
		"single sentence": "The quick brown fox jumps over the lazy dog.",
		"dead end":        "one two three",
		"built-in":        markov.DefaultCorpus,
	}
	for name, corpus := range cases {
		t.Run(name, func(t *testing.T) {
			chain, err := markov.New(corpus)
			if err != nil {
				t.Fatal(err)
			}
			known := strings.Fields(corpus)
			rng := rand.New(rand.NewPCG(1, 2))

			const wanted = 500
			count := 0
			for word := range chain.Words(rng) {
				if !slices.Contains(known, word) {
					t.Fatalf("word %q is not in the corpus", word)
				}
				count++
				if count == wanted {
					break
				}
			}
			if count != wanted {
				t.Errorf("got %d words, want an endless stream of at least %d", count, wanted)
			}
		})
	}
}
