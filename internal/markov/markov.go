package markov

import (
	_ "embed"
	"fmt"
	"iter"
	"math/rand/v2"
	"strings"
)

//go:embed corpus.txt
var DefaultCorpus string

type CorpusTooSmallError struct {
	Words int
}

func (e CorpusTooSmallError) Error() string {
	return fmt.Sprintf("corpus has %d words, need at least %d to build a chain", e.Words, minimumWords)
}

const minimumWords = 3

type pair [2]string

type Chain struct {
	starts     []pair
	successors map[pair][]string
}

func New(corpus string) (*Chain, error) {
	words := strings.Fields(corpus)
	if len(words) < minimumWords {
		return nil, CorpusTooSmallError{Words: len(words)}
	}

	chain := &Chain{successors: make(map[pair][]string)}
	for index := range len(words) - 2 {
		current := pair{words[index], words[index+1]}
		chain.successors[current] = append(chain.successors[current], words[index+2])
		if index == 0 || endsSentence(words[index-1]) {
			chain.starts = append(chain.starts, current)
		}
	}
	return chain, nil
}

func endsSentence(word string) bool {
	return strings.HasSuffix(word, ".") || strings.HasSuffix(word, "?") || strings.HasSuffix(word, "!")
}

// Words yields an endless stream of words; the caller decides when to stop.
func (c *Chain) Words(rng *rand.Rand) iter.Seq[string] {
	return func(yield func(string) bool) {
		for {
			current := c.starts[rng.IntN(len(c.starts))]
			if !yield(current[0]) || !yield(current[1]) {
				return
			}
			for {
				successors := c.successors[current]
				if len(successors) == 0 {
					break
				}
				next := successors[rng.IntN(len(successors))]
				if !yield(next) {
					return
				}
				current = pair{current[1], next}
			}
		}
	}
}
