package notify_test

import (
	"context"
	"testing"
	"time"

	"github.com/itisrazza/markov-canary/internal/canary"
	"github.com/itisrazza/markov-canary/internal/notify"
)

type countingNotifier struct {
	sent []canary.Detection
}

func (n *countingNotifier) Notify(_ context.Context, detection canary.Detection) error {
	n.sent = append(n.sent, detection)
	return nil
}

func TestThrottled(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	leak := func(key string, after time.Duration) canary.Detection {
		return canary.Detection{
			Kind: canary.KindLeak, Token: &canary.Token{Key: key},
			KeyHash: canary.HashKey(key), OccurredAt: start.Add(after),
		}
	}
	flag := func(key string, after time.Duration) canary.Detection {
		return canary.Detection{Kind: canary.KindFlag, KeyHash: canary.HashKey(key), OccurredAt: start.Add(after)}
	}

	cases := []struct {
		name       string
		detections []canary.Detection
		wantSent   int
	}{
		{"first use is sent", []canary.Detection{leak("a", 0)}, 1},
		{"repeat within cooldown is held back", []canary.Detection{leak("a", 0), leak("a", 59*time.Minute)}, 1},
		{"repeat after cooldown is sent", []canary.Detection{leak("a", 0), leak("a", time.Hour)}, 2},
		{"different keys do not share a cooldown", []canary.Detection{leak("a", 0), leak("b", time.Minute)}, 2},
		{"all flags share one cooldown", []canary.Detection{flag("x", 0), flag("y", time.Minute), flag("z", 2*time.Minute)}, 1},
		{"a flag does not hold back a leak", []canary.Detection{flag("x", 0), leak("a", time.Minute)}, 2},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			counter := &countingNotifier{}
			throttled := &notify.Throttled{Next: counter, Cooldown: time.Hour}
			for _, detection := range testCase.detections {
				if err := throttled.Notify(context.Background(), detection); err != nil {
					t.Fatal(err)
				}
			}
			if len(counter.sent) != testCase.wantSent {
				t.Errorf("sent %d notifications, want %d", len(counter.sent), testCase.wantSent)
			}
		})
	}
}
