package notify_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/itisrazza/markov-canary/internal/canary"
	"github.com/itisrazza/markov-canary/internal/notify"
)

type receivedWebhook struct {
	Text  string `json:"text"`
	Kind  string `json:"kind"`
	Token *struct {
		Label string `json:"label"`
	} `json:"token"`
	KeyPrefix string `json:"key_prefix"`
}

func TestWebhook(t *testing.T) {
	leak := canary.Detection{
		ID: 7, Kind: canary.KindLeak, Provider: canary.OpenAI, KeyPrefix: "sk-proj-abc",
		Token:      &canary.Token{ID: 1, Provider: canary.OpenAI, Label: "decoy .env"},
		OccurredAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	flag := canary.Detection{ID: 8, Kind: canary.KindFlag, Provider: canary.Anthropic, KeyPrefix: "sk-ant-xyz"}

	cases := []struct {
		name       string
		detection  canary.Detection
		answer     int
		wantLabel  string
		wantStatus int
	}{
		{name: "leak is delivered with its token", detection: leak, answer: http.StatusNoContent, wantLabel: "decoy .env"},
		{name: "flag is delivered without a token", detection: flag, answer: http.StatusOK},
		{name: "server error is reported", detection: leak, answer: http.StatusInternalServerError, wantLabel: "decoy .env", wantStatus: http.StatusInternalServerError},
		{name: "client error is reported", detection: flag, answer: http.StatusForbidden, wantStatus: http.StatusForbidden},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var received receivedWebhook
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if err := json.Unmarshal(body, &received); err != nil {
					t.Errorf("webhook body is not JSON: %v (%s)", err, body)
				}
				w.WriteHeader(testCase.answer)
			}))
			defer receiver.Close()

			webhook := notify.Webhook{URL: receiver.URL, Client: receiver.Client()}
			err := webhook.Notify(context.Background(), testCase.detection)

			var statusError notify.WebhookStatusError
			gotStatus := 0
			if errors.As(err, &statusError) {
				gotStatus = statusError.Status
			}
			if gotStatus != testCase.wantStatus || (err != nil) != (testCase.wantStatus != 0) {
				t.Errorf("Notify error = %v, want status %d", err, testCase.wantStatus)
			}
			if received.Kind != string(testCase.detection.Kind) || received.KeyPrefix != testCase.detection.KeyPrefix {
				t.Errorf("received %+v, want kind %q and key prefix %q",
					received, testCase.detection.Kind, testCase.detection.KeyPrefix)
			}
			if received.Text == "" {
				t.Error("received no text summary")
			}
			gotLabel := ""
			if received.Token != nil {
				gotLabel = received.Token.Label
			}
			if gotLabel != testCase.wantLabel {
				t.Errorf("received token label %q, want %q", gotLabel, testCase.wantLabel)
			}
		})
	}
}

type failingNotifier struct{ err error }

func (n failingNotifier) Notify(context.Context, canary.Detection) error { return n.err }

func TestAllKeepsGoingWhenOneChannelFails(t *testing.T) {
	broken := errors.New("smtp is down")
	working := &countingNotifier{}
	err := notify.All{failingNotifier{err: broken}, working}.Notify(context.Background(), canary.Detection{})

	if !errors.Is(err, broken) {
		t.Errorf("error = %v, want it to include %v", err, broken)
	}
	if len(working.sent) != 1 {
		t.Errorf("working channel got %d notifications, want 1", len(working.sent))
	}
}
