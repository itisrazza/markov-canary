package server_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/itisrazza/markov-canary/internal/canary"
	"github.com/itisrazza/markov-canary/internal/config"
	"github.com/itisrazza/markov-canary/internal/markov"
	"github.com/itisrazza/markov-canary/internal/server"
	"github.com/itisrazza/markov-canary/internal/store"
)

const (
	maxTokens  = 8
	unknownKey = "sk-not-issued-by-this-server"
)

type recordingNotifier struct {
	detections chan canary.Detection
}

func (n recordingNotifier) Notify(_ context.Context, detection canary.Detection) error {
	n.detections <- detection
	return nil
}

type fixture struct {
	url        string
	store      *store.Store
	notified   chan canary.Detection
	issuedKeys map[canary.Provider]string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	ctx := context.Background()
	database, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	issuedKeys := make(map[canary.Provider]string)
	for _, provider := range []canary.Provider{canary.OpenAI, canary.Anthropic} {
		key, err := canary.GenerateKey(provider)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.IssueToken(ctx, provider, key, "planted "+string(provider)); err != nil {
			t.Fatal(err)
		}
		issuedKeys[provider] = key
	}

	chain, err := markov.New(markov.DefaultCorpus)
	if err != nil {
		t.Fatal(err)
	}
	notified := make(chan canary.Detection, 16)
	canaryServer := &server.Server{
		Store:    database,
		Notifier: recordingNotifier{detections: notified},
		Chain:    chain,
		Tarpit:   config.Tarpit{TokenDelay: time.Millisecond, MaxTokens: maxTokens},
		Logger:   slog.New(slog.DiscardHandler),
	}
	httpServer := httptest.NewServer(canaryServer.Handler())
	t.Cleanup(httpServer.Close)
	return fixture{url: httpServer.URL, store: database, notified: notified, issuedKeys: issuedKeys}
}

type call struct {
	method  string
	path    string
	headers map[string]string
	body    string
}

func (f fixture) do(t *testing.T, request call) (int, string) {
	t.Helper()
	httpRequest, err := http.NewRequest(request.method, f.url+request.path, strings.NewReader(request.body))
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range request.headers {
		httpRequest.Header.Set(name, value)
	}
	response, err := http.DefaultClient.Do(httpRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, string(body)
}

func bearer(key string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + key}
}

func apiKey(key string) map[string]string {
	return map[string]string{"x-api-key": key}
}

func TestDetection(t *testing.T) {
	const chatBody = `{"model":"gpt-4o","max_tokens":2,"messages":[]}`
	const messagesBody = `{"model":"claude-sonnet-5-5","max_tokens":2,"messages":[]}`

	cases := []struct {
		name       string
		request    func(f fixture) call
		wantStatus int
		wantKind   canary.Kind
		wantLabel  string
	}{
		{
			name: "issued openai key on chat completions is a leak",
			request: func(f fixture) call {
				return call{"POST", "/v1/chat/completions", bearer(f.issuedKeys[canary.OpenAI]), chatBody}
			},
			wantStatus: http.StatusOK, wantKind: canary.KindLeak, wantLabel: "planted openai",
		},
		{
			name: "issued anthropic key on messages is a leak",
			request: func(f fixture) call {
				return call{"POST", "/v1/messages", apiKey(f.issuedKeys[canary.Anthropic]), messagesBody}
			},
			wantStatus: http.StatusOK, wantKind: canary.KindLeak, wantLabel: "planted anthropic",
		},
		{
			name: "issued key listing openai models is a leak",
			request: func(f fixture) call {
				return call{"GET", "/v1/models", bearer(f.issuedKeys[canary.OpenAI]), ""}
			},
			wantStatus: http.StatusOK, wantKind: canary.KindLeak, wantLabel: "planted openai",
		},
		{
			name: "issued key listing anthropic models is a leak",
			request: func(f fixture) call {
				return call{"GET", "/v1/models", apiKey(f.issuedKeys[canary.Anthropic]), ""}
			},
			wantStatus: http.StatusOK, wantKind: canary.KindLeak, wantLabel: "planted anthropic",
		},
		{
			name: "issued key on an unsupported endpoint is still a leak",
			request: func(f fixture) call {
				return call{"POST", "/v1/embeddings", bearer(f.issuedKeys[canary.OpenAI]), `{}`}
			},
			wantStatus: http.StatusNotFound, wantKind: canary.KindLeak, wantLabel: "planted openai",
		},
		{
			name: "issued key with a malformed body is still a leak",
			request: func(f fixture) call {
				return call{"POST", "/v1/messages", apiKey(f.issuedKeys[canary.Anthropic]), `not json`}
			},
			wantStatus: http.StatusBadRequest, wantKind: canary.KindLeak, wantLabel: "planted anthropic",
		},
		{
			name: "unknown openai key is a flag",
			request: func(fixture) call {
				return call{"POST", "/v1/chat/completions", bearer(unknownKey), chatBody}
			},
			wantStatus: http.StatusUnauthorized, wantKind: canary.KindFlag,
		},
		{
			name: "unknown anthropic key is a flag",
			request: func(fixture) call {
				return call{"POST", "/v1/messages", apiKey(unknownKey), messagesBody}
			},
			wantStatus: http.StatusUnauthorized, wantKind: canary.KindFlag,
		},
		{
			name: "no key is rejected without a detection",
			request: func(fixture) call {
				return call{"POST", "/v1/chat/completions", nil, chatBody}
			},
			wantStatus: http.StatusUnauthorized,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			f := newFixture(t)
			status, body := f.do(t, testCase.request(f))
			if status != testCase.wantStatus {
				t.Errorf("status = %d, want %d (body %s)", status, testCase.wantStatus, body)
			}

			detections, err := f.store.ListDetections(context.Background(), 10)
			if err != nil {
				t.Fatal(err)
			}
			if testCase.wantKind == "" {
				if len(detections) != 0 {
					t.Errorf("recorded %d detections, want none", len(detections))
				}
				return
			}
			if len(detections) != 1 {
				t.Fatalf("recorded %d detections, want 1", len(detections))
			}
			if detections[0].Kind != testCase.wantKind {
				t.Errorf("recorded kind = %q, want %q", detections[0].Kind, testCase.wantKind)
			}
			if label := labelOf(detections[0]); label != testCase.wantLabel {
				t.Errorf("recorded token label = %q, want %q", label, testCase.wantLabel)
			}

			select {
			case notified := <-f.notified:
				if notified.Kind != testCase.wantKind {
					t.Errorf("notified kind = %q, want %q", notified.Kind, testCase.wantKind)
				}
			case <-time.After(5 * time.Second):
				t.Error("no notification was sent")
			}
		})
	}
}

func labelOf(detection canary.Detection) string {
	if detection.Token == nil {
		return ""
	}
	return detection.Token.Label
}

func TestUnknownKeyIsNotStoredInFull(t *testing.T) {
	f := newFixture(t)
	f.do(t, call{"POST", "/v1/messages", apiKey(unknownKey), `{}`})

	detections, err := f.store.ListDetections(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(detections) != 1 {
		t.Fatalf("recorded %d detections, want 1", len(detections))
	}
	if strings.Contains(detections[0].KeyPrefix, unknownKey) {
		t.Errorf("stored prefix %q contains the whole key", detections[0].KeyPrefix)
	}
}

func TestTarpitLength(t *testing.T) {
	type chatReply struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	type messagesReply struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	chatText := func(t *testing.T, body string) string {
		var reply chatReply
		if err := json.Unmarshal([]byte(body), &reply); err != nil || len(reply.Choices) != 1 {
			t.Fatalf("unexpected chat completion %s (error %v)", body, err)
		}
		return reply.Choices[0].Message.Content
	}
	messagesText := func(t *testing.T, body string) string {
		var reply messagesReply
		if err := json.Unmarshal([]byte(body), &reply); err != nil || len(reply.Content) != 1 {
			t.Fatalf("unexpected message %s (error %v)", body, err)
		}
		return reply.Content[0].Text
	}

	cases := []struct {
		name      string
		provider  canary.Provider
		body      string
		wantWords int
	}{
		{"openai honours max_tokens", canary.OpenAI, `{"model":"m","max_tokens":3}`, 3},
		{"openai honours max_completion_tokens", canary.OpenAI, `{"model":"m","max_completion_tokens":4}`, 4},
		{"openai caps at the configured maximum", canary.OpenAI, `{"model":"m","max_tokens":9999}`, maxTokens},
		{"openai defaults to the configured maximum", canary.OpenAI, `{"model":"m"}`, maxTokens},
		{"anthropic honours max_tokens", canary.Anthropic, `{"model":"m","max_tokens":3}`, 3},
		{"anthropic caps at the configured maximum", canary.Anthropic, `{"model":"m","max_tokens":9999}`, maxTokens},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			f := newFixture(t)
			var text string
			if testCase.provider == canary.OpenAI {
				_, body := f.do(t, call{"POST", "/v1/chat/completions", bearer(f.issuedKeys[canary.OpenAI]), testCase.body})
				text = chatText(t, body)
			} else {
				_, body := f.do(t, call{"POST", "/v1/messages", apiKey(f.issuedKeys[canary.Anthropic]), testCase.body})
				text = messagesText(t, body)
			}
			if words := len(strings.Fields(text)); words != testCase.wantWords {
				t.Errorf("got %d words (%q), want %d", words, text, testCase.wantWords)
			}
		})
	}
}

func TestStreaming(t *testing.T) {
	cases := []struct {
		name       string
		request    func(f fixture) call
		deltaLine  string
		wantSuffix string
	}{
		{
			name: "openai",
			request: func(f fixture) call {
				return call{"POST", "/v1/chat/completions", bearer(f.issuedKeys[canary.OpenAI]),
					`{"model":"m","stream":true,"max_tokens":3}`}
			},
			deltaLine:  `"finish_reason":null`,
			wantSuffix: "data: [DONE]\n\n",
		},
		{
			name: "anthropic",
			request: func(f fixture) call {
				return call{"POST", "/v1/messages", apiKey(f.issuedKeys[canary.Anthropic]),
					`{"model":"m","stream":true,"max_tokens":3}`}
			},
			deltaLine:  "event: content_block_delta",
			wantSuffix: "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			f := newFixture(t)
			status, body := f.do(t, testCase.request(f))
			if status != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", status, body)
			}
			if !strings.HasSuffix(body, testCase.wantSuffix) {
				t.Errorf("stream does not end with %q:\n%s", testCase.wantSuffix, body)
			}
			// OpenAI sends one extra opening chunk that carries only the role.
			wantDeltas := 3
			if testCase.name == "openai" {
				wantDeltas = 4
			}
			if deltas := strings.Count(body, testCase.deltaLine); deltas != wantDeltas {
				t.Errorf("got %d delta events, want %d:\n%s", deltas, wantDeltas, body)
			}
		})
	}
}
