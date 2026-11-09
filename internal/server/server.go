package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/itisrazza/markov-canary/internal/canary"
	"github.com/itisrazza/markov-canary/internal/config"
	"github.com/itisrazza/markov-canary/internal/markov"
	"github.com/itisrazza/markov-canary/internal/notify"
)

const (
	maxBodyBytes       = 1 << 20
	maxStoredBodyBytes = 16 << 10
	notifyTimeout      = 30 * time.Second
)

type DetectionStore interface {
	FindToken(ctx context.Context, key string) (canary.Token, bool, error)
	RecordDetection(ctx context.Context, detection canary.Detection) (canary.Detection, error)
}

type Server struct {
	Store    DetectionStore
	Notifier notify.Notifier
	Chain    *markov.Chain
	Tarpit   config.Tarpit
	Logger   *slog.Logger
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/chat/completions", s.handleChatCompletions)
	mux.HandleFunc("POST /v1/messages", s.handleMessages)
	mux.HandleFunc("GET /v1/models", s.handleModels)
	mux.HandleFunc("/", s.handleUnknown)
	return mux
}

func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	provider := guessProvider(r)
	if _, ok := s.intercept(w, r, provider); !ok {
		return
	}
	if provider == canary.Anthropic {
		writeJSON(w, http.StatusOK, anthropicModels())
		return
	}
	writeJSON(w, http.StatusOK, openAIModels())
}

// handleUnknown still records the key on endpoints the canary does not mimic.
func (s *Server) handleUnknown(w http.ResponseWriter, r *http.Request) {
	provider := guessProvider(r)
	if _, ok := s.intercept(w, r, provider); !ok {
		return
	}
	writeFailure(w, provider, failureNotFound)
}

// intercept records the presented key and answers the request itself unless
// the key is an issued canary, in which case the caller carries on to the tarpit.
func (s *Server) intercept(w http.ResponseWriter, r *http.Request, provider canary.Provider) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeFailure(w, provider, failureBadRequest)
		return nil, false
	}
	key := presentedKey(r)
	if key == "" {
		writeFailure(w, provider, failureUnauthenticated)
		return nil, false
	}

	detection, err := s.record(r, provider, key, body)
	if err != nil {
		s.Logger.Error("recording detection failed", "error", err, "path", r.URL.Path, "remote_addr", r.RemoteAddr)
		writeFailure(w, provider, failureInternal)
		return nil, false
	}
	s.Logger.Warn("canary key detected",
		"detection", detection.ID, "kind", detection.Kind, "provider", detection.Provider,
		"key_prefix", detection.KeyPrefix, "remote_addr", detection.RemoteAddr, "path", detection.Path)
	go s.notify(detection)

	if detection.Kind == canary.KindFlag {
		writeFailure(w, provider, failureUnauthenticated)
		return nil, false
	}
	return body, true
}

func (s *Server) record(r *http.Request, provider canary.Provider, key string, body []byte) (canary.Detection, error) {
	detection := canary.Detection{
		OccurredAt:   time.Now().UTC(),
		Kind:         canary.KindFlag,
		Provider:     provider,
		KeyHash:      canary.HashKey(key),
		KeyPrefix:    canary.KeyPrefix(key),
		RemoteAddr:   r.RemoteAddr,
		ForwardedFor: r.Header.Get("X-Forwarded-For"),
		UserAgent:    r.UserAgent(),
		Method:       r.Method,
		Path:         r.URL.RequestURI(),
		Body:         string(body[:min(len(body), maxStoredBodyBytes)]),
	}

	token, issued, err := s.Store.FindToken(r.Context(), key)
	if err != nil {
		return canary.Detection{}, err
	}
	if issued {
		detection.Kind = canary.KindLeak
		detection.Token = &token
	}
	return s.Store.RecordDetection(r.Context(), detection)
}

func (s *Server) notify(detection canary.Detection) {
	ctx, cancel := context.WithTimeout(context.Background(), notifyTimeout)
	defer cancel()
	if err := s.Notifier.Notify(ctx, detection); err != nil {
		s.Logger.Error("notification failed", "error", err, "detection", detection.ID)
	}
}

func presentedKey(r *http.Request) string {
	if key := r.Header.Get("x-api-key"); key != "" {
		return key
	}
	key, isBearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !isBearer {
		return ""
	}
	return strings.TrimSpace(key)
}

func guessProvider(r *http.Request) canary.Provider {
	if r.Header.Get("x-api-key") != "" || r.Header.Get("anthropic-version") != "" {
		return canary.Anthropic
	}
	return canary.OpenAI
}

type failure struct {
	status           int
	openAIType       string
	openAICode       *string
	openAIMessage    string
	anthropicType    string
	anthropicMessage string
}

var (
	invalidAPIKeyCode = "invalid_api_key"

	failureUnauthenticated = failure{
		status:           http.StatusUnauthorized,
		openAIType:       "invalid_request_error",
		openAICode:       &invalidAPIKeyCode,
		openAIMessage:    "Incorrect API key provided. You can find your API key at https://platform.openai.com/account/api-keys.",
		anthropicType:    "authentication_error",
		anthropicMessage: "invalid x-api-key",
	}
	failureBadRequest = failure{
		status:           http.StatusBadRequest,
		openAIType:       "invalid_request_error",
		openAIMessage:    "We could not parse the JSON body of your request.",
		anthropicType:    "invalid_request_error",
		anthropicMessage: "The request body is not valid JSON.",
	}
	failureNotFound = failure{
		status:           http.StatusNotFound,
		openAIType:       "invalid_request_error",
		openAIMessage:    "Invalid URL.",
		anthropicType:    "not_found_error",
		anthropicMessage: "Not found.",
	}
	failureInternal = failure{
		status:           http.StatusInternalServerError,
		openAIType:       "server_error",
		openAIMessage:    "The server had an error while processing your request.",
		anthropicType:    "api_error",
		anthropicMessage: "Internal server error.",
	}
)

type openAIErrorDetail struct {
	Message string  `json:"message"`
	Type    string  `json:"type"`
	Param   *string `json:"param"`
	Code    *string `json:"code"`
}

type openAIError struct {
	Error openAIErrorDetail `json:"error"`
}

type anthropicErrorDetail struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type anthropicError struct {
	Type  string               `json:"type"`
	Error anthropicErrorDetail `json:"error"`
}

func writeFailure(w http.ResponseWriter, provider canary.Provider, failed failure) {
	if provider == canary.Anthropic {
		writeJSON(w, failed.status, anthropicError{
			Type:  "error",
			Error: anthropicErrorDetail{Type: failed.anthropicType, Message: failed.anthropicMessage},
		})
		return
	}
	writeJSON(w, failed.status, openAIError{
		Error: openAIErrorDetail{Message: failed.openAIMessage, Type: failed.openAIType, Code: failed.openAICode},
	})
}

func writeJSON[T any](w http.ResponseWriter, status int, payload T) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// The only way this fails is the client hanging up, which needs no handling.
	_ = json.NewEncoder(w).Encode(payload)
}
