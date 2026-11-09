package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/itisrazza/markov-canary/internal/canary"
)

const maxErrorBodyBytes = 1 << 10

type WebhookStatusError struct {
	URL    string
	Status int
	Body   string
}

func (e WebhookStatusError) Error() string {
	return fmt.Sprintf("webhook %s answered %d: %s", e.URL, e.Status, e.Body)
}

type webhookToken struct {
	ID       int64           `json:"id"`
	Provider canary.Provider `json:"provider"`
	Label    string          `json:"label"`
	IssuedAt time.Time       `json:"issued_at"`
}

type webhookPayload struct {
	// Text is a one-line summary for receivers that only show a message.
	Text         string          `json:"text"`
	ID           int64           `json:"id"`
	Kind         canary.Kind     `json:"kind"`
	OccurredAt   time.Time       `json:"occurred_at"`
	Provider     canary.Provider `json:"provider"`
	Token        *webhookToken   `json:"token"`
	KeyPrefix    string          `json:"key_prefix"`
	KeySHA256    string          `json:"key_sha256"`
	RemoteAddr   string          `json:"remote_addr"`
	ForwardedFor string          `json:"forwarded_for"`
	UserAgent    string          `json:"user_agent"`
	Method       string          `json:"method"`
	Path         string          `json:"path"`
	Body         string          `json:"body"`
}

func newWebhookPayload(detection canary.Detection) webhookPayload {
	payload := webhookPayload{
		Text:         subject(detection),
		ID:           detection.ID,
		Kind:         detection.Kind,
		OccurredAt:   detection.OccurredAt,
		Provider:     detection.Provider,
		KeyPrefix:    detection.KeyPrefix,
		KeySHA256:    detection.KeyHash,
		RemoteAddr:   detection.RemoteAddr,
		ForwardedFor: detection.ForwardedFor,
		UserAgent:    detection.UserAgent,
		Method:       detection.Method,
		Path:         detection.Path,
		Body:         detection.Body,
	}
	if detection.Token != nil {
		payload.Token = &webhookToken{
			ID:       detection.Token.ID,
			Provider: detection.Token.Provider,
			Label:    detection.Token.Label,
			IssuedAt: detection.Token.CreatedAt,
		}
	}
	return payload
}

// Webhook posts each detection as JSON and treats any non-2xx answer as a failure.
type Webhook struct {
	URL    string
	Client *http.Client
}

func (n Webhook) Notify(ctx context.Context, detection canary.Detection) error {
	body, err := json.Marshal(newWebhookPayload(detection))
	if err != nil {
		return fmt.Errorf("encode detection %d for webhook: %w", detection.ID, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build webhook request for detection %d: %w", detection.ID, err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "markov-canary")

	response, err := n.Client.Do(request)
	if err != nil {
		return fmt.Errorf("post detection %d to webhook: %w", detection.ID, err)
	}
	defer response.Body.Close()
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	answer, err := io.ReadAll(io.LimitReader(response.Body, maxErrorBodyBytes))
	if err != nil {
		return fmt.Errorf("read webhook answer for detection %d (status %d): %w", detection.ID, response.StatusCode, err)
	}
	return fmt.Errorf("post detection %d: %w", detection.ID,
		WebhookStatusError{URL: n.URL, Status: response.StatusCode, Body: string(answer)})
}

// All sends through every channel, so one failing does not silence the others.
type All []Notifier

func (n All) Notify(ctx context.Context, detection canary.Detection) error {
	failures := make([]error, len(n))
	for index, notifier := range n {
		failures[index] = notifier.Notify(ctx, detection)
	}
	return errors.Join(failures...)
}
