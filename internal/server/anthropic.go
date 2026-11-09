package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/itisrazza/markov-canary/internal/canary"
)

type messagesRequest struct {
	Model     string `json:"model"`
	Stream    bool   `json:"stream"`
	MaxTokens *int   `json:"max_tokens"`
}

type textBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type messageUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type message struct {
	ID           string       `json:"id"`
	Type         string       `json:"type"`
	Role         string       `json:"role"`
	Model        string       `json:"model"`
	Content      []textBlock  `json:"content"`
	StopReason   *string      `json:"stop_reason"`
	StopSequence *string      `json:"stop_sequence"`
	Usage        messageUsage `json:"usage"`
}

type messageStart struct {
	Type    string  `json:"type"`
	Message message `json:"message"`
}

type contentBlockStart struct {
	Type         string    `json:"type"`
	Index        int       `json:"index"`
	ContentBlock textBlock `json:"content_block"`
}

type textDelta struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type contentBlockDelta struct {
	Type  string    `json:"type"`
	Index int       `json:"index"`
	Delta textDelta `json:"delta"`
}

type contentBlockStop struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
}

type stopDelta struct {
	StopReason   string  `json:"stop_reason"`
	StopSequence *string `json:"stop_sequence"`
}

type outputUsage struct {
	OutputTokens int `json:"output_tokens"`
}

type messageDelta struct {
	Type  string      `json:"type"`
	Delta stopDelta   `json:"delta"`
	Usage outputUsage `json:"usage"`
}

type messageStop struct {
	Type string `json:"type"`
}

type anthropicModel struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	CreatedAt   string `json:"created_at"`
}

type anthropicModelList struct {
	Data    []anthropicModel `json:"data"`
	HasMore bool             `json:"has_more"`
	FirstID string           `json:"first_id"`
	LastID  string           `json:"last_id"`
}

func anthropicModels() anthropicModelList {
	models := []anthropicModel{
		{Type: "model", ID: "claude-opus-5-5", DisplayName: "Claude Opus 5.5", CreatedAt: "2026-01-01T00:00:00Z"},
		{Type: "model", ID: "claude-sonnet-5-5", DisplayName: "Claude Sonnet 5.5", CreatedAt: "2026-01-01T00:00:00Z"},
		{Type: "model", ID: "claude-haiku-5-5", DisplayName: "Claude Haiku 5.5", CreatedAt: "2026-01-01T00:00:00Z"},
	}
	return anthropicModelList{Data: models, FirstID: models[0].ID, LastID: models[len(models)-1].ID}
}

const stopReasonMaxTokens = "max_tokens"

func (s *Server) handleMessages(w http.ResponseWriter, r *http.Request) {
	body, ok := s.intercept(w, r, canary.Anthropic)
	if !ok {
		return
	}
	var request messagesRequest
	if err := json.Unmarshal(body, &request); err != nil {
		writeFailure(w, canary.Anthropic, failureBadRequest)
		return
	}

	started := time.Now()
	budget := s.tokenBudget(request.MaxTokens)
	reply := message{
		ID:      "msg_01" + canary.RandomID(22),
		Type:    "message",
		Role:    "assistant",
		Model:   request.Model,
		Content: []textBlock{},
		Usage:   messageUsage{InputTokens: estimateTokens(body), OutputTokens: 1},
	}
	if request.Stream {
		s.logTarpitEnd(r, started, s.streamMessage(w, r, reply, budget))
		return
	}

	text, err := s.dripText(r.Context(), budget)
	s.logTarpitEnd(r, started, err)
	if err != nil {
		return
	}
	stopReason := stopReasonMaxTokens
	reply.Content = []textBlock{{Type: "text", Text: text}}
	reply.StopReason = &stopReason
	reply.Usage.OutputTokens = budget
	writeJSON(w, http.StatusOK, reply)
}

func (s *Server) streamMessage(w http.ResponseWriter, r *http.Request, reply message, budget int) error {
	stream := startEventStream(w)
	if err := sendEvent(stream, "message_start", messageStart{Type: "message_start", Message: reply}); err != nil {
		return err
	}
	blockStart := contentBlockStart{Type: "content_block_start", ContentBlock: textBlock{Type: "text"}}
	if err := sendEvent(stream, blockStart.Type, blockStart); err != nil {
		return err
	}

	err := s.drip(r.Context(), budget, func(chunk string) error {
		return sendEvent(stream, "content_block_delta", contentBlockDelta{
			Type:  "content_block_delta",
			Delta: textDelta{Type: "text_delta", Text: chunk},
		})
	})
	if err != nil {
		return err
	}

	if err := sendEvent(stream, "content_block_stop", contentBlockStop{Type: "content_block_stop"}); err != nil {
		return err
	}
	delta := messageDelta{
		Type:  "message_delta",
		Delta: stopDelta{StopReason: stopReasonMaxTokens},
		Usage: outputUsage{OutputTokens: budget},
	}
	if err := sendEvent(stream, delta.Type, delta); err != nil {
		return err
	}
	return sendEvent(stream, "message_stop", messageStop{Type: "message_stop"})
}
