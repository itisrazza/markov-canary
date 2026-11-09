package server

import (
	"cmp"
	"encoding/json"
	"net/http"
	"time"

	"github.com/itisrazza/markov-canary/internal/canary"
)

type chatRequest struct {
	Model               string `json:"model"`
	Stream              bool   `json:"stream"`
	MaxTokens           *int   `json:"max_tokens"`
	MaxCompletionTokens *int   `json:"max_completion_tokens"`
}

type chatMessage struct {
	Role    string  `json:"role"`
	Content string  `json:"content"`
	Refusal *string `json:"refusal"`
}

type chatChoice struct {
	Index        int         `json:"index"`
	Message      chatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

type chatUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type chatCompletion struct {
	ID      string       `json:"id"`
	Object  string       `json:"object"`
	Created int64        `json:"created"`
	Model   string       `json:"model"`
	Choices []chatChoice `json:"choices"`
	Usage   chatUsage    `json:"usage"`
}

type chatDelta struct {
	Role    string  `json:"role,omitempty"`
	Content *string `json:"content,omitempty"`
}

type chatChunkChoice struct {
	Index        int       `json:"index"`
	Delta        chatDelta `json:"delta"`
	FinishReason *string   `json:"finish_reason"`
}

type chatChunk struct {
	ID      string            `json:"id"`
	Object  string            `json:"object"`
	Created int64             `json:"created"`
	Model   string            `json:"model"`
	Choices []chatChunkChoice `json:"choices"`
}

type openAIModel struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

type openAIModelList struct {
	Object string        `json:"object"`
	Data   []openAIModel `json:"data"`
}

func openAIModels() openAIModelList {
	ids := []string{"gpt-4o", "gpt-4o-mini", "gpt-4.1", "gpt-4.1-mini", "o3", "o4-mini"}
	models := make([]openAIModel, len(ids))
	for index, id := range ids {
		models[index] = openAIModel{ID: id, Object: "model", Created: 1715367049, OwnedBy: "system"}
	}
	return openAIModelList{Object: "list", Data: models}
}

func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	body, ok := s.intercept(w, r, canary.OpenAI)
	if !ok {
		return
	}
	var request chatRequest
	if err := json.Unmarshal(body, &request); err != nil {
		writeFailure(w, canary.OpenAI, failureBadRequest)
		return
	}

	started := time.Now()
	budget := s.tokenBudget(cmp.Or(request.MaxCompletionTokens, request.MaxTokens))
	id := "chatcmpl-" + canary.RandomID(29)
	if request.Stream {
		s.logTarpitEnd(r, started, s.streamChatCompletion(w, r, id, request.Model, budget))
		return
	}

	text, err := s.dripText(r.Context(), budget)
	s.logTarpitEnd(r, started, err)
	if err != nil {
		return
	}
	promptTokens := estimateTokens(body)
	writeJSON(w, http.StatusOK, chatCompletion{
		ID:      id,
		Object:  "chat.completion",
		Created: started.Unix(),
		Model:   request.Model,
		Choices: []chatChoice{{
			Message:      chatMessage{Role: "assistant", Content: text},
			FinishReason: "length",
		}},
		Usage: chatUsage{
			PromptTokens:     promptTokens,
			CompletionTokens: budget,
			TotalTokens:      promptTokens + budget,
		},
	})
}

func (s *Server) streamChatCompletion(w http.ResponseWriter, r *http.Request, id, model string, budget int) error {
	stream := startEventStream(w)
	created := time.Now().Unix()
	sendChunk := func(delta chatDelta, finishReason *string) error {
		return sendEvent(stream, "", chatChunk{
			ID:      id,
			Object:  "chat.completion.chunk",
			Created: created,
			Model:   model,
			Choices: []chatChunkChoice{{Delta: delta, FinishReason: finishReason}},
		})
	}

	empty := ""
	if err := sendChunk(chatDelta{Role: "assistant", Content: &empty}, nil); err != nil {
		return err
	}
	err := s.drip(r.Context(), budget, func(chunk string) error {
		return sendChunk(chatDelta{Content: &chunk}, nil)
	})
	if err != nil {
		return err
	}
	finishReason := "length"
	if err := sendChunk(chatDelta{}, &finishReason); err != nil {
		return err
	}
	return stream.sendRaw("", "[DONE]")
}
