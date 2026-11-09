package server

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"
)

func (s *Server) tokenBudget(requested *int) int {
	if requested == nil || *requested <= 0 || *requested > s.Tarpit.MaxTokens {
		return s.Tarpit.MaxTokens
	}
	return *requested
}

// drip emits budget chunks of Markov text, one TokenDelay apart, and gives up
// as soon as the client goes away.
func (s *Server) drip(ctx context.Context, budget int, emit func(chunk string) error) error {
	rng := rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
	emitted := 0
	for word := range s.Chain.Words(rng) {
		if emitted >= budget {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.Tarpit.TokenDelay):
		}
		if emitted > 0 {
			word = " " + word
		}
		if err := emit(word); err != nil {
			return err
		}
		emitted++
	}
	return nil
}

// dripText is the non-streaming tarpit: the client waits for the whole budget
// before getting anything back.
func (s *Server) dripText(ctx context.Context, budget int) (string, error) {
	var text strings.Builder
	err := s.drip(ctx, budget, func(chunk string) error {
		text.WriteString(chunk)
		return nil
	})
	return text.String(), err
}

func (s *Server) logTarpitEnd(r *http.Request, started time.Time, err error) {
	s.Logger.Info("tarpit released",
		"remote_addr", r.RemoteAddr, "path", r.URL.Path,
		"held_for", time.Since(started).Round(time.Millisecond).String(), "ended_by", err)
}

func estimateTokens(body []byte) int {
	return len(body) / 4
}

type eventStream struct {
	writer     http.ResponseWriter
	controller *http.ResponseController
}

func startEventStream(w http.ResponseWriter) eventStream {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	return eventStream{writer: w, controller: http.NewResponseController(w)}
}

// sendEvent writes one server-sent event; OpenAI events have no name.
func sendEvent[T any](stream eventStream, name string, payload T) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode %T event: %w", payload, err)
	}
	return stream.sendRaw(name, string(data))
}

func (e eventStream) sendRaw(name, data string) error {
	if name != "" {
		if _, err := fmt.Fprintf(e.writer, "event: %s\n", name); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(e.writer, "data: %s\n\n", data); err != nil {
		return err
	}
	return e.controller.Flush()
}
