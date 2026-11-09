package notify

import (
	"bytes"
	"context"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/itisrazza/markov-canary/internal/canary"
	"github.com/itisrazza/markov-canary/internal/config"
)

type Notifier interface {
	Notify(ctx context.Context, detection canary.Detection) error
}

// SMTP sends through a server that offers STARTTLS (usually port 587).
// Implicit TLS on port 465 is not supported.
type SMTP struct {
	Config config.SMTP
}

func (n SMTP) Notify(_ context.Context, detection canary.Detection) error {
	message, err := buildMessage(n.Config, detection)
	if err != nil {
		return err
	}

	var auth smtp.Auth
	if n.Config.Username != "" {
		auth = smtp.PlainAuth("", n.Config.Username, n.Config.Password, n.Config.Host)
	}
	address := net.JoinHostPort(n.Config.Host, strconv.Itoa(n.Config.Port))
	if err := smtp.SendMail(address, auth, n.Config.From, n.Config.To, message); err != nil {
		return fmt.Errorf("send detection %d via %s to %s: %w",
			detection.ID, address, strings.Join(n.Config.To, ", "), err)
	}
	return nil
}

func buildMessage(cfg config.SMTP, detection canary.Detection) ([]byte, error) {
	var message bytes.Buffer
	headers := []struct{ name, value string }{
		{"From", cfg.From},
		{"To", strings.Join(cfg.To, ", ")},
		{"Subject", mime.QEncoding.Encode("utf-8", subject(detection))},
		{"Date", detection.OccurredAt.Format(time.RFC1123Z)},
		{"MIME-Version", "1.0"},
		{"Content-Type", `text/plain; charset="utf-8"`},
		{"Content-Transfer-Encoding", "quoted-printable"},
	}
	for _, header := range headers {
		fmt.Fprintf(&message, "%s: %s\r\n", header.name, header.value)
	}
	message.WriteString("\r\n")

	body := quotedprintable.NewWriter(&message)
	if _, err := body.Write([]byte(describe(detection))); err != nil {
		return nil, fmt.Errorf("encode body of detection %d: %w", detection.ID, err)
	}
	if err := body.Close(); err != nil {
		return nil, fmt.Errorf("encode body of detection %d: %w", detection.ID, err)
	}
	return message.Bytes(), nil
}

func subject(detection canary.Detection) string {
	if detection.Token != nil {
		return fmt.Sprintf("[markov-canary] leak: %s", detection.Token.Label)
	}
	return fmt.Sprintf("[markov-canary] flag: unknown %s key %s…", detection.Provider, detection.KeyPrefix)
}

func describe(detection canary.Detection) string {
	var text strings.Builder
	if detection.Token != nil {
		fmt.Fprintf(&text, "Canary key %q (issued %s) was used.\r\n\r\n",
			detection.Token.Label, detection.Token.CreatedAt.Format(time.RFC3339))
	} else {
		text.WriteString("A key this server never issued was tried.\r\n\r\n")
	}

	fields := []struct{ name, value string }{
		{"Detection", strconv.FormatInt(detection.ID, 10)},
		{"Kind", string(detection.Kind)},
		{"Time", detection.OccurredAt.Format(time.RFC3339)},
		{"Provider", string(detection.Provider)},
		{"Key prefix", detection.KeyPrefix},
		{"Key SHA-256", detection.KeyHash},
		{"Remote address", detection.RemoteAddr},
		{"X-Forwarded-For", detection.ForwardedFor},
		{"User agent", detection.UserAgent},
		{"Request", detection.Method + " " + detection.Path},
	}
	for _, field := range fields {
		fmt.Fprintf(&text, "%-16s %s\r\n", field.name+":", field.value)
	}
	fmt.Fprintf(&text, "\r\nRequest body:\r\n%s\r\n", detection.Body)
	return text.String()
}

// Throttled lets one notification through per issued key per cooldown, so a
// client hammering the tarpit does not turn into a flood of email. All flags
// share a single cooldown, otherwise spraying random keys would send one
// email each. The cooldown is kept in memory and resets when the server restarts.
type Throttled struct {
	Next     Notifier
	Cooldown time.Duration

	mutex    sync.Mutex
	lastSent map[string]time.Time
}

func (n *Throttled) Notify(ctx context.Context, detection canary.Detection) error {
	if !n.claim(detection) {
		return nil
	}
	return n.Next.Notify(ctx, detection)
}

func (n *Throttled) claim(detection canary.Detection) bool {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if n.lastSent == nil {
		n.lastSent = make(map[string]time.Time)
	}
	bucket := throttleBucket(detection)
	last, seen := n.lastSent[bucket]
	if seen && detection.OccurredAt.Sub(last) < n.Cooldown {
		return false
	}
	n.lastSent[bucket] = detection.OccurredAt
	return true
}

func throttleBucket(detection canary.Detection) string {
	if detection.Token == nil {
		return string(canary.KindFlag)
	}
	return detection.KeyHash
}
