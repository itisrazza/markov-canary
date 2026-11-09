package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const envPrefix = "MARKOV_CANARY_"

type MissingVariableError struct {
	Name string
}

func (e MissingVariableError) Error() string {
	return fmt.Sprintf("environment variable %s is required but not set", e.Name)
}

type InvalidVariableError struct {
	Name  string
	Value string
	Cause error
}

func (e InvalidVariableError) Error() string {
	return fmt.Sprintf("environment variable %s has invalid value %q: %v", e.Name, e.Value, e.Cause)
}

func (e InvalidVariableError) Unwrap() error {
	return e.Cause
}

type NoNotifierError struct{}

func (NoNotifierError) Error() string {
	return fmt.Sprintf("no notification channel configured: set %sSMTP_HOST for email, %sWEBHOOK_URL for a webhook, or both",
		envPrefix, envPrefix)
}

type SMTP struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	To       []string
}

type Tarpit struct {
	TokenDelay time.Duration
	MaxTokens  int
	CorpusPath string
}

// Server needs at least one of SMTP and WebhookURL; a nil SMTP or an empty
// WebhookURL means that channel is switched off.
type Server struct {
	ListenAddr     string
	NotifyCooldown time.Duration
	SMTP           *SMTP
	WebhookURL     string
	Tarpit         Tarpit
}

func DatabasePath() string {
	return optional("DATABASE", "markov-canary.db")
}

func LoadServer() (Server, error) {
	smtp, err := loadSMTP()
	if err != nil {
		return Server{}, err
	}
	webhookURL, err := loadWebhookURL()
	if err != nil {
		return Server{}, err
	}
	if smtp == nil && webhookURL == "" {
		return Server{}, NoNotifierError{}
	}
	tarpit, err := loadTarpit()
	if err != nil {
		return Server{}, err
	}
	cooldown, err := parsed("NOTIFY_COOLDOWN", "1h", time.ParseDuration)
	if err != nil {
		return Server{}, err
	}
	return Server{
		ListenAddr:     optional("LISTEN", "127.0.0.1:8080"),
		NotifyCooldown: cooldown,
		SMTP:           smtp,
		WebhookURL:     webhookURL,
		Tarpit:         tarpit,
	}, nil
}

func loadWebhookURL() (string, error) {
	return parsed("WEBHOOK_URL", "", func(value string) (string, error) {
		if value == "" {
			return "", nil
		}
		parsedURL, err := url.Parse(value)
		if err != nil {
			return "", err
		}
		if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" || parsedURL.Host == "" {
			return "", errors.New("must be an absolute http or https URL")
		}
		return value, nil
	})
}

func loadSMTP() (*SMTP, error) {
	host := optional("SMTP_HOST", "")
	if host == "" {
		return nil, nil
	}
	from, err := required("MAIL_FROM")
	if err != nil {
		return nil, err
	}
	to, err := required("MAIL_TO")
	if err != nil {
		return nil, err
	}
	port, err := parsed("SMTP_PORT", "587", strconv.Atoi)
	if err != nil {
		return nil, err
	}
	return &SMTP{
		Host:     host,
		Port:     port,
		Username: optional("SMTP_USERNAME", ""),
		Password: optional("SMTP_PASSWORD", ""),
		From:     from,
		To:       splitList(to),
	}, nil
}

func loadTarpit() (Tarpit, error) {
	delay, err := parsed("TOKEN_DELAY", "200ms", time.ParseDuration)
	if err != nil {
		return Tarpit{}, err
	}
	maxTokens, err := parsed("MAX_TOKENS", "1024", strconv.Atoi)
	if err != nil {
		return Tarpit{}, err
	}
	return Tarpit{
		TokenDelay: delay,
		MaxTokens:  maxTokens,
		CorpusPath: optional("CORPUS", ""),
	}, nil
}

func optional(name, defaultValue string) string {
	value, ok := os.LookupEnv(envPrefix + name)
	if !ok || value == "" {
		return defaultValue
	}
	return value
}

func required(name string) (string, error) {
	value := optional(name, "")
	if value == "" {
		return "", MissingVariableError{Name: envPrefix + name}
	}
	return value, nil
}

func parsed[T any](name, defaultValue string, parse func(string) (T, error)) (T, error) {
	value := optional(name, defaultValue)
	result, err := parse(value)
	if err != nil {
		return result, InvalidVariableError{Name: envPrefix + name, Value: value, Cause: err}
	}
	return result, nil
}

func splitList(value string) []string {
	var items []string
	for item := range strings.SplitSeq(value, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			items = append(items, trimmed)
		}
	}
	return items
}
