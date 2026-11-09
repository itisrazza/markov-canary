package config

import (
	"fmt"
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

type Server struct {
	ListenAddr     string
	NotifyCooldown time.Duration
	SMTP           SMTP
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
		Tarpit:         tarpit,
	}, nil
}

func loadSMTP() (SMTP, error) {
	host, err := required("SMTP_HOST")
	if err != nil {
		return SMTP{}, err
	}
	from, err := required("MAIL_FROM")
	if err != nil {
		return SMTP{}, err
	}
	to, err := required("MAIL_TO")
	if err != nil {
		return SMTP{}, err
	}
	port, err := parsed("SMTP_PORT", "587", strconv.Atoi)
	if err != nil {
		return SMTP{}, err
	}
	return SMTP{
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
