package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/itisrazza/markov-canary/internal/canary"
)

const schema = `
CREATE TABLE IF NOT EXISTS tokens (
	id         INTEGER PRIMARY KEY,
	provider   TEXT NOT NULL,
	key        TEXT NOT NULL UNIQUE,
	label      TEXT NOT NULL,
	created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS detections (
	id            INTEGER PRIMARY KEY,
	occurred_at   TEXT NOT NULL,
	kind          TEXT NOT NULL,
	token_id      INTEGER REFERENCES tokens (id),
	provider      TEXT NOT NULL,
	key_hash      TEXT NOT NULL,
	key_prefix    TEXT NOT NULL,
	remote_addr   TEXT NOT NULL,
	forwarded_for TEXT NOT NULL,
	user_agent    TEXT NOT NULL,
	method        TEXT NOT NULL,
	path          TEXT NOT NULL,
	body          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS detections_occurred_at ON detections (occurred_at);
`

type Store struct {
	db *sql.DB
}

func Open(ctx context.Context, path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database %q: %w", path, err)
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema to database %q: %w", path, err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) IssueToken(ctx context.Context, provider canary.Provider, key, label string) (canary.Token, error) {
	token := canary.Token{Provider: provider, Key: key, Label: label, CreatedAt: time.Now().UTC()}
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO tokens (provider, key, label, created_at) VALUES (?, ?, ?, ?)`,
		token.Provider, token.Key, token.Label, formatTime(token.CreatedAt))
	if err != nil {
		return canary.Token{}, fmt.Errorf("insert token %q: %w", label, err)
	}
	token.ID, err = result.LastInsertId()
	if err != nil {
		return canary.Token{}, fmt.Errorf("read id of token %q: %w", label, err)
	}
	return token, nil
}

func (s *Store) FindToken(ctx context.Context, key string) (canary.Token, bool, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, provider, key, label, created_at FROM tokens WHERE key = ?`, key)
	token, err := scanToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return canary.Token{}, false, nil
	}
	if err != nil {
		return canary.Token{}, false, fmt.Errorf("find token: %w", err)
	}
	return token, true, nil
}

func (s *Store) ListTokens(ctx context.Context) ([]canary.Token, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, provider, key, label, created_at FROM tokens ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list tokens: %w", err)
	}
	defer rows.Close()

	var tokens []canary.Token
	for rows.Next() {
		token, err := scanToken(rows)
		if err != nil {
			return nil, fmt.Errorf("list tokens: %w", err)
		}
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

func (s *Store) RecordDetection(ctx context.Context, detection canary.Detection) (canary.Detection, error) {
	var tokenID sql.NullInt64
	if detection.Token != nil {
		tokenID = sql.NullInt64{Int64: detection.Token.ID, Valid: true}
	}
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO detections (
			occurred_at, kind, token_id, provider, key_hash, key_prefix,
			remote_addr, forwarded_for, user_agent, method, path, body
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		formatTime(detection.OccurredAt), detection.Kind, tokenID, detection.Provider,
		detection.KeyHash, detection.KeyPrefix, detection.RemoteAddr, detection.ForwardedFor,
		detection.UserAgent, detection.Method, detection.Path, detection.Body)
	if err != nil {
		return canary.Detection{}, fmt.Errorf("insert detection for key %s…: %w", detection.KeyPrefix, err)
	}
	detection.ID, err = result.LastInsertId()
	if err != nil {
		return canary.Detection{}, fmt.Errorf("read id of detection for key %s…: %w", detection.KeyPrefix, err)
	}
	return detection, nil
}

func (s *Store) ListDetections(ctx context.Context, limit int) ([]canary.Detection, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT d.id, d.occurred_at, d.kind, d.provider, d.key_hash, d.key_prefix,
			d.remote_addr, d.forwarded_for, d.user_agent, d.method, d.path, d.body,
			t.id, t.provider, t.key, t.label, t.created_at
		FROM detections d
		LEFT JOIN tokens t ON t.id = d.token_id
		ORDER BY d.id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list detections: %w", err)
	}
	defer rows.Close()

	var detections []canary.Detection
	for rows.Next() {
		detection, err := scanDetection(rows)
		if err != nil {
			return nil, fmt.Errorf("list detections: %w", err)
		}
		detections = append(detections, detection)
	}
	return detections, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanToken(row scanner) (canary.Token, error) {
	var token canary.Token
	var createdAt string
	if err := row.Scan(&token.ID, &token.Provider, &token.Key, &token.Label, &createdAt); err != nil {
		return canary.Token{}, err
	}
	var err error
	token.CreatedAt, err = parseTime(createdAt)
	return token, err
}

func scanDetection(row scanner) (canary.Detection, error) {
	var detection canary.Detection
	var occurredAt string
	var tokenID sql.NullInt64
	var tokenProvider, tokenKey, tokenLabel, tokenCreatedAt sql.NullString
	err := row.Scan(
		&detection.ID, &occurredAt, &detection.Kind, &detection.Provider,
		&detection.KeyHash, &detection.KeyPrefix, &detection.RemoteAddr, &detection.ForwardedFor,
		&detection.UserAgent, &detection.Method, &detection.Path, &detection.Body,
		&tokenID, &tokenProvider, &tokenKey, &tokenLabel, &tokenCreatedAt)
	if err != nil {
		return canary.Detection{}, err
	}
	detection.OccurredAt, err = parseTime(occurredAt)
	if err != nil {
		return canary.Detection{}, err
	}
	if !tokenID.Valid {
		return detection, nil
	}
	createdAt, err := parseTime(tokenCreatedAt.String)
	if err != nil {
		return canary.Detection{}, err
	}
	detection.Token = &canary.Token{
		ID:        tokenID.Int64,
		Provider:  canary.Provider(tokenProvider.String),
		Key:       tokenKey.String,
		Label:     tokenLabel.String,
		CreatedAt: createdAt,
	}
	return detection, nil
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse stored timestamp %q: %w", value, err)
	}
	return parsed, nil
}
