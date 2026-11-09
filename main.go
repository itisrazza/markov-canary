package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/itisrazza/markov-canary/internal/canary"
	"github.com/itisrazza/markov-canary/internal/config"
	"github.com/itisrazza/markov-canary/internal/markov"
	"github.com/itisrazza/markov-canary/internal/notify"
	"github.com/itisrazza/markov-canary/internal/server"
	"github.com/itisrazza/markov-canary/internal/store"
)

const usage = `usage: markov-canary <command>

commands:
  serve                                   run the canary server
  issue -provider <name> -label <text>    issue a canary key (provider: openai, anthropic)
  tokens                                  list issued canary keys
  detections [-limit <n>]                 list recorded detections, newest first`

const shutdownTimeout = 10 * time.Second

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "markov-canary:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("no command given\n\n" + usage)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch args[0] {
	case "serve":
		return serve(ctx)
	case "issue":
		return issue(ctx, args[1:])
	case "tokens":
		return listTokens(ctx)
	case "detections":
		return listDetections(ctx, args[1:])
	}
	return fmt.Errorf("unknown command %q\n\n%s", args[0], usage)
}

func serve(ctx context.Context) error {
	cfg, err := config.LoadServer()
	if err != nil {
		return err
	}
	chain, err := loadChain(cfg.Tarpit.CorpusPath)
	if err != nil {
		return err
	}
	database, err := store.Open(ctx, config.DatabasePath())
	if err != nil {
		return err
	}
	defer database.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	canaryServer := &server.Server{
		Store:    database,
		Notifier: &notify.Throttled{Next: notifiers(cfg), Cooldown: cfg.NotifyCooldown},
		Chain:    chain,
		Tarpit:   cfg.Tarpit,
		Logger:   logger,
	}
	// No write timeout: holding responses open for a long time is the point.
	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           canaryServer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
	}

	failed := make(chan error, 1)
	go func() { failed <- httpServer.ListenAndServe() }()
	logger.Info("listening", "address", cfg.ListenAddr, "database", config.DatabasePath())

	select {
	case err := <-failed:
		return fmt.Errorf("serve on %s: %w", cfg.ListenAddr, err)
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("shut down server: %w", err)
	}
	return nil
}

func notifiers(cfg config.Server) notify.All {
	var channels notify.All
	if cfg.SMTP != nil {
		channels = append(channels, notify.SMTP{Config: *cfg.SMTP})
	}
	if cfg.WebhookURL != "" {
		channels = append(channels, notify.Webhook{URL: cfg.WebhookURL, Client: http.DefaultClient})
	}
	return channels
}

func loadChain(corpusPath string) (*markov.Chain, error) {
	if corpusPath == "" {
		return markov.New(markov.DefaultCorpus)
	}
	corpus, err := os.ReadFile(corpusPath)
	if err != nil {
		return nil, fmt.Errorf("read corpus: %w", err)
	}
	chain, err := markov.New(string(corpus))
	if err != nil {
		return nil, fmt.Errorf("build chain from corpus %q: %w", corpusPath, err)
	}
	return chain, nil
}

func issue(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("issue", flag.ContinueOnError)
	providerName := flags.String("provider", "", "provider to mimic: openai or anthropic")
	label := flags.String("label", "", "where the key will be planted, shown in alerts")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *label == "" {
		return errors.New("issue: -label is required, so an alert can say where the key leaked from")
	}
	provider, err := canary.ParseProvider(*providerName)
	if err != nil {
		return fmt.Errorf("issue: -provider: %w", err)
	}
	key, err := canary.GenerateKey(provider)
	if err != nil {
		return err
	}

	database, err := store.Open(ctx, config.DatabasePath())
	if err != nil {
		return err
	}
	defer database.Close()
	token, err := database.IssueToken(ctx, provider, key, *label)
	if err != nil {
		return err
	}
	fmt.Println(token.Key)
	return nil
}

func listTokens(ctx context.Context) error {
	database, err := store.Open(ctx, config.DatabasePath())
	if err != nil {
		return err
	}
	defer database.Close()
	tokens, err := database.ListTokens(ctx)
	if err != nil {
		return err
	}

	table := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "ID\tPROVIDER\tCREATED\tLABEL\tKEY")
	for _, token := range tokens {
		fmt.Fprintf(table, "%d\t%s\t%s\t%s\t%s\n",
			token.ID, token.Provider, token.CreatedAt.Format(time.RFC3339), token.Label, token.Key)
	}
	return table.Flush()
}

func listDetections(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("detections", flag.ContinueOnError)
	limit := flags.Int("limit", 50, "maximum number of detections to show")
	if err := flags.Parse(args); err != nil {
		return err
	}

	database, err := store.Open(ctx, config.DatabasePath())
	if err != nil {
		return err
	}
	defer database.Close()
	detections, err := database.ListDetections(ctx, *limit)
	if err != nil {
		return err
	}

	table := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "ID\tTIME\tKIND\tPROVIDER\tKEY\tREMOTE\tREQUEST\tLABEL")
	for _, detection := range detections {
		fmt.Fprintf(table, "%d\t%s\t%s\t%s\t%s…\t%s\t%s %s\t%s\n",
			detection.ID, detection.OccurredAt.Format(time.RFC3339), detection.Kind, detection.Provider,
			detection.KeyPrefix, detection.RemoteAddr, detection.Method, detection.Path, tokenLabel(detection))
	}
	return table.Flush()
}

func tokenLabel(detection canary.Detection) string {
	if detection.Token == nil {
		return "-"
	}
	return detection.Token.Label
}
