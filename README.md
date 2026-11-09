# markov-canary

Canary tokens for AI API keys. The server issues fake OpenAI and Anthropic API
keys for you to plant where real ones might leak from. When someone uses one,
the request is recorded, an email alert is sent, and the caller is fed a slow
drip of Markov-generated text instead of a real completion.

## Detections

| Kind   | Meaning                                         | Response                |
| ------ | ----------------------------------------------- | ----------------------- |
| `leak` | A key issued by this server was used            | Markov tarpit           |
| `flag` | A key this server never issued was tried        | `401`, as the real APIs |

Keys that were not issued here are stored only as a 16 character prefix and a
SHA-256 hash, in case a real key is ever sent by mistake.

## Endpoints

| Endpoint                    | Behaviour                                         |
| --------------------------- | ------------------------------------------------- |
| `POST /v1/chat/completions` | OpenAI tarpit, streaming and non-streaming        |
| `POST /v1/messages`         | Anthropic tarpit, streaming and non-streaming     |
| `GET /v1/models`            | Model list for whichever provider the key implies |
| anything else               | Key is still recorded, then `404`                 |

## Usage

```bash
just build
./markov-canary issue -provider anthropic -label "decoy .env in infra repo"
./markov-canary serve
./markov-canary tokens
./markov-canary detections -limit 20
```

The planted key only reports back if whoever finds it sends it to this server,
so plant it alongside a base URL pointing here (for example `OPENAI_BASE_URL`
or `ANTHROPIC_BASE_URL` in the same decoy file).

## Configuration

Everything is configured through environment variables.

| Variable                        | Default            | Purpose                                              |
| ------------------------------- | ------------------ | ---------------------------------------------------- |
| `MARKOV_CANARY_DATABASE`        | `markov-canary.db` | SQLite database path                                 |
| `MARKOV_CANARY_LISTEN`          | `127.0.0.1:8080`   | Listen address                                       |
| `MARKOV_CANARY_SMTP_HOST`       | required           | SMTP server (STARTTLS; implicit TLS is unsupported)  |
| `MARKOV_CANARY_SMTP_PORT`       | `587`              | SMTP port                                            |
| `MARKOV_CANARY_SMTP_USERNAME`   | none               | SMTP username; authentication is skipped when empty  |
| `MARKOV_CANARY_SMTP_PASSWORD`   | none               | SMTP password                                        |
| `MARKOV_CANARY_MAIL_FROM`       | required           | Sender address                                       |
| `MARKOV_CANARY_MAIL_TO`         | required           | Comma-separated recipient addresses                  |
| `MARKOV_CANARY_NOTIFY_COOLDOWN` | `1h`               | Minimum gap between emails for the same key          |
| `MARKOV_CANARY_TOKEN_DELAY`     | `200ms`            | Delay before each generated word                     |
| `MARKOV_CANARY_MAX_TOKENS`      | `1024`             | Upper bound on words per response                    |
| `MARKOV_CANARY_CORPUS`          | built-in           | Text file to train the Markov chain on               |

Every detection is recorded, but email is throttled: one per issued key per
cooldown, and one per cooldown for all flags combined.

The server speaks plain HTTP and is meant to sit behind a TLS-terminating
reverse proxy. `X-Forwarded-For` is recorded as sent, not trusted.
