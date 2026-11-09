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
| `MARKOV_CANARY_SMTP_HOST`       | none               | SMTP server (STARTTLS; implicit TLS is unsupported)  |
| `MARKOV_CANARY_SMTP_PORT`       | `587`              | SMTP port                                            |
| `MARKOV_CANARY_SMTP_USERNAME`   | none               | SMTP username; authentication is skipped when empty  |
| `MARKOV_CANARY_SMTP_PASSWORD`   | none               | SMTP password                                        |
| `MARKOV_CANARY_MAIL_FROM`       | with SMTP          | Sender address                                       |
| `MARKOV_CANARY_MAIL_TO`         | with SMTP          | Comma-separated recipient addresses                  |
| `MARKOV_CANARY_WEBHOOK_URL`     | none               | URL to `POST` each alert to as JSON                  |
| `MARKOV_CANARY_NOTIFY_COOLDOWN` | `1h`               | Minimum gap between alerts for the same key          |
| `MARKOV_CANARY_TOKEN_DELAY`     | `200ms`            | Delay before each generated word                     |
| `MARKOV_CANARY_MAX_TOKENS`      | `1024`             | Upper bound on words per response                    |
| `MARKOV_CANARY_CORPUS`          | built-in           | Text file to train the Markov chain on               |

At least one alert channel is required: set `MARKOV_CANARY_SMTP_HOST` for
email, `MARKOV_CANARY_WEBHOOK_URL` for a webhook, or both.

Every detection is recorded, but alerts are throttled: one per issued key per
cooldown, and one per cooldown for all flags combined.

The server speaks plain HTTP and is meant to sit behind a TLS-terminating
reverse proxy. `X-Forwarded-For` is recorded as sent, not trusted.

### Webhook payload

The webhook receives a JSON object; any answer outside `2xx` is logged as a
failure. `token` is `null` for flags.

```json
{
  "text": "[markov-canary] leak: decoy .env in infra repo",
  "id": 12,
  "kind": "leak",
  "occurred_at": "2026-11-10T01:02:03Z",
  "provider": "anthropic",
  "token": { "id": 3, "provider": "anthropic", "label": "decoy .env in infra repo", "issued_at": "2026-11-01T09:00:00Z" },
  "key_prefix": "sk-ant-api03-zHM",
  "key_sha256": "3f79…",
  "remote_addr": "203.0.113.7:51234",
  "forwarded_for": "",
  "user_agent": "python-requests/2.32",
  "method": "POST",
  "path": "/v1/messages",
  "body": "{\"model\":\"…\"}"
}
```

## Docker

Images for `linux/amd64` and `linux/arm64` are published to GitHub Packages
on every push to `main` (tagged `main`) and every `v*` tag (tagged with the
version and `latest`).

```bash
docker run -d --name markov-canary -p 8080:8080 -v markov-canary:/data -e MARKOV_CANARY_WEBHOOK_URL=https://example.com/hook ghcr.io/itisrazza/markov-canary:main
```

```bash
docker exec markov-canary markov-canary issue -provider openai -label "decoy .env in infra repo"
```

The database lives in the `/data` volume, and the container runs as a
non-root user.

## Licence

[MIT](LICENSE)
