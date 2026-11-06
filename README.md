# tinylinkd

A small, self-hosted URL shortener. One static executable, one SQLite database,
no external services: an Instance is a single deployment serving a handful of
Users who create Links that redirect visitors to Destination URLs.

tinylinkd is designed for individuals and small teams who want their Link data
and Click analytics on their own infrastructure.

## Features

- Short links at `<base_url>/<slug>` with HTTP 302 redirects that preserve query
  parameters; links may be password-protected or set to expire.
- Click analytics: total, human, and bot counts, device breakdown, recent
  Clicks, and daily statistics in the Instance timezone.
- Users with an Admin role, one-time Invites, and one-time password-reset
  tokens. There is no public registration and no email is sent.
- A JSON API at `/_/api/v1` authenticated with Bearer API tokens, with an
  OpenAPI 3.1 document at `/_/api/openapi.json` and RFC 9457 Problem Details.
- A server-rendered admin UI at `/` for Links, Users, Invites, and Instance
  settings, built on the same application services as the API.
- SQLite in WAL mode with migrations embedded in the binary, and consistent
  online backups with `VACUUM INTO`.
- Static musl binaries for Linux amd64/arm64, a native macOS arm64 binary, and
  a multi-arch distroless Docker image.

## Quickstart

### Binary

Download the binary for your platform and the checksum file from
[GitHub Releases](https://github.com/DreamWalkerXZ/tinylinkd/releases):

```bash
VERSION=v0.1.0
curl -LO "https://github.com/DreamWalkerXZ/tinylinkd/releases/download/${VERSION}/tld-x86_64-unknown-linux-musl"
curl -LO "https://github.com/DreamWalkerXZ/tinylinkd/releases/download/${VERSION}/SHA256SUMS"
sha256sum -c SHA256SUMS --ignore-missing
chmod +x tld-x86_64-unknown-linux-musl
sudo mv tld-x86_64-unknown-linux-musl /usr/local/bin/tld
```

Start the server. `TLD_BASE_URL` is required and must be the public URL that
short links will use:

```bash
TLD_BASE_URL=https://links.example.com tld serve
```

Data is stored in `./data` by default. Create the first Admin either with the
CLI (an interactive password prompt) or with bootstrap environment variables on
the first start:

```bash
tld admin create --username admin
# or, for headless first start:
# TLD_BOOTSTRAP_ADMIN_USERNAME=admin TLD_BOOTSTRAP_ADMIN_PASSWORD='...' tld serve
```

Create an API token for automation. The plaintext is printed once:

```bash
tld token create --user admin --name automation
```

Then sign in to the admin UI at `https://links.example.com/`.

### Docker

The image runs as the distroless `nonroot` user (UID 65532) and stores data in
`/data`. Make the mounted directory writable by that UID:

```bash
mkdir -p data
sudo chown 65532:65532 data

docker run -d --name tinylinkd \
  --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  -v "$PWD/data:/data" \
  -e TLD_BASE_URL=https://links.example.com \
  ghcr.io/dreamwalkerxz/tinylinkd:latest
```

The image defaults to `TLD_LISTEN_ADDR=0.0.0.0:8080` and `TLD_DATA_DIR=/data`.
`TLD_BASE_URL` is always supplied by the operator. For a headless first start,
add `TLD_BOOTSTRAP_ADMIN_USERNAME`, `TLD_BOOTSTRAP_ADMIN_PASSWORD`, and
optionally `TLD_BOOTSTRAP_ADMIN_EMAIL`.

To create an Admin after the container is running, override the entrypoint:

```bash
docker run --rm -it --entrypoint /usr/local/bin/tld \
  -v "$PWD/data:/data" \
  ghcr.io/dreamwalkerxz/tinylinkd:latest \
  admin create --username admin
```

## Configuration

Deployment settings come from environment variables or command-line flags.
Flags override environment variables; there is no configuration file. Run
`tld serve --help` for the full list.

| Environment variable | Flag | Default | Description |
| --- | --- | --- | --- |
| `TLD_BASE_URL` | `--base-url` | required | Absolute `http` or `https` URL used to build short URLs and to decide whether cookies are `Secure`. |
| `TLD_LISTEN_ADDR` | `--listen-addr` | `127.0.0.1:8080` (`0.0.0.0:8080` in Docker) | Socket address to listen on. |
| `TLD_DATA_DIR` | `--data-dir` | `./data` (`/data` in Docker) | Directory holding `tinylinkd.db` and its WAL/SHM files. |
| `TLD_LOG_FORMAT` | `--log-format` | `text` | `text` or `json`. Logs always go to stderr. |
| `TLD_TRUST_PROXY` | `--trust-proxy` | `false` | Trust the first address in `X-Forwarded-For` as the client IP. |
| `TLD_BOOTSTRAP_ADMIN_USERNAME` | — | unset | First-Admin bootstrap username. |
| `TLD_BOOTSTRAP_ADMIN_PASSWORD` | — | unset | First-Admin bootstrap password. |
| `TLD_BOOTSTRAP_ADMIN_EMAIL` | — | unset | Optional first-Admin email. |

Bootstrap credentials require both the username and password. They are used
only while no Admin exists and are ignored afterwards, so remove them once the
Instance has been bootstrapped.

### Instance settings

These are stored in the database and editable by an Admin in the UI or through
the settings API:

| Setting | Default | Description |
| --- | --- | --- |
| `instance_name` | `tinylinkd` | Display name of the Instance. |
| `timezone` | `UTC` | IANA timezone used for display and daily statistics buckets. Storage is always UTC. |
| `click_retention_days` | `90` | Number of days to keep Clicks; older rows are deleted daily. |
| `password_unlock_ttl_seconds` | `3600` | How long a correct Link password keeps a visitor unlocked. |

IP addresses are stored raw with no hashing or truncation mode. See
[SECURITY.md](SECURITY.md).

## Reverse proxy and TLS

tinylinkd does not terminate TLS itself. Put it behind a reverse proxy, set
`TLD_BASE_URL` to the public HTTPS URL, and set `TLD_TRUST_PROXY=true` so Click
records and rate limits use the real client IP. Only enable proxy trust when
the proxy overwrites `X-Forwarded-For`; otherwise clients can spoof it.

Caddy:

```caddyfile
links.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Nginx:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name links.example.com;

    ssl_certificate     /etc/letsencrypt/live/links.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/links.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Apply HSTS and any other TLS policy at the proxy. HTML responses already carry
a restrictive Content-Security-Policy, `X-Content-Type-Options: nosniff`, and
`Referrer-Policy: no-referrer`.

## Backup

Create an online, consistent snapshot of the SQLite database with
`VACUUM INTO`. The server may keep running:

```bash
tld backup --output "/backups/tinylinkd-$(date +%Y%m%dT%H%M%S).db"
```

`backup` uses `TLD_DATA_DIR` like the other data commands, does not require
`TLD_BASE_URL`, and refuses to overwrite an existing file. In Docker, override
the image entrypoint:

```bash
docker run --rm --entrypoint /usr/local/bin/tld \
  -v "$PWD/data:/data" -v "$PWD/backups:/backups" \
  ghcr.io/dreamwalkerxz/tinylinkd:latest \
  backup --output "/backups/tinylinkd-$(date +%Y%m%dT%H%M%S).db"
```

To restore, stop the service, replace `<data_dir>/tinylinkd.db` with the backup,
remove any stale `tinylinkd.db-wal` and `tinylinkd.db-shm` files, and start the
service again.

A backup contains all User data, password hashes, hashed API/invite/reset/session
tokens, raw Click IP addresses, and the HMAC signing key used for password-unlock
cookies. Treat backups as sensitive data.

## Migrations and upgrades

Schema migrations live in `migrations/` and are embedded in the binary. They
run automatically at startup and stop startup if one fails. To apply them
explicitly (for example, in an init container or during a maintenance window):

```bash
tld migrate
```

To upgrade, take a backup, replace the binary or Docker image, and restart.
`serve` and `migrate` use the same `TLD_DATA_DIR`.

## CLI

```text
tld serve                     Run the HTTP server.
tld migrate                   Apply embedded migrations and exit.
tld backup --output <path>    Create a consistent SQLite snapshot and exit.
tld admin create              Create the first Admin (interactive password).
tld token create --user <u>   Create an API token and print it once.
```

All commands accept `--data-dir` (or `TLD_DATA_DIR`) and `--log-format` (or
`TLD_LOG_FORMAT`).

## API

- Base path: `/_/api/v1`; authenticate with `Authorization: Bearer <token>`.
- OpenAPI 3.1 document: `GET /_/api/openapi.json`.
- Health check: `GET /_/health` returns `{"status":"ok","database":"ok","version":"..."}`
  or `503` when the database is unavailable.
- Errors use RFC 9457 Problem Details with a machine-readable `code`.
- Lists use `limit` and `offset` and return `{items, total, limit, offset}`.
- The admin UI is served at `/`; there is no public landing page.

## Development

Requirements: Rust 1.85 or newer (edition 2024). Zig plus `cargo-zigbuild` is
only needed for Linux musl cross-builds; Docker is needed for image builds.

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

Run a local server:

```bash
TLD_BASE_URL=http://127.0.0.1:8080 cargo run -- serve
```

Tests use real temporary SQLite databases. Application behavior is tested at
the HTTP seam (`tests/common/mod.rs`) and CLI behavior at the CLI seam
(`tests/cli.rs`). OpenAPI output is snapshot-tested; update the snapshot with:

```bash
INSTA_UPDATE=always cargo test --test openapi
```

The Dockerfile expects the static binaries at `dist/amd64/tld` and
`dist/arm64/tld`, as produced by CI with `cargo zigbuild`. To build a local
image for your own architecture, cross-compile the matching musl target first:

```bash
cargo zigbuild --release --target x86_64-unknown-linux-musl
mkdir -p dist/amd64
cp target/x86_64-unknown-linux-musl/release/tld dist/amd64/tld
docker buildx build --platform linux/amd64 --load -t tinylinkd .
```

Use `aarch64-unknown-linux-musl`, `dist/arm64`, and `linux/arm64` on arm64
hosts.

## License

Licensed under either of

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option. Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in this project shall be dual-licensed
as above, without any additional terms or conditions.
