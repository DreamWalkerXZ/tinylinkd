# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities privately through GitHub's private
vulnerability reporting:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**.
3. Include the affected version, a description of the issue, reproduction
   steps, and the impact you expect.

Do not open a public issue for a suspected vulnerability. Maintainers will
acknowledge the report, investigate, and coordinate a fix and disclosure with
you. This is a volunteer project, so response times are best effort; there is no
bug bounty.

## Supported versions

tinylinkd is pre-1.0. Security fixes are made on the latest release in the
`0.1.x` line. Older releases, unreleased commits, and self-modified builds are
not supported. Run the latest published binary or container image.

## Deployment and data handling notes

- **TLS**: tinylinkd serves plain HTTP and expects TLS to be terminated by a
  reverse proxy. Always expose it over HTTPS in production.
- **Proxy trust**: `TLD_TRUST_PROXY=true` makes the first `X-Forwarded-For`
  address the client IP for Click records and rate limits. Enable it only when
  your proxy overwrites that header; otherwise clients can spoof IPs and evade
  rate limits.
- **Raw IP addresses**: Clicks store the visitor's raw IP address with no
  hashing or truncation. Retention defaults to 90 days and is configurable with
  the `click_retention_days` Instance setting. Consider your privacy
  obligations before deploying.
- **Credentials at rest**: passwords are hashed with Argon2id. API tokens,
  Invite tokens, password-reset tokens, and session tokens are stored only as
  SHA-256 hashes. The HMAC key used to sign password-unlock cookies lives in
  the `secrets` table.
- **Backups**: `tld backup` snapshots the whole database, including raw IPs,
  password hashes, token hashes, and the HMAC signing key. Protect backups as
  you would the live database.
- **Bootstrap credentials**: `TLD_BOOTSTRAP_ADMIN_USERNAME` and
  `TLD_BOOTSTRAP_ADMIN_PASSWORD` are used only while no Admin exists. Remove
  them from the environment after the first Admin is created.
- **Logging**: logs go to stderr and never include passwords, API tokens,
  Invite or reset tokens, token hashes, unlock cookies, or the HMAC signing
  key. Use `TLD_LOG_FORMAT=json` for structured collection.
- **Container**: the official image is distroless and runs as the non-root
  `nonroot` user (UID 65532). Mount `/data` with ownership that lets that UID
  write.
- **Rate limits**: login, password unlock, Link creation, and API requests are
  rate-limited in process. The buckets are per-process and reset on restart.
