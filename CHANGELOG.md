# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-06

### Added

- Short links with exact-Slug redirects, query-parameter forwarding, optional
  password protection, and optional expiry.
- Click recording with raw IP, User-Agent, referer, device classification, and
  best-effort analytics that never block a redirect.
- Statistics for total, human, and bot Clicks, device breakdown, and daily
  buckets in the Instance timezone.
- Users with Admin and User roles, one-time Invites, one-time password-reset
  tokens, and API tokens shown once at creation.
- JSON API at `/_/api/v1` with RFC 9457 Problem Details, pagination, rate
  limits, and an OpenAPI 3.1 document at `/_/api/openapi.json`.
- Server-rendered admin UI with sessions, CSRF protection, Link management,
  User and Invite administration, and Instance settings.
- CLI commands: `tld serve`, `tld migrate`, `tld admin create`,
  `tld token create`, and `tld backup --output <path>`.
- Embedded SQLite migrations in WAL mode, graceful shutdown on SIGINT and
  SIGTERM, and daily Click-retention cleanup.
- Static musl binaries for Linux amd64 and arm64, a native macOS arm64 binary,
  and a multi-arch distroless Docker image running as a non-root user.
- Release automation that publishes binaries with SHA-256 checksums to GitHub
  Releases and multi-arch images to GHCR on `v*` tags.
- Operator documentation, including configuration, reverse-proxy TLS examples,
  backups, and migrations.

[Unreleased]: https://github.com/DreamWalkerXZ/tinylinkd/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/DreamWalkerXZ/tinylinkd/releases/tag/v0.1.0
