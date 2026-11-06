# Contributing to tinylinkd

Thanks for taking the time to contribute. This project is small on purpose:
please keep changes focused and keep the existing behavior and tests intact.

## Issues and design discussion

Issues and specifications live in the GitHub issue tracker
(`DreamWalkerXZ/tinylinkd`). Use the `gh` CLI or the web UI to search for an
existing issue before opening a new one.

- Small bug fixes and documentation improvements can go straight to a pull
  request.
- For larger changes, open an issue first so the behavior and scope can be
  agreed before implementation.
- Maintainer triage uses the labels `needs-triage`, `needs-info`,
  `ready-for-agent`, `ready-for-human`, and `wontfix`.
- Read `GLOSSARY.md` and the ADRs in `docs/adr/` before changing domain
  behavior. If a change contradicts an ADR, say so explicitly in the issue or
  pull request rather than silently overriding the decision.

## Build

Requirements: Rust 1.85 or newer (edition 2024).

```bash
cargo build
```

The debug profile compiles the password-hashing crates optimized so tests are
not dominated by Argon2. Linux musl cross-builds use Zig:

```bash
rustup target add x86_64-unknown-linux-musl
cargo install cargo-zigbuild
cargo zigbuild --release --target x86_64-unknown-linux-musl
```

## Test, format, and lint

Run all three before opening a pull request:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

- Application behavior is tested end to end through the axum router at the HTTP
  seam (`tests/common/mod.rs`), using real temporary SQLite databases. Do not
  mock the database.
- CLI behavior (`migrate`, `backup`, `admin create`, `token create`) is tested
  at the CLI seam in `tests/cli.rs`.
- The OpenAPI document is snapshot-tested. Update the snapshot deliberately
  with `INSTA_UPDATE=always cargo test --test openapi` and include the change
  in your pull request.

New behavior should come with a test that fails before the change and passes
after it. Keep tests on public behavior; do not test private functions or
implementation details.

## Pull requests

1. Fork the repository or create a branch in it.
2. Make a focused change with tests and, when behavior or operation changes,
   documentation updates.
3. Ensure the format, clippy, and test commands above pass.
4. Open a pull request describing the problem, the change, and how it was
   tested. Reference the issue it addresses.

CI runs the same checks plus the release build matrix. Pull requests must pass
CI before merge. Do not include secrets, credentials, or generated databases in
a pull request.

## Commit messages

Use an imperative subject line, for example `feat: add backup command` or
`fix: reject expired unlock cookies`. Keep unrelated changes in separate
commits when practical.

## License

tinylinkd is licensed under MIT OR Apache-2.0. By contributing, you agree that
your contribution is dual-licensed under those terms.
