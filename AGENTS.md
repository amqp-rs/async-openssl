# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Check (every target, as CI does)
cargo check --workspace --all-targets --all-features

# Run tests, including the README example as a doctest (compiled, not run)
cargo test

# Run a single test
cargo test <test_name>

# Lint (CI denies clippy warnings)
cargo clippy --all-features --all-targets -- -D warnings

# Format
cargo fmt

# Check formatting
cargo fmt --all -- --check

# Check docs (warnings as errors)
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items --all-features
```

CI denies warnings: builds and tests run with `RUSTFLAGS=-D warnings`, and the lint job runs clippy (on every target and feature set) and rustdoc with warnings denied.

The workflows in `.github/workflows/` delegate to the shared composite actions in [`amqp-rs/actions`](https://github.com/amqp-rs/actions) at `@main`. That reference is intentionally unpinned: `amqp-rs/actions` is our own repository and keeps action bumps in sync across all amqp-rs crates. The third-party actions it wraps use major tags and are bumped there by Dependabot, which is why this repository's Dependabot config covers `cargo` only; the exceptions are `dtolnay/rust-toolchain`, referenced by branch as upstream recommends, and the tools pinned through action inputs (`actionlint`, `cargo-hack`), bumped by hand there. Do not pin actions to a SHA or tag, and do not report unpinned actions as review or audit findings.

The build workflow has a 30-minute job timeout, unlike the other amqp-rs crates: a test stuck inside one poll is caught by the tests' own `join`, but anything else that hangs would otherwise run for GitHub's six hours.

Minimum supported Rust version: **1.85.0** (edition 2024). Supported TLS libraries: OpenSSL 1.1.0 or newer and LibreSSL 3.5 or newer, as the openssl-sys floor allows; the early-data methods need OpenSSL 1.1.1 or newer.

## Architecture

This is a small, focused crate: a single public type `SslStream<S>` wrapping `openssl::ssl::SslStream` to implement `futures_io::AsyncRead` and `AsyncWrite` instead of std's blocking traits. The entire implementation lives in `src/lib.rs`.

**The bridging pattern:** OpenSSL's synchronous I/O model is bridged to async by an internal `StreamWrapper<S>` type that implements std `Read`/`Write` by calling `poll_read`/`poll_write` on the inner async stream. When the async stream returns `Poll::Pending`, `StreamWrapper` returns `WouldBlock`, and the two `cvt`/`cvt_ossl` helpers convert back from `WouldBlock` / `WANT_READ` / `WANT_WRITE` to `Poll::Pending`. The current waker is stored on `StreamWrapper` and updated each time `with_context` is called.

**Feature gate:** `build.rs` detects the OpenSSL version via `DEP_OPENSSL_VERSION_NUMBER` and sets the `ossl111` cfg flag for OpenSSL ≥ 1.1.1. `openssl-sys` must remain a direct target dependency so Cargo passes that metadata to the build script. Methods guarded by `#[cfg(ossl111)]` expose TLS 1.3 early-data support; LibreSSL only has stubs for early data, so they are not built there.

**Tests** (`src/test.rs`) use `smol` as the async runtime. The TLS tests use local servers with the self-signed cert/key in `tests/`, over sockets without Nagle's algorithm; they do not require an outbound connection. Each TLS peer, and each client, runs on its own thread and executor (`Peer::run`), so the peer's I/O cannot re-poll the client and mask a lost wakeup. Both sides run under `deadline`, which polls its timer first, so a hang fails the test instead of passing late, and `join` fails a thread that never returns from a poll. `Faulty` wraps each transport to inject `Faults`, such as a pending close. The acceptor negotiates TLS 1.3 unless a test asks for TLS 1.2, and sends no session tickets unless the client reads them: unread tickets make the client's close reset the connection. A version check catches an `ossl111` cfg that does not match the linked library.
