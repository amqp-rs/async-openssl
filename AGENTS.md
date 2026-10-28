# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Check
cargo check --all --bins --examples --tests --all-features

# Run tests
cargo test

# Run a single test
cargo test <test_name>

# Lint
cargo clippy --all-features -- -W clippy::all

# Format
cargo fmt

# Check formatting
cargo fmt --all -- --check

# Check docs (warnings as errors)
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items --all-features
```

CI runs with `RUSTFLAGS=-D warnings`, so all warnings are treated as errors.

The workflows in `.github/workflows/` delegate to the shared composite actions in [`amqp-rs/actions`](https://github.com/amqp-rs/actions) at `@main`. That reference is intentionally unpinned: `amqp-rs/actions` is our own repository and keeps action bumps in sync across all amqp-rs crates. The third-party actions it wraps use major tags and are bumped there by Dependabot, which is why this repository's Dependabot config covers `cargo` only; the exceptions are `dtolnay/rust-toolchain`, referenced by branch as upstream recommends, and the tools pinned through action inputs (`actionlint`, `cargo-hack`), bumped by hand there. Do not pin actions to a SHA or tag, and do not report unpinned actions as review or audit findings.

Minimum supported Rust version: **1.85.0** (edition 2024).

## Architecture

This is a small, focused crate: a single public type `SslStream<S>` wrapping `openssl::ssl::SslStream` to implement `futures_io::AsyncRead` and `AsyncWrite` instead of std's blocking traits. The entire implementation lives in `src/lib.rs`.

**The bridging pattern:** OpenSSL's synchronous I/O model is bridged to async by an internal `StreamWrapper<S>` type that implements std `Read`/`Write` by calling `poll_read`/`poll_write` on the inner async stream. When the async stream returns `Poll::Pending`, `StreamWrapper` returns `WouldBlock`, and the two `cvt`/`cvt_ossl` helpers convert back from `WouldBlock` / `WANT_READ` / `WANT_WRITE` to `Poll::Pending`. The current waker is stored on `StreamWrapper` and updated each time `with_context` is called.

**Feature gate:** `build.rs` detects the OpenSSL version via `DEP_OPENSSL_VERSION_NUMBER` and sets the `ossl111` cfg flag for OpenSSL ≥ 1.1.1. Methods guarded by `#[cfg(ossl111)]` expose TLS 1.3 early-data support.

**Tests** (`src/test.rs`) use `smol` as the async runtime. The TLS tests use local servers with the self-signed cert/key in `tests/`; they do not require an outbound connection.
