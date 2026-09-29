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

Minimum supported Rust version: **1.85.0** (edition 2024).

## Architecture

This is a small, focused crate: a single public type `SslStream<S>` wrapping `openssl::ssl::SslStream` to implement `futures_io::AsyncRead` and `AsyncWrite` instead of std's blocking traits. The entire implementation lives in `src/lib.rs`.

**The bridging pattern:** OpenSSL's synchronous I/O model is bridged to async by an internal `StreamWrapper<S>` type that implements std `Read`/`Write` by polling the inner async stream. When it returns `Poll::Pending`, `StreamWrapper` returns `WouldBlock`; the `cvt`/`cvt_ossl` helpers turn that back into `Poll::Pending` and propagate other I/O errors. `with_context` updates the waker stored on `StreamWrapper` before each OpenSSL call.

**Pending writes:** Normal and early-data writes share a `WriteState` lifecycle for staging, retrying, waking waiters, and completion receipts. `WriteKind` selects the OpenSSL call and its zero-length behavior. A write finishes any pending write of the other kind first, except that an empty normal write returns immediately. Each state stages at most one 16 KiB record in a reusable buffer; OpenSSL retries use the unchanged bytes and address. A cancelled write retains only that chunk, and the next TLS operation retries it before doing its own work. A positive short retry reports only the accepted bytes. Completion receipts let original writers observe success if another operation finishes their write; pending retries wake both writer and interleaved reader when they have different tasks.

**Write identity:** `AsyncWrite::poll_write` has no operation identity, so a caller must flush after cancelling a write before submitting the same buffer as a new trait write. `SslStream::write_cancellable` and the async `write_early_data` wrapper assign per-call IDs so a later call with the same buffer is distinct.

**Feature gate:** `build.rs` detects the OpenSSL version via `DEP_OPENSSL_VERSION_NUMBER` and sets the `ossl111` cfg flag for OpenSSL ≥ 1.1.1. `openssl-sys` must remain a direct target dependency so Cargo passes that metadata to the build script. Methods guarded by `#[cfg(ossl111)]` expose TLS 1.3 early-data support.

**Tests** (`src/test.rs`) use `smol` as the async runtime. The TLS tests use local servers with the self-signed cert/key in `tests/`; they do not require an outbound connection. The pending-write tests cover cancellation during a handshake, retry and completion receipts across read and peek, bounded staging, large writes, and both flushing and per-call IDs before reuse of the same buffer. A version check catches a missing `ossl111` cfg on OpenSSL 1.1.1 or newer.
