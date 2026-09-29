<div align="center">

[![API Docs](https://docs.rs/async-openssl/badge.svg)](https://docs.rs/async-openssl)
[![Build status](https://github.com/amqp-rs/async-openssl/workflows/Build%20and%20test/badge.svg)](https://github.com/amqp-rs/async-openssl/actions)
[![Downloads](https://img.shields.io/crates/d/async-openssl.svg)](https://crates.io/crates/async-openssl)
[![Dependency Status](https://deps.rs/repo/github/amqp-rs/async-openssl/status.svg)](https://deps.rs/repo/github/amqp-rs/async-openssl)
[![LICENSE](https://img.shields.io/crates/l/async-openssl)](LICENSE-MIT)

**Async TLS streams backed by OpenSSL.**

</div>

Provides `SslStream`, an async wrapper around `openssl::ssl::SslStream` that
implements `futures_io::AsyncRead` and `futures_io::AsyncWrite` instead of the
blocking `std::io::Read` / `std::io::Write` traits, making it usable with any
runtime that builds on the `futures-io` ecosystem.

Forked from [tokio-openssl](https://github.com/tokio-rs/tokio-openssl) and
reworked to target the runtime-agnostic `futures-io` traits rather than the
tokio-specific ones.

## Pending writes

When OpenSSL pauses a write, `SslStream` retains the staged bytes and retries
them before the next TLS operation, including a read or peek. Use
`SslStream::write_cancellable` when you need a new write to remain distinct
after cancelling an earlier write with the **same buffer**. For writes through
`AsyncWrite`, flush before reusing that buffer as a separate operation: the
trait cannot distinguish that call from another poll of the cancelled write.
The same rule applies to `poll_write_early_data`; its async `write_early_data`
wrapper distinguishes separate calls.
If an interleaved read finishes a pending write, the original writer is woken
and receives its byte count when polled again.

Each write stages at most 16 KiB in a reusable buffer. Large `write_all` calls
advance one chunk at a time, so copying grows linearly with the input size.
An OpenSSL short write can cause the unsent part of a chunk to be staged again.
If a pending write completes with a positive short count, the original caller
receives that count and remains responsible for submitting the unsent suffix.
If a write is cancelled while pending, only its staged chunk is retained; the
rest of the original input has not been accepted.

## Example

```rust,no_run
use async_openssl::SslStream;
use openssl::ssl::{SslConnector, SslMethod};
use std::pin::Pin;

async fn connect(host: &str) -> Result<(), Box<dyn std::error::Error>> {
    use smol::net::TcpStream;

    let connector = SslConnector::builder(SslMethod::tls())?.build();
    let stream = TcpStream::connect((host, 443u16)).await?;
    let ssl = connector.configure()?.into_ssl(host)?;
    let mut stream = SslStream::new(ssl, stream)?;
    Pin::new(&mut stream).connect().await?;
    Ok(())
}
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
