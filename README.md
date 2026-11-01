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
tokio-specific ones. It builds against OpenSSL 1.1.0 or newer and LibreSSL 3.5
or newer.

## Buffered writes

OpenSSL requires a write that the transport refused to be retried with the same
bytes, which a caller that drops a pending write cannot do. So `SslStream` never
lets the transport refuse OpenSSL: what it does not take right away is buffered,
and sent before anything else.

As with a `BufWriter`, a write completes once OpenSSL has encrypted its bytes. A
write that finds output left over, or a transport flush that OpenSSL asked for
still pending, waits for it without writing anything, so it can be dropped, or
polled again with other bytes, at any time. Each write hands OpenSSL at most
16 KiB, which bounds what it can leave over. Reads, peeks and handshakes that go
to the transport send that output too, and flush the transport before they wait
for the peer. They do not wait for the output while at most 64 KiB of it is
left, so a peer that stops reading until it is read from cannot deadlock the
stream. Flush to know that everything was sent, and close the stream rather than
drop it.

## Errors

A transport error while sending earlier output is returned by the write, flush
or close that sends it, or by a read, peek or handshake that would otherwise
wait for the peer. It is not remembered: the output stays buffered, and a later
call that sends again reports the error only if it recurs, so a transient error
loses nothing.

Reads and writes return transport errors as they were and keep them from
OpenSSL, so a transient one leaves the session usable. Peeks, handshake calls
and `read_early_data` can only return them through OpenSSL, inside an
`ssl::Error`: OpenSSL 4 then fails the session unless the error is `WouldBlock`
or `NotConnected`, and LibreSSL returns an error of its own instead.
`write_early_data` never returns them.

## Upgrading from 0.2.10

- A write can complete before the transport took its bytes, and a handshake call
  before its last flight left: flush what you depend on, and close the stream
  rather than drop it or close its transport directly, or the buffered output is
  lost.
- A transport write error comes back from a later call that sends, if it recurs,
  not from the write whose bytes it concerns.
- One write hands OpenSSL at most 16 KiB, even without
  `SSL_MODE_ENABLE_PARTIAL_WRITE`.
- Reads flush the transport before they wait for the peer.
- A close without a TLS session to close (no handshake, a handshake in progress,
  a failed session) closes the transport, then returns an error, and so does
  every later close; 0.2.10 returned the error with the transport still open.
  After the peer's `close_notify`, failing to send ours is no longer an error.
- A panic in the transport poisons the stream: later calls that use the
  transport fail.
- OpenSSL 1.0 and LibreSSL older than 3.5 are no longer supported.
- The early-data methods are back, on OpenSSL 1.1.1 or newer only: 0.2.10 never
  compiled them. LibreSSL only has stubs for them, so they are not provided
  there.

## Example

```rust,no_run
use async_openssl::SslStream;
use openssl::ssl::{SslConnector, SslMethod};
use smol::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use std::pin::Pin;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    smol::block_on(async {
        let connector = SslConnector::builder(SslMethod::tls())?.build();
        let ssl = connector.configure()?.into_ssl("example.com")?;
        let stream = TcpStream::connect(("example.com", 443)).await?;
        let mut stream = SslStream::new(ssl, stream)?;
        Pin::new(&mut stream).connect().await?;

        stream
            .write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
            .await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        println!("{}", String::from_utf8_lossy(&response));
        stream.close().await?;
        Ok(())
    })
}
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
