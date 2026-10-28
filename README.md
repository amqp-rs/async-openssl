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
