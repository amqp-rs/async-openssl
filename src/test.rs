use crate::SslStream;
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::future;
use openssl::ssl::{Ssl, SslAcceptor, SslConnector, SslFiletype, SslMethod};
use smol::{
    Async,
    io::{AsyncReadExt, AsyncWriteExt},
};
use std::{
    io,
    net::{SocketAddr, TcpListener, TcpStream},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

fn acceptor() -> SslAcceptor {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor
        .set_private_key_file("tests/key.pem", SslFiletype::PEM)
        .unwrap();
    acceptor
        .set_certificate_chain_file("tests/cert.pem")
        .unwrap();
    acceptor.build()
}

fn client_ssl() -> Ssl {
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file("tests/cert.pem").unwrap();
    connector
        .build()
        .configure()
        .unwrap()
        .into_ssl("localhost")
        .unwrap()
}

#[cfg(target_os = "windows")] // certificate chain not configured in CI on Windows, noop
async fn test_google() -> io::Result<()> {
    Ok(())
}

#[cfg(not(target_os = "windows"))]
async fn test_google() -> io::Result<()> {
    use std::net::ToSocketAddrs;

    let addr = "google.com:443".to_socket_addrs().unwrap().next().unwrap();
    let stream = Async::<TcpStream>::connect(addr).await?;

    let ssl = SslConnector::builder(SslMethod::tls())
        .unwrap()
        .build()
        .configure()
        .unwrap()
        .into_ssl("google.com")
        .unwrap();
    let mut stream = SslStream::new(ssl, stream).unwrap();

    Pin::new(&mut stream).connect().await.unwrap();

    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();

    let mut buf = vec![];
    stream.read_to_end(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf);
    let response = response.trim_end();

    // any response code is fine
    assert!(response.starts_with("HTTP/1.0 "));
    assert!(response.ends_with("</html>") || response.ends_with("</HTML>"));

    Ok(())
}

#[test]
fn google() {
    smol::block_on(test_google()).unwrap();
}

async fn test_server() -> io::Result<()> {
    let listener = Async::<TcpListener>::bind(([127, 0, 0, 1], 0))?;
    let addr = listener.get_ref().local_addr().unwrap();

    let server = async move {
        let ssl = Ssl::new(acceptor().context()).unwrap();
        let stream = listener.accept().await.unwrap().0;
        let mut stream = SslStream::new(ssl, stream).unwrap();

        Pin::new(&mut stream).accept().await.unwrap();

        let mut buf = [0; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"asdf");

        stream.write_all(b"jkl;").await.unwrap();

        future::poll_fn(|ctx| Pin::new(&mut stream).poll_close(ctx))
            .await
            .unwrap()
    };

    let client = async {
        let stream = Async::<TcpStream>::connect(addr).await.unwrap();
        let mut stream = SslStream::new(client_ssl(), stream).unwrap();

        Pin::new(&mut stream).connect().await.unwrap();

        stream.write_all(b"asdf").await.unwrap();

        // Peeking leaves the data queued for the read below.
        let mut peeked = [0; 4];
        assert_eq!(Pin::new(&mut stream).peek(&mut peeked).await.unwrap(), 4);
        assert_eq!(&peeked, b"jkl;");

        let mut buf = vec![];
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"jkl;");
    };

    future::join(server, client).await;

    Ok(())
}

#[test]
fn server() {
    smol::block_on(test_server()).unwrap();
}

/// Runs `client` against a local TLS peer that completes the handshake and then goes quiet,
/// never sending `close_notify`.
///
/// Panics rather than hanging if `client` does not finish, so that a regression shows up as a
/// test failure instead of a stuck test run.
async fn with_quiet_peer<C, F>(client: C)
where
    C: FnOnce(SocketAddr) -> F,
    F: Future<Output = ()>,
{
    let listener = Async::<TcpListener>::bind(([127, 0, 0, 1], 0)).unwrap();
    let addr = listener.get_ref().local_addr().unwrap();

    let peer = async move {
        let ssl = Ssl::new(acceptor().context()).unwrap();
        let stream = listener.accept().await.unwrap().0;
        let mut stream = SslStream::new(ssl, stream).unwrap();
        Pin::new(&mut stream).accept().await.unwrap();
        std::future::pending::<()>().await
    };

    let timeout = async {
        smol::Timer::after(Duration::from_secs(10)).await;
        panic!("timed out waiting for the client to finish");
    };

    smol::future::or(client(addr), smol::future::or(peer, timeout)).await
}

#[test]
fn peek_with_an_empty_buffer_completes() {
    smol::block_on(with_quiet_peer(|addr| async move {
        let stream = Async::<TcpStream>::connect(addr).await.unwrap();
        let mut stream = SslStream::new(client_ssl(), stream).unwrap();
        Pin::new(&mut stream).connect().await.unwrap();

        // The peer sends nothing, but there is nothing to peek into an empty buffer either, so
        // this must resolve instead of waiting for readability that never comes.
        assert_eq!(Pin::new(&mut stream).peek(&mut []).await.unwrap(), 0);
    }));
}

/// Delegates to the inner stream, except that the first `poll_close` returns `Pending`.
struct PendingCloseOnce<S> {
    inner: S,
    pended: bool,
}

impl<S: AsyncRead + Unpin> AsyncRead for PendingCloseOnce<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(ctx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PendingCloseOnce<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(ctx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(ctx)
    }

    fn poll_close(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.pended {
            self.pended = true;
            ctx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_close(ctx)
    }
}

#[test]
fn close_completes_when_the_inner_close_pends() {
    smol::block_on(with_quiet_peer(|addr| async move {
        let stream = PendingCloseOnce {
            inner: Async::<TcpStream>::connect(addr).await.unwrap(),
            pended: false,
        };
        let mut stream = SslStream::new(client_ssl(), stream).unwrap();
        Pin::new(&mut stream).connect().await.unwrap();

        // The inner `poll_close` pends once, so `SslStream::poll_close` gets polled again after
        // it has already sent `close_notify`. It must not call `SSL_shutdown` a second time and
        // start waiting for the peer's `close_notify`, which this peer never sends.
        future::poll_fn(|ctx| Pin::new(&mut stream).poll_close(ctx))
            .await
            .unwrap();
    }));
}
