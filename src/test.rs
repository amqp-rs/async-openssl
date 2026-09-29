use crate::{SslStream, WRITE_CHUNK_SIZE};
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
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
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

#[test]
fn early_data_cfg_matches_linked_openssl() {
    let has_early_data = openssl::version::version().starts_with("OpenSSL")
        && openssl::version::number() >= 0x1010_1000;
    assert!(!has_early_data || cfg!(ossl111));
}

struct PendingWriteOnce<S> {
    inner: S,
    arm: bool,
    fail_not_connected: bool,
}

impl<S: AsyncRead + Unpin> AsyncRead for PendingWriteOnce<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(ctx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PendingWriteOnce<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.fail_not_connected {
            self.fail_not_connected = false;
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        }
        if self.arm {
            self.arm = false;
            ctx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_write(ctx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(ctx)
    }

    fn poll_close(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(ctx)
    }
}

struct CountingWake(AtomicUsize);

impl Wake for CountingWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn cancelled_write_is_retried_before_new_data() {
    smol::block_on(async {
        let listener = Async::<TcpListener>::bind(([127, 0, 0, 1], 0)).unwrap();
        let addr = listener.get_ref().local_addr().unwrap();

        let server = async move {
            let ssl = Ssl::new(acceptor().context()).unwrap();
            let stream = listener.accept().await.unwrap().0;
            let mut stream = SslStream::new(ssl, stream).unwrap();
            Pin::new(&mut stream).accept().await.unwrap();

            let mut buf = [0; 15];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"oldnewoldoldend");
            stream.read_to_end(&mut Vec::new()).await.unwrap();
        };

        let client = async {
            let stream = PendingWriteOnce {
                inner: Async::<TcpStream>::connect(addr).await.unwrap(),
                arm: false,
                fail_not_connected: false,
            };
            let mut stream = SslStream::new(client_ssl(), stream).unwrap();
            Pin::new(&mut stream).connect().await.unwrap();
            stream.get_mut().arm = true;

            future::poll_fn(|ctx| {
                assert!(Pin::new(&mut stream).poll_write(ctx, b"old").is_pending());
                Poll::Ready(())
            })
            .await;

            // Empty reads and writes perform no TLS I/O, so they must not wait for the
            // queued OpenSSL retry.
            stream.get_mut().arm = true;
            let mut context = Context::from_waker(Waker::noop());
            assert!(matches!(
                Pin::new(&mut stream).poll_read(&mut context, &mut []),
                Poll::Ready(Ok(0))
            ));
            assert!(matches!(
                Pin::new(&mut stream).poll_write(&mut context, &[]),
                Poll::Ready(Ok(0))
            ));
            assert!(stream.get_ref().arm);

            stream.write_all(b"new").await.unwrap();

            // A separate write with identical contents must still send another copy.
            let first = Box::new(*b"old");
            let second = Box::new(*b"old");
            assert_ne!(first.as_ptr(), second.as_ptr());
            stream.get_mut().arm = true;
            future::poll_fn(|ctx| {
                assert!(
                    Pin::new(&mut stream)
                        .poll_write(ctx, &first[..])
                        .is_pending()
                );
                Poll::Ready(())
            })
            .await;
            stream.write_all(&second[..]).await.unwrap();

            stream.get_mut().arm = true;
            future::poll_fn(|ctx| {
                assert!(Pin::new(&mut stream).poll_write(ctx, b"end").is_pending());
                Poll::Ready(())
            })
            .await;
            future::poll_fn(|ctx| Pin::new(&mut stream).poll_close(ctx))
                .await
                .unwrap();
        };

        future::join(server, client).await;
    });
}

#[test]
fn pending_write_completion_survives_read_and_peek() {
    smol::block_on(async {
        let listener = Async::<TcpListener>::bind(([127, 0, 0, 1], 0)).unwrap();
        let addr = listener.get_ref().local_addr().unwrap();

        let server = async move {
            let ssl = Ssl::new(acceptor().context()).unwrap();
            let stream = listener.accept().await.unwrap().0;
            let mut stream = SslStream::new(ssl, stream).unwrap();
            Pin::new(&mut stream).accept().await.unwrap();

            let mut buf = [0; 3];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"old");
            stream.write_all(b"one").await.unwrap();
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"two");
            stream.write_all(b"two").await.unwrap();
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"end");
            stream.write_all(b"fin").await.unwrap();
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"abc");
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"def");
            let mut extra = Vec::new();
            stream.read_to_end(&mut extra).await.unwrap();
            assert!(extra.is_empty(), "a completed write was sent twice");
        };

        let client = async {
            let stream = PendingWriteOnce {
                inner: Async::<TcpStream>::connect(addr).await.unwrap(),
                arm: false,
                fail_not_connected: false,
            };
            let mut stream = SslStream::new(client_ssl(), stream).unwrap();
            Pin::new(&mut stream).connect().await.unwrap();
            let wake_count = Arc::new(CountingWake(AtomicUsize::new(0)));
            let writer_waker = Waker::from(wake_count.clone());
            let mut writer_context = Context::from_waker(&writer_waker);

            stream.get_mut().arm = true;
            assert!(
                Pin::new(&mut stream)
                    .poll_write(&mut writer_context, b"old")
                    .is_pending()
            );
            wake_count.0.store(0, Ordering::SeqCst);
            let mut buf = [0; 3];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"one");
            assert!(wake_count.0.load(Ordering::SeqCst) > 0);
            // A later poll of the original write must observe its completed byte count.
            assert_eq!(
                future::poll_fn(|ctx| Pin::new(&mut stream).poll_write(ctx, b"old"))
                    .await
                    .unwrap(),
                3
            );

            stream.get_mut().arm = true;
            assert!(
                Pin::new(&mut stream)
                    .poll_write(&mut writer_context, b"two")
                    .is_pending()
            );
            wake_count.0.store(0, Ordering::SeqCst);
            assert_eq!(Pin::new(&mut stream).peek(&mut buf).await.unwrap(), 3);
            assert_eq!(&buf, b"two");
            assert!(wake_count.0.load(Ordering::SeqCst) > 0);
            assert_eq!(
                future::poll_fn(|ctx| Pin::new(&mut stream).poll_write(ctx, b"two"))
                    .await
                    .unwrap(),
                3
            );
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"two");

            // If the writer completes a retry that left the reader waiting, the reader must
            // also be woken so it can continue into the TLS read.
            let reader_wake_count = Arc::new(CountingWake(AtomicUsize::new(0)));
            let reader_waker = Waker::from(reader_wake_count.clone());
            let mut reader_context = Context::from_waker(&reader_waker);
            stream.get_mut().arm = true;
            assert!(
                Pin::new(&mut stream)
                    .poll_write(&mut writer_context, b"end")
                    .is_pending()
            );
            wake_count.0.store(0, Ordering::SeqCst);
            stream.get_mut().arm = true;
            assert!(
                Pin::new(&mut stream)
                    .poll_read(&mut reader_context, &mut buf)
                    .is_pending()
            );
            assert!(wake_count.0.load(Ordering::SeqCst) > 0);
            reader_wake_count.0.store(0, Ordering::SeqCst);
            assert!(matches!(
                Pin::new(&mut stream).poll_write(&mut writer_context, b"end"),
                Poll::Ready(Ok(3))
            ));
            assert!(reader_wake_count.0.load(Ordering::SeqCst) > 0);
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"fin");

            // A different write must not replace the original writer's waker while it
            // waits for its queued retry.
            stream.get_mut().arm = true;
            assert!(
                Pin::new(&mut stream)
                    .poll_write(&mut writer_context, b"abc")
                    .is_pending()
            );
            wake_count.0.store(0, Ordering::SeqCst);
            stream.get_mut().arm = true;
            assert!(
                Pin::new(&mut stream)
                    .poll_write(&mut reader_context, b"def")
                    .is_pending()
            );
            assert!(wake_count.0.load(Ordering::SeqCst) > 0);
            reader_wake_count.0.store(0, Ordering::SeqCst);
            assert!(matches!(
                Pin::new(&mut stream).poll_write(&mut writer_context, b"abc"),
                Poll::Ready(Ok(3))
            ));
            assert!(reader_wake_count.0.load(Ordering::SeqCst) > 0);
            assert!(matches!(
                Pin::new(&mut stream).poll_write(&mut reader_context, b"def"),
                Poll::Ready(Ok(3))
            ));
            stream.close().await.unwrap();
        };

        let timeout = async {
            smol::Timer::after(Duration::from_secs(10)).await;
            panic!("timed out waiting for a cancelled write to finish before a read");
        };
        smol::future::or(future::join(server, client), timeout).await;
    });
}

#[test]
fn cancelled_large_write_finishes_only_its_staged_chunk() {
    smol::block_on(async {
        let listener = Async::<TcpListener>::bind(([127, 0, 0, 1], 0)).unwrap();
        let addr = listener.get_ref().local_addr().unwrap();

        let server = async move {
            let ssl = Ssl::new(acceptor().context()).unwrap();
            let stream = listener.accept().await.unwrap().0;
            let mut stream = SslStream::new(ssl, stream).unwrap();
            Pin::new(&mut stream).accept().await.unwrap();

            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received.len(), WRITE_CHUNK_SIZE);
            assert!(received.iter().all(|&byte| byte == b'x'));
        };

        let client = async {
            let mut ssl = client_ssl();
            ssl.set_connect_state();
            let stream = Async::<TcpStream>::connect(addr).await.unwrap();
            let mut stream = SslStream::new(ssl, stream).unwrap();
            let mut bytes = vec![b'x'; 2 * WRITE_CHUNK_SIZE];
            bytes[WRITE_CHUNK_SIZE..].fill(b'y');

            // The first write pends in the handshake. Only the staged TLS record belongs to
            // that cancelled poll, so flush must not send the rest of the caller's old buffer.
            future::poll_fn(|ctx| {
                assert!(Pin::new(&mut stream).poll_write(ctx, &bytes).is_pending());
                Poll::Ready(())
            })
            .await;
            drop(bytes);

            stream.flush().await.unwrap();
            stream.close().await.unwrap();
        };

        future::join(server, client).await;
    });
}

#[test]
fn large_write_all_reuses_a_bounded_staging_buffer() {
    smol::block_on(async {
        let listener = Async::<TcpListener>::bind(([127, 0, 0, 1], 0)).unwrap();
        let addr = listener.get_ref().local_addr().unwrap();
        let data: Vec<u8> = (0..(1024 * 1024 + 123)).map(|i| (i % 251) as u8).collect();

        let server_data = data.clone();
        let server = async move {
            let ssl = Ssl::new(acceptor().context()).unwrap();
            let stream = listener.accept().await.unwrap().0;
            let mut stream = SslStream::new(ssl, stream).unwrap();
            Pin::new(&mut stream).accept().await.unwrap();

            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received.len(), server_data.len() + 4);
            assert!(
                received[..server_data.len()] == server_data[..],
                "large payload differs"
            );
            assert_eq!(&received[server_data.len()..], b"tail");
        };

        let client = async {
            let stream = PendingWriteOnce {
                inner: Async::<TcpStream>::connect(addr).await.unwrap(),
                arm: false,
                fail_not_connected: false,
            };
            let mut stream = SslStream::new(client_ssl(), stream).unwrap();
            Pin::new(&mut stream).connect().await.unwrap();
            stream.get_mut().arm = true;

            let first = stream.write(&data).await.unwrap();
            assert!(first > 0 && first <= WRITE_CHUNK_SIZE);
            stream.write_all(&data[first..]).await.unwrap();
            let staging_ptr = stream.write.buffer.as_ptr();
            assert!(stream.write.buffer.len() <= WRITE_CHUNK_SIZE);
            assert!(stream.write.buffer.capacity() >= WRITE_CHUNK_SIZE);

            stream.write_all(b"tail").await.unwrap();
            assert_eq!(stream.write.buffer.as_ptr(), staging_ptr);
            stream.close().await.unwrap();
        };

        future::join(server, client).await;
    });
}

#[test]
fn flush_separates_cancelled_and_new_writes_from_the_same_buffer() {
    smol::block_on(async {
        let listener = Async::<TcpListener>::bind(([127, 0, 0, 1], 0)).unwrap();
        let addr = listener.get_ref().local_addr().unwrap();

        let server = async move {
            let ssl = Ssl::new(acceptor().context()).unwrap();
            let stream = listener.accept().await.unwrap().0;
            let mut stream = SslStream::new(ssl, stream).unwrap();
            Pin::new(&mut stream).accept().await.unwrap();

            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, b"samesame");
        };

        let client = async {
            let stream = PendingWriteOnce {
                inner: Async::<TcpStream>::connect(addr).await.unwrap(),
                arm: false,
                fail_not_connected: false,
            };
            let mut stream = SslStream::new(client_ssl(), stream).unwrap();
            Pin::new(&mut stream).connect().await.unwrap();
            stream.get_mut().arm = true;
            let bytes = b"same";

            future::poll_fn(|ctx| {
                assert!(Pin::new(&mut stream).poll_write(ctx, bytes).is_pending());
                Poll::Ready(())
            })
            .await;
            stream.flush().await.unwrap();
            stream.write_all(bytes).await.unwrap();
            stream.close().await.unwrap();
        };

        future::join(server, client).await;
    });
}

#[test]
fn cancellable_writes_separate_reused_buffers() {
    smol::block_on(async {
        let listener = Async::<TcpListener>::bind(([127, 0, 0, 1], 0)).unwrap();
        let addr = listener.get_ref().local_addr().unwrap();

        let server = async move {
            let ssl = Ssl::new(acceptor().context()).unwrap();
            let stream = listener.accept().await.unwrap().0;
            let mut stream = SslStream::new(ssl, stream).unwrap();
            Pin::new(&mut stream).accept().await.unwrap();

            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, b"samesame");
        };

        let client = async {
            let stream = PendingWriteOnce {
                inner: Async::<TcpStream>::connect(addr).await.unwrap(),
                arm: false,
                fail_not_connected: false,
            };
            let mut stream = SslStream::new(client_ssl(), stream).unwrap();
            Pin::new(&mut stream).connect().await.unwrap();
            stream.get_mut().arm = true;
            let bytes = b"same";

            let mut first = Box::pin(Pin::new(&mut stream).write_cancellable(bytes));
            future::poll_fn(|ctx| {
                assert!(first.as_mut().poll(ctx).is_pending());
                Poll::Ready(())
            })
            .await;
            drop(first);

            assert_eq!(
                Pin::new(&mut stream)
                    .write_cancellable(bytes)
                    .await
                    .unwrap(),
                bytes.len()
            );
            stream.close().await.unwrap();
        };

        future::join(server, client).await;
    });
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
fn not_connected_write_error_is_not_left_pending() {
    smol::block_on(with_quiet_peer(|addr| async move {
        let stream = PendingWriteOnce {
            inner: Async::<TcpStream>::connect(addr).await.unwrap(),
            arm: false,
            fail_not_connected: false,
        };
        let mut stream = SslStream::new(client_ssl(), stream).unwrap();
        Pin::new(&mut stream).connect().await.unwrap();

        stream.get_mut().fail_not_connected = true;
        let mut context = Context::from_waker(Waker::noop());
        match Pin::new(&mut stream).poll_write(&mut context, b"data") {
            Poll::Ready(Err(error)) => assert_eq!(error.kind(), io::ErrorKind::NotConnected),
            other => panic!("expected NotConnected, got {other:?}"),
        }
    }));
}

#[cfg(ossl111)]
#[test]
fn empty_early_data_write_after_handshake_reports_openssl_error() {
    smol::block_on(with_quiet_peer(|addr| async move {
        let stream = Async::<TcpStream>::connect(addr).await.unwrap();
        let mut stream = SslStream::new(client_ssl(), stream).unwrap();
        Pin::new(&mut stream).connect().await.unwrap();

        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            Pin::new(&mut stream).poll_write_early_data(&mut context, &[]),
            Poll::Ready(Err(_))
        ));
    }));
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
