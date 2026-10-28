use crate::SslStream;
use futures_io::{AsyncRead, AsyncWrite};
use openssl::ssl::{
    Ssl, SslAcceptor, SslAcceptorBuilder, SslConnector, SslConnectorBuilder, SslFiletype,
    SslMethod, SslVersion,
};
use smol::{
    Async, Timer, future,
    io::{AsyncReadExt, AsyncWriteExt},
};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    ops::{Deref, DerefMut},
    panic,
    pin::Pin,
    task::{Context, Poll},
    thread,
    time::{Duration, Instant},
};

const DEADLINE: Duration = Duration::from_secs(10);

/// Fails the test instead of hanging when `fut` does not finish in time.
///
/// `future::or` polls the timer first, so that its firing cannot rescue, with an extra poll, a
/// future that registered no waker. `join` catches a future that never returns from a poll.
async fn deadline<T>(what: &str, fut: impl Future<Output = T>) -> T {
    future::or(
        async {
            Timer::after(DEADLINE).await;
            panic!("timed out: {what}");
        },
        fut,
    )
    .await
}

/// Waits for `thread`, failing the test if it is still running well past `DEADLINE`: then it
/// spins inside one poll, which `deadline` cannot interrupt.
fn join(thread: thread::JoinHandle<()>, what: &str) {
    let limit = Instant::now() + DEADLINE + Duration::from_secs(5);
    while !thread.is_finished() {
        assert!(Instant::now() < limit, "{what} never returned from a poll");
        thread::sleep(Duration::from_millis(1));
    }
    if let Err(panic) = thread.join() {
        panic::resume_unwind(panic);
    }
}

#[derive(Clone, Copy, Debug)]
enum Tls {
    V1_2,
    V1_3,
}

/// A TLS 1.3 server sends session tickets after the handshake. Unless a test reads them, they
/// are still unread when the client closes its socket, which then resets the connection.
fn acceptor() -> SslAcceptor {
    acceptor_builder(Tls::V1_3, 0).build()
}

fn acceptor_builder(tls: Tls, tickets: usize) -> SslAcceptorBuilder {
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor
        .set_private_key_file("tests/key.pem", SslFiletype::PEM)
        .unwrap();
    acceptor
        .set_certificate_chain_file("tests/cert.pem")
        .unwrap();
    if let Tls::V1_2 = tls {
        acceptor
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .unwrap();
    }
    #[cfg(ossl111)]
    acceptor.set_num_tickets(tickets).unwrap();
    #[cfg(not(ossl111))]
    let _ = tickets;
    acceptor
}

/// A connector that trusts the test certificate.
fn connector() -> SslConnectorBuilder {
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file("tests/cert.pem").unwrap();
    connector
}

fn ssl_for(connector: &SslConnector) -> Ssl {
    connector
        .configure()
        .unwrap()
        .into_ssl("localhost")
        .unwrap()
}

fn client_ssl_with(configure: impl FnOnce(&mut SslConnectorBuilder)) -> Ssl {
    let mut connector = connector();
    configure(&mut connector);
    ssl_for(&connector.build())
}

fn client_ssl() -> Ssl {
    client_ssl_with(|_| {})
}

type Stream = SslStream<Faulty<Async<TcpStream>>>;

/// A socket that sends each record at once: Nagle's algorithm would hold small ones back.
fn socket(stream: Async<TcpStream>) -> Faulty<Async<TcpStream>> {
    stream.get_ref().set_nodelay(true).unwrap();
    Faulty::new(stream)
}

/// A TLS peer running on its own thread and executor, so that its I/O never re-polls the client
/// under test.
struct Peer {
    addr: SocketAddr,
    thread: thread::JoinHandle<()>,
}

impl Peer {
    fn spawn<F, Fut>(peer: F) -> Self
    where
        F: FnOnce(Stream) -> Fut + Send + 'static,
        Fut: Future<Output = ()>,
    {
        Self::spawn_with(acceptor(), peer)
    }

    fn spawn_with<F, Fut>(acceptor: SslAcceptor, peer: F) -> Self
    where
        F: FnOnce(Stream) -> Fut + Send + 'static,
        Fut: Future<Output = ()>,
    {
        Self::spawn_unaccepted(acceptor, |mut stream| async move {
            Pin::new(&mut stream).accept().await.unwrap();
            peer(stream).await;
        })
    }

    /// Like `spawn_with`, but leaves the TLS handshake to `peer`.
    fn spawn_unaccepted<F, Fut>(acceptor: SslAcceptor, peer: F) -> Self
    where
        F: FnOnce(Stream) -> Fut + Send + 'static,
        Fut: Future<Output = ()>,
    {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let thread = thread::spawn(move || {
            smol::block_on(deadline("TLS peer", async move {
                let listener = Async::new(listener).unwrap();
                let stream = socket(listener.accept().await.unwrap().0);
                let ssl = Ssl::new(acceptor.context()).unwrap();
                peer(SslStream::new(ssl, stream).unwrap()).await;
            }))
        });
        Self { addr, thread }
    }

    /// A peer that writes `greeting`, then reads until the client goes away, and never writes
    /// `close_notify`.
    fn greeting(greeting: &'static [u8]) -> Self {
        Self::spawn(move |mut stream| async move {
            stream.write_all(greeting).await.unwrap();
            // Returns, or fails, once the client goes away.
            let _ = stream.read_to_end(&mut Vec::new()).await;
        })
    }

    /// A peer that completes the handshake, then never writes, not even `close_notify`.
    fn quiet() -> Self {
        Self::greeting(b"")
    }

    /// Runs `client` to completion on its own thread against this peer, then waits for the peer.
    fn run<C, Fut>(self, client: C)
    where
        C: FnOnce(SocketAddr) -> Fut + Send + 'static,
        Fut: Future<Output = ()>,
    {
        let addr = self.addr;
        let client = thread::spawn(move || smol::block_on(deadline("client", client(addr))));
        join(client, "client");
        join(self.thread, "TLS peer");
    }
}

/// The faults that `Faulty` injects.
#[derive(Default)]
struct Faults {
    /// The next `poll_close` calls that return `Pending` (and wake the task) instead.
    pending_closes: usize,
}

/// Delegates to the inner stream, injecting the faults that are armed.
struct Faulty<S> {
    inner: S,
    faults: Faults,
}

impl<S> Faulty<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            faults: Faults::default(),
        }
    }
}

impl<S> Deref for Faulty<S> {
    type Target = Faults;

    fn deref(&self) -> &Faults {
        &self.faults
    }
}

impl<S> DerefMut for Faulty<S> {
    fn deref_mut(&mut self) -> &mut Faults {
        &mut self.faults
    }
}

/// Whether this call pends (and wakes the task) because `counter` is armed, which it counts down.
fn pend_once(counter: &mut usize, ctx: &Context<'_>) -> bool {
    let armed = *counter > 0;
    if armed {
        *counter -= 1;
        ctx.waker().wake_by_ref();
    }
    armed
}

impl<S: AsyncRead + Unpin> AsyncRead for Faulty<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(ctx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Faulty<S> {
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
        if pend_once(&mut self.pending_closes, ctx) {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_close(ctx)
    }
}

/// Connects a client stream without starting the handshake.
async fn client_stream(addr: SocketAddr, ssl: Ssl) -> Stream {
    let stream = socket(Async::<TcpStream>::connect(addr).await.unwrap());
    SslStream::new(ssl, stream).unwrap()
}

/// Connects a client stream and completes the handshake.
async fn connect_with(addr: SocketAddr, ssl: Ssl) -> Stream {
    let mut stream = client_stream(addr, ssl).await;
    Pin::new(&mut stream).connect().await.unwrap();
    stream
}

async fn connect(addr: SocketAddr) -> Stream {
    connect_with(addr, client_ssl()).await
}

fn exchange(tls: Tls) {
    // The client reads, so it also processes any session tickets.
    let peer = Peer::spawn_with(acceptor_builder(tls, 2).build(), |mut stream| async move {
        let mut buf = [0; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"asdf");
        stream.write_all(b"jkl;").await.unwrap();
        stream.close().await.unwrap();
    });
    peer.run(|addr| async move {
        let mut stream = connect(addr).await;
        stream.write_all(b"asdf").await.unwrap();

        // Peeking leaves the data queued for the read below.
        let mut peeked = [0; 4];
        assert_eq!(Pin::new(&mut stream).peek(&mut peeked).await.unwrap(), 4);
        assert_eq!(&peeked, b"jkl;");

        let mut buf = vec![];
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"jkl;");
    });
}

#[test]
fn exchange_tls12() {
    exchange(Tls::V1_2);
}

#[test]
fn exchange_tls13() {
    exchange(Tls::V1_3);
}

#[test]
fn early_data_cfg_matches_linked_openssl() {
    let ossl111 = openssl::version::version().starts_with("OpenSSL")
        && openssl::version::number() >= 0x1010_1000;
    assert_eq!(cfg!(ossl111), ossl111);
}

#[test]
fn peek_with_an_empty_buffer_completes() {
    Peer::quiet().run(|addr| async move {
        let mut stream = connect(addr).await;
        // The peer sends nothing, but there is nothing to peek into an empty buffer either, so
        // this must resolve instead of waiting for readability that never comes.
        assert_eq!(Pin::new(&mut stream).peek(&mut []).await.unwrap(), 0);
    });
}

#[test]
fn close_completes_when_the_inner_close_pends() {
    Peer::quiet().run(|addr| async move {
        let mut stream = connect(addr).await;
        stream.get_mut().pending_closes = 1;

        // The inner `poll_close` pends once, so `poll_close` runs again after writing
        // `close_notify`. Calling `SSL_shutdown` again would wait for the peer's, which never
        // comes.
        stream.close().await.unwrap();
    });
}
