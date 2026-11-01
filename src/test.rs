use crate::{MAX_WAITERS, SslStream, StreamWrapper, WakerSet};
use futures_io::{AsyncRead, AsyncWrite};
use openssl::ssl::{
    ShutdownState, Ssl, SslAcceptor, SslAcceptorBuilder, SslConnector, SslConnectorBuilder,
    SslContext, SslFiletype, SslMethod, SslOptions, SslVerifyMode, SslVersion,
};
use smol::{
    Async, Timer, future,
    io::{AsyncReadExt, AsyncWriteExt},
};
use std::{
    cell::RefCell,
    error::Error,
    fmt, io,
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    ops::{Deref, DerefMut},
    panic::{self, AssertUnwindSafe},
    pin::Pin,
    rc::Rc,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    thread,
    time::{Duration, Instant},
};

const DEADLINE: Duration = Duration::from_secs(10);

/// The documented limits, written out so that a change to the constants shows.
const CHUNK: usize = 16 * 1024;
const LIMIT: usize = 64 * 1024;

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

/// Waits until the socket holds data and has stopped receiving more.
#[cfg(ossl111)]
async fn settled(socket: &Async<TcpStream>) {
    let mut buf = vec![0; 64 * 1024];
    let mut seen = 0;
    loop {
        socket.readable().await.unwrap();
        Timer::after(Duration::from_millis(5)).await;
        let now = socket.get_ref().peek(&mut buf).unwrap();
        if now == seen {
            return;
        }
        seen = now;
    }
}

/// Waits until the socket holds `len` bytes that were not read yet.
async fn holding(socket: &Async<TcpStream>, len: usize) {
    let mut buf = vec![0; len];
    loop {
        socket.readable().await.unwrap();
        if socket.get_ref().peek(&mut buf).unwrap() == len {
            return;
        }
        Timer::after(Duration::from_millis(1)).await;
    }
}

/// Whether the linked library is LibreSSL.
fn libressl() -> bool {
    openssl::version::version().starts_with("LibreSSL")
}

/// Whether the library is OpenSSL, not LibreSSL, at `version` or newer.
fn openssl_from(version: i64) -> bool {
    !libressl() && openssl::version::number() >= version
}

/// Whether the library speaks TLS 1.3 (OpenSSL 1.1.1 or newer, or LibreSSL).
fn tls13() -> bool {
    openssl::version::number() >= 0x1010_1000
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

/// Sets `SSL_OP_IGNORE_UNEXPECTED_EOF` (OpenSSL 3.0 or newer), which rust-openssl only names
/// under a cfg this crate cannot see.
fn ignore_unexpected_eof(connector: &mut SslConnectorBuilder) {
    connector.set_options(SslOptions::from_bits_retain(1 << 7));
}

fn client_ssl() -> Ssl {
    client_ssl_with(|_| {})
}

/// A client `Ssl` from a plain context: unlike `SslConnector`, it enables neither
/// `ACCEPT_MOVING_WRITE_BUFFER` nor `ENABLE_PARTIAL_WRITE`.
fn raw_client_ssl() -> Ssl {
    let mut context = SslContext::builder(SslMethod::tls_client()).unwrap();
    context.set_ca_file("tests/cert.pem").unwrap();
    context.set_verify(SslVerifyMode::PEER);
    let mut ssl = Ssl::new(&context.build()).unwrap();
    ssl.param_mut().set_host("localhost").unwrap();
    ssl
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

    /// A peer that receives everything and returns it once the client closes the connection.
    fn receiving(check: impl FnOnce(Vec<u8>) + Send + 'static) -> Self {
        Self::spawn(|mut stream| async move {
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            check(received);
        })
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

    /// A peer that answers `request` with `reply`, then reads to the end.
    fn answering(request: &'static [u8], reply: &'static [u8]) -> Self {
        Self::spawn(move |mut stream| async move {
            let mut received = vec![0; request.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, request);
            stream.write_all(reply).await.unwrap();
            stream.read_to_end(&mut Vec::new()).await.unwrap();
        })
    }

    /// A peer whose handshake fails, as the client never completes it.
    fn failing_handshake() -> Self {
        Self::spawn_unaccepted(acceptor(), |mut stream| async move {
            assert!(Pin::new(&mut stream).accept().await.is_err());
        })
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

/// The payload of the errors that `Faulty` injects, to check that callers get the transport's
/// error itself rather than a copy.
#[derive(Debug)]
struct Injected;

impl fmt::Display for Injected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("injected")
    }
}

impl Error for Injected {}

fn injected(kind: io::ErrorKind) -> io::Error {
    io::Error::new(kind, Injected)
}

/// Checks that the error is OpenSSL's reason, not the transport's or one of the stream's own.
#[track_caller]
fn assert_openssl_reason(error: &io::Error) {
    let reason = error
        .get_ref()
        .is_some_and(|e| e.is::<openssl::ssl::Error>());
    assert!(reason, "not OpenSSL's reason: {error:?}");
}

#[track_caller]
fn assert_injected(error: &io::Error, kind: io::ErrorKind) {
    assert_eq!(error.kind(), kind, "{error}");
    let injected = error.get_ref().is_some_and(|inner| inner.is::<Injected>());
    assert!(injected, "not the transport's own error: {error:?}");
}

/// Checks the transport error inside an `ssl::Error`. LibreSSL queues an error of its own for a
/// failed transport read, which rust-openssl then returns instead of the transport's.
#[track_caller]
fn assert_injected_ssl(error: openssl::ssl::Error, kind: io::ErrorKind) {
    match error.into_io_error() {
        Ok(error) => assert_injected(&error, kind),
        Err(error) => assert!(libressl(), "no transport error: {error:?}"),
    }
}

/// Keeps only the latest poll's waker, and wakes it once. Like tokio, it drops the waker it
/// replaces without waking it, but keeps one for both directions where tokio keeps one for each.
#[derive(Default)]
struct LatestWaker(Mutex<Option<Waker>>);

impl LatestWaker {
    /// Records the polling task, and returns the waker to hand the inner stream instead.
    fn register(self: &Arc<Self>, waker: &Waker) -> Waker {
        *self.0.lock().unwrap() = Some(waker.clone());
        Waker::from(self.clone())
    }
}

impl Wake for LatestWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let waker = self.0.lock().unwrap().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// Holds a direction of the transport back, without waking anyone, until released.
#[derive(Default)]
struct Block {
    on: bool,
    waker: Option<Waker>,
}

impl Block {
    /// Whether the direction is held back, recording the waker to wake on release.
    fn holds(&mut self, ctx: &Context<'_>) -> bool {
        if self.on {
            self.waker = Some(ctx.waker().clone());
        }
        self.on
    }

    fn release(&mut self) {
        self.on = false;
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

/// Makes every other call return `Pending` (and wake the task) while on.
#[derive(Default)]
struct Alternate {
    on: bool,
    pended: bool,
}

impl Alternate {
    /// Whether this call pends.
    fn pends(&mut self, ctx: &Context<'_>) -> bool {
        if !self.on {
            return false;
        }
        self.pended = !self.pended;
        if self.pended {
            ctx.waker().wake_by_ref();
        }
        self.pended
    }
}

/// How many times a direction of the transport was polled, and with a waker that would not wake
/// the previous one.
#[derive(Default)]
struct Polls {
    count: usize,
    waker_changes: usize,
    last_waker: Option<Waker>,
}

impl Polls {
    fn record(&mut self, waker: &Waker) {
        self.count += 1;
        if !self
            .last_waker
            .as_ref()
            .is_some_and(|last| last.will_wake(waker))
        {
            self.waker_changes += 1;
            self.last_waker = Some(waker.clone());
        }
    }
}

/// The faults that `Faulty` injects, and what it counts.
#[derive(Default)]
struct Faults {
    /// The next `poll_write` calls that return `Pending` (and wake the task) instead.
    pending_writes: usize,
    /// An error that the next `poll_write` returns instead of writing.
    write_error: Option<io::ErrorKind>,
    /// An error that every `poll_write` returns instead of writing.
    broken_writes: Option<io::ErrorKind>,
    /// Makes every `poll_write` return `Ok(0)` instead of writing.
    zero_writes: bool,
    /// Makes every `poll_write` report one more byte than it was given.
    over_reported_writes: bool,
    /// Makes every `poll_write` panic.
    panicking_writes: bool,
    /// The most bytes that one `poll_write` takes, if not 0.
    short_writes: usize,
    /// With `short_writes`, makes every other `poll_write` return `Pending` (and wake the task).
    short_pending: Alternate,
    writes: Block,
    /// An error that the next `poll_read` returns instead of reading.
    read_error: Option<io::ErrorKind>,
    /// How many more bytes reads deliver, then fail with the error, or end the stream.
    failing_reads: Option<(usize, Option<io::ErrorKind>)>,
    /// Makes every `poll_read` report one more byte than it was given.
    over_reported_reads: bool,
    reads: Block,
    /// The next `poll_flush` calls that return `Pending` (and wake the task) instead.
    pending_flushes: usize,
    /// Makes every flush return `Pending` (and wake the task) once before it goes through.
    alternate_flushes: Alternate,
    flushes_blocked: Block,
    /// An error that the next `poll_flush` returns instead of flushing.
    flush_error: Option<io::ErrorKind>,
    /// Makes the next `poll_flush` panic.
    panicking_flush: bool,
    /// The next `poll_close` calls that return `Pending` (and wake the task) instead.
    pending_closes: usize,
    /// An error that the next `poll_close` returns instead of closing.
    close_error: Option<io::ErrorKind>,
    /// Set by `latest_waker_only`.
    latest_waker: Option<Arc<LatestWaker>>,
    /// The calls of `poll_read` and `poll_write`.
    read_polls: Polls,
    write_polls: Polls,
    /// How many bytes the inner stream took.
    written: usize,
    /// How many `poll_flush` and `poll_close` calls reached the inner stream.
    flushes: usize,
    inner_closes: usize,
}

impl Faults {
    /// Makes the transport wake only the task that polled it last, whatever it polled.
    fn latest_waker_only(&mut self) {
        self.latest_waker = Some(Arc::default());
    }
}

/// Delegates to the inner stream, injecting the faults that are armed.
struct Faulty<S> {
    inner: S,
    faults: Faults,
}

impl<S: fmt::Debug> fmt::Debug for Faulty<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
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

impl<S: Unpin> Faulty<S> {
    /// Polls the inner stream, through `latest_waker` if there is one.
    fn poll_inner<T>(
        &mut self,
        ctx: &mut Context<'_>,
        poll: impl FnOnce(Pin<&mut S>, &mut Context<'_>) -> T,
    ) -> T {
        match &self.faults.latest_waker {
            Some(latest) => {
                let waker = latest.register(ctx.waker());
                poll(Pin::new(&mut self.inner), &mut Context::from_waker(&waker))
            }
            None => poll(Pin::new(&mut self.inner), ctx),
        }
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
        mut buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let faults = &mut self.faults;
        faults.read_polls.record(ctx.waker());
        if faults.reads.holds(ctx) {
            return Poll::Pending;
        }
        if let Some(kind) = faults.read_error.take() {
            return Poll::Ready(Err(injected(kind)));
        }
        if let Some((left, end)) = faults.failing_reads {
            if left == 0 {
                return Poll::Ready(end.map_or(Ok(0), |kind| Err(injected(kind))));
            }
            let len = buf.len().min(left);
            buf = &mut buf[..len];
        }
        let over = faults.over_reported_reads;
        let result =
            std::task::ready!(self.poll_inner(ctx, |inner, ctx| inner.poll_read(ctx, buf)));
        if let (Ok(n), Some((left, _))) = (&result, &mut self.faults.failing_reads) {
            *left -= n;
        }
        Poll::Ready(result.map(|n| n + usize::from(over && n > 0)))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Faulty<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        mut buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let faults = &mut self.faults;
        faults.write_polls.record(ctx.waker());
        assert!(!faults.panicking_writes, "injected panic");
        if faults.writes.holds(ctx) {
            return Poll::Pending;
        }
        if let Some(kind) = faults.write_error.take().or(faults.broken_writes) {
            return Poll::Ready(Err(injected(kind)));
        }
        if pend_once(&mut faults.pending_writes, ctx) {
            return Poll::Pending;
        }
        if faults.zero_writes {
            return Poll::Ready(Ok(0));
        }
        if faults.over_reported_writes {
            return Poll::Ready(Ok(buf.len() + 1));
        }
        if faults.short_writes > 0 {
            if faults.short_pending.pends(ctx) {
                return Poll::Pending;
            }
            buf = &buf[..buf.len().min(faults.short_writes)];
        }
        let result = self.poll_inner(ctx, |inner, ctx| inner.poll_write(ctx, buf));
        if let Poll::Ready(Ok(n)) = result {
            self.faults.written += n;
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let faults = &mut self.faults;
        assert!(
            !std::mem::take(&mut faults.panicking_flush),
            "injected panic"
        );
        if faults.flushes_blocked.holds(ctx) {
            return Poll::Pending;
        }
        if pend_once(&mut faults.pending_flushes, ctx) {
            return Poll::Pending;
        }
        if faults.alternate_flushes.pends(ctx) {
            return Poll::Pending;
        }
        if let Some(kind) = faults.flush_error.take() {
            return Poll::Ready(Err(injected(kind)));
        }
        faults.flushes += 1;
        self.poll_inner(ctx, |inner, ctx| inner.poll_flush(ctx))
    }

    fn poll_close(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if pend_once(&mut self.pending_closes, ctx) {
            return Poll::Pending;
        }
        if let Some(kind) = self.close_error.take() {
            return Poll::Ready(Err(injected(kind)));
        }
        self.inner_closes += 1;
        self.poll_inner(ctx, |inner, ctx| inner.poll_close(ctx))
    }
}

/// Connects a client stream without starting the handshake.
async fn client_stream(addr: SocketAddr, ssl: Ssl) -> Stream {
    let stream = socket(Async::<TcpStream>::connect(addr).await.unwrap());
    SslStream::new(ssl, stream).unwrap()
}

/// Connects a client stream whose first read or write drives the handshake.
async fn lazy_client_stream(addr: SocketAddr, mut ssl: Ssl) -> Stream {
    ssl.set_connect_state();
    client_stream(addr, ssl).await
}

/// Connects a client stream, lazy or not.
async fn maybe_lazy_client_stream(addr: SocketAddr, lazy: bool) -> Stream {
    if lazy {
        lazy_client_stream(addr, client_ssl()).await
    } else {
        client_stream(addr, client_ssl()).await
    }
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

/// How many times the transport was polled to write and to read.
fn polls(stream: &Stream) -> (usize, usize) {
    let faults = stream.get_ref();
    (faults.write_polls.count, faults.read_polls.count)
}

/// How many bytes of TLS output the transport has not taken yet.
fn unsent(stream: &Stream) -> usize {
    stream.inner.get_ref().unsent()
}

/// Polls `fut` once and asserts that it is pending, which drops (cancels) it.
async fn assert_pending<T: fmt::Debug>(fut: impl Future<Output = T>) {
    if let Some(output) = future::poll_once(fut).await {
        panic!("expected Pending, got Ready({output:?})");
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

fn counting_waker() -> (Arc<CountingWake>, Waker) {
    let count = Arc::new(CountingWake(AtomicUsize::new(0)));
    (count.clone(), Waker::from(count))
}

impl CountingWake {
    fn take(&self) -> usize {
        self.0.swap(0, Ordering::SeqCst)
    }
}

/// Polls a write once on behalf of the task that `waker` wakes.
fn poll_write(stream: &mut Stream, waker: &Waker, buf: &[u8]) -> Poll<usize> {
    let poll = Pin::new(stream).poll_write(&mut Context::from_waker(waker), buf);
    poll.map(Result::unwrap)
}

fn poll_read(stream: &mut Stream, waker: &Waker, buf: &mut [u8]) -> Poll<usize> {
    let poll = Pin::new(stream).poll_read(&mut Context::from_waker(waker), buf);
    poll.map(Result::unwrap)
}

fn poll_flush(stream: &mut Stream, waker: &Waker) -> Poll<()> {
    let poll = Pin::new(stream).poll_flush(&mut Context::from_waker(waker));
    poll.map(Result::unwrap)
}

/// Polls `poll` once with a waker that does nothing.
fn poll_once<T>(poll: impl FnOnce(&mut Context<'_>) -> Poll<T>) -> Poll<T> {
    poll(&mut Context::from_waker(Waker::noop()))
}

/// A payload that makes misplaced bytes visible.
fn pattern(len: usize) -> Vec<u8> {
    let cycle: Vec<u8> = (0..=250).collect();
    let mut data = cycle.repeat(len.div_ceil(cycle.len()));
    data.truncate(len);
    data
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
        assert!(format!("{stream:?}").contains("unsent: 0"));
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
fn a_write_completes_before_the_transport_takes_it() {
    let peer = Peer::receiving(|received| assert_eq!(received, b"data"));
    peer.run(|addr| async move {
        let mut stream = connect(addr).await;
        let (wakes, waker) = counting_waker();
        stream.get_mut().writes.on = true;
        // OpenSSL encrypted the bytes, so they count as written.
        assert_eq!(poll_write(&mut stream, &waker, b"data"), Poll::Ready(4));
        assert!(unsent(&stream) > 0);
        assert_eq!(poll_flush(&mut stream, &waker), Poll::Pending);
        stream.get_mut().writes.release();
        assert_eq!(wakes.take(), 1);
        assert_eq!(poll_flush(&mut stream, &waker), Poll::Ready(()));
        stream.close().await.unwrap();
    });
}

#[test]
fn a_write_waiting_for_earlier_output_writes_nothing() {
    let peer = Peer::receiving(|received| assert_eq!(received, b"oldsamesameAAAABBBB"));
    peer.run(|addr| async move {
        let mut stream = connect(addr).await;
        stream.get_mut().writes.on = true;
        assert_eq!(stream.write(b"old").await.unwrap(), 3);
        // Dropped while it waits, so none of its bytes may go out.
        assert_pending(stream.write(b"cancelled")).await;
        stream.get_mut().writes.release();
        stream.flush().await.unwrap();

        stream.get_mut().writes.on = true;
        assert_eq!(stream.write(b"same").await.unwrap(), 4);
        let mut buffer = b"same".to_vec();
        assert_pending(stream.write(&buffer)).await;
        // `io::copy` and `BufWriter` top up their buffer while a write is pending, then retry
        // with the longer slice. Writing the same bytes again is a second write.
        buffer.extend_from_slice(b"AAAABBBB");
        stream.get_mut().writes.release();
        stream.write_all(&buffer).await.unwrap();
        stream.close().await.unwrap();
    });
}

#[test]
fn a_write_cancelled_while_it_drives_the_handshake_writes_nothing() {
    let peer = Peer::receiving(|received| assert_eq!(received, b"second"));
    peer.run(|addr| async move {
        let mut stream = lazy_client_stream(addr, client_ssl()).await;
        stream.get_mut().reads.on = true;
        // The write sends the ClientHello, then waits for the server's answer.
        assert_pending(stream.write(b"first")).await;
        stream.get_mut().reads.release();
        stream.write_all(b"second").await.unwrap();
        stream.close().await.unwrap();
    });
}

#[test]
fn empty_reads_and_writes_do_not_touch_the_transport() {
    Peer::quiet().run(|addr| async move {
        let mut stream = connect(addr).await;
        stream.get_mut().writes.on = true;
        assert_eq!(stream.write(b"data").await.unwrap(), 4);
        let before = polls(&stream);
        assert_eq!(
            poll_read(&mut stream, Waker::noop(), &mut []),
            Poll::Ready(0)
        );
        assert_eq!(poll_write(&mut stream, Waker::noop(), &[]), Poll::Ready(0));
        assert_eq!(polls(&stream), before);
    });
}

#[test]
fn a_write_hands_openssl_at_most_one_chunk() {
    let peer = Peer::receiving(|received| {
        assert_eq!(received.len(), CHUNK);
        assert!(received.iter().all(|&byte| byte == b'x'));
    });
    peer.run(|addr| async move {
        // Without partial writes, OpenSSL encrypts everything it is given at once.
        let mut stream = connect_with(addr, raw_client_ssl()).await;
        stream.get_mut().writes.on = true;
        let mut bytes = vec![b'x'; 2 * CHUNK];
        bytes[CHUNK..].fill(b'y');
        assert_eq!(stream.write(&bytes).await.unwrap(), CHUNK);
        assert!(unsent(&stream) < 2 * CHUNK);
        // The rest waits for those bytes, then is abandoned.
        assert_pending(stream.write(&bytes[CHUNK..])).await;
        stream.get_mut().writes.release();
        stream.close().await.unwrap();
    });
}

#[test]
fn large_writes_go_out_whole_and_in_order() {
    let data = pattern(1024 * 1024 + 123);
    let expected = data.clone();
    let peer = Peer::receiving(move |received| {
        assert!(
            received == [expected, b"tail".to_vec()].concat(),
            "payload differs"
        );
    });
    peer.run(move |addr| async move {
        let mut stream = connect(addr).await;
        stream.get_mut().pending_writes = 3;
        stream.write_all(&data).await.unwrap();
        stream.write_all(b"tail").await.unwrap();
        stream.flush().await.unwrap();
        // Sent output keeps memory for a full chunk's record, and not much more.
        let capacity = stream.inner.get_ref().out.capacity();
        assert!((CHUNK + 1..=2 * CHUNK).contains(&capacity), "{capacity}");
        stream.close().await.unwrap();
    });
}

#[test]
fn short_transport_writes_go_out_whole_and_in_order() {
    let data = pattern(40 * 1024 + 7);
    let expected = data.clone();
    let peer = Peer::receiving(move |received| assert!(received == expected, "payload differs"));
    peer.run(move |addr| async move {
        let mut stream = connect(addr).await;
        stream.get_mut().short_writes = 1000;
        stream.get_mut().short_pending.on = true;
        stream.write_all(&data).await.unwrap();
        stream.flush().await.unwrap();
        stream.close().await.unwrap();
    });
}

#[test]
fn a_transient_transport_write_error_loses_nothing() {
    for kind in [
        io::ErrorKind::NotConnected,
        io::ErrorKind::BrokenPipe,
        io::ErrorKind::TimedOut,
    ] {
        let peer = Peer::receiving(|received| assert_eq!(received, b"dataDATA"));
        peer.run(move |addr| async move {
            let mut stream = connect(addr).await;
            stream.get_mut().write_error = Some(kind);
            // The bytes were encrypted, so they count as written, and the next attempt sends them.
            assert_eq!(stream.write(b"data").await.unwrap(), 4);
            stream.write_all(b"DATA").await.unwrap();
            stream.close().await.unwrap();
        });
    }
}

#[test]
fn a_broken_transport_fails_writes_with_its_own_error_and_reads_go_on() {
    for kind in [
        io::ErrorKind::NotConnected,
        io::ErrorKind::BrokenPipe,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::TimedOut,
        io::ErrorKind::Interrupted,
    ] {
        let peer = Peer::spawn(|mut stream| async move {
            stream.write_all(b"hello").await.unwrap();
            stream.write_all(b"world").await.unwrap();
            let mut received = Vec::new();
            let _ = stream.read_to_end(&mut received).await;
            assert!(received.is_empty(), "{received:?}");
        });
        peer.run(move |addr| async move {
            let mut stream = connect(addr).await;
            let mut buf = [0; 5];
            stream.read_exact(&mut buf).await.unwrap();
            // The second record is in the socket, but not yet read.
            stream.get_ref().inner.readable().await.unwrap();
            stream.get_mut().broken_writes = Some(kind);

            // OpenSSL encrypted the bytes, so the write succeeds. Later calls report the error.
            assert_eq!(stream.write(b"data").await.unwrap(), 4);
            assert_injected(&stream.write(b"more").await.unwrap_err(), kind);
            assert_injected(&stream.flush().await.unwrap_err(), kind);
            // A read still gets what the peer sent, but reports the error instead of waiting for
            // an answer to bytes that the peer never got.
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"world");
            assert_injected(&stream.read(&mut buf).await.unwrap_err(), kind);
            // Closing reports it each time, and leaves the transport open to retry.
            assert_injected(&stream.close().await.unwrap_err(), kind);
            assert_injected(&stream.close().await.unwrap_err(), kind);
            assert_eq!(stream.get_ref().inner_closes, 0);
        });
    }
}

#[test]
fn a_close_that_could_not_send_sends_when_closing_again() {
    let peer = Peer::receiving(|received| assert_eq!(received, b"data"));
    peer.run(|addr| async move {
        let mut stream = connect(addr).await;
        stream.get_mut().writes.on = true;
        assert_eq!(stream.write(b"data").await.unwrap(), 4);
        // The transport recovers without a wakeup, but fails once.
        stream.get_mut().writes.on = false;
        stream.get_mut().write_error = Some(io::ErrorKind::TimedOut);
        let error = stream.close().await.unwrap_err();
        assert_injected(&error, io::ErrorKind::TimedOut);
        assert_eq!(stream.get_ref().inner_closes, 0);
        stream.close().await.unwrap();
        assert_eq!(stream.get_ref().inner_closes, 1);
    });
    // The same with only close_notify left to send.
    let peer = Peer::receiving(|received| assert_eq!(received, b""));
    peer.run(|addr| async move {
        let mut stream = connect(addr).await;
        let kind = io::ErrorKind::TimedOut;
        stream.get_mut().broken_writes = Some(kind);
        assert_injected(&stream.close().await.unwrap_err(), kind);
        assert_eq!(stream.get_ref().inner_closes, 0);
        stream.get_mut().broken_writes = None;
        stream.close().await.unwrap();
        assert_eq!(stream.get_ref().inner_closes, 1);
    });
}

/// The peer goes away after its own close_notify, while the client still has `buffered` output.
fn close_after_the_peers_close_notify(buffered: bool) {
    let peer = Peer::spawn(|mut stream| async move {
        stream.write_all(b"bye").await.unwrap();
        stream.close().await.unwrap();
        let _ = stream.read_to_end(&mut Vec::new()).await;
    });
    peer.run(move |addr| async move {
        let mut stream = connect(addr).await;
        if buffered {
            stream.get_mut().writes.on = true;
            assert_eq!(stream.write(b"data").await.unwrap(), 4);
        }
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"bye");
        stream.get_mut().writes.on = false;
        let kind = io::ErrorKind::BrokenPipe;
        stream.get_mut().broken_writes = Some(kind);
        if buffered {
            // Data that never went out is an error, whatever the peer did.
            assert_injected(&stream.close().await.unwrap_err(), kind);
            assert_eq!(stream.get_ref().inner_closes, 0);
        } else {
            // Our close_notify only acknowledges the peer's.
            stream.close().await.unwrap();
            assert_eq!(stream.get_ref().inner_closes, 1);
        }
    });
}

#[test]
fn a_close_after_the_peers_close_notify_ignores_a_failure_to_send_ours() {
    close_after_the_peers_close_notify(false);
}

#[test]
fn a_close_after_the_peers_close_notify_reports_unsent_data() {
    close_after_the_peers_close_notify(true);
}

#[test]
fn a_zero_byte_transport_write_is_an_error() {
    Peer::quiet().run(|addr| async move {
        let mut stream = connect(addr).await;
        stream.get_mut().zero_writes = true;
        assert_eq!(stream.write(b"data").await.unwrap(), 4);
        let error = stream.flush().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    });
}

#[test]
fn an_over_reported_transport_write_is_an_error() {
    Peer::quiet().run(|addr| async move {
        let mut stream = connect(addr).await;
        stream.get_mut().over_reported_writes = true;
        assert_eq!(stream.write(b"data").await.unwrap(), 4);
        let error = stream.flush().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    });
}

#[test]
fn an_over_reported_transport_read_is_an_error() {
    Peer::greeting(b"hello").run(|addr| async move {
        let mut stream = connect(addr).await;
        stream.get_mut().over_reported_reads = true;
        let error = stream.read(&mut [0; 5]).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    });
}

/// Polls `poll` once, expecting the transport to panic.
fn assert_panics<T>(poll: impl FnOnce(&mut Context<'_>) -> Poll<T>) {
    assert!(panic::catch_unwind(AssertUnwindSafe(|| poll_once(poll))).is_err());
}

#[test]
fn a_panicking_transport_poisons_the_stream() {
    Peer::quiet().run(|addr| async move {
        let mut stream = connect(addr).await;
        stream.get_mut().panicking_writes = true;
        assert_panics(|cx| Pin::new(&mut stream).poll_write(cx, b"data"));
        // The transport may have taken part of a record, so nothing may follow it.
        stream.get_mut().panicking_writes = false;
        let faults = |stream: &Stream| {
            let faults = stream.get_ref();
            (polls(stream), faults.flushes, faults.inner_closes)
        };
        let before = faults(&stream);
        assert!(stream.write(b"more").await.is_err());
        assert!(stream.read(&mut [0; 4]).await.is_err());
        assert!(stream.flush().await.is_err());
        assert!(stream.close().await.is_err());
        assert_eq!(faults(&stream), before);
    });
    // Also while the transport has taken part of the buffered output.
    Peer::quiet().run(|addr| async move {
        let mut stream = connect(addr).await;
        stream.get_mut().short_writes = 5;
        stream.get_mut().short_pending.on = true;
        assert_eq!(stream.write(b"data").await.unwrap(), 4);
        assert_eq!(poll_flush(&mut stream, Waker::noop()), Poll::Pending);
        assert!(stream.inner.get_ref().sent > 0);
        stream.get_mut().panicking_writes = true;
        assert_panics(|cx| Pin::new(&mut stream).poll_flush(cx));
        stream.get_mut().panicking_writes = false;
        assert!(stream.read(&mut [0; 4]).await.is_err());
    });
}

#[test]
fn a_panicking_transport_flush_comes_out_of_its_own_call() {
    Peer::quiet().run(|addr| async move {
        let mut stream = connect(addr).await;
        // OpenSSL ignores the result of its flush after close_notify, so the call would succeed
        // and leave the panic to a later one.
        stream.get_mut().panicking_flush = true;
        assert_panics(|cx| Pin::new(&mut stream).poll_close(cx));
        assert!(stream.read(&mut [0; 4]).await.is_err());
    });
}

#[test]
fn transport_read_errors_are_returned_whole() {
    for kind in [io::ErrorKind::ConnectionReset, io::ErrorKind::NotConnected] {
        Peer::quiet().run(move |addr| async move {
            let mut stream = connect(addr).await;
            stream.get_mut().read_error = Some(kind);
            assert_injected(&stream.read(&mut [0; 4]).await.unwrap_err(), kind);
        });
        // OpenSSL 4 fails the session after a peek's ConnectionReset, so each gets its own.
        Peer::quiet().run(move |addr| async move {
            let mut stream = connect(addr).await;
            stream.get_mut().read_error = Some(kind);
            let error = Pin::new(&mut stream).peek(&mut [0; 4]).await.unwrap_err();
            assert_injected_ssl(error, kind);
        });
    }
}

#[test]
fn a_transient_read_error_leaves_the_session_usable() {
    Peer::answering(b"ping", b"pong").run(|addr| async move {
        let mut stream = connect(addr).await;
        stream.write_all(b"ping").await.unwrap();
        let kind = io::ErrorKind::TimedOut;
        stream.get_mut().read_error = Some(kind);
        let mut buf = [0; 4];
        assert_injected(&stream.read(&mut buf).await.unwrap_err(), kind);
        // OpenSSL never saw the error.
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        stream.close().await.unwrap();
    });
}

#[test]
fn a_read_reporting_a_send_failure_leaves_the_session_usable() {
    Peer::answering(b"data", b"resp").run(|addr| async move {
        let mut stream = connect(addr).await;
        let kind = io::ErrorKind::TimedOut;
        stream.get_mut().broken_writes = Some(kind);
        assert_eq!(stream.write(b"data").await.unwrap(), 4);
        let mut buf = [0; 4];
        assert_injected(&stream.read(&mut buf).await.unwrap_err(), kind);
        // OpenSSL never saw the error, so once the transport recovers, the request goes out
        // and the answer comes back.
        stream.get_mut().broken_writes = None;
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"resp");
        stream.close().await.unwrap();
    });
}

#[test]
fn reads_and_peeks_do_not_wait_for_unsent_output() {
    let peer = Peer::spawn(|mut stream| async move {
        stream.write_all(b"hello").await.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"data");
    });
    peer.run(|addr| async move {
        let mut stream = connect(addr).await;
        // The transport takes nothing until the peer is read from, as when the peer stops
        // reading until it is read from.
        stream.get_mut().writes.on = true;
        assert_eq!(stream.write(b"data").await.unwrap(), 4);
        let mut buf = [0; 5];
        assert_eq!(Pin::new(&mut stream).peek(&mut buf).await.unwrap(), 5);
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        stream.get_mut().writes.release();
        stream.close().await.unwrap();
    });
}

#[test]
fn reads_send_unsent_output() {
    Peer::answering(b"ping", b"pong").run(|addr| async move {
        let mut stream = connect(addr).await;
        stream.get_mut().pending_writes = 1;
        assert_eq!(stream.write(b"ping").await.unwrap(), 4);
        assert!(unsent(&stream) > 0);
        // No flush: the peer only answers once it got the request.
        let mut buf = [0; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        stream.close().await.unwrap();
    });
}

#[test]
fn reads_flush_the_transport_before_waiting_once_output_went_out() {
    Peer::answering(b"ping", b"pong").run(|addr| async move {
        let mut stream = connect(addr).await;
        let flushes = |stream: &Stream| stream.get_ref().flushes;
        let mut buf = [0; 4];
        stream.get_mut().reads.on = true;
        // Nothing went out since the handshake's own flush.
        let before = flushes(&stream);
        assert_eq!(
            poll_read(&mut stream, Waker::noop(), &mut buf),
            Poll::Pending
        );
        assert_eq!(flushes(&stream), before);
        // A transport that only sends on flush would otherwise never send the request.
        stream.write_all(b"ping").await.unwrap();
        assert_eq!(
            poll_read(&mut stream, Waker::noop(), &mut buf),
            Poll::Pending
        );
        assert_eq!(flushes(&stream), before + 1);
        assert_eq!(
            poll_read(&mut stream, Waker::noop(), &mut buf),
            Poll::Pending
        );
        assert_eq!(flushes(&stream), before + 1);
        stream.flush().await.unwrap();
        assert_eq!(flushes(&stream), before + 2);
        assert_eq!(
            poll_read(&mut stream, Waker::noop(), &mut buf),
            Poll::Pending
        );
        assert_eq!(flushes(&stream), before + 2);
        stream.get_mut().reads.release();
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        stream.close().await.unwrap();
    });
}

#[test]
fn a_read_that_cannot_flush_before_waiting_reports_why() {
    Peer::answering(b"ping", b"pong").run(|addr| async move {
        let mut stream = connect(addr).await;
        stream.write_all(b"ping").await.unwrap();
        stream.get_mut().reads.on = true;
        let kind = io::ErrorKind::BrokenPipe;
        stream.get_mut().flush_error = Some(kind);
        let mut buf = [0; 4];
        assert_injected(&stream.read(&mut buf).await.unwrap_err(), kind);
        stream.get_mut().reads.release();
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        stream.close().await.unwrap();
    });
}

#[test]
fn reads_wait_for_output_past_the_limit() {
    Peer::greeting(b"hello").run(|addr| async move {
        let mut stream = connect(addr).await;
        stream.get_mut().writes.on = true;
        // As if OpenSSL had written that much by itself while reading. The transport never
        // takes it.
        stream.inner.get_mut().out = vec![0; LIMIT + 1];
        stream.get_ref().inner.readable().await.unwrap();
        let polls = stream.get_ref().read_polls.count;
        let (wakes, waker) = counting_waker();
        let mut buf = [0; 5];
        assert_eq!(poll_read(&mut stream, &waker, &mut buf), Poll::Pending);
        assert_eq!(stream.get_ref().read_polls.count, polls);
        // The read waits for the transport to take the output.
        stream.get_mut().writes.release();
        assert_eq!(wakes.take(), 1);
    });
}

#[test]
fn reads_past_the_limit_report_a_failure_to_send() {
    for peek in [false, true] {
        Peer::greeting(b"hello").run(move |addr| async move {
            let mut stream = connect(addr).await;
            stream.get_ref().inner.readable().await.unwrap();
            stream.inner.get_mut().out = vec![0; LIMIT + 1];
            let kind = io::ErrorKind::TimedOut;
            stream.get_mut().broken_writes = Some(kind);
            // The peer's data is there, but the output must not grow any further.
            let mut buf = [0; 5];
            if peek {
                let error = Pin::new(&mut stream).peek(&mut buf).await.unwrap_err();
                assert_injected_ssl(error, kind);
            } else {
                assert_injected(&stream.read(&mut buf).await.unwrap_err(), kind);
            }
        });
    }
}

#[test]
fn a_refusing_transport_is_asked_again_only_once_it_wakes_the_stream() {
    Peer::greeting(b"hello").run(|addr| async move {
        let mut stream = connect(addr).await;
        stream.get_mut().writes.on = true;
        assert_eq!(stream.write(b"data").await.unwrap(), 4);
        stream.get_ref().inner.readable().await.unwrap();
        let polls = stream.get_ref().write_polls.count;
        let mut buf = [0; 5];
        assert_eq!(
            poll_read(&mut stream, Waker::noop(), &mut buf),
            Poll::Ready(5)
        );
        // The stream's own wakes, such as for the records that read got, change nothing.
        assert_eq!(
            poll_read(&mut stream, Waker::noop(), &mut buf),
            Poll::Pending
        );
        assert_eq!(stream.get_ref().write_polls.count, polls);
        stream.get_mut().writes.release();
        assert_eq!(
            poll_read(&mut stream, Waker::noop(), &mut buf),
            Poll::Pending
        );
        assert_eq!(stream.get_ref().write_polls.count, polls + 1);
    });
}

#[test]
fn a_failing_transport_is_asked_once_per_call() {
    Peer::greeting(b"hello").run(|addr| async move {
        let mut stream = connect(addr).await;
        stream.get_ref().inner.readable().await.unwrap();
        stream.get_mut().broken_writes = Some(io::ErrorKind::TimedOut);
        assert_eq!(stream.write(b"data").await.unwrap(), 4);
        let polls = stream.get_ref().write_polls.count;
        // OpenSSL reads the record's header and body separately.
        let mut buf = [0; 5];
        assert_eq!(
            poll_read(&mut stream, Waker::noop(), &mut buf),
            Poll::Ready(5)
        );
        assert_eq!(stream.get_ref().write_polls.count, polls + 1);
    });
}

/// An end-to-end check of full-duplex traffic over real sockets, against a peer that only reads
/// while its own writes go through. The socket buffers are large enough that it rarely blocks:
/// `reads_and_peeks_do_not_wait_for_unsent_output` checks the no-deadlock property reliably.
#[test]
fn full_duplex_echo_completes() {
    const LEN: usize = 8 * 1024 * 1024;
    let peer = Peer::spawn(|mut stream| async move {
        let mut buf = vec![0; 64 * 1024];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).await.unwrap();
        }
        stream.close().await.unwrap();
    });
    peer.run(|addr| async move {
        let data = pattern(LEN);
        let (mut reader, mut writer) = smol::io::split(connect(addr).await);
        let write = async {
            writer.write_all(&data).await.unwrap();
            writer.close().await.unwrap();
        };
        let read = async {
            let mut echoed = Vec::with_capacity(LEN);
            reader.read_to_end(&mut echoed).await.unwrap();
            echoed
        };
        let ((), echoed) = future::zip(write, read).await;
        assert!(echoed == data, "echoed data differs");
    });
}

#[test]
fn tasks_waiting_on_one_stream_share_a_stable_waker() {
    let peer = Peer::receiving(|received| assert_eq!(received, b"abcdefghi"));
    peer.run(|addr| async move {
        let mut stream = connect(addr).await;
        let (x_wakes, x) = counting_waker();
        let (y_wakes, y) = counting_waker();

        stream.get_mut().writes.on = true;
        assert_eq!(poll_write(&mut stream, &x, b"abc"), Poll::Ready(3));
        // A task whose call completed does not wait.
        assert!(stream.inner.get_ref().wakers.lock().is_empty());
        for _ in 0..3 {
            assert_eq!(poll_write(&mut stream, &x, b"def"), Poll::Pending);
            assert_eq!(poll_write(&mut stream, &y, b"ghi"), Poll::Pending);
        }
        // A transport that wakes the waker it replaces would otherwise make both tasks wake
        // each other forever.
        assert_eq!(stream.get_ref().write_polls.waker_changes, 1);
        assert_eq!(stream.get_ref().read_polls.waker_changes, 1);

        stream.get_mut().writes.release();
        assert_eq!((x_wakes.take(), y_wakes.take()), (1, 1));
        assert_eq!(poll_write(&mut stream, &x, b"def"), Poll::Ready(3));
        assert_eq!(poll_write(&mut stream, &y, b"ghi"), Poll::Ready(3));
        stream.close().await.unwrap();
    });
}

#[test]
fn the_waker_set_stays_bounded() {
    let set = Arc::new(WakerSet::default());
    let generation = set.generation();
    let tasks: Vec<_> = (0..=MAX_WAITERS).map(|_| counting_waker()).collect();
    for (_, waker) in &tasks {
        set.join(waker, true, generation);
        set.join(waker, true, generation);
    }
    // Making room for the last task woke the others, which join again if they still wait.
    assert!(
        tasks[..MAX_WAITERS]
            .iter()
            .all(|(wakes, _)| wakes.take() == 1)
    );
    assert_eq!(set.lock().len(), 1);
    Waker::from(set.clone()).wake();
    assert_eq!(tasks[MAX_WAITERS].0.take(), 1);
    let waiters = set.lock();
    assert!(waiters.is_empty() && waiters.capacity() > 0);
    drop(waiters);
    // A task whose call ran across that wake is woken as it joins.
    set.join(&tasks[0].1, true, generation);
    assert_eq!(tasks[0].0.take(), 1);
    assert!(set.lock().is_empty());
}

#[test]
fn output_the_transport_took_is_dropped_before_more_is_queued() {
    let mut wrapper = StreamWrapper::new(smol::io::Cursor::new(Vec::new()));
    wrapper.out = vec![0; 100];
    // Less was taken than is left: nothing moves yet.
    wrapper.sent = 40;
    io::Write::write(&mut wrapper, b"data").unwrap();
    assert_eq!((wrapper.out.len(), wrapper.sent), (104, 40));
    wrapper.sent = 60;
    io::Write::write(&mut wrapper, b"more").unwrap();
    assert_eq!((wrapper.out.len(), wrapper.sent), (48, 0));
    assert_eq!(&wrapper.out[44..], b"more");
}

#[test]
fn records_read_by_one_task_only_wake_tasks_waiting_for_records() {
    let set = WakerSet::default();
    let (sender_wakes, sender) = counting_waker();
    let (reader_wakes, reader) = counting_waker();
    set.join(&sender, false, set.generation());
    set.join(&reader, true, set.generation());
    set.wake_tasks(false, true);
    assert_eq!((sender_wakes.take(), reader_wakes.take()), (0, 1));
    set.wake_tasks(true, false);
    assert_eq!(sender_wakes.take(), 1);
}

#[test]
fn a_panicking_waker_leaves_the_others_their_wakeup() {
    struct PanickingWake;

    impl Wake for PanickingWake {
        fn wake(self: Arc<Self>) {
            panic!("injected panic");
        }
    }

    let set = WakerSet::default();
    let (first_wakes, first) = counting_waker();
    let (last_wakes, last) = counting_waker();
    for waker in [&first, &Waker::from(Arc::new(PanickingWake)), &last] {
        set.join(waker, true, set.generation());
    }
    let wake = || set.wake_tasks(true, false);
    assert!(panic::catch_unwind(AssertUnwindSafe(wake)).is_err());
    assert_eq!(first_wakes.take(), 1);
    set.wake_tasks(true, false);
    assert_eq!(last_wakes.take(), 1);
}

#[test]
fn a_task_waiting_for_records_another_task_read_is_woken() {
    // The test needs a handshake that one read can finish.
    if !tls13() {
        return;
    }
    let (report, flight) = smol::channel::bounded(1);
    let mut report = Some(report);
    let peer = Peer::spawn_unaccepted(acceptor(), move |mut stream| async move {
        future::poll_fn(|cx| {
            let accepted = Pin::new(&mut stream).poll_accept(cx);
            // The server's whole flight went out: it waits for the client's.
            let written = stream.get_ref().written;
            if accepted.is_pending() && written > 0 && unsent(&stream) == 0 {
                if let Some(report) = report.take() {
                    report.try_send(written).unwrap();
                }
            }
            accepted
        })
        .await
        .unwrap();
        let mut request = [0; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"data");
        stream.write_all(b"resp").await.unwrap();
        stream.read_to_end(&mut Vec::new()).await.unwrap();
    });
    peer.run(|addr| async move {
        let mut stream = lazy_client_stream(addr, client_ssl()).await;
        let (writer_wakes, writer) = counting_waker();
        let (_, reader) = counting_waker();
        let mut buf = [0; 4];
        // The writer drives the handshake and waits for the server's answer, and so does the
        // reader.
        stream.get_mut().reads.on = true;
        assert_eq!(poll_write(&mut stream, &writer, b"data"), Poll::Pending);
        assert_eq!(poll_read(&mut stream, &reader, &mut buf), Poll::Pending);
        // The server's flight arrives, and the reader reads it before any transport wakeup, as
        // when a reactor reports readiness after another task emptied the socket.
        stream.get_mut().reads.on = false;
        holding(&stream.get_ref().inner, flight.recv().await.unwrap()).await;
        writer_wakes.take();
        assert_eq!(poll_read(&mut stream, &reader, &mut buf), Poll::Pending);
        // Nothing else would wake the writer, which waited for what the reader read.
        assert_eq!(writer_wakes.take(), 1);
        assert_eq!(poll_write(&mut stream, &writer, b"data"), Poll::Ready(4));
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"resp");
        stream.close().await.unwrap();
    });
}

#[test]
fn a_task_waiting_on_the_stream_is_woken_when_a_send_fails() {
    Peer::answering(b"ping", b"pong").run(|addr| async move {
        let mut stream = connect(addr).await;
        // The answer must not end the reader's wait before the test is done.
        stream.get_mut().reads.on = true;
        let (reader_wakes, reader) = counting_waker();
        let mut buf = [0; 4];
        let kind = io::ErrorKind::TimedOut;
        // The request cannot be sent this time, and the reader waits for its answer: it has to
        // retry the send, or report why it fails.
        assert_eq!(poll_read(&mut stream, &reader, &mut buf), Poll::Pending);
        stream.get_mut().write_error = Some(kind);
        assert_eq!(
            poll_write(&mut stream, Waker::noop(), b"ping"),
            Poll::Ready(4)
        );
        assert_eq!(reader_wakes.take(), 1);
        // Also when the send of earlier output fails, or a flush.
        assert_eq!(poll_read(&mut stream, &reader, &mut buf), Poll::Pending);
        stream.get_mut().writes.on = true;
        assert_eq!(
            poll_write(&mut stream, Waker::noop(), b"more"),
            Poll::Ready(4)
        );
        // The transport recovers without a wakeup, then fails.
        stream.get_mut().writes.on = false;
        stream.get_mut().write_error = Some(kind);
        let error = poll_once(|cx| Pin::new(&mut stream).poll_write(cx, b"more"));
        assert!(matches!(error, Poll::Ready(Err(_))), "{error:?}");
        assert_eq!(reader_wakes.take(), 1);
        assert_eq!(poll_read(&mut stream, &reader, &mut buf), Poll::Pending);
        stream.get_mut().flush_error = Some(kind);
        let error = poll_once(|cx| Pin::new(&mut stream).poll_flush(cx));
        assert!(matches!(error, Poll::Ready(Err(_))), "{error:?}");
        assert_eq!(reader_wakes.take(), 1);
        // Also a task that waits for the transport to take output, not for the peer.
        let (writer_wakes, writer) = counting_waker();
        stream.get_mut().writes.on = true;
        assert_eq!(poll_write(&mut stream, &writer, b"next"), Poll::Ready(4));
        assert_eq!(poll_write(&mut stream, &writer, b"last"), Poll::Pending);
        // The transport recovers without a wakeup, then fails a flush.
        stream.get_mut().writes.on = false;
        stream.get_mut().flush_error = Some(kind);
        let error = poll_once(|cx| Pin::new(&mut stream).poll_flush(cx));
        assert!(matches!(error, Poll::Ready(Err(_))), "{error:?}");
        assert_eq!(writer_wakes.take(), 1);
        stream.get_mut().reads.release();
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        stream.close().await.unwrap();
    });
}

/// A writer task drives the handshake (a lazy client, then a write), which waits for the
/// server's answer. A reader task then reads, which waits for the same answer. The transport
/// keeps only the waker of its latest poll, and holds back the answer until both tasks wait.
fn reader_and_writer_share_the_transport(writer_first: bool) {
    Peer::answering(b"data", b"resp").run(move |addr| async move {
        let mut stream = lazy_client_stream(addr, client_ssl()).await;
        stream.get_mut().latest_waker_only();
        stream.get_mut().reads.on = true;
        let stream = Rc::new(RefCell::new(stream));
        let executor = smol::LocalExecutor::new();
        let writer = executor.spawn({
            let stream = stream.clone();
            async move {
                if !writer_first {
                    future::yield_now().await;
                }
                future::poll_fn(|cx| Pin::new(&mut *stream.borrow_mut()).poll_write(cx, b"data"))
                    .await
                    .unwrap()
            }
        });
        let reader = executor.spawn({
            let stream = stream.clone();
            async move {
                if writer_first {
                    future::yield_now().await;
                }
                let mut buf = [0; 4];
                let mut read = 0;
                while read < buf.len() {
                    let n = future::poll_fn(|cx| {
                        Pin::new(&mut *stream.borrow_mut()).poll_read(cx, &mut buf[read..])
                    })
                    .await
                    .unwrap();
                    assert_ne!(n, 0, "the peer closed before answering");
                    read += n;
                }
                buf
            }
        });
        while executor.try_tick() {}
        stream.borrow_mut().get_mut().reads.release();
        let (written, read) = executor.run(future::zip(writer, reader)).await;
        assert_eq!((written, &read), (4, b"resp"));
        drop(executor);
        let mut stream = Rc::try_unwrap(stream).ok().unwrap().into_inner();
        // Both tasks got the stream's own waker.
        assert_eq!(stream.get_ref().read_polls.waker_changes, 1);
        stream.close().await.unwrap();
    });
}

#[test]
fn a_writer_first_and_a_reader_share_a_transport_that_keeps_one_waker() {
    reader_and_writer_share_the_transport(true);
}

#[test]
fn a_reader_first_and_a_writer_share_a_transport_that_keeps_one_waker() {
    reader_and_writer_share_the_transport(false);
}

#[test]
fn closing_leaves_a_waiting_reader_its_wakeup() {
    let peer = Peer::spawn(|mut stream| async move {
        // Answers the client's close_notify.
        stream.read_to_end(&mut Vec::new()).await.unwrap();
        stream.write_all(b"bye").await.unwrap();
        stream.close().await.unwrap();
    });
    peer.run(|addr| async move {
        let mut stream = connect(addr).await;
        stream.get_mut().latest_waker_only();
        let (reader_wakes, reader) = counting_waker();
        let mut buf = [0; 3];
        assert_eq!(poll_read(&mut stream, &reader, &mut buf), Poll::Pending);
        stream.close().await.unwrap();
        let woken = async {
            while reader_wakes.take() == 0 {
                Timer::after(Duration::from_millis(1)).await;
            }
        };
        deadline("reader wakeup", woken).await;
        assert_eq!(poll_read(&mut stream, &reader, &mut buf), Poll::Ready(3));
        assert_eq!(&buf, b"bye");
    });
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

#[test]
fn close_without_a_session_still_closes_the_transport_and_writes_nothing_after() {
    for lazy in [false, true] {
        Peer::failing_handshake().run(move |addr| async move {
            let mut stream = maybe_lazy_client_stream(addr, lazy).await;
            // There is no TLS session to close, but the transport still has to be closed. The
            // first close says why, and closing again fails too.
            let first = stream.close().await.unwrap_err();
            // LibreSSL reports success during its handshake, and so gives no reason then.
            if !(lazy && libressl()) {
                assert_openssl_reason(&first);
            }
            assert!(stream.close().await.is_err());
            assert_eq!(stream.get_ref().inner_closes, 2);
            // A write must not start a handshake on the closed transport.
            let before = polls(&stream);
            assert!(stream.write(b"data").await.is_err());
            assert_eq!(polls(&stream), before);
        });
    }
}

#[test]
fn a_write_does_not_ask_a_transport_that_refused_a_flush() {
    let peer = Peer::receiving(|received| assert_eq!(received, b"data"));
    peer.run(|addr| async move {
        let mut stream = connect(addr).await;
        stream.get_mut().flushes_blocked.on = true;
        assert_eq!(poll_flush(&mut stream, Waker::noop()), Poll::Pending);
        // Until the transport wakes the stream, OpenSSL's write goes to the buffer.
        let before = polls(&stream);
        assert_eq!(
            poll_write(&mut stream, Waker::noop(), b"data"),
            Poll::Ready(4)
        );
        assert_eq!(polls(&stream), before);
        stream.get_mut().flushes_blocked.release();
        stream.close().await.unwrap();
    });
}

/// A server that reads the whole ClientHello, so that its close is a clean end, not a reset, and
/// then goes away without a handshake, after a plaintext warning close_notify if `alert`, which
/// anyone on the path can send.
fn handshake_cut_off(alert: bool) -> Peer {
    Peer::spawn_unaccepted(acceptor(), move |mut stream| async move {
        let transport = stream.get_mut();
        let mut header = [0; 5];
        transport.read_exact(&mut header).await.unwrap();
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        transport.read_exact(&mut vec![0; len]).await.unwrap();
        if alert {
            let close_notify = [0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00];
            transport.write_all(&close_notify).await.unwrap();
        }
    })
}

#[test]
fn a_handshake_cut_off_under_a_lazy_read_is_an_error() {
    // The end without an alert is a `SYSCALL` before OpenSSL 4. A close_notify reads as
    // `ZERO_RETURN` everywhere, and so does that end under `SSL_OP_IGNORE_UNEXPECTED_EOF` on
    // OpenSSL 4.
    for (alert, ignore_eof) in [(false, false), (true, false), (false, true)] {
        if ignore_eof && !openssl_from(0x3000_0000) {
            continue;
        }
        handshake_cut_off(alert).run(move |addr| async move {
            let ssl = client_ssl_with(|connector| {
                if ignore_eof {
                    ignore_unexpected_eof(connector);
                }
            });
            let mut stream = lazy_client_stream(addr, ssl).await;
            let result = stream.read_to_end(&mut Vec::new()).await;
            assert!(
                result.is_err(),
                "alert: {alert}, ignore_eof: {ignore_eof}: {result:?}"
            );
        });
    }
}

#[test]
fn close_reports_the_transports_close_error() {
    Peer::quiet().run(|addr| async move {
        let mut stream = connect(addr).await;
        let kind = io::ErrorKind::ConnectionReset;
        stream.get_mut().close_error = Some(kind);
        assert_injected(&stream.close().await.unwrap_err(), kind);
    });
    // Also without a session, where OpenSSL's reason waits for the close that closes it.
    Peer::failing_handshake().run(|addr| async move {
        let mut stream = client_stream(addr, client_ssl()).await;
        let kind = io::ErrorKind::ConnectionReset;
        stream.get_mut().close_error = Some(kind);
        assert_injected(&stream.close().await.unwrap_err(), kind);
        assert_openssl_reason(&stream.close().await.unwrap_err());
    });
}

#[test]
fn close_flushes_the_transport() {
    Peer::quiet().run(|addr| async move {
        let mut stream = connect(addr).await;
        stream.write_all(b"data").await.unwrap();
        let flushes = stream.get_ref().flushes;
        stream.close().await.unwrap();
        assert_eq!(stream.get_ref().flushes, flushes + 1);
    });
}

#[test]
fn writes_after_close_fail() {
    Peer::quiet().run(|addr| async move {
        let mut stream = connect(addr).await;
        stream.close().await.unwrap();
        assert!(stream.write(b"data").await.is_err());
    });
}

#[test]
fn writes_after_close_fail_after_the_library_forgets_close_notify() {
    Peer::receiving(|received| assert_eq!(received, b"")).run(|addr| async move {
        let mut stream = connect(addr).await;
        stream.close().await.unwrap();
        // As OpenSSL 4 does when a read hits an unclean end under SSL_OP_IGNORE_UNEXPECTED_EOF.
        // The wrapper would otherwise discard the write, which would then succeed.
        stream.inner.set_shutdown(ShutdownState::RECEIVED);
        assert_eq!(stream.read(&mut [0; 4]).await.unwrap(), 0);
        assert!(stream.write(b"data").await.is_err());
    });
}

#[test]
fn writes_after_close_fail_after_an_unclean_end_too() {
    // `SSL_OP_IGNORE_UNEXPECTED_EOF` exists from OpenSSL 3.0 on.
    if !openssl_from(0x3000_0000) {
        return;
    }
    let peer = Peer::spawn(|mut stream| async move {
        stream.write_all(b"hello").await.unwrap();
        // Takes the client's close_notify, then goes away without sending its own.
        stream.read_to_end(&mut Vec::new()).await.unwrap();
    });
    peer.run(|addr| async move {
        let mut stream = connect_with(addr, client_ssl_with(ignore_unexpected_eof)).await;
        stream.close().await.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"hello");
        assert!(stream.write(b"data").await.is_err());
    });
}

#[test]
fn a_stream_cut_without_close_notify_ends_or_fails_by_openssl_version() {
    let peer = Peer::spawn(|mut stream| async move {
        stream.write_all(b"hello").await.unwrap();
        // Goes away without close_notify.
    });
    peer.run(|addr| async move {
        let mut stream = connect(addr).await;
        let mut received = Vec::new();
        let result = stream.read_to_end(&mut received).await;
        if openssl_from(0x4000_0000) {
            assert!(result.is_err(), "{result:?}");
        } else {
            result.unwrap();
            assert_eq!(received, b"hello");
        }
    });
}

#[test]
fn flushes_and_handshakes_flush_the_transport() {
    let peer = Peer::spawn_unaccepted(acceptor(), |mut stream| async move {
        stream.get_mut().pending_flushes = 1;
        Pin::new(&mut stream).accept().await.unwrap();
        assert_eq!(stream.get_ref().pending_flushes, 0);
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"data");
    });
    peer.run(|addr| async move {
        let mut stream = client_stream(addr, client_ssl()).await;
        stream.get_mut().pending_flushes = 1;
        // The server's answer waits until the client's flush pended, so that the client's
        // next poll, not the same one, retries it.
        stream.get_mut().reads.on = true;
        assert_pending(Pin::new(&mut stream).connect()).await;
        stream.get_mut().reads.release();
        Pin::new(&mut stream).connect().await.unwrap();
        assert_eq!(stream.get_ref().pending_flushes, 0);
        assert!(!stream.inner.get_ref().flush_needed);
        stream.write_all(b"data").await.unwrap();
        let flushes = stream.get_ref().flushes;
        stream.flush().await.unwrap();
        assert_eq!(stream.get_ref().flushes, flushes + 1);
        let kind = io::ErrorKind::BrokenPipe;
        stream.get_mut().flush_error = Some(kind);
        assert_injected(&stream.flush().await.unwrap_err(), kind);
        stream.close().await.unwrap();
    });
}

#[test]
fn a_write_driven_handshake_flushes_the_transport() {
    let peer = Peer::receiving(|received| assert_eq!(received, b"data"));
    peer.run(|addr| async move {
        let mut stream = lazy_client_stream(addr, client_ssl()).await;
        stream.get_mut().pending_flushes = 1;
        stream.get_mut().reads.on = true;
        assert_pending(stream.write(b"data")).await;
        stream.get_mut().reads.release();
        stream.write_all(b"data").await.unwrap();
        assert_eq!(stream.get_ref().pending_flushes, 0);
        stream.close().await.unwrap();
    });
}

#[test]
fn a_transient_error_during_a_write_driven_handshake_stops_nothing() {
    for kind in [
        io::ErrorKind::NotConnected,
        io::ErrorKind::TimedOut,
        io::ErrorKind::BrokenPipe,
    ] {
        let peer = Peer::receiving(|received| assert_eq!(received, b"req-2req-3"));
        peer.run(move |addr| async move {
            let mut stream = lazy_client_stream(addr, client_ssl()).await;
            stream.get_mut().write_error = Some(kind);
            // The ClientHello could not be sent, so waiting for the answer would never end.
            assert_injected(&stream.write(b"req-1").await.unwrap_err(), kind);
            stream.write_all(b"req-2").await.unwrap();
            Pin::new(&mut stream).connect().await.unwrap();
            stream.write_all(b"req-3").await.unwrap();
            stream.close().await.unwrap();
        });
    }
}

#[test]
fn handshakes_and_peeks_report_transport_errors() {
    let kind = io::ErrorKind::BrokenPipe;
    for lazy in [false, true] {
        Peer::failing_handshake().run(move |addr| async move {
            let mut stream = maybe_lazy_client_stream(addr, lazy).await;
            stream.get_mut().broken_writes = Some(kind);
            let error = if lazy {
                Pin::new(&mut stream).do_handshake().await
            } else {
                Pin::new(&mut stream).connect().await
            };
            assert_injected_ssl(error.unwrap_err(), kind);
        });
    }
    let peer = Peer::spawn_unaccepted(acceptor(), move |mut stream| async move {
        stream.get_mut().read_error = Some(io::ErrorKind::ConnectionReset);
        let error = Pin::new(&mut stream).accept().await.unwrap_err();
        assert_injected_ssl(error, io::ErrorKind::ConnectionReset);
    });
    peer.run(|addr| async move {
        let mut stream = client_stream(addr, client_ssl()).await;
        let _ = Pin::new(&mut stream).connect().await;
    });
    Peer::quiet().run(move |addr| async move {
        let mut stream = connect(addr).await;
        let kind = io::ErrorKind::TimedOut;
        stream.get_mut().broken_writes = Some(kind);
        assert_eq!(stream.write(b"data").await.unwrap(), 4);
        let error = Pin::new(&mut stream).peek(&mut [0; 4]).await.unwrap_err();
        assert_injected_ssl(error, kind);
    });
}

#[test]
fn a_stale_openssl_error_does_not_fail_a_read() {
    Peer::answering(b"ping", b"pong").run(|addr| async move {
        let mut stream = connect(addr).await;
        stream.write_all(b"ping").await.unwrap();
        stream.get_mut().reads.on = true;
        // Left on the thread's queue by unrelated code. OpenSSL < 4 and LibreSSL would take it
        // as the reason that a read that has to wait failed.
        openssl::x509::X509::from_pem(b"not a certificate")
            .unwrap_err()
            .put();
        let mut buf = [0; 4];
        assert_eq!(
            poll_read(&mut stream, Waker::noop(), &mut buf),
            Poll::Pending
        );
        // The entry is not the stream's to discard.
        assert!(!openssl::error::ErrorStack::get().errors().is_empty());
        stream.get_mut().reads.release();
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        stream.close().await.unwrap();
    });
}

/// TLS inside TLS: the outer session's transport is an inner session.
#[test]
fn an_enclosing_openssl_call_keeps_its_errors() {
    let peer = Peer::spawn(|inner| async move {
        let ssl = Ssl::new(acceptor().context()).unwrap();
        let mut outer = SslStream::new(ssl, inner).unwrap();
        assert!(Pin::new(&mut outer).accept().await.is_err());
    });
    peer.run(|addr| async move {
        let inner = connect(addr).await;
        // The outer session does not trust the test certificate.
        let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();
        let mut outer = SslStream::new(ssl_for(&connector), inner).unwrap();
        let error = Pin::new(&mut outer).connect().await.unwrap_err();
        // The outer call's reason survives the inner calls that sent its alert.
        let reason = error
            .ssl_error()
            .map(ToString::to_string)
            .unwrap_or_default();
        assert!(reason.contains("certificate verify failed"), "{error:?}");
    });
}

/// Test-only setup that rust-openssl does not offer through safe code.
#[cfg(ossl111)]
#[allow(unsafe_code)]
mod unsafe_setup {
    use openssl::ssl::{SslAcceptor, SslConnectorBuilder, SslContextRef, SslRef, SslSessionRef};
    use std::{
        os::raw::{c_int, c_void},
        ptr,
    };

    unsafe extern "C" {
        fn SSL_CTX_set_tlsext_max_fragment_length(
            ctx: *mut openssl_sys::SSL_CTX,
            mode: u8,
        ) -> c_int;
        fn SSL_verify_client_post_handshake(ssl: *mut openssl_sys::SSL) -> c_int;
        fn SSL_key_update(ssl: *mut openssl_sys::SSL, update_type: c_int) -> c_int;
        fn SSL_CTX_set_session_ticket_cb(
            ctx: *mut openssl_sys::SSL_CTX,
            generate: Option<unsafe extern "C" fn(*mut openssl_sys::SSL, *mut c_void) -> c_int>,
            decrypt: *const c_void,
            arg: *mut c_void,
        ) -> c_int;
    }

    /// The `SSL` pointer that `ssl` wraps: a reference to an `SslRef` is that pointer
    /// (foreign-types).
    fn ssl_ptr(ssl: &SslRef) -> *mut openssl_sys::SSL {
        ssl as *const SslRef as *mut openssl_sys::SSL
    }

    /// Makes the client ask for records of at most 512 bytes (RFC 6066).
    pub(super) fn request_512_byte_records(connector: &mut SslConnectorBuilder) {
        // SAFETY: the builder owns a valid `SSL_CTX`, and 1 is `TLSEXT_max_fragment_length_512`.
        let ret = unsafe { SSL_CTX_set_tlsext_max_fragment_length(connector.as_ptr(), 1) };
        assert_eq!(ret, 1);
    }

    /// Clears `SSL_MODE_AUTO_RETRY`, which rust-openssl cannot do: OpenSSL then returns
    /// `WANT_READ` after handling a record without application data.
    pub(super) fn clear_auto_retry(connector: &mut SslConnectorBuilder) {
        const SSL_CTRL_CLEAR_MODE: c_int = 78;
        // SAFETY: the builder owns a valid `SSL_CTX`, and clearing a mode takes no pointer.
        unsafe {
            openssl_sys::SSL_CTX_ctrl(
                connector.as_ptr(),
                SSL_CTRL_CLEAR_MODE,
                openssl_sys::SSL_MODE_AUTO_RETRY,
                ptr::null_mut(),
            );
        }
    }

    /// Lets the server ask the client for a certificate after the handshake (TLS 1.3).
    pub(super) fn allow_post_handshake_auth(connector: &mut SslConnectorBuilder) {
        // SAFETY: the builder owns a valid `SSL_CTX`.
        unsafe { openssl_sys::SSL_CTX_set_post_handshake_auth(connector.as_ptr(), 1) };
    }

    /// Makes the server ask for the client's certificate with its next message.
    pub(super) fn request_client_certificate(ssl: &SslRef) {
        // SAFETY: the pointer is valid while `ssl` is, and OpenSSL only queues a message on it.
        let ret = unsafe { SSL_verify_client_post_handshake(ssl_ptr(ssl)) };
        assert_eq!(ret, 1);
    }

    /// Makes the next message update our keys and ask the peer to update its own (TLS 1.3).
    pub(super) fn request_key_update(ssl: &SslRef) {
        const SSL_KEY_UPDATE_REQUESTED: c_int = 1;
        // SAFETY: the pointer is valid while `ssl` is, and OpenSSL only queues a message on it.
        let ret = unsafe { SSL_key_update(ssl_ptr(ssl), SSL_KEY_UPDATE_REQUESTED) };
        assert_eq!(ret, 1);
    }

    unsafe extern "C" fn refuse_ticket(_: *mut openssl_sys::SSL, _: *mut c_void) -> c_int {
        0
    }

    /// Makes `acceptor` fail to make session tickets, which fails the handshake that sends one.
    pub(super) fn refuse_new_tickets(acceptor: &SslAcceptor) {
        let context = acceptor.context() as *const SslContextRef as *mut openssl_sys::SSL_CTX;
        // SAFETY: a reference to an `SslContextRef` is the `SSL_CTX` pointer it wraps
        // (foreign-types), no handshake runs on it meanwhile, a null decryption callback keeps
        // OpenSSL's own, and the generation callback uses none of its arguments.
        let ret = unsafe {
            SSL_CTX_set_session_ticket_cb(
                context,
                Some(refuse_ticket),
                ptr::null(),
                ptr::null_mut(),
            )
        };
        assert_eq!(ret, 1);
    }

    /// Makes `ssl` resume `session`, which must come from the same connector.
    pub(super) fn resume(ssl: &mut SslRef, session: &SslSessionRef) {
        // SAFETY: the callers take `session` from a connection of the connector that made `ssl`,
        // so both share an `SSL_CTX`.
        unsafe { ssl.set_session(session) }.unwrap();
    }
}

#[cfg(ossl111)]
#[test]
fn small_records_carry_exactly_what_writes_report() {
    let peer = Peer::spawn(|mut stream| async move {
        // With partial writes, OpenSSL takes one 512-byte record per write.
        stream.get_mut().pending_writes = 1;
        let data = [b'x'; CHUNK];
        let written = stream.write(&data).await.unwrap();
        assert!(written <= 512, "{written}");
        stream.write_all(&data[written..]).await.unwrap();
        stream.write_all(b"NEXT").await.unwrap();
        stream.close().await.unwrap();
    });
    peer.run(|addr| async move {
        let ssl = client_ssl_with(unsafe_setup::request_512_byte_records);
        let mut stream = connect_with(addr, ssl).await;
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        let xs = received.iter().take_while(|&&byte| byte == b'x').count();
        assert_eq!(xs, CHUNK);
        assert_eq!(&received[xs..], b"NEXT");
    });
}

/// OpenSSL writes the client's certificate from inside the read that gets the server's request,
/// while output from an earlier write is still unsent.
#[cfg(ossl111)]
#[test]
fn a_read_answers_a_post_handshake_certificate_request_behind_unsent_output() {
    // `SSL_VERIFY_POST_HANDSHAKE`, which openssl-sys only has from 0.9.117 on.
    const POST_HANDSHAKE: i32 = 0x08;
    // OpenSSL sends new tickets after a client certificate, which the client would not read.
    let mut acceptor = acceptor_builder(Tls::V1_3, 0);
    let verify = SslVerifyMode::PEER.bits() | POST_HANDSHAKE;
    acceptor.set_verify(SslVerifyMode::from_bits_retain(verify));
    let peer = Peer::spawn_with(acceptor.build(), |mut stream| async move {
        unsafe_setup::request_client_certificate(stream.ssl());
        stream.write_all(b"hello").await.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"data");
    });
    peer.run(|addr| async move {
        let ssl = client_ssl_with(unsafe_setup::allow_post_handshake_auth);
        let mut stream = connect_with(addr, ssl).await;
        stream.get_mut().writes.on = true;
        assert_eq!(stream.write(b"data").await.unwrap(), 4);
        let mut buf = [0; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        stream.get_mut().writes.release();
        stream.close().await.unwrap();
    });
}

/// After close_notify, OpenSSL still answers the peer's key update requests from inside reads;
/// that answer must not go out.
#[cfg(ossl111)]
#[test]
fn nothing_goes_out_after_close_notify() {
    let peer = Peer::spawn(|mut stream| async move {
        // Answers the client's close_notify, asking for key updates.
        stream.read_to_end(&mut Vec::new()).await.unwrap();
        for part in [b"a", b"b", b"c"] {
            unsafe_setup::request_key_update(stream.ssl());
            stream.write_all(part).await.unwrap();
        }
        stream.close().await.unwrap();
    });
    peer.run(|addr| async move {
        let mut stream = connect(addr).await;
        stream.close().await.unwrap();
        let (polls, flushes) = (stream.get_ref().write_polls.count, stream.get_ref().flushes);
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"abc");
        assert_eq!(stream.get_ref().write_polls.count, polls);
        assert_eq!(stream.get_ref().flushes, flushes);
    });
}

/// A TLS 1.3 session that a client can resume with early data.
#[cfg(ossl111)]
struct Resumable {
    acceptor: SslAcceptor,
    connector: SslConnector,
    session: openssl::ssl::SslSession,
}

#[cfg(ossl111)]
fn resumable_session() -> Resumable {
    use openssl::ssl::{SslSession, SslSessionCacheMode};

    let mut acceptor = acceptor_builder(Tls::V1_3, 1);
    acceptor.set_max_early_data(16 * 1024).unwrap();
    acceptor.set_session_id_context(b"async-openssl").unwrap();
    let acceptor = acceptor.build();

    let session: Arc<Mutex<Option<SslSession>>> = Arc::default();
    let mut connector = connector();
    connector.set_session_cache_mode(SslSessionCacheMode::CLIENT);
    let slot = session.clone();
    connector.set_new_session_callback(move |_, new| *slot.lock().unwrap() = Some(new));
    let connector = connector.build();

    let peer = Peer::spawn_with(acceptor.clone(), |mut stream| async move {
        stream.write_all(b"hi").await.unwrap();
        stream.read_to_end(&mut Vec::new()).await.unwrap();
        // OpenSSL drops a session from its cache, and with it the right to early data, unless
        // the connection was shut down. The client is gone, so sending may fail.
        let _ = stream.close().await;
    });
    let ssl = ssl_for(&connector);
    peer.run(|addr| async move {
        let mut stream = connect_with(addr, ssl).await;
        // Reading processes the ticket, which comes first.
        stream.read_exact(&mut [0; 2]).await.unwrap();
        stream.close().await.unwrap();
    });
    let session = session.lock().unwrap().take().expect("no session ticket");
    assert!(session.max_early_data() > 0);
    Resumable {
        acceptor,
        connector,
        session,
    }
}

#[cfg(ossl111)]
impl Resumable {
    /// Runs `client` against `peer` with a stream that resumes the session, whose first write or
    /// early-data write drives the handshake.
    fn run<C, Fut>(&self, peer: Peer, client: C)
    where
        C: FnOnce(Stream) -> Fut + Send + 'static,
        Fut: Future<Output = ()>,
    {
        let mut ssl = ssl_for(&self.connector);
        unsafe_setup::resume(&mut ssl, &self.session);
        peer.run(|addr| async move { client(lazy_client_stream(addr, ssl).await).await });
    }

    /// The early-data server of `early_data_peer`, for this session.
    fn peer(&self, check: impl FnOnce(Vec<u8>) + Send + 'static) -> Peer {
        early_data_peer(self.acceptor.clone(), check)
    }
}

/// A server that reads all early data, checks it, completes the handshake and writes "!" behind
/// this connection's session ticket, if any, so that the client reads the ticket with it.
#[cfg(ossl111)]
fn early_data_peer(acceptor: SslAcceptor, check: impl FnOnce(Vec<u8>) + Send + 'static) -> Peer {
    Peer::spawn_unaccepted(acceptor, |mut stream| async move {
        check(read_all_early_data(&mut stream).await);
        Pin::new(&mut stream).accept().await.unwrap();
        stream.write_all(b"!").await.unwrap();
        stream.read_to_end(&mut Vec::new()).await.unwrap();
    })
}

#[cfg(ossl111)]
async fn read_all_early_data(stream: &mut Stream) -> Vec<u8> {
    let mut early = Vec::new();
    let mut buf = [0; 4096];
    loop {
        match Pin::new(&mut *stream)
            .read_early_data(&mut buf)
            .await
            .unwrap()
        {
            0 => return early,
            n => early.extend_from_slice(&buf[..n]),
        }
    }
}

/// Completes the client's handshake, reads the server's "!" and closes.
#[cfg(ossl111)]
async fn finish(mut stream: Stream) {
    Pin::new(&mut stream).connect().await.unwrap();
    stream.read_exact(&mut [0; 1]).await.unwrap();
    stream.close().await.unwrap();
}

#[cfg(ossl111)]
#[test]
fn early_data_is_sent_on_a_resumed_session() {
    let resumable = resumable_session();
    let peer = Peer::spawn_unaccepted(resumable.acceptor.clone(), |mut stream| async move {
        let mut buf = [0; 16];
        let n = Pin::new(&mut stream)
            .read_early_data(&mut buf)
            .await
            .unwrap();
        assert_eq!(&buf[..n], b"early");
        // An empty buffer must not read as the end of early data.
        let empty = Pin::new(&mut stream).read_early_data(&mut []).await;
        assert!(empty.is_err());
        assert_eq!(read_all_early_data(&mut stream).await, b"more");
        Pin::new(&mut stream).accept().await.unwrap();
        stream.write_all(b"!").await.unwrap();
        let mut late = Vec::new();
        stream.read_to_end(&mut late).await.unwrap();
        assert_eq!(late, b"late");
    });
    resumable.run(peer, |mut stream| async move {
        // OpenSSL flushes after writing early data; neither a pending nor a failed flush, nor a
        // transient send error, may lose the data.
        stream.get_mut().alternate_flushes.on = true;
        stream.get_mut().write_error = Some(io::ErrorKind::TimedOut);
        let early = Pin::new(&mut stream).write_early_data(b"early").await;
        assert_eq!(early.unwrap(), 5);
        stream.get_mut().flush_error = Some(io::ErrorKind::TimedOut);
        let more = Pin::new(&mut stream).write_early_data(b"more").await;
        assert_eq!(more.unwrap(), 4);
        Pin::new(&mut stream).connect().await.unwrap();
        assert!(stream.ssl().session_reused());
        stream.read_exact(&mut [0; 1]).await.unwrap();
        stream.write_all(b"late").await.unwrap();
        stream.close().await.unwrap();
    });
}

#[cfg(ossl111)]
#[test]
fn early_data_writes_wait_for_earlier_output_but_go_on_after_an_error() {
    let resumable = resumable_session();
    let peer = resumable.peer(|early| assert_eq!(early, b"earlymore"));
    resumable.run(peer, |mut stream| async move {
        stream.get_mut().writes.on = true;
        let early = Pin::new(&mut stream).write_early_data(b"early").await;
        assert_eq!(early.unwrap(), 5);
        // The ClientHello and the early data are still unsent.
        let more = poll_once(|cx| Pin::new(&mut stream).poll_write_early_data(cx, b"more"));
        assert!(more.is_pending());
        // The transport recovers without a wakeup, but fails once: the call goes on.
        stream.get_mut().writes.on = false;
        stream.get_mut().write_error = Some(io::ErrorKind::TimedOut);
        let more = poll_once(|cx| Pin::new(&mut stream).poll_write_early_data(cx, b"more"));
        assert!(matches!(more, Poll::Ready(Ok(4))), "{more:?}");
        finish(stream).await;
    });
}

#[cfg(ossl111)]
#[test]
fn an_early_data_write_hands_openssl_at_most_one_chunk() {
    let resumable = resumable_session();
    let peer = resumable.peer(|early| assert_eq!(early.len(), CHUNK));
    resumable.run(peer, |mut stream| async move {
        let data = [b'x'; 2 * CHUNK];
        let written = Pin::new(&mut stream).write_early_data(&data).await;
        assert_eq!(written.unwrap(), CHUNK);
        finish(stream).await;
    });
}

#[cfg(ossl111)]
#[test]
fn early_data_writes_fail_on_a_poisoned_stream() {
    let resumable = resumable_session();
    let peer = Peer::spawn_unaccepted(resumable.acceptor.clone(), |mut stream| async move {
        let _ = Pin::new(&mut stream).accept().await;
    });
    resumable.run(peer, |mut stream| async move {
        stream.get_mut().panicking_writes = true;
        assert_panics(|cx| Pin::new(&mut stream).poll_write_early_data(cx, b"early"));
        stream.get_mut().panicking_writes = false;
        let early = Pin::new(&mut stream).write_early_data(b"early").await;
        assert!(early.is_err(), "{early:?}");
    });
}

#[cfg(ossl111)]
#[test]
fn an_empty_early_data_write_after_the_handshake_reports_openssl_error() {
    Peer::quiet().run(|addr| async move {
        let mut stream = connect(addr).await;
        let poll = future::poll_once(Pin::new(&mut stream).write_early_data(&[])).await;
        assert!(matches!(poll, Some(Err(_))), "{poll:?}");
    });
}

/// OpenSSL writes a session ticket from inside the read that finishes the handshake, while the
/// server's early response (0.5-RTT data) is still unsent.
#[cfg(ossl111)]
#[test]
fn a_read_writes_a_session_ticket_behind_unsent_early_response() {
    let resumable = resumable_session();
    let peer = Peer::spawn_unaccepted(resumable.acceptor.clone(), |mut stream| async move {
        let mut buf = [0; 5];
        let n = Pin::new(&mut stream)
            .read_early_data(&mut buf)
            .await
            .unwrap();
        assert_eq!(&buf[..n], b"early");
        stream.get_mut().writes.on = true;
        let response = [b'z'; CHUNK];
        let written = Pin::new(&mut stream).write_early_data(&response).await;
        assert_eq!(written.unwrap(), CHUNK);
        // The client's Finished arrives, and OpenSSL answers with a ticket.
        assert_eq!(read_all_early_data(&mut stream).await, b"");
        Pin::new(&mut stream).accept().await.unwrap();
        stream.get_mut().writes.release();
        // Behind the ticket, which the client reads with it.
        stream.write_all(b"!").await.unwrap();
        stream.read_to_end(&mut Vec::new()).await.unwrap();
    });
    resumable.run(peer, |mut stream| async move {
        let early = Pin::new(&mut stream).write_early_data(b"early").await;
        assert_eq!(early.unwrap(), 5);
        Pin::new(&mut stream).connect().await.unwrap();
        let mut response = vec![0; CHUNK + 1];
        stream.read_exact(&mut response).await.unwrap();
        let (response, end) = response.split_at(CHUNK);
        assert!(response.iter().all(|&byte| byte == b'z'));
        assert_eq!(end, b"!");
        stream.close().await.unwrap();
    });
}

/// The server fails to make the resumed connection's ticket, right after the client's end of
/// early data, in the same `SSL_read_early_data` call: that is no end of early data.
#[cfg(ossl111)]
#[test]
fn a_handshake_failing_right_after_early_data_is_not_its_end() {
    // Also when the server cannot send its alert: that is not why the handshake failed.
    for alert_fails in [false, true] {
        handshake_failing_right_after_early_data(alert_fails);
    }
}

#[cfg(ossl111)]
fn handshake_failing_right_after_early_data(alert_fails: bool) {
    let resumable = resumable_session();
    unsafe_setup::refuse_new_tickets(&resumable.acceptor);
    let peer = Peer::spawn_unaccepted(resumable.acceptor.clone(), move |mut stream| async move {
        let mut early = Vec::new();
        let mut buf = [0; 16];
        let error = loop {
            match Pin::new(&mut stream).read_early_data(&mut buf).await {
                Ok(0) => panic!("the handshake failure read as the end of early data"),
                Ok(n) => early.extend_from_slice(&buf[..n]),
                Err(error) => break error,
            }
            if alert_fails {
                stream.get_mut().broken_writes = Some(io::ErrorKind::BrokenPipe);
            }
        };
        assert_eq!(early, b"early");
        let reason = error
            .ssl_error()
            .is_some_and(|stack| !stack.errors().is_empty());
        assert!(reason, "{error:?}");
    });
    resumable.run(peer, |mut stream| async move {
        let early = Pin::new(&mut stream).write_early_data(b"early").await;
        assert_eq!(early.unwrap(), 5);
        // The client's end of early data and Finished go out together, so that the server reads
        // both in one call.
        stream.get_mut().writes.on = true;
        Pin::new(&mut stream).connect().await.unwrap();
        stream.get_mut().writes.release();
        stream.flush().await.unwrap();
        let _ = stream.read_to_end(&mut Vec::new()).await;
    });
}

/// The transport fails, or ends, right after the client's end of early data.
#[cfg(ossl111)]
fn transport_end_right_after_early_data(end: Option<io::ErrorKind>) {
    let resumable = resumable_session();
    let peer = Peer::spawn_unaccepted(resumable.acceptor.clone(), move |mut stream| async move {
        let mut buf = [0; 16];
        let n = Pin::new(&mut stream)
            .read_early_data(&mut buf)
            .await
            .unwrap();
        assert_eq!(&buf[..n], b"early");
        settled(&stream.get_ref().inner).await;
        // Only the 26-byte record of the end of early data gets through.
        stream.get_mut().failing_reads = Some((26, end));
        let error = Pin::new(&mut stream)
            .read_early_data(&mut buf)
            .await
            .unwrap_err();
        if let Some(kind) = end {
            assert_injected_ssl(error, kind);
        }
    });
    resumable.run(peer, |mut stream| async move {
        let early = Pin::new(&mut stream).write_early_data(b"early").await;
        assert_eq!(early.unwrap(), 5);
        Pin::new(&mut stream).connect().await.unwrap();
        let _ = stream.read_to_end(&mut Vec::new()).await;
    });
}

#[cfg(ossl111)]
#[test]
fn a_transport_failing_right_after_early_data_is_not_its_end() {
    for kind in [io::ErrorKind::ConnectionReset, io::ErrorKind::NotConnected] {
        transport_end_right_after_early_data(Some(kind));
    }
}

#[cfg(ossl111)]
#[test]
fn a_transport_ending_right_after_early_data_is_not_its_end() {
    transport_end_right_after_early_data(None);
}

#[cfg(ossl111)]
#[test]
fn early_data_that_the_server_rejects_ends_at_once() {
    let resumable = resumable_session();
    // Other ticket keys: the server cannot resume the session, so it rejects the early data.
    let mut acceptor = acceptor_builder(Tls::V1_3, 0);
    acceptor.set_max_early_data(16 * 1024).unwrap();
    let peer = early_data_peer(acceptor.build(), |early| assert_eq!(early, b""));
    resumable.run(peer, |mut stream| async move {
        let early = Pin::new(&mut stream).write_early_data(b"early").await;
        assert_eq!(early.unwrap(), 5);
        Pin::new(&mut stream).connect().await.unwrap();
        assert!(!stream.ssl().session_reused());
        stream.read_exact(&mut [0; 1]).await.unwrap();
        stream.close().await.unwrap();
    });
}

#[cfg(ossl111)]
#[test]
fn reading_early_data_reports_transport_errors() {
    let kind = io::ErrorKind::ConnectionReset;
    let peer = Peer::spawn_unaccepted(acceptor(), move |mut stream| async move {
        stream.get_mut().read_error = Some(kind);
        let error = Pin::new(&mut stream)
            .read_early_data(&mut [0; 16])
            .await
            .unwrap_err();
        assert_injected_ssl(error, kind);
    });
    peer.run(|addr| async move {
        let mut stream = client_stream(addr, client_ssl()).await;
        let _ = Pin::new(&mut stream).connect().await;
    });
}

#[cfg(ossl111)]
fn read_past_session_tickets<F>(client: F)
where
    F: AsyncFnOnce(&mut Stream) + Send + 'static,
{
    let peer = Peer::spawn_with(
        acceptor_builder(Tls::V1_3, 2).build(),
        |mut stream| async move {
            stream.write_all(b"hello").await.unwrap();
            stream.read_to_end(&mut Vec::new()).await.unwrap();
        },
    );
    peer.run(|addr| async move {
        let ssl = client_ssl_with(unsafe_setup::clear_auto_retry);
        let mut stream = connect_with(addr, ssl).await;
        client(&mut stream).await;
    });
}

#[cfg(ossl111)]
#[test]
fn peek_without_auto_retry_reads_past_session_tickets() {
    read_past_session_tickets(async |stream| {
        // The session tickets come first. Each makes OpenSSL return `WANT_READ` without a
        // pending read, so waiting for the transport would never end.
        let mut buf = [0; 5];
        assert_eq!(Pin::new(&mut *stream).peek(&mut buf).await.unwrap(), 5);
        assert_eq!(&buf, b"hello");
        stream.read_exact(&mut buf).await.unwrap();
        stream.close().await.unwrap();
    });
}

/// A blocked transport flush must not make a call that OpenSSL asks to retry look like it waits
/// for the transport.
#[cfg(ossl111)]
#[test]
fn reads_without_auto_retry_go_past_session_tickets_while_a_flush_is_blocked() {
    read_past_session_tickets(async |stream| {
        stream.get_mut().flushes_blocked.on = true;
        assert_pending(stream.close()).await;
        assert!(stream.inner.get_ref().flush_needed);
        let mut buf = [0; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        stream.get_mut().flushes_blocked.release();
        stream.close().await.unwrap();
    });
}
