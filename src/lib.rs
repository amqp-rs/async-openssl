//! Async TLS streams backed by OpenSSL.
//!
//! This crate provides a wrapper around the [`openssl`] crate's [`SslStream`](ssl::SslStream) type
//! that works with with [`futures_io`]'s [`AsyncRead`] and [`AsyncWrite`] traits rather than std's
//! blocking [`Read`] and [`Write`] traits.
#![deny(missing_docs, missing_debug_implementations, unsafe_code)]
#![warn(unreachable_pub, unused_qualifications, unused_lifetimes)]
#![warn(
    clippy::must_use_candidate,
    clippy::unwrap_in_result,
    clippy::panic_in_result_fn
)]

use futures_io::{AsyncRead, AsyncWrite};
use openssl::{
    error::ErrorStack,
    ssl::{self, ErrorCode, ShutdownResult, Ssl, SslRef},
};
use std::{
    fmt, future,
    io::{self, Read, Write},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
};

#[cfg(test)]
mod test;

struct StreamWrapper<S: Unpin> {
    stream: S,
    waker: Option<Waker>,
}

impl<S> fmt::Debug for StreamWrapper<S>
where
    S: fmt::Debug + Unpin,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.stream.fmt(fmt)
    }
}

impl<S: Unpin> StreamWrapper<S> {
    fn parts(&mut self) -> (Pin<&mut S>, Context<'_>) {
        let stream = Pin::new(&mut self.stream);
        // The wrapper is only ever driven from inside `SslStream::with_context`, which installs
        // the current waker first, so the fallback is unreachable in practice.
        let context = Context::from_waker(self.waker.as_ref().unwrap_or(Waker::noop()));
        (stream, context)
    }
}

impl<S> Read for StreamWrapper<S>
where
    S: AsyncRead + Unpin,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (stream, mut cx) = self.parts();
        match stream.poll_read(&mut cx, buf)? {
            Poll::Ready(nread) => Ok(nread),
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

impl<S> Write for StreamWrapper<S>
where
    S: AsyncWrite + Unpin,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (stream, mut cx) = self.parts();
        match stream.poll_write(&mut cx, buf) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let (stream, mut cx) = self.parts();
        match stream.poll_flush(&mut cx) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

fn cvt<T>(r: io::Result<T>) -> Poll<io::Result<T>> {
    match r {
        Ok(v) => Poll::Ready(Ok(v)),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
        Err(e) => Poll::Ready(Err(e)),
    }
}

fn cvt_ossl<T>(r: Result<T, ssl::Error>) -> Poll<Result<T, ssl::Error>> {
    match r {
        Ok(v) => Poll::Ready(Ok(v)),
        Err(e) => match e.code() {
            ErrorCode::WANT_READ | ErrorCode::WANT_WRITE
                if e.io_error()
                    .is_none_or(|io_error| io_error.kind() == io::ErrorKind::WouldBlock) =>
            {
                Poll::Pending
            }
            _ => Poll::Ready(Err(e)),
        },
    }
}

fn ssl_error_to_io(e: ssl::Error) -> io::Error {
    e.into_io_error().unwrap_or_else(io::Error::other)
}

const WRITE_CHUNK_SIZE: usize = 16 * 1024;

struct WakeBoth(Waker, Waker);

impl Wake for WakeBoth {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.wake_by_ref();
        self.1.wake_by_ref();
    }
}

struct PendingWrite {
    bytes: Vec<u8>,
    caller_addr: usize,
    caller_len: usize,
    operation_id: Option<u64>,
    accepted: usize,
    waker: Option<Waker>,
    other_waker: Option<Waker>,
}

impl PendingWrite {
    fn new(buf: &[u8], operation_id: Option<u64>, mut bytes: Vec<u8>) -> Self {
        bytes.clear();
        bytes.extend_from_slice(&buf[..buf.len().min(WRITE_CHUNK_SIZE)]);
        Self {
            bytes,
            caller_addr: buf.as_ptr() as usize,
            caller_len: buf.len(),
            operation_id,
            accepted: 0,
            waker: None,
            other_waker: None,
        }
    }

    fn set_waker(&mut self, waker: &Waker) {
        match &mut self.waker {
            Some(current) => current.clone_from(waker),
            slot @ None => *slot = Some(waker.clone()),
        }
    }

    fn set_other_waker(&mut self, waker: &Waker) {
        if self
            .waker
            .as_ref()
            .is_some_and(|writer| writer.will_wake(waker))
        {
            return;
        }
        match &mut self.other_waker {
            Some(current) => current.clone_from(waker),
            slot @ None => *slot = Some(waker.clone()),
        }
    }

    fn wake_waiters(&mut self) {
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.other_waker.take() {
            waker.wake();
        }
    }

    fn combined_waker(&self) -> Option<Waker> {
        Some(Waker::from(Arc::new(WakeBoth(
            self.waker.as_ref()?.clone(),
            self.other_waker.as_ref()?.clone(),
        ))))
    }

    fn is_same_write(&self, buf: &[u8], operation_id: Option<u64>) -> bool {
        match operation_id {
            Some(id) => self.operation_id == Some(id),
            None => {
                // Only the staged prefix was attempted; the rest of the caller's input was not
                // captured and does not belong to this poll of the write.
                self.operation_id.is_none()
                    && self.caller_addr == buf.as_ptr() as usize
                    && self.caller_len == buf.len()
                    && self.bytes.as_slice() == &buf[..self.bytes.len()]
            }
        }
    }

    fn staged(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Default)]
struct WriteState {
    pending: Option<PendingWrite>,
    // Another TLS operation may finish a write before its original caller observes the result.
    completed: Option<PendingWrite>,
    buffer: Vec<u8>,
}

impl WriteState {
    fn register_writer(&mut self, buf: &[u8], operation_id: Option<u64>, waker: &Waker) {
        if let Some(pending) = &mut self.pending {
            if pending.is_same_write(buf, operation_id) {
                pending.set_waker(waker);
            } else {
                pending.set_other_waker(waker);
            }
        }
    }

    fn take_completion(&mut self, buf: &[u8], operation_id: Option<u64>) -> Option<usize> {
        let completed = self.completed.take()?;
        let accepted = completed
            .is_same_write(buf, operation_id)
            .then_some(completed.accepted);
        self.buffer = completed.bytes;
        accepted
    }

    fn recycle_completion(&mut self) {
        if let Some(completed) = self.completed.take() {
            self.buffer = completed.bytes;
        }
    }

    fn finish_initial(
        &mut self,
        mut pending: PendingWrite,
        waker: &Waker,
        result: Poll<Result<usize, ssl::Error>>,
    ) -> Poll<Result<usize, ssl::Error>> {
        match result {
            Poll::Pending => {
                pending.set_waker(waker);
                self.pending = Some(pending);
                Poll::Pending
            }
            ready => {
                self.buffer = pending.bytes;
                ready
            }
        }
    }

    fn finish_retry(
        &mut self,
        mut pending: PendingWrite,
        result: Poll<Result<usize, ssl::Error>>,
        zero_is_success: bool,
    ) -> Poll<Result<(), ssl::Error>> {
        match result {
            Poll::Pending => {
                self.pending = Some(pending);
                Poll::Pending
            }
            Poll::Ready(Ok(n)) => {
                pending.wake_waiters();
                if n == 0 && !(zero_is_success && pending.bytes.is_empty()) {
                    self.buffer = pending.bytes;
                    Poll::Ready(Err(ErrorStack::get().into()))
                } else {
                    // A positive short write completes this call; the caller owns the suffix.
                    pending.accepted = n;
                    self.completed = Some(pending);
                    Poll::Ready(Ok(()))
                }
            }
            Poll::Ready(Err(error)) => {
                pending.wake_waiters();
                self.buffer = pending.bytes;
                Poll::Ready(Err(error))
            }
        }
    }
}

#[derive(Clone, Copy)]
enum WriteKind {
    Normal,
    #[cfg(ossl111)]
    Early,
}

impl WriteKind {
    fn zero_is_success(self) -> bool {
        match self {
            Self::Normal => false,
            #[cfg(ossl111)]
            Self::Early => true,
        }
    }
}

/// An asynchronous version of [`openssl::ssl::SslStream`].
///
/// Each write stages at most 16 KiB. If it returns `Pending`, that chunk remains queued for an
/// OpenSSL retry. Cancelling the write future does not discard the staged chunk; the next TLS
/// operation retries it first. The rest of the original input is not retained. This also
/// applies to TLS 1.3 early-data writes.
/// A cancelled [`AsyncWrite::poll_write`] followed by a new write from the same address and with
/// the same length and staged prefix cannot be distinguished from polling the original write
/// again. Use [`write_cancellable`](Self::write_cancellable) for distinct write operations, or
/// flush the stream before reusing that buffer for a separate trait write.
pub struct SslStream<S: Unpin> {
    inner: ssl::SslStream<StreamWrapper<S>>,
    // OpenSSL requires a pending write to be retried with the same bytes and length.
    write: WriteState,
    #[cfg(ossl111)]
    early_write: WriteState,
    next_write_id: u64,
    /// Whether `close_notify` has already been handed to the peer by
    /// [`poll_close`](AsyncWrite::poll_close). See that method for why this has to be remembered
    /// across polls.
    close_notify_sent: bool,
}

impl<S> fmt::Debug for SslStream<S>
where
    S: fmt::Debug + Unpin,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_tuple("SslStream").field(&self.inner).finish()
    }
}

impl<S> SslStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Like [`SslStream::new`](ssl::SslStream::new).
    pub fn new(ssl: Ssl, stream: S) -> Result<Self, ErrorStack> {
        ssl::SslStream::new(
            ssl,
            StreamWrapper {
                stream,
                waker: None,
            },
        )
        .map(|inner| SslStream {
            inner,
            write: WriteState::default(),
            #[cfg(ossl111)]
            early_write: WriteState::default(),
            next_write_id: 0,
            close_notify_sent: false,
        })
    }

    /// Writes once, keeping this call distinct from later calls with the same buffer.
    ///
    /// If this future is cancelled while a write is pending, a later write or flush finishes the
    /// queued bytes. A subsequent call to `write_cancellable` then sends a separate copy even if
    /// it uses the same buffer. The returned count may be less than `buf.len()`.
    pub async fn write_cancellable(mut self: Pin<&mut Self>, buf: &[u8]) -> io::Result<usize> {
        let id = self.as_mut().get_mut().allocate_write_id();
        future::poll_fn(|cx| self.as_mut().poll_write_inner(cx, buf, Some(id))).await
    }

    /// Like [`SslStream::connect`](ssl::SslStream::connect).
    pub fn poll_connect(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ssl::Error>> {
        std::task::ready!(self.as_mut().poll_finish_pending_writes(cx))?;
        self.as_mut().with_context(cx, |s| cvt_ossl(s.connect()))
    }

    /// A convenience method wrapping [`poll_connect`](Self::poll_connect).
    pub async fn connect(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_connect(cx)).await
    }

    /// Like [`SslStream::accept`](ssl::SslStream::accept).
    pub fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ssl::Error>> {
        std::task::ready!(self.as_mut().poll_finish_pending_writes(cx))?;
        self.as_mut().with_context(cx, |s| cvt_ossl(s.accept()))
    }

    /// A convenience method wrapping [`poll_accept`](Self::poll_accept).
    pub async fn accept(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_accept(cx)).await
    }

    /// Like [`SslStream::do_handshake`](ssl::SslStream::do_handshake).
    pub fn poll_do_handshake(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ssl::Error>> {
        std::task::ready!(self.as_mut().poll_finish_pending_writes(cx))?;
        self.as_mut()
            .with_context(cx, |s| cvt_ossl(s.do_handshake()))
    }

    /// A convenience method wrapping [`poll_do_handshake`](Self::poll_do_handshake).
    pub async fn do_handshake(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_do_handshake(cx)).await
    }

    /// Like [`SslStream::ssl_peek`](ssl::SslStream::ssl_peek).
    pub fn poll_peek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ssl::Error>> {
        // `SSL_peek_ex` reports a zero-length peek as a failure with `WANT_READ`, which we would
        // translate into a `Pending` that never resolves. Nothing can be peeked into an empty
        // buffer anyway, so answer directly and match what `poll_read` does for an empty buffer.
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        std::task::ready!(self.as_mut().poll_finish_pending_writes(cx))?;
        self.as_mut()
            .with_context(cx, |s| cvt_ossl(s.ssl_peek(buf)))
    }

    /// A convenience method wrapping [`poll_peek`](Self::poll_peek).
    pub async fn peek(mut self: Pin<&mut Self>, buf: &mut [u8]) -> Result<usize, ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_peek(cx, buf)).await
    }

    /// Like [`SslStream::read_early_data`](ssl::SslStream::read_early_data).
    #[cfg(ossl111)]
    pub fn poll_read_early_data(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ssl::Error>> {
        std::task::ready!(self.as_mut().poll_finish_pending_writes(cx))?;
        self.with_context(cx, |s| cvt_ossl(s.read_early_data(buf)))
    }

    /// A convenience method wrapping [`poll_read_early_data`](Self::poll_read_early_data).
    #[cfg(ossl111)]
    pub async fn read_early_data(
        mut self: Pin<&mut Self>,
        buf: &mut [u8],
    ) -> Result<usize, ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_read_early_data(cx, buf)).await
    }

    /// Like [`SslStream::write_early_data`](ssl::SslStream::write_early_data).
    ///
    /// If this returns `Pending`, the bytes are retained for a retry. Flush before using the same
    /// buffer for a separate write after cancellation, or use
    /// [`write_early_data`](Self::write_early_data) to distinguish separate calls.
    #[cfg(ossl111)]
    pub fn poll_write_early_data(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, ssl::Error>> {
        self.poll_write_operation(cx, buf, None, WriteKind::Early)
    }

    /// Writes TLS 1.3 early data as a distinct operation, including after cancellation.
    ///
    /// If this future is cancelled while an early-data write is pending, a later write or flush
    /// finishes the queued bytes. A subsequent call sends a separate copy even if it uses the
    /// same buffer. The returned count may be less than `buf.len()`.
    #[cfg(ossl111)]
    pub async fn write_early_data(
        mut self: Pin<&mut Self>,
        buf: &[u8],
    ) -> Result<usize, ssl::Error> {
        let id = self.as_mut().get_mut().allocate_write_id();
        future::poll_fn(|cx| {
            self.as_mut()
                .poll_write_operation(cx, buf, Some(id), WriteKind::Early)
        })
        .await
    }
}

impl<S: Unpin> SslStream<S> {
    /// Returns a shared reference to the `Ssl` object associated with this stream.
    #[must_use]
    pub fn ssl(&self) -> &SslRef {
        self.inner.ssl()
    }

    /// Returns a shared reference to the underlying stream.
    #[must_use]
    pub fn get_ref(&self) -> &S {
        &self.inner.get_ref().stream
    }

    /// Returns a mutable reference to the underlying stream.
    ///
    /// # Warning
    ///
    /// Reading from or writing to the underlying stream directly will corrupt the TLS session.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner.get_mut().stream
    }

    /// Returns a pinned mutable reference to the underlying stream.
    ///
    /// # Warning
    ///
    /// Reading from or writing to the underlying stream directly will corrupt the TLS session.
    #[must_use]
    pub fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut S> {
        Pin::new(&mut self.get_mut().inner.get_mut().stream)
    }

    fn with_context<F, R>(self: Pin<&mut Self>, ctx: &mut Context<'_>, f: F) -> R
    where
        F: FnOnce(&mut ssl::SslStream<StreamWrapper<S>>) -> R,
    {
        let this = self.get_mut();
        match &mut this.inner.get_mut().waker {
            // `Waker::clone_from` skips the refcount traffic when the task did not change, which
            // is the common case across the repeated polls of a single read or write.
            Some(waker) => waker.clone_from(ctx.waker()),
            waker @ None => *waker = Some(ctx.waker().clone()),
        }
        f(&mut this.inner)
    }
}

impl<S> AsyncRead for SslStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        std::task::ready!(self.as_mut().poll_finish_pending_writes(ctx))
            .map_err(ssl_error_to_io)?;
        self.as_mut().with_context(ctx, |s| cvt(s.read(buf)))
    }
}

impl<S> AsyncWrite for SslStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, ctx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.poll_write_inner(ctx, buf, None)
    }

    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
        std::task::ready!(self.as_mut().poll_finish_pending_writes(ctx))
            .map_err(ssl_error_to_io)?;
        self.as_mut().get_mut().recycle_completed_writes();
        self.with_context(ctx, |s| cvt(s.flush()))
    }

    fn poll_close(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
        std::task::ready!(self.as_mut().poll_finish_pending_writes(ctx))
            .map_err(ssl_error_to_io)?;
        self.as_mut().get_mut().recycle_completed_writes();
        // We send close_notify but do not wait for the peer's reply before closing the
        // underlying stream. This is permitted by RFC 8446 §6.1 and avoids a half-close
        // deadlock, but it means any in-flight data from the peer is silently discarded.
        //
        // Sending it is a one-shot step, so it has to be remembered: once our close_notify is
        // out, a further `SSL_shutdown` moves on to the second phase and waits for the peer's
        // close_notify, reporting `WANT_READ` until it arrives. Calling it again on a re-poll
        // would therefore reintroduce exactly the half-close deadlock we mean to avoid, and the
        // underlying stream would never be closed.
        if !self.close_notify_sent {
            match self.as_mut().with_context(ctx, |s| s.shutdown()) {
                Ok(ShutdownResult::Sent | ShutdownResult::Received) => {}
                Err(ref e) if e.code() == ErrorCode::ZERO_RETURN => {}
                Err(ref e)
                    if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE =>
                {
                    return Poll::Pending;
                }
                Err(e) => {
                    return Poll::Ready(Err(ssl_error_to_io(e)));
                }
            }
            self.as_mut().get_mut().close_notify_sent = true;
        }

        self.get_pin_mut().poll_close(ctx)
    }
}

impl<S> SslStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_ssl_write_kind(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
        kind: WriteKind,
    ) -> Poll<Result<usize, ssl::Error>> {
        match kind {
            WriteKind::Normal => self.with_context(ctx, |s| {
                loop {
                    match s.ssl_write(buf) {
                        // Match `openssl::ssl::SslStream`'s `Write` implementation: OpenSSL can
                        // ask for an internal read retry without polling the underlying stream.
                        Err(ref e)
                            if e.code() == ErrorCode::WANT_READ && e.io_error().is_none() => {}
                        result => break cvt_ossl(result),
                    }
                }
            }),
            #[cfg(ossl111)]
            WriteKind::Early => self.with_context(ctx, |s| cvt_ossl(s.write_early_data(buf))),
        }
    }

    fn allocate_write_id(&mut self) -> u64 {
        let id = self.next_write_id;
        self.next_write_id = id.wrapping_add(1);
        id
    }

    fn write_state_mut(&mut self, kind: WriteKind) -> &mut WriteState {
        match kind {
            WriteKind::Normal => &mut self.write,
            #[cfg(ossl111)]
            WriteKind::Early => &mut self.early_write,
        }
    }

    fn recycle_completed_writes(&mut self) {
        self.write.recycle_completion();
        #[cfg(ossl111)]
        self.early_write.recycle_completion();
    }

    fn poll_write_inner(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
        operation_id: Option<u64>,
    ) -> Poll<io::Result<usize>> {
        self.poll_write_operation(ctx, buf, operation_id, WriteKind::Normal)
            .map(|result| result.map_err(ssl_error_to_io))
    }

    fn poll_write_operation(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
        operation_id: Option<u64>,
        kind: WriteKind,
    ) -> Poll<Result<usize, ssl::Error>> {
        if matches!(kind, WriteKind::Normal) && buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Finish a write of the other kind before starting or resuming this one.
        #[cfg(ossl111)]
        {
            let other = match kind {
                WriteKind::Normal => WriteKind::Early,
                WriteKind::Early => WriteKind::Normal,
            };
            std::task::ready!(self.as_mut().poll_finish_pending_write_kind(ctx, other))?;
        }

        self.as_mut()
            .get_mut()
            .write_state_mut(kind)
            .register_writer(buf, operation_id, ctx.waker());
        std::task::ready!(self.as_mut().poll_finish_pending_write_kind(ctx, kind))?;
        if let Some(written) = self
            .as_mut()
            .get_mut()
            .write_state_mut(kind)
            .take_completion(buf, operation_id)
        {
            return Poll::Ready(Ok(written));
        }
        // Stage at most one TLS record in a reusable buffer. A cancelled future may leave the
        // caller's buffer unavailable, and OpenSSL requires the same bytes and address on retry.
        let bytes = std::mem::take(&mut self.as_mut().get_mut().write_state_mut(kind).buffer);
        let pending = PendingWrite::new(buf, operation_id, bytes);
        let result = self
            .as_mut()
            .poll_ssl_write_kind(ctx, pending.staged(), kind);
        self.get_mut()
            .write_state_mut(kind)
            .finish_initial(pending, ctx.waker(), result)
    }

    // Other TLS operations finish queued early-data writes before normal writes. Write entry
    // points finish the other kind first, then register the original writer for their own kind.
    fn poll_finish_pending_writes(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
    ) -> Poll<Result<(), ssl::Error>> {
        #[cfg(ossl111)]
        std::task::ready!(
            self.as_mut()
                .poll_finish_pending_write_kind(ctx, WriteKind::Early)
        )?;
        std::task::ready!(
            self.as_mut()
                .poll_finish_pending_write_kind(ctx, WriteKind::Normal)
        )?;
        Poll::Ready(Ok(()))
    }

    fn poll_finish_pending_write_kind(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        kind: WriteKind,
    ) -> Poll<Result<(), ssl::Error>> {
        let Some(mut pending) = self.as_mut().get_mut().write_state_mut(kind).pending.take() else {
            return Poll::Ready(Ok(()));
        };
        pending.set_other_waker(ctx.waker());
        let result = if let Some(waker) = pending.combined_waker() {
            let mut combined_context = Context::from_waker(&waker);
            self.as_mut()
                .poll_ssl_write_kind(&mut combined_context, pending.staged(), kind)
        } else {
            self.as_mut()
                .poll_ssl_write_kind(ctx, pending.staged(), kind)
        };
        self.get_mut()
            .write_state_mut(kind)
            .finish_retry(pending, result, kind.zero_is_success())
    }
}
