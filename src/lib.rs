//! Async TLS streams backed by OpenSSL.
//!
//! This crate provides [`SslStream`], a wrapper around the [`openssl`] crate's
//! [`SslStream`](ssl::SslStream) type that works with [`futures_io`]'s [`AsyncRead`] and
//! [`AsyncWrite`] traits rather than std's blocking [`Read`] and [`Write`] traits. Its output is
//! buffered: see [`SslStream`] for what that means for flushing, closing and errors.
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
    ssl::{self, ErrorCode, ShutdownState, Ssl, SslRef},
};
use std::{
    any::Any,
    fmt, future,
    io::{self, Read, Write},
    mem,
    panic::{self, AssertUnwindSafe},
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

#[cfg(test)]
mod test;

// Compiles the README's example as a doctest.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

/// The most bytes that one write hands to OpenSSL, which bounds the output it can leave unsent.
const WRITE_CHUNK_SIZE: usize = 16 * 1024;

/// How much output may wait for the transport before reads wait for it too. A write leaves at
/// most one chunk; the rest is what OpenSSL writes by itself while reading or handshaking.
const MAX_UNSENT: usize = 4 * WRITE_CHUNK_SIZE;

/// How many tasks a [`WakerSet`] keeps.
const MAX_WAITERS: usize = 32;

fn chunk(buf: &[u8]) -> &[u8] {
    &buf[..buf.len().min(WRITE_CHUNK_SIZE)]
}

/// The tasks waiting on a stream.
///
/// The transport always gets this set's waker, which wakes every waiting task: OpenSSL may read
/// while writing and write while reading, so any transport event may be what a task waits for. A
/// stable waker keeps a transport that keeps one waker (tokio, per direction) from dropping a task,
/// and one that wakes the waker it replaces (async-io) from making tasks wake each other. Every
/// event thus wakes every task; a set per direction would lose tasks on a transport that keeps one
/// waker for both.
///
/// A task joins when its operation returns `Pending` and leaves when woken; `generation` catches a
/// transport wake that came before it joined. A full set is woken and emptied before it takes a
/// new task, so stale wakers cost a wake each but cannot grow it. More than `MAX_WAITERS` tasks
/// waiting at once keep waking each other.
#[derive(Default)]
struct WakerSet {
    waiters: Mutex<Vec<Waiter>>,
    /// How many times the transport woke the set. It only changes with `waiters` locked.
    generation: AtomicUsize,
}

struct Waiter {
    waker: Waker,
    /// Whether the task waits for records, which another task's read may take, rather than for
    /// the transport to take output.
    records: bool,
}

impl WakerSet {
    fn lock(&self) -> MutexGuard<'_, Vec<Waiter>> {
        self.waiters.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn generation(&self) -> usize {
        self.generation.load(Ordering::Acquire)
    }

    /// Adds a task, or wakes it at once if the transport woke the set since `generation`.
    fn join(&self, waker: &Waker, records: bool, generation: usize) {
        let mut waiters = self.lock();
        if self.generation.load(Ordering::Relaxed) != generation {
            drop(waiters);
            waker.wake_by_ref();
            return;
        }
        if let Some(waiter) = waiters.iter_mut().find(|w| w.waker.will_wake(waker)) {
            waiter.records |= records;
            return;
        }
        let waiter = Waiter {
            waker: waker.clone(),
            records,
        };
        if waiters.len() < MAX_WAITERS {
            waiters.push(waiter);
        } else {
            let evicted = mem::replace(&mut *waiters, vec![waiter]);
            drop(waiters);
            self.wake_all(evicted);
        }
    }

    /// Wakes the waiting tasks, or only those waiting for records.
    fn wake_tasks(&self, by_transport: bool, records_only: bool) {
        let woken = {
            let mut waiters = self.lock();
            if by_transport {
                self.generation.fetch_add(1, Ordering::Release);
            }
            if waiters.is_empty() || (records_only && !waiters.iter().any(|w| w.records)) {
                return;
            }
            let all = mem::take(&mut *waiters);
            if records_only {
                let (woken, kept) = all.into_iter().partition(|waiter| waiter.records);
                *waiters = kept;
                woken
            } else {
                all
            }
        };
        self.wake_all(woken);
    }

    /// Wakes `wakers` and reuses their allocation for the set. If a waker panics, those not woken
    /// yet go back into the set.
    fn wake_all(&self, wakers: Vec<Waiter>) {
        struct Requeue<'a> {
            set: &'a WakerSet,
            wakers: Vec<Waiter>,
            next: usize,
        }

        impl Drop for Requeue<'_> {
            fn drop(&mut self) {
                if self.next < self.wakers.len() {
                    let rest = self.wakers.drain(self.next..);
                    self.set.lock().extend(rest);
                }
            }
        }

        let mut requeue = Requeue {
            set: self,
            wakers,
            next: 0,
        };
        while let Some(waiter) = requeue.wakers.get(requeue.next) {
            requeue.next += 1;
            waiter.waker.wake_by_ref();
        }
        let mut wakers = mem::take(&mut requeue.wakers);
        wakers.clear();
        let mut waiters = self.lock();
        if waiters.capacity() == 0 {
            *waiters = wakers;
        }
    }
}

impl Wake for WakerSet {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_tasks(true, false);
    }
}

/// Runs `f`, which calls OpenSSL, on an empty error queue, then puts the thread's entries back.
/// OpenSSL and LibreSSL take any queued entry as the reason a call failed, even a call that only
/// has to be retried, and the entries belong to other code, such as an OpenSSL call that uses this
/// stream as its transport.
fn keeping_foreign_errors<T>(f: impl FnOnce() -> T) -> T {
    let foreign = ErrorStack::get();
    let result = f();
    foreign.put();
    result
}

/// Whether the handshake is finished. rust-openssl binds `SSL_is_init_finished` for OpenSSL only;
/// both libraries describe that state the same way.
fn handshake_finished(ssl: &SslRef) -> bool {
    ssl.state_string_long() == "SSL negotiation finished successfully"
}

/// Writes `buf` from `*written` on until the transport took all of it, returned `Pending` or
/// failed.
fn poll_write_all<S: AsyncWrite + ?Sized>(
    mut stream: Pin<&mut S>,
    cx: &mut Context<'_>,
    buf: &[u8],
    written: &mut usize,
) -> Poll<io::Result<()>> {
    while *written < buf.len() {
        let left = buf.len() - *written;
        match std::task::ready!(stream.as_mut().poll_write(cx, &buf[*written..]))? {
            0 => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
            n if n > left => {
                let error = "the transport reported writing more than it was given";
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error)));
            }
            n => *written += n,
        }
    }
    Poll::Ready(Ok(()))
}

/// Where a transport error goes when an OpenSSL call meets one: a read error, or a failure to send
/// buffered output when the call would otherwise wait for the peer, who may be waiting for it.
#[derive(Clone, Copy, Default)]
enum ErrorPath {
    /// To OpenSSL, as the error of a transport read: the only way rust-openssl puts an `io::Error`
    /// in an `ssl::Error`. OpenSSL 4 then fails the session unless rust-openssl asks it to retry,
    /// and LibreSSL reports an error of its own.
    #[default]
    ThroughOpenSsl,
    /// To the caller, through `Call`: OpenSSL only sees a read that would wait, and the session
    /// stays usable.
    ToCaller,
}

/// What the last transport read of an OpenSSL call did.
#[derive(Clone, Copy, Default)]
enum LastRead {
    /// The read got data, or the call made no read.
    #[default]
    Data,
    Eof,
    /// The BIO told OpenSSL to wait: the transport will wake the stream's tasks, or the call has
    /// an error for the caller.
    Waiting,
    /// The BIO gave OpenSSL an error.
    Failed,
}

/// What the transport did during one OpenSSL call.
///
/// The errors are `AssertUnwindSafe` to keep `SslStream` unwind safe: an `io::Error` never changes
/// once made, so a panic cannot leave one broken.
#[derive(Default)]
struct Call {
    path: ErrorPath,
    read: LastRead,
    /// The transport refused or failed to take output, so it is not asked again during this call.
    send_blocked: bool,
    /// Why sending the buffered output failed. That output stays buffered.
    write_error: Option<AssertUnwindSafe<io::Error>>,
    /// A transport read error kept from OpenSSL (`ErrorPath::ToCaller`).
    read_error: Option<AssertUnwindSafe<io::Error>>,
    /// A transport error kept from OpenSSL that the next read hands it, as the reason the call
    /// fails.
    inject: Option<AssertUnwindSafe<io::Error>>,
}

/// What the transport did during one operation of the stream, which can make several OpenSSL
/// calls.
#[derive(Default)]
struct Op {
    /// A read got records, which tasks waiting for records may have waited for.
    read_progress: bool,
    /// A send failed, which every waiting task has to retry or report.
    send_failed: bool,
    /// A read waits for the transport, rather than for the transport to take output.
    read_wait: bool,
}

/// How [`StreamWrapper::poll_send`] flushes the transport after sending the buffered output.
#[derive(Clone, Copy)]
enum Flush {
    /// If OpenSSL asked for a flush.
    Requested,
    /// Also if output was written since the transport's last flush.
    Unflushed,
    /// Always.
    Always,
}

/// The transport, as OpenSSL sees it through rust-openssl's BIO.
///
/// Writes never wait: what the transport does not take at once is buffered and sent first. So
/// OpenSSL never holds a record it must retry with the same bytes, and what it writes on its own,
/// such as a session ticket or a key update during a read, never fails on a pending write.
struct StreamWrapper<S: Unpin> {
    stream: S,
    wakers: Arc<WakerSet>,
    /// The waker of `wakers`, which the transport always gets.
    waker: Waker,
    /// TLS output, of which the transport took the first `sent` bytes.
    out: Vec<u8>,
    sent: usize,
    /// Whether OpenSSL asked for a transport flush that has not completed yet.
    flush_needed: bool,
    /// Whether output was written, to the transport or to `out`, since the transport's last flush.
    unflushed: bool,
    /// The generation of `wakers` at which the transport last refused output (`Pending`), if not
    /// polled since: OpenSSL calls do not ask it again until it wakes the set. A transport that
    /// failed is asked again.
    refused: Option<usize>,
    /// Whether a transport poll panicked: the transport may have taken part of a record, so
    /// nothing else may go through it.
    poisoned: bool,
    /// The payload of that panic, resumed once the operation's bookkeeping is done.
    panic: Mutex<Option<Box<dyn Any + Send>>>,
    /// Whether the stream was closed.
    close: Close,
    op: Op,
    call: Call,
}

impl<S> fmt::Debug for StreamWrapper<S>
where
    S: fmt::Debug + Unpin,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("StreamWrapper")
            .field("stream", &self.stream)
            .field("unsent", &self.unsent())
            .field("flush_needed", &self.flush_needed)
            .field("unflushed", &self.unflushed)
            .field("poisoned", &self.poisoned)
            .field("close", &self.close)
            .finish_non_exhaustive()
    }
}

impl<S: Unpin> StreamWrapper<S> {
    fn unsent(&self) -> usize {
        self.out.len() - self.sent
    }
}

impl<S: AsyncWrite + Unpin> StreamWrapper<S> {
    fn new(stream: S) -> Self {
        let wakers = Arc::<WakerSet>::default();
        Self {
            stream,
            waker: Waker::from(wakers.clone()),
            wakers,
            out: Vec::new(),
            sent: 0,
            flush_needed: false,
            unflushed: false,
            refused: None,
            poisoned: false,
            panic: Mutex::new(None),
            close: Close::Open,
            op: Op::default(),
            call: Call::default(),
        }
    }

    fn check_poisoned(&self) -> io::Result<()> {
        if self.poisoned {
            let error = "the transport panicked during an earlier call";
            return Err(io::Error::other(error));
        }
        Ok(())
    }

    /// Polls the transport with the stream's waker, unless an earlier poll panicked. A panic fails
    /// the poll, poisons the stream, and is resumed at the end of the operation, even where
    /// OpenSSL ignores the failure.
    fn poll_transport<T>(
        &mut self,
        poll: impl FnOnce(Pin<&mut S>, &mut Context<'_>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        self.check_poisoned()?;
        let stream = Pin::new(&mut self.stream);
        let mut cx = Context::from_waker(&self.waker);
        match panic::catch_unwind(AssertUnwindSafe(|| poll(stream, &mut cx))) {
            Ok(result) => result,
            Err(payload) => {
                self.poisoned = true;
                *self.panic.get_mut().unwrap_or_else(PoisonError::into_inner) = Some(payload);
                Poll::Ready(Err(io::Error::other("the transport panicked")))
            }
        }
    }

    /// Polls the transport to take output, noting a refusal (`refused`) or a failure
    /// (`Op::send_failed`).
    fn poll_output<T>(
        &mut self,
        poll: impl FnOnce(Pin<&mut S>, &mut Context<'_>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        let generation = self.wakers.generation();
        let result = self.poll_transport(poll);
        self.refused = result.is_pending().then_some(generation);
        if let Poll::Ready(Err(_)) = result {
            self.op.send_failed = true;
        }
        result
    }

    /// Sends the buffered output, then flushes the transport as `flush` says.
    fn poll_send(&mut self, flush: Flush) -> Poll<io::Result<()>> {
        if let Err(error) = self.check_poisoned() {
            self.op.send_failed = true;
            return Poll::Ready(Err(error));
        }
        if self.unsent() > 0 {
            let out = mem::take(&mut self.out);
            let mut sent = self.sent;
            let result = self.poll_output(|stream, cx| poll_write_all(stream, cx, &out, &mut sent));
            (self.out, self.sent) = (out, sent);
            std::task::ready!(result)?;
            // Only a slow transport needs the buffer: keep enough memory for a full chunk's record.
            self.out.clear();
            self.out.shrink_to(2 * WRITE_CHUNK_SIZE);
            self.sent = 0;
        }
        let needed = match flush {
            Flush::Requested => self.flush_needed,
            Flush::Unflushed => self.flush_needed || self.unflushed,
            Flush::Always => true,
        };
        if needed {
            std::task::ready!(self.poll_output(|stream, cx| stream.poll_flush(cx)))?;
            self.flush_needed = false;
            self.unflushed = false;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close(&mut self) -> Poll<io::Result<()>> {
        self.poll_transport(|stream, cx| stream.poll_close(cx))
    }

    /// Whether an OpenSSL call may ask the transport to take output.
    fn may_send(&self) -> bool {
        !self.call.send_blocked && self.refused != Some(self.wakers.generation())
    }

    /// Prepares for an OpenSSL call.
    fn start_call(&mut self, path: ErrorPath) {
        self.call = Call {
            path,
            ..Call::default()
        };
    }

    /// Sends the buffered output as far as the transport allows during an OpenSSL call.
    fn send(&mut self, flush: Flush) {
        if !self.may_send() {
            return;
        }
        let result = self.poll_send(flush);
        self.note_send(result);
    }

    /// Records what sending during an OpenSSL call did: a transport that refused or failed is not
    /// asked again during the call, and its error is kept.
    fn note_send(&mut self, result: Poll<io::Result<()>>) {
        match result {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => {
                self.call.send_blocked = true;
                self.call.write_error = Some(AssertUnwindSafe(error));
            }
            Poll::Pending => self.call.send_blocked = true,
        }
    }

    /// Tells OpenSSL to wait.
    fn wait(&mut self) -> io::Result<usize> {
        self.call.read = LastRead::Waiting;
        Err(io::ErrorKind::WouldBlock.into())
    }

    fn read_failed(&mut self, error: io::Error) -> io::Result<usize> {
        match self.call.path {
            ErrorPath::ThroughOpenSsl => {
                self.call.read = LastRead::Failed;
                Err(error)
            }
            ErrorPath::ToCaller => {
                self.call.read_error = Some(AssertUnwindSafe(error));
                self.wait()
            }
        }
    }

    /// Fails with the error that kept output from being sent, if any, as the peer may never answer
    /// output it did not get. Otherwise tells OpenSSL to wait.
    fn fail_or_wait(&mut self) -> io::Result<usize> {
        match self.call.write_error.take() {
            Some(AssertUnwindSafe(error)) => self.read_failed(error),
            None => self.wait(),
        }
    }

    /// Takes the transport error that an `ErrorPath::ToCaller` call kept from OpenSSL.
    fn kept_error(&mut self) -> Option<io::Error> {
        (self.call.read_error.take())
            .or_else(|| self.call.write_error.take())
            .map(|AssertUnwindSafe(error)| error)
    }
}

impl<S> Read for StreamWrapper<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(AssertUnwindSafe(error)) = self.call.inject.take() {
            self.call.read = LastRead::Failed;
            return Err(error);
        }
        // What OpenSSL waits for may be the answer to the output, so send it first.
        self.send(Flush::Requested);
        // Bound what OpenSSL writes by itself while reading: past the limit, wait for the
        // transport to take it, or report why it cannot.
        if self.unsent() > MAX_UNSENT {
            return self.fail_or_wait();
        }
        let len = buf.len();
        match self.poll_transport(|stream, cx| stream.poll_read(cx, buf)) {
            Poll::Ready(Ok(0)) => {
                self.call.read = LastRead::Eof;
                Ok(0)
            }
            Poll::Ready(Ok(n)) if n > len => {
                let error = "the transport reported reading more than it was given";
                self.read_failed(io::Error::new(io::ErrorKind::InvalidData, error))
            }
            Poll::Ready(Ok(n)) => {
                self.call.read = LastRead::Data;
                self.op.read_progress = true;
                Ok(n)
            }
            Poll::Ready(Err(error)) => self.read_failed(error),
            Poll::Pending => {
                self.op.read_wait = true;
                // Before waiting for the peer, make sure that it got what was written: some
                // transports only send on flush, and some TLS libraries never ask for one.
                self.send(Flush::Unflushed);
                self.fail_or_wait()
            }
        }
    }
}

impl<S> Write for StreamWrapper<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Nothing more may go out after a transport panic, and OpenSSL may as well know.
        self.check_poisoned()?;
        let mut written = 0;
        // Skip the copy when nothing is buffered, which is the common case.
        if self.out.is_empty() && self.may_send() {
            let result =
                self.poll_output(|stream, cx| poll_write_all(stream, cx, buf, &mut written));
            self.note_send(result);
        } else if self.sent > 0 && self.sent >= self.unsent() {
            // Drop what the transport took once that is at least what is left, so that a transport
            // that keeps taking part of the output cannot make the buffer grow without bound.
            self.out.drain(..self.sent);
            self.sent = 0;
        }
        self.out.extend_from_slice(&buf[written..]);
        self.unflushed = true;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // Never fails: a failed flush leaves `SSL_write_early_data` counting its next bytes as
        // written without writing them. The next send finishes the flush.
        self.flush_needed = true;
        self.send(Flush::Requested);
        Ok(())
    }
}

/// Whether [`AsyncWrite::poll_close`] closed the stream.
#[derive(Debug)]
enum Close {
    Open,
    /// `close_notify` was written. Calling `SSL_shutdown` again would wait for the peer's.
    Sent,
    /// No session to close (no handshake, a handshake or post-handshake exchange in progress, or a
    /// failed session): the transport is closed anyway, and the close that closes it returns
    /// OpenSSL's reason, if any.
    NoSession(Option<AssertUnwindSafe<io::Error>>),
}

/// An asynchronous version of [`openssl::ssl::SslStream`].
///
/// # Buffered output
///
/// OpenSSL writes into a buffer, from which the transport takes what it can. As with a
/// [`BufWriter`](std::io::BufWriter), a write completes once OpenSSL has encrypted its bytes, and
/// a handshake call can complete with its last flight still buffered. Buffered output goes out
/// with later writes, flushes and closes, and with reads, peeks and handshake calls that read from
/// the transport, which flush it before they wait for the peer. [`flush`](AsyncWrite::poll_flush)
/// returns once everything was sent and the transport flushed. [`close`](AsyncWrite::poll_close)
/// the stream rather than drop it, or close or flush its transport directly, or buffered output is
/// lost.
///
/// A write first waits for buffered output, and for a transport flush that OpenSSL asked for:
/// until then it returns `Pending` without writing, so it can be dropped or polled again with
/// other bytes. Each write hands OpenSSL at most 16 KiB. Reads, peeks and handshake calls do not
/// wait for output, so a peer that stops reading until it is read from cannot deadlock the
/// stream, unless more than 64 KiB is waiting (what OpenSSL wrote by itself while reading or
/// handshaking, on top of what writes left).
///
/// # Errors
///
/// A transport error while sending buffered output is returned by the write, flush or close that
/// sends it, or by a call that would otherwise wait for the peer, who may be waiting for that
/// output. A write whose own bytes the transport refuses still completes: OpenSSL wrote them. The
/// output stays buffered and the error is not kept: a later call reports it if it recurs, so a
/// transient error loses nothing.
///
/// Reads and writes return transport errors as they were, without passing them to OpenSSL.
/// Peeks, handshake calls and [`read_early_data`](Self::read_early_data) return them through
/// OpenSSL, inside an [`ssl::Error`]. OpenSSL 4 then fails the session, unless the error is
/// [`WouldBlock`](io::ErrorKind::WouldBlock) or [`NotConnected`](io::ErrorKind::NotConnected),
/// which rust-openssl asks it to retry. LibreSSL replaces the error with its own, and may report
/// the transport error again later as the cause of an unrelated end of stream.
/// [`write_early_data`](Self::write_early_data) never returns them.
///
/// A transport end without `close_notify` after the handshake reads as the end of the stream on
/// OpenSSL 1.1.1, 3.x and LibreSSL, as with rust-openssl's own streams. On OpenSSL 4 it is an
/// error, and a close then fails too, unless the session has `SslOptions::IGNORE_UNEXPECTED_EOF`.
/// A transport end or a `close_notify` during a handshake that a read drives, renegotiation
/// included, is always an error.
///
/// # Closing
///
/// A close sends the output left, writes `close_notify` once, sends it and closes the transport.
/// If it cannot send, it returns the error without closing the transport, so that closing again
/// retries; dropping the stream releases the transport. After the peer's `close_notify`, failing
/// to send ours is no error. If there is no session to close (no handshake, a handshake or a
/// post-handshake exchange in progress, or a session that failed), the close closes the transport
/// and returns OpenSSL's reason, if it gave one, or the transport's error if closing it failed;
/// every later close returns an error too.
///
/// # Tasks
///
/// Waiting tasks are woken when the transport is ready or another task's call failed to send, and
/// those waiting for the peer also when another task's call read from the transport. Keep one
/// waker per task: each new one costs an extra wake, and more than 32 tasks waiting at once keep
/// waking each other.
///
/// A panic in the transport poisons the stream: every later call that uses the transport fails.
pub struct SslStream<S: Unpin> {
    inner: ssl::SslStream<StreamWrapper<S>>,
}

impl<S> fmt::Debug for SslStream<S>
where
    S: fmt::Debug + Unpin,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("SslStream")
            .field("stream", self.inner.get_ref())
            .field("ssl", self.inner.ssl())
            .finish()
    }
}

impl<S> SslStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Like [`SslStream::new`](ssl::SslStream::new).
    pub fn new(ssl: Ssl, stream: S) -> Result<Self, ErrorStack> {
        ssl::SslStream::new(ssl, StreamWrapper::new(stream)).map(|inner| SslStream { inner })
    }

    /// Like [`SslStream::connect`](ssl::SslStream::connect).
    ///
    /// It can complete while its last flight is still [buffered](Self#buffered-output), and
    /// returns transport errors through OpenSSL, as [described](Self#errors).
    pub fn poll_connect(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ssl::Error>> {
        self.poll_ssl_op(cx, |s| s.connect())
    }

    /// A convenience method wrapping [`poll_connect`](Self::poll_connect).
    pub async fn connect(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_connect(cx)).await
    }

    /// Like [`SslStream::accept`](ssl::SslStream::accept).
    ///
    /// It can complete while its last flight is still [buffered](Self#buffered-output), and
    /// returns transport errors through OpenSSL, as [described](Self#errors).
    pub fn poll_accept(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ssl::Error>> {
        self.poll_ssl_op(cx, |s| s.accept())
    }

    /// A convenience method wrapping [`poll_accept`](Self::poll_accept).
    pub async fn accept(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_accept(cx)).await
    }

    /// Like [`SslStream::do_handshake`](ssl::SslStream::do_handshake).
    ///
    /// It can complete while its last flight is still [buffered](Self#buffered-output), and
    /// returns transport errors through OpenSSL, as [described](Self#errors).
    pub fn poll_do_handshake(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ssl::Error>> {
        self.poll_ssl_op(cx, |s| s.do_handshake())
    }

    /// A convenience method wrapping [`poll_do_handshake`](Self::poll_do_handshake).
    pub async fn do_handshake(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_do_handshake(cx)).await
    }

    /// Like [`SslStream::ssl_peek`](ssl::SslStream::ssl_peek).
    ///
    /// Like a read, it sends [buffered output](Self#buffered-output) without waiting for it
    /// below the limit, and it returns transport errors through OpenSSL, as
    /// [described](Self#errors).
    pub fn poll_peek(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ssl::Error>> {
        // A zero-length `SSL_peek_ex` waits for a record, then fails. There is nothing to peek
        // into an empty buffer anyway.
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.poll_ssl_op(cx, |s| s.ssl_peek(buf))
    }

    /// A convenience method wrapping [`poll_peek`](Self::poll_peek).
    pub async fn peek(mut self: Pin<&mut Self>, buf: &mut [u8]) -> Result<usize, ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_peek(cx, buf)).await
    }

    /// Like [`SslStream::read_early_data`](ssl::SslStream::read_early_data), except that a
    /// handshake failure, or a transport failure or end, right after the early data is an error,
    /// not the end of early data (`Ok(0)`). After the end of early data, it advances the handshake
    /// without waiting; [`accept`](Self::accept) finishes it.
    ///
    /// An empty buffer returns `Ok(0)` if no early data was accepted or it is over, and an error
    /// once an early-data record arrives.
    ///
    /// Requires OpenSSL 1.1.1 or newer (LibreSSL only has stubs for early data).
    #[cfg(ossl111)]
    pub fn poll_read_early_data(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ssl::Error>> {
        self.poll_op(cx, |this| {
            // Transport errors are kept from the first call: one right after the end of early data
            // would make OpenSSL 4 fail the session without a reason. A second call gets it.
            this.poll_ssl(ErrorPath::ToCaller, |s| {
                let early = s.read_early_data(buf);
                let over = matches!(early, Ok(0));
                // Advance the handshake after the end of early data, or rejected early data. This
                // also reports a handshake that failed in the same call: OpenSSL still returns the
                // end of early data, and leaves the reason on the error queue for
                // `SSL_do_handshake`.
                let result = match early {
                    Ok(0) => s.do_handshake().map(|()| 0),
                    result => result,
                };
                let Err(error) = result else {
                    return result;
                };
                // A kept error is why the call stopped only if it waited: then a second call hands
                // it to OpenSSL. One kept from a call that OpenSSL failed by itself, such as
                // sending its alert, is dropped.
                let waited = matches!(s.get_ref().call.read, LastRead::Waiting);
                match waited.then(|| s.get_mut().kept_error()).flatten() {
                    Some(kept) => {
                        s.get_mut().call.inject = Some(AssertUnwindSafe(kept));
                        if over {
                            s.do_handshake().map(|()| 0)
                        } else {
                            s.read_early_data(buf)
                        }
                    }
                    // `accept` waits for the rest: `SSL_read_early_data` would fail now.
                    None if over
                        && matches!(error.code(), ErrorCode::WANT_READ | ErrorCode::WANT_WRITE) =>
                    {
                        Ok(0)
                    }
                    None => Err(error),
                }
            })
        })
    }

    /// A convenience method wrapping [`poll_read_early_data`](Self::poll_read_early_data).
    ///
    /// Requires OpenSSL 1.1.1 or newer.
    #[cfg(ossl111)]
    pub async fn read_early_data(
        mut self: Pin<&mut Self>,
        buf: &mut [u8],
    ) -> Result<usize, ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_read_early_data(cx, buf)).await
    }

    /// Like [`SslStream::write_early_data`](ssl::SslStream::write_early_data).
    ///
    /// Like a write, it first waits for [buffered output](Self#buffered-output), and writes at
    /// most 16 KiB. Unlike a write, it goes on after a transport error, which it cannot return: an
    /// [`ssl::Error`] only carries one that OpenSSL read, and `SSL_write_early_data` never reads.
    /// The next call that sends reports it if it recurs. Until then, the output it leaves is
    /// bounded by the session's maximum early data on a client, and only by the caller on a
    /// server.
    ///
    /// Requires OpenSSL 1.1.1 or newer (LibreSSL only has stubs for early data).
    #[cfg(ossl111)]
    pub fn poll_write_early_data(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, ssl::Error>> {
        self.poll_op(cx, |this| {
            let _ = std::task::ready!(this.wrapper().poll_send(Flush::Requested));
            let buf = chunk(buf);
            this.poll_ssl(ErrorPath::ThroughOpenSsl, |s| s.write_early_data(buf))
        })
    }

    /// A convenience method wrapping [`poll_write_early_data`](Self::poll_write_early_data).
    ///
    /// Requires OpenSSL 1.1.1 or newer.
    #[cfg(ossl111)]
    pub async fn write_early_data(
        mut self: Pin<&mut Self>,
        buf: &[u8],
    ) -> Result<usize, ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_write_early_data(cx, buf)).await
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
    /// Reading from or writing to the underlying stream directly will corrupt the TLS session,
    /// and closing or flushing it directly misses the [buffered output](Self#buffered-output).
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner.get_mut().stream
    }

    /// Returns a pinned mutable reference to the underlying stream.
    ///
    /// # Warning
    ///
    /// Reading from or writing to the underlying stream directly will corrupt the TLS session,
    /// and closing or flushing it directly misses the [buffered output](Self#buffered-output).
    #[must_use]
    pub fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut S> {
        Pin::new(Pin::into_inner(self).get_mut())
    }

    fn wrapper(&mut self) -> &mut StreamWrapper<S> {
        self.inner.get_mut()
    }
}

impl<S> SslStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Runs one poll of an operation, and joins the waiting tasks if it returns `Pending`. A failed
    /// send wakes every waiting task, to retry or report it. A read that got records wakes the
    /// tasks waiting for records: no transport event will report those again.
    fn poll_op<T>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        op: impl FnOnce(&mut Self) -> Poll<T>,
    ) -> Poll<T> {
        let this = self.get_mut();
        let wrapper = this.wrapper();
        let generation = wrapper.wakers.generation();
        wrapper.op = Op::default();
        let result = op(this);
        let wrapper = this.wrapper();
        if wrapper.op.send_failed || wrapper.op.read_progress {
            wrapper.wakers.wake_tasks(false, !wrapper.op.send_failed);
        }
        if result.is_pending() {
            let records = wrapper.op.read_wait;
            wrapper.wakers.join(cx.waker(), records, generation);
        }
        let panic = wrapper.panic.get_mut();
        if let Some(panic) = panic.unwrap_or_else(PoisonError::into_inner).take() {
            panic::resume_unwind(panic);
        }
        result
    }

    /// Runs an OpenSSL call until it completes or waits on the transport.
    fn poll_ssl<T>(
        &mut self,
        path: ErrorPath,
        mut f: impl FnMut(&mut ssl::SslStream<StreamWrapper<S>>) -> Result<T, ssl::Error>,
    ) -> Poll<Result<T, ssl::Error>> {
        keeping_foreign_errors(|| {
            loop {
                self.inner.get_mut().start_call(path);
                let error = match f(&mut self.inner) {
                    Ok(value) => break Poll::Ready(Ok(value)),
                    Err(error) => error,
                };
                match (self.inner.get_ref().call.read, error.code()) {
                    (LastRead::Waiting, _) => break Poll::Pending,
                    (LastRead::Failed | LastRead::Eof, _) => break Poll::Ready(Err(error)),
                    // Call again: OpenSSL handled a record without application data (without
                    // `SSL_MODE_AUTO_RETRY`), or LibreSSL finished a handshake inside `SSL_write`
                    // (`WANT_WRITE`, as the BIO never refuses a write).
                    (LastRead::Data, ErrorCode::WANT_READ | ErrorCode::WANT_WRITE) => {}
                    (LastRead::Data, _) => break Poll::Ready(Err(error)),
                }
            }
        })
    }

    /// Sets `SSL_SENT_SHUTDOWN`, which makes OpenSSL refuse every later write.
    fn refuse_writes(&mut self) {
        let state = self.inner.get_shutdown();
        self.inner.set_shutdown(state | ShutdownState::SENT);
    }

    /// Runs an OpenSSL call that returns transport errors through OpenSSL, as one operation.
    fn poll_ssl_op<T>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        f: impl FnMut(&mut ssl::SslStream<StreamWrapper<S>>) -> Result<T, ssl::Error>,
    ) -> Poll<Result<T, ssl::Error>> {
        self.poll_op(cx, |this| this.poll_ssl(ErrorPath::ThroughOpenSsl, f))
    }

    /// Runs an OpenSSL call for `poll_read` or `poll_write`, returning transport errors as they
    /// were without passing them to OpenSSL, so a transient one leaves the session usable.
    fn poll_ssl_io<T>(
        &mut self,
        f: impl FnMut(&mut ssl::SslStream<StreamWrapper<S>>) -> Result<T, ssl::Error>,
    ) -> Poll<io::Result<T>> {
        match self.poll_ssl(ErrorPath::ToCaller, f) {
            Poll::Ready(result) => Poll::Ready(result.map_err(io::Error::other)),
            Poll::Pending => match self.wrapper().kept_error() {
                Some(error) => Poll::Ready(Err(error)),
                None => Poll::Pending,
            },
        }
    }
}

impl<S> AsyncRead for SslStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.poll_op(cx, |this| {
            this.poll_ssl_io(|s| match s.ssl_read(buf) {
                // Like `Read for ssl::SslStream`, end the stream at `close_notify` (also OpenSSL
                // 4's unclean end under `SSL_OP_IGNORE_UNEXPECTED_EOF`), and at the transport's end
                // where the library reports it as `SYSCALL` (all but OpenSSL 4, as rust-openssl's
                // BIO does not report its end). Not during a handshake, renegotiation included: no
                // session was made.
                Err(error)
                    if (error.code() == ErrorCode::ZERO_RETURN
                        || (error.code() == ErrorCode::SYSCALL
                            && matches!(s.get_ref().call.read, LastRead::Eof)))
                        && handshake_finished(s.ssl()) =>
                {
                    Ok(0)
                }
                result => result,
            })
        })
    }
}

impl<S> AsyncWrite for SslStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.poll_op(cx, |this| {
            std::task::ready!(this.wrapper().poll_send(Flush::Requested))?;
            let buf = chunk(buf);
            // A transport error while sending these bytes is not returned: OpenSSL wrote them,
            // and they stay buffered for the next call that sends.
            this.poll_ssl_io(|s| s.ssl_write(buf))
        })
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_op(cx, |this| this.wrapper().poll_send(Flush::Always))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Close the transport without waiting for the peer's close_notify, as RFC 8446 §6.1
        // permits, to avoid a half-close deadlock. The peer's data stays readable until the
        // transport goes away.
        self.poll_op(cx, |this| {
            if matches!(this.inner.get_ref().close, Close::Open) {
                // What earlier writes left goes first, and failing to send it is an error.
                std::task::ready!(this.wrapper().poll_send(Flush::Requested))?;
                // `SSL_shutdown` runs once, outside `poll_ssl` (see `Close::Sent`); the first call
                // never reads.
                this.inner.get_mut().start_call(ErrorPath::ThroughOpenSsl);
                let shutdown = keeping_foreign_errors(|| this.inner.shutdown());
                let sent = this.inner.get_shutdown().contains(ShutdownState::SENT);
                this.inner.get_mut().close = match shutdown {
                    Ok(_) if sent => Close::Sent,
                    // LibreSSL also reports success without writing close_notify while the
                    // handshake is unfinished.
                    Ok(_) => Close::NoSession(None),
                    Err(error) => {
                        let error = error.into_io_error().unwrap_or_else(io::Error::other);
                        Close::NoSession(Some(AssertUnwindSafe(error)))
                    }
                };
                // Without a session, OpenSSL then refuses later writes, which would start a
                // handshake.
                this.refuse_writes();
            }
            if matches!(this.inner.get_ref().close, Close::NoSession(_)) {
                // A transport that fails to close says so first, and keeps the reason for the
                // close that closes it.
                std::task::ready!(this.wrapper().poll_close())?;
                let reason = match &mut this.wrapper().close {
                    Close::NoSession(reason) => reason.take(),
                    Close::Open | Close::Sent => None,
                };
                let error = reason.map_or_else(
                    || io::Error::other("no TLS session to close"),
                    |AssertUnwindSafe(error)| error,
                );
                return Poll::Ready(Err(error));
            }
            match std::task::ready!(this.wrapper().poll_send(Flush::Unflushed)) {
                Ok(()) => {}
                // No error: ours only acknowledges the peer's close_notify, and the peer may be
                // gone.
                Err(_) if this.inner.get_shutdown().contains(ShutdownState::RECEIVED) => {}
                // The output stays buffered, so that closing again retries.
                Err(error) => return Poll::Ready(Err(error)),
            }
            this.wrapper().poll_close()
        })
    }
}
