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
    task::{Context, Poll, Waker},
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
            ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => Poll::Pending,
            _ => Poll::Ready(Err(e)),
        },
    }
}

/// An asynchronous version of [`openssl::ssl::SslStream`].
pub struct SslStream<S: Unpin> {
    inner: ssl::SslStream<StreamWrapper<S>>,
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
            close_notify_sent: false,
        })
    }

    /// Like [`SslStream::connect`](ssl::SslStream::connect).
    pub fn poll_connect(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ssl::Error>> {
        self.with_context(cx, |s| cvt_ossl(s.connect()))
    }

    /// A convenience method wrapping [`poll_connect`](Self::poll_connect).
    pub async fn connect(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_connect(cx)).await
    }

    /// Like [`SslStream::accept`](ssl::SslStream::accept).
    pub fn poll_accept(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ssl::Error>> {
        self.with_context(cx, |s| cvt_ossl(s.accept()))
    }

    /// A convenience method wrapping [`poll_accept`](Self::poll_accept).
    pub async fn accept(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_accept(cx)).await
    }

    /// Like [`SslStream::do_handshake`](ssl::SslStream::do_handshake).
    pub fn poll_do_handshake(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ssl::Error>> {
        self.with_context(cx, |s| cvt_ossl(s.do_handshake()))
    }

    /// A convenience method wrapping [`poll_do_handshake`](Self::poll_do_handshake).
    pub async fn do_handshake(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_do_handshake(cx)).await
    }

    /// Like [`SslStream::ssl_peek`](ssl::SslStream::ssl_peek).
    pub fn poll_peek(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ssl::Error>> {
        // `SSL_peek_ex` reports a zero-length peek as a failure with `WANT_READ`, which we would
        // translate into a `Pending` that never resolves. Nothing can be peeked into an empty
        // buffer anyway, so answer directly and match what `poll_read` does for an empty buffer.
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.with_context(cx, |s| cvt_ossl(s.ssl_peek(buf)))
    }

    /// A convenience method wrapping [`poll_peek`](Self::poll_peek).
    pub async fn peek(mut self: Pin<&mut Self>, buf: &mut [u8]) -> Result<usize, ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_peek(cx, buf)).await
    }

    /// Like [`SslStream::read_early_data`](ssl::SslStream::read_early_data).
    #[cfg(ossl111)]
    pub fn poll_read_early_data(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ssl::Error>> {
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
    #[cfg(ossl111)]
    pub fn poll_write_early_data(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, ssl::Error>> {
        self.with_context(cx, |s| cvt_ossl(s.write_early_data(buf)))
    }

    /// A convenience method wrapping [`poll_write_early_data`](Self::poll_write_early_data).
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
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.with_context(ctx, |s| cvt(s.read(buf)))
    }
}

impl<S> AsyncWrite for SslStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, ctx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.with_context(ctx, |s| cvt(s.write(buf)))
    }

    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
        self.with_context(ctx, |s| cvt(s.flush()))
    }

    fn poll_close(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
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
                    return Poll::Ready(Err(e.into_io_error().unwrap_or_else(io::Error::other)));
                }
            }
            self.as_mut().get_mut().close_notify_sent = true;
        }

        self.get_pin_mut().poll_close(ctx)
    }
}
