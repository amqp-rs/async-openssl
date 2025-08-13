//! Async TLS streams backed by OpenSSL.
//!
//! This crate provides a wrapper around the [`openssl`] crate's [`SslStream`](ssl::SslStream) type
//! that works with with [`futures-io`]'s [`AsyncRead`] and [`AsyncWrite`] traits rather than std's
//! blocking [`Read`] and [`Write`] traits.
#![warn(missing_docs)]

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
    waker: Waker,
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
        let context = Context::from_waker(&self.waker);
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
#[derive(Debug)]
pub struct SslStream<S: Unpin>(ssl::SslStream<StreamWrapper<S>>);

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
                waker: Waker::noop().clone(),
            },
        )
        .map(SslStream)
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
    pub fn ssl(&self) -> &SslRef {
        self.0.ssl()
    }

    /// Returns a shared reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        &self.0.get_ref().stream
    }

    /// Returns a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.0.get_mut().stream
    }

    /// Returns a pinned mutable reference to the underlying stream.
    pub fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut S> {
        Pin::new(&mut self.get_mut().0.get_mut().stream)
    }

    fn with_context<F, R>(self: Pin<&mut Self>, ctx: &mut Context<'_>, f: F) -> R
    where
        F: FnOnce(&mut ssl::SslStream<StreamWrapper<S>>) -> R,
    {
        let this = unsafe { self.get_unchecked_mut() };
        this.0.get_mut().waker = ctx.waker().clone();
        f(&mut this.0)
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
        match self.as_mut().with_context(ctx, |s| s.shutdown()) {
            Ok(ShutdownResult::Sent) | Ok(ShutdownResult::Received) => {}
            Err(ref e) if e.code() == ErrorCode::ZERO_RETURN => {}
            Err(ref e) if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE => {
                return Poll::Pending;
            }
            Err(e) => {
                return Poll::Ready(Err(e.into_io_error().unwrap_or_else(io::Error::other)));
            }
        }

        self.get_pin_mut().poll_close(ctx)
    }
}
