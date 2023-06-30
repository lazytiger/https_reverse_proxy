use std::future::Future;
use std::io::{Error, ErrorKind, Read, Write};
use std::marker::PhantomData;
use std::ops::DerefMut;
use std::pin::pin;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use rustls::client::ClientConnectionData;
use rustls::server::ServerConnectionData;
use rustls::{ClientConnection, ConnectionCommon, ServerConnection};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::{options, types};

pub type TlsServerStream = TlsStream<ServerConnection, ServerConnectionData>;
#[allow(dead_code)]
pub type TlsClientStream = TlsStream<ClientConnection, ClientConnectionData>;

pub struct TlsReadHalf<T, D> {
    stream: Arc<Mutex<TlsStream<T, D>>>,
}

impl<T, D> AsyncRead for TlsReadHalf<T, D>
where
    T: DerefMut<Target = ConnectionCommon<D>>,
    T: Unpin,
    D: Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let pin = self.get_mut();
        let mut lock = pin.stream.lock();
        let mut lock = ready!(pin!(lock).poll(cx));
        Pin::new(lock.deref_mut()).poll_read(cx, buf)
    }
}

pub struct TlsWriteHalf<T, D> {
    stream: Arc<Mutex<TlsStream<T, D>>>,
}

impl<T, D> AsyncWrite for TlsWriteHalf<T, D>
where
    T: DerefMut<Target = ConnectionCommon<D>>,
    T: Unpin,
    D: Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let pin = self.get_mut();
        let mut lock = pin.stream.lock();
        let mut lock = ready!(pin!(lock).poll(cx));
        Pin::new(lock.deref_mut()).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let pin = self.get_mut();
        let mut lock = pin.stream.lock();
        let mut lock = ready!(pin!(lock).poll(cx));
        Pin::new(lock.deref_mut()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let pin = self.get_mut();
        let mut lock = pin.stream.lock();
        let mut lock = ready!(pin!(lock).poll(cx));
        Pin::new(lock.deref_mut()).poll_shutdown(cx)
    }
}

pub struct TlsStream<T, D> {
    stream: TcpStream,
    session: T,
    recv_buf: Vec<u8>,
    send_buf: Vec<u8>,
    _phantom: PhantomData<D>,
}

impl<T, D> TlsStream<T, D>
where
    T: DerefMut<Target = ConnectionCommon<D>>,
    T: Unpin,
{
    pub(crate) fn new(stream: TcpStream, session: T) -> types::Result<Self> {
        Ok(Self {
            stream,
            session,
            recv_buf: vec![0u8; options().as_run().net_buffer_size * 1024],
            send_buf: Vec::new(),
            _phantom: Default::default(),
        })
    }

    #[allow(dead_code)]
    pub fn into_split(self) -> (TlsReadHalf<T, D>, TlsWriteHalf<T, D>) {
        let stream = Arc::new(Mutex::new(self));
        (
            TlsReadHalf {
                stream: stream.clone(),
            },
            TlsWriteHalf { stream },
        )
    }

    fn poll_tls_write(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize, Error>> {
        if self.session.wants_write() {
            if let Err(err) = self.session.write_tls(&mut self.send_buf) {
                return Poll::Ready(Err(err));
            }
        }
        if self.send_buf.is_empty() {
            Poll::Ready(Ok(0))
        } else {
            match Pin::new(&mut self.stream).poll_write(cx, self.send_buf.as_slice()) {
                Poll::Ready(Ok(n)) => {
                    self.send_buf.copy_within(n.., 0);
                    unsafe {
                        self.send_buf.set_len(self.send_buf.len() - n);
                    }
                    Poll::Ready(Ok(n))
                }
                ret => ret,
            }
        }
    }
}

impl<T, D> AsyncRead for TlsStream<T, D>
where
    T: DerefMut<Target = ConnectionCommon<D>>,
    T: Unpin,
    D: Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let pin = self.get_mut();
        match pin.session.reader().read(buf.initialize_unfilled()) {
            Err(err) => {
                if err.kind() != ErrorKind::WouldBlock {
                    return Poll::Ready(Err(err));
                }
            }
            Ok(n) => {
                buf.set_filled(buf.filled().len() + n);
                return Poll::Ready(Ok(()));
            }
        }
        let mut raw_buf = ReadBuf::new(pin.recv_buf.as_mut_slice());
        match Pin::new(&mut pin.stream).poll_read(cx, &mut raw_buf) {
            Poll::Ready(Ok(_)) => {
                if raw_buf.filled().is_empty() {
                    Poll::Ready(Ok(()))
                } else if let Err(err) = pin.session.read_tls(&mut raw_buf.filled()) {
                    Poll::Ready(Err(err))
                } else if let Err(_) = pin.session.process_new_packets() {
                    Poll::Ready(Err(ErrorKind::InvalidData.into()))
                } else {
                    // when handshaking, auto send data
                    if pin.session.is_handshaking() {
                        if let Poll::Ready(Err(err)) = pin.poll_tls_write(cx) {
                            return Poll::Ready(Err(err));
                        }
                    }
                    Pin::new(pin).poll_read(cx, buf)
                }
            }
            ret => ret,
        }
    }
}

impl<T, D> AsyncWrite for TlsStream<T, D>
where
    T: DerefMut<Target = ConnectionCommon<D>>,
    T: Unpin,
    D: Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let pin = self.get_mut();
        match pin.session.writer().write(buf) {
            // read actual data from session, drain the session.
            Ok(n) => match pin.poll_tls_write(cx) {
                // trying to flush data
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(n)),
                ret => ret,
            },
            Err(err) => Poll::Ready(Err(err)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let pin = self.get_mut();
        pin.poll_tls_write(cx).map(|r| r.map(|_| ()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let pin = self.get_mut();
        Pin::new(&mut pin.stream).poll_shutdown(cx)
    }
}