use std::io::{SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use hyper::body::Bytes;
use hyper::Body;
use tokio::io::{AsyncRead, AsyncSeekExt, ReadBuf};

use crate::{options, types};

pub struct FileStream {
    file: tokio::fs::File,
    offset: usize,
    range_end: usize,
}

impl FileStream {
    pub async fn new(
        name: impl AsRef<Path>,
        range_start: usize,
        mut range_end: usize,
    ) -> types::Result<FileStream> {
        if range_end == 0 {
            range_end = std::fs::metadata(&name)?.len() as usize;
        }
        let mut file = tokio::fs::File::open(name).await?;
        file.seek(SeekFrom::Start(range_start as u64)).await?;
        Ok(Self {
            file,
            offset: range_start,
            range_end,
        })
    }
}

impl futures_core::Stream for FileStream {
    type Item = types::Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut data = vec![0u8; options().as_run().file_buffer_size * 1024];
        let len = data.len().min(self.range_end - self.offset);
        let mut buf = ReadBuf::new(&mut data.as_mut_slice()[..len]);
        if self.range_end == self.offset {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.file).poll_read(cx, &mut buf) {
            Poll::Ready(Ok(_)) => {
                unsafe {
                    let len = buf.filled().len();
                    self.offset += len;
                    data.set_len(len);
                }
                Poll::Ready(Some(Ok(data)))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Some(Err(err.into()))),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct BodySaverStream {
    file: std::fs::File,
    body: Body,
    tmp_file: String,
    name: PathBuf,
    content_length: usize,
    length: usize,
    completed: bool,
}

impl BodySaverStream {
    pub(crate) fn new(
        file: std::fs::File,
        body: Body,
        tmp_file: String,
        name: PathBuf,
        content_length: usize,
    ) -> BodySaverStream {
        Self {
            file,
            body,
            tmp_file,
            name,
            content_length,
            length: 0,
            completed: false,
        }
    }
    fn done(&self, mut ok: bool) {
        if self.completed {
            return;
        }
        if self.content_length != self.length {
            if ok {
                log::error!(
                    "{} - {}, content_length not match length",
                    self.content_length,
                    self.length
                );
                ok = false;
            }
        }
        log::info!("body saver finished:{}", ok);

        let ret = if ok {
            std::fs::rename(&self.tmp_file, &self.name)
        } else {
            std::fs::remove_file(&self.tmp_file)
        };

        if let Err(err) = ret {
            log::error!("file operation failed:{}", err);
        }
    }
}

impl futures_core::Stream for BodySaverStream {
    type Item = types::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.body).poll_next(cx) {
            Poll::Ready(Some(Ok(item))) => {
                if let Err(err) = self.file.write_all(item.as_ref()) {
                    self.done(false);
                    Poll::Ready(Some(Err(err.into())))
                } else {
                    self.length += item.len();
                    if self.length == self.content_length {
                        log::info!("done now");
                        self.done(true);
                    }
                    Poll::Ready(Some(Ok(item)))
                }
            }
            Poll::Ready(None) => {
                self.done(true);
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(err))) => {
                self.done(false);
                Poll::Ready(Some(Err(err.into())))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
