use std::{io, str};

use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::TcpStream,
};

#[derive(Clone, Debug)]
pub struct Header {
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(Debug)]
pub struct RequestHead {
    pub method: String,
    pub target: String,
}

#[derive(Debug)]
pub struct ResponseHead {
    pub version: u8,
    pub status: u16,
    pub headers: Vec<Header>,
}

impl ResponseHead {
    pub fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.headers
            .iter()
            .filter(move |header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_slice())
    }

    pub fn connection_close(&self) -> bool {
        let has_token = |expected: &str| {
            self.header_values("connection").any(|value| {
                str::from_utf8(value).is_ok_and(|value| {
                    value
                        .split(',')
                        .any(|part| part.trim().eq_ignore_ascii_case(expected))
                })
            })
        };

        has_token("close") || (self.version == 0 && !has_token("keep-alive"))
    }

    fn content_length(&self) -> Result<Option<usize>, HttpError> {
        let mut parsed = None;
        for value in self.header_values("content-length") {
            let value = str::from_utf8(value)
                .map_err(|_| HttpError::InvalidContentLength)?
                .trim()
                .parse::<usize>()
                .map_err(|_| HttpError::InvalidContentLength)?;
            if parsed.is_some_and(|previous| previous != value) {
                return Err(HttpError::ConflictingContentLength);
            }
            parsed = Some(value);
        }
        Ok(parsed)
    }

    fn is_chunked(&self) -> bool {
        self.header_values("transfer-encoding").any(|value| {
            str::from_utf8(value).is_ok_and(|value| {
                value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
            })
        })
    }
}

#[derive(Debug, Error)]
pub enum HttpError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("connection closed before the HTTP headers were complete")]
    UnexpectedEof,
    #[error("HTTP headers exceed the configured limit")]
    HeaderTooLarge,
    #[error("malformed HTTP message: {0}")]
    Parse(#[from] httparse::Error),
    #[error("HTTP message is missing required request fields")]
    MissingRequestFields,
    #[error("HTTP header contains invalid UTF-8")]
    InvalidHeaderText,
    #[error("invalid Content-Length header")]
    InvalidContentLength,
    #[error("response contains conflicting Content-Length headers")]
    ConflictingContentLength,
    #[error("malformed chunked response body")]
    InvalidChunkedBody,
}

pub async fn read_request_head<R>(
    reader: &mut R,
    max_header_bytes: usize,
) -> Result<(RequestHead, Vec<u8>), HttpError>
where
    R: AsyncRead + Unpin,
{
    let bytes = read_head_bytes(reader, max_header_bytes).await?;
    let end = find_header_end(&bytes).ok_or(HttpError::UnexpectedEof)?;
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    request.parse(&bytes[..end])?;

    let method = request
        .method
        .ok_or(HttpError::MissingRequestFields)?
        .to_owned();
    let target = request
        .path
        .ok_or(HttpError::MissingRequestFields)?
        .to_owned();

    Ok((RequestHead { method, target }, bytes[end..].to_vec()))
}

pub struct BufferedStream {
    stream: TcpStream,
    buffer: Vec<u8>,
}

impl BufferedStream {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            buffer: Vec::new(),
        }
    }

    pub fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    pub async fn read_response_head(
        &mut self,
        max_header_bytes: usize,
    ) -> Result<ResponseHead, HttpError> {
        loop {
            if let Some(end) = find_header_end(&self.buffer) {
                let head = self.buffer[..end].to_vec();
                self.buffer.drain(..end);
                return parse_response_head(&head);
            }
            if self.buffer.len() >= max_header_bytes {
                return Err(HttpError::HeaderTooLarge);
            }

            let remaining = max_header_bytes - self.buffer.len();
            let mut chunk = [0_u8; 8192];
            let wanted = chunk.len().min(remaining);
            let read = self.stream.read(&mut chunk[..wanted]).await?;
            if read == 0 {
                return Err(HttpError::UnexpectedEof);
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }

    pub async fn drain_response_body(&mut self, response: &ResponseHead) -> Result<(), HttpError> {
        if response.is_chunked() {
            self.drain_chunked().await
        } else if let Some(length) = response.content_length()? {
            self.discard_exact(length).await
        } else {
            // Authentication responses normally carry no body. If a proxy uses
            // close-delimited framing, `connection_close` prevents reuse.
            Ok(())
        }
    }

    pub fn into_parts(self) -> (TcpStream, Vec<u8>) {
        (self.stream, self.buffer)
    }

    async fn discard_exact(&mut self, mut remaining: usize) -> Result<(), HttpError> {
        let buffered = remaining.min(self.buffer.len());
        self.buffer.drain(..buffered);
        remaining -= buffered;

        let mut chunk = [0_u8; 8192];
        while remaining > 0 {
            let wanted = remaining.min(chunk.len());
            let read = self.stream.read(&mut chunk[..wanted]).await?;
            if read == 0 {
                return Err(HttpError::UnexpectedEof);
            }
            remaining -= read;
        }
        Ok(())
    }

    async fn read_line(&mut self, max_bytes: usize) -> Result<Vec<u8>, HttpError> {
        loop {
            if let Some(index) = self.buffer.windows(2).position(|window| window == b"\r\n") {
                let line = self.buffer[..index].to_vec();
                self.buffer.drain(..index + 2);
                return Ok(line);
            }
            if self.buffer.len() >= max_bytes {
                return Err(HttpError::InvalidChunkedBody);
            }

            let mut chunk = [0_u8; 1024];
            let read = self.stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(HttpError::UnexpectedEof);
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }

    async fn drain_chunked(&mut self) -> Result<(), HttpError> {
        loop {
            let line = self.read_line(8192).await?;
            let size_text = str::from_utf8(&line)
                .map_err(|_| HttpError::InvalidChunkedBody)?
                .split(';')
                .next()
                .ok_or(HttpError::InvalidChunkedBody)?
                .trim();
            let size =
                usize::from_str_radix(size_text, 16).map_err(|_| HttpError::InvalidChunkedBody)?;

            if size == 0 {
                loop {
                    if self.read_line(8192).await?.is_empty() {
                        return Ok(());
                    }
                }
            }

            self.discard_exact(size).await?;
            let terminator = self.read_line(2).await?;
            if !terminator.is_empty() {
                return Err(HttpError::InvalidChunkedBody);
            }
        }
    }
}

fn parse_response_head(bytes: &[u8]) -> Result<ResponseHead, HttpError> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    response.parse(bytes)?;
    let version = response.version.ok_or(HttpError::MissingRequestFields)?;
    let status = response.code.ok_or(HttpError::MissingRequestFields)?;
    let headers = response
        .headers
        .iter()
        .map(|header| Header {
            name: header.name.to_owned(),
            value: header.value.to_vec(),
        })
        .collect();
    Ok(ResponseHead {
        version,
        status,
        headers,
    })
}

async fn read_head_bytes<R>(reader: &mut R, max_header_bytes: usize) -> Result<Vec<u8>, HttpError>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = Vec::with_capacity(1024);
    loop {
        if find_header_end(&bytes).is_some() {
            return Ok(bytes);
        }
        if bytes.len() >= max_header_bytes {
            return Err(HttpError::HeaderTooLarge);
        }

        let remaining = max_header_bytes - bytes.len();
        let mut chunk = [0_u8; 8192];
        let wanted = chunk.len().min(remaining);
        let read = reader.read(&mut chunk[..wanted]).await?;
        if read == 0 {
            return Err(HttpError::UnexpectedEof);
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::{ResponseHead, read_request_head};

    #[tokio::test]
    async fn preserves_bytes_after_connect_head() {
        let (mut writer, mut reader) = tokio::io::duplex(256);
        writer
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\nTLS")
            .await
            .unwrap();

        let (head, remaining) = read_request_head(&mut reader, 8192).await.unwrap();
        assert_eq!(head.method, "CONNECT");
        assert_eq!(head.target, "example.com:443");
        assert_eq!(remaining, b"TLS");
    }

    #[test]
    fn detects_connection_close_case_insensitively() {
        let response = ResponseHead {
            version: 1,
            status: 407,
            headers: vec![super::Header {
                name: "Connection".to_owned(),
                value: b"keep-alive, Close".to_vec(),
            }],
        };
        assert!(response.connection_close());
    }

    #[test]
    fn treats_http_1_0_as_closed_without_keep_alive() {
        let closed = ResponseHead {
            version: 0,
            status: 407,
            headers: Vec::new(),
        };
        assert!(closed.connection_close());

        let reusable = ResponseHead {
            version: 0,
            status: 407,
            headers: vec![super::Header {
                name: "Connection".to_owned(),
                value: b"Keep-Alive".to_vec(),
            }],
        };
        assert!(!reusable.connection_close());
    }
}
