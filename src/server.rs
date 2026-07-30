use std::{future::Future, io, net::SocketAddr, str, sync::Arc};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use thiserror::Error;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    time::timeout,
};
use tracing::{debug, info, warn};

use crate::{
    AuthError, AuthFactory, AuthMode, AuthScheme, Endpoint, NativeAuthFactory, ProxyConfig,
    http1::{BufferedStream, HttpError, ResponseHead, read_request_head},
    relay::relay_bidirectional,
};

const MAX_AUTH_ROUNDS: usize = 4;

#[derive(Clone)]
pub struct Proxy {
    config: Arc<ProxyConfig>,
    auth_factory: Arc<dyn AuthFactory>,
    connections: Arc<Semaphore>,
}

impl Proxy {
    #[must_use]
    pub fn new(config: ProxyConfig) -> Self {
        Self::with_auth_factory(config, Arc::new(NativeAuthFactory))
    }

    #[must_use]
    pub fn with_auth_factory(config: ProxyConfig, auth_factory: Arc<dyn AuthFactory>) -> Self {
        let max_connections = config.max_connections;
        Self {
            config: Arc::new(config),
            auth_factory,
            connections: Arc::new(Semaphore::new(max_connections)),
        }
    }

    /// Accept client connections until `shutdown` completes.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if accepting a new client connection fails.
    pub async fn serve_until<F>(&self, listener: TcpListener, shutdown: F) -> io::Result<()>
    where
        F: Future<Output = ()>,
    {
        tokio::pin!(shutdown);
        loop {
            let permit = tokio::select! {
                biased;
                () = &mut shutdown => {
                    info!("shutdown requested");
                    return Ok(());
                }
                permit = self.connections.clone().acquire_owned() => {
                    let Ok(permit) = permit else {
                        return Ok(());
                    };
                    permit
                }
            };

            tokio::select! {
                biased;
                () = &mut shutdown => {
                    info!("shutdown requested");
                    return Ok(());
                }
                accepted = listener.accept() => {
                    let (stream, peer) = accepted?;
                    let proxy = self.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(error) = proxy.handle_client(stream, peer).await {
                            debug!(%peer, %error, "connection closed with an error");
                        }
                    });
                }
            }
        }
    }

    /// Process one local proxy connection.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError`] for malformed requests, upstream connection or
    /// authentication failures, and tunnel relay I/O errors.
    pub async fn handle_client(
        &self,
        mut client: TcpStream,
        peer: SocketAddr,
    ) -> Result<(), ProxyError> {
        client.set_nodelay(true)?;
        let request = read_request_head(&mut client, self.config.max_header_bytes).await;
        let (request, client_prefetched) = match request {
            Ok(request) => request,
            Err(error) => {
                send_error(&mut client, 400, "Bad Request").await?;
                return Err(error.into());
            }
        };

        if !request.method.eq_ignore_ascii_case("CONNECT") {
            send_error(&mut client, 405, "CONNECT Required").await?;
            return Ok(());
        }

        let destination = match request.target.parse::<Endpoint>() {
            Ok(destination) => destination,
            Err(error) => {
                send_error(&mut client, 400, "Invalid CONNECT Target").await?;
                return Err(ProxyError::InvalidDestination(error.to_string()));
            }
        };

        debug!(%peer, %destination, "opening tunnel");
        let tunnel = match self.establish_tunnel(&destination).await {
            Ok(tunnel) => tunnel,
            Err(error) => {
                warn!(%peer, %destination, %error, "upstream CONNECT failed");
                send_error(&mut client, 502, "Bad Gateway").await?;
                return Err(error);
            }
        };

        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        let (mut upstream, upstream_prefetched) = tunnel.into_parts();
        if !client_prefetched.is_empty() {
            upstream.write_all(&client_prefetched).await?;
        }
        if !upstream_prefetched.is_empty() {
            client.write_all(&upstream_prefetched).await?;
        }

        let (sent, received) =
            relay_bidirectional(client, upstream, self.config.idle_timeout).await?;
        debug!(
            %peer,
            %destination,
            client_to_upstream = sent,
            upstream_to_client = received,
            "tunnel closed"
        );
        Ok(())
    }

    async fn establish_tunnel(&self, destination: &Endpoint) -> Result<BufferedStream, ProxyError> {
        let mut upstream = self.connect_upstream().await?;

        send_connect_request(upstream.stream_mut(), destination, None).await?;
        let mut response = upstream
            .read_response_head(self.config.max_header_bytes)
            .await?;

        if is_connect_success(&response) {
            return Ok(upstream);
        }
        if response.status != 407 {
            return Err(ProxyError::UpstreamStatus(response.status));
        }
        if self.config.auth == AuthMode::None {
            return Err(ProxyError::AuthenticationRequired);
        }

        let (scheme, first_challenge) = choose_scheme(&response, self.config.auth)?;
        let target_name = format!("HTTP/{}", self.config.upstream.host());
        let mut context = self.auth_factory.create(scheme, &target_name)?;
        let mut challenge = decode_challenge(first_challenge)?;
        let mut must_drain_response = true;

        // Some proxies close the unauthenticated probe connection. A challenge
        // without a token is not connection-bound yet, so it is safe to open a
        // fresh socket and send the initial client token there.
        if response.connection_close() {
            if challenge.is_some() {
                return Err(ProxyError::ConnectionClosedDuringAuth);
            }
            upstream = self.connect_upstream().await?;
            must_drain_response = false;
        }

        for _ in 0..MAX_AUTH_ROUNDS {
            if must_drain_response {
                if response.connection_close() {
                    return Err(ProxyError::ConnectionClosedDuringAuth);
                }
                upstream.drain_response_body(&response).await?;
            }

            let token = context.step(challenge.as_deref())?;
            let encoded = STANDARD.encode(token);
            let authorization = format!("{} {encoded}", scheme.header_name());
            send_connect_request(upstream.stream_mut(), destination, Some(&authorization)).await?;
            response = upstream
                .read_response_head(self.config.max_header_bytes)
                .await?;

            if is_connect_success(&response) {
                return Ok(upstream);
            }
            if response.status != 407 {
                return Err(ProxyError::UpstreamStatus(response.status));
            }

            challenge = decode_challenge(
                find_challenge(&response, scheme).ok_or(ProxyError::AuthenticationSchemeMissing)?,
            )?;
            must_drain_response = true;
        }

        Err(ProxyError::TooManyAuthenticationRounds)
    }

    async fn connect_upstream(&self) -> Result<BufferedStream, ProxyError> {
        let connect =
            TcpStream::connect((self.config.upstream.host(), self.config.upstream.port()));
        let stream = timeout(self.config.connect_timeout, connect)
            .await
            .map_err(|_| ProxyError::ConnectTimeout)??;
        stream.set_nodelay(true)?;
        Ok(BufferedStream::new(stream))
    }
}

#[derive(Clone, Copy)]
struct Challenge<'a> {
    token: Option<&'a str>,
}

fn choose_scheme(
    response: &ResponseHead,
    mode: AuthMode,
) -> Result<(AuthScheme, Challenge<'_>), ProxyError> {
    let schemes: &[AuthScheme] = match mode {
        AuthMode::Auto => &[AuthScheme::Negotiate, AuthScheme::Ntlm],
        AuthMode::Negotiate => &[AuthScheme::Negotiate],
        AuthMode::Ntlm => &[AuthScheme::Ntlm],
        AuthMode::None => return Err(ProxyError::AuthenticationRequired),
    };

    for &scheme in schemes {
        if let Some(challenge) = find_challenge(response, scheme) {
            return Ok((scheme, challenge));
        }
    }
    Err(ProxyError::AuthenticationSchemeMissing)
}

fn find_challenge(response: &ResponseHead, scheme: AuthScheme) -> Option<Challenge<'_>> {
    for value in response.header_values("proxy-authenticate") {
        let Ok(value) = str::from_utf8(value) else {
            continue;
        };
        for item in value.split(',') {
            let mut fields = item.split_whitespace();
            let Some(name) = fields.next() else {
                continue;
            };
            if name.eq_ignore_ascii_case(scheme.header_name()) {
                return Some(Challenge {
                    token: fields.next(),
                });
            }
        }
    }
    None
}

fn decode_challenge(challenge: Challenge<'_>) -> Result<Option<Vec<u8>>, ProxyError> {
    challenge
        .token
        .map(|token| {
            STANDARD
                .decode(token)
                .map_err(|_| ProxyError::InvalidAuthenticationToken)
        })
        .transpose()
}

fn is_connect_success(response: &ResponseHead) -> bool {
    (200..300).contains(&response.status)
}

async fn send_connect_request(
    stream: &mut TcpStream,
    destination: &Endpoint,
    authorization: Option<&str>,
) -> io::Result<()> {
    let mut request = format!(
        "CONNECT {destination} HTTP/1.1\r\n\
         Host: {destination}\r\n\
         Proxy-Connection: Keep-Alive\r\n\
         Connection: Keep-Alive\r\n"
    );
    if let Some(authorization) = authorization {
        request.push_str("Proxy-Authorization: ");
        request.push_str(authorization);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await
}

async fn send_error(stream: &mut TcpStream, status: u16, reason: &str) -> io::Result<()> {
    let body = format!("{status} {reason}\n");
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Connection: close\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await
}

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("HTTP protocol error: {0}")]
    Http(#[from] HttpError),
    #[error("authentication error: {0}")]
    Authentication(#[from] AuthError),
    #[error("upstream connection timed out")]
    ConnectTimeout,
    #[error("invalid CONNECT destination: {0}")]
    InvalidDestination(String),
    #[error("upstream proxy returned HTTP {0}")]
    UpstreamStatus(u16),
    #[error("upstream proxy requires authentication but auth is disabled")]
    AuthenticationRequired,
    #[error("upstream proxy did not offer the configured authentication scheme")]
    AuthenticationSchemeMissing,
    #[error("upstream proxy supplied an invalid base64 authentication token")]
    InvalidAuthenticationToken,
    #[error("upstream proxy closed the connection during authentication")]
    ConnectionClosedDuringAuth,
    #[error("upstream proxy exceeded the authentication round limit")]
    TooManyAuthenticationRounds,
}

#[cfg(test)]
mod tests {
    use super::{choose_scheme, decode_challenge};
    use crate::{
        AuthMode, AuthScheme,
        http1::{Header, ResponseHead},
    };

    #[test]
    fn auto_prefers_negotiate() {
        let response = ResponseHead {
            version: 1,
            status: 407,
            headers: vec![
                Header {
                    name: "Proxy-Authenticate".to_owned(),
                    value: b"NTLM".to_vec(),
                },
                Header {
                    name: "proxy-authenticate".to_owned(),
                    value: b"Negotiate dHlwZTI=".to_vec(),
                },
            ],
        };
        let (scheme, challenge) = choose_scheme(&response, AuthMode::Auto).unwrap();
        assert_eq!(scheme, AuthScheme::Negotiate);
        assert_eq!(decode_challenge(challenge).unwrap().unwrap(), b"type2");
    }

    #[test]
    fn forced_ntlm_uses_ntlm_challenge() {
        let response = ResponseHead {
            version: 1,
            status: 407,
            headers: vec![Header {
                name: "Proxy-Authenticate".to_owned(),
                value: b"Negotiate, NTLM dHlwZTI=".to_vec(),
            }],
        };
        let (scheme, challenge) = choose_scheme(&response, AuthMode::Ntlm).unwrap();
        assert_eq!(scheme, AuthScheme::Ntlm);
        assert_eq!(decode_challenge(challenge).unwrap().unwrap(), b"type2");
    }
}
