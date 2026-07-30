use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use fastpx::{
    AuthContext, AuthError, AuthFactory, AuthMode, AuthScheme, Endpoint, Proxy, ProxyConfig,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn connect_tunnel_relays_early_client_data() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.unwrap();
        let (head, leftover) = read_head(&mut stream).await.unwrap();
        assert!(head.starts_with("CONNECT example.test:443 HTTP/1.1\r\n"));
        assert!(leftover.is_empty());

        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });

    let (proxy_address, proxy_task) =
        spawn_proxy(upstream_address, AuthMode::None, Arc::new(MockFactory)).await;
    let mut client = TcpStream::connect(proxy_address).await.unwrap();
    client
        .write_all(
            b"CONNECT example.test:443 HTTP/1.1\r\n\
              Host: example.test:443\r\n\r\n\
              ping",
        )
        .await
        .unwrap();

    let (response, mut leftover) = timeout(TEST_TIMEOUT, read_head(&mut client))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200 "));
    while leftover.len() < 4 {
        let mut chunk = [0_u8; 4];
        let read = client.read(&mut chunk).await.unwrap();
        assert_ne!(read, 0);
        leftover.extend_from_slice(&chunk[..read]);
    }
    assert_eq!(&leftover[..4], b"pong");

    drop(client);
    upstream_task.await.unwrap();
    proxy_task.await.unwrap();
}

#[tokio::test]
async fn ntlm_handshake_reuses_connection_and_drains_407_body() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.unwrap();

        let (first, leftover) = read_head(&mut stream).await.unwrap();
        assert!(first.starts_with("CONNECT service.test:443 HTTP/1.1\r\n"));
        assert!(!first.to_ascii_lowercase().contains("proxy-authorization"));
        assert!(leftover.is_empty());
        stream
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: NTLM\r\n\
                  Content-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();

        let (second, leftover) = read_head(&mut stream).await.unwrap();
        assert!(second.contains("Proxy-Authorization: NTLM dHlwZTE=\r\n"));
        assert!(leftover.is_empty());
        stream
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: NTLM dHlwZTI=\r\n\
                  Content-Length: 5\r\n\r\n\
                  hello",
            )
            .await
            .unwrap();

        let (third, leftover) = read_head(&mut stream).await.unwrap();
        assert!(third.contains("Proxy-Authorization: NTLM dHlwZTM=\r\n"));
        assert!(leftover.is_empty());
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();

        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });

    let (proxy_address, proxy_task) =
        spawn_proxy(upstream_address, AuthMode::Ntlm, Arc::new(MockFactory)).await;
    let mut client = TcpStream::connect(proxy_address).await.unwrap();
    client
        .write_all(
            b"CONNECT service.test:443 HTTP/1.1\r\n\
              Host: service.test:443\r\n\r\n",
        )
        .await
        .unwrap();

    let (response, _) = timeout(TEST_TIMEOUT, read_head(&mut client))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200 "));
    client.write_all(b"ping").await.unwrap();
    let mut reply = [0_u8; 4];
    timeout(TEST_TIMEOUT, client.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"pong");

    drop(client);
    upstream_task.await.unwrap();
    proxy_task.await.unwrap();
}

#[tokio::test]
async fn ntlm_reconnects_after_tokenless_407_closes_probe_socket() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut probe, _) = upstream_listener.accept().await.unwrap();
        let _ = read_head(&mut probe).await.unwrap();
        probe
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: NTLM\r\n\
                  Connection: close\r\n\
                  Content-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
        drop(probe);

        let (mut authenticated, _) = upstream_listener.accept().await.unwrap();
        let (type_one, _) = read_head(&mut authenticated).await.unwrap();
        assert!(type_one.contains("Proxy-Authorization: NTLM dHlwZTE=\r\n"));
        authenticated
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: NTLM dHlwZTI=\r\n\
                  Content-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
        let (type_three, _) = read_head(&mut authenticated).await.unwrap();
        assert!(type_three.contains("Proxy-Authorization: NTLM dHlwZTM=\r\n"));
        authenticated
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
    });

    let (proxy_address, proxy_task) =
        spawn_proxy(upstream_address, AuthMode::Ntlm, Arc::new(MockFactory)).await;
    let mut client = TcpStream::connect(proxy_address).await.unwrap();
    client
        .write_all(b"CONNECT service.test:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let (response, _) = timeout(TEST_TIMEOUT, read_head(&mut client))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200 "));

    drop(client);
    upstream_task.await.unwrap();
    proxy_task.await.unwrap();
}

async fn spawn_proxy(
    upstream: SocketAddr,
    auth: AuthMode,
    factory: Arc<dyn AuthFactory>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config = ProxyConfig {
        listen: address,
        upstream: Endpoint::new(upstream.ip().to_string(), upstream.port()),
        auth,
        connect_timeout: TEST_TIMEOUT,
        idle_timeout: Some(TEST_TIMEOUT),
        max_header_bytes: 32 * 1024,
        max_connections: 16,
    };
    let proxy = Proxy::with_auth_factory(config, factory);
    let task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        proxy.handle_client(stream, peer).await.unwrap();
    });
    (address, task)
}

async fn read_head(stream: &mut TcpStream) -> io::Result<(String, Vec<u8>)> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let end = position + 4;
            let remaining = bytes.split_off(end);
            let head = String::from_utf8(bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            return Ok((head, remaining));
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before headers completed",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
}

#[derive(Debug)]
struct MockFactory;

impl AuthFactory for MockFactory {
    fn create(
        &self,
        scheme: AuthScheme,
        target_name: &str,
    ) -> Result<Box<dyn AuthContext>, AuthError> {
        if scheme != AuthScheme::Ntlm {
            return Err(AuthError::Native("expected NTLM".to_owned()));
        }
        if !target_name.starts_with("HTTP/127.0.0.1") {
            return Err(AuthError::Native(format!(
                "unexpected target name {target_name}"
            )));
        }
        Ok(Box::new(MockContext { step: 0 }))
    }
}

struct MockContext {
    step: usize,
}

impl AuthContext for MockContext {
    fn step(&mut self, challenge: Option<&[u8]>) -> Result<Vec<u8>, AuthError> {
        let token = match self.step {
            0 if challenge.is_none() => b"type1".to_vec(),
            1 if challenge == Some(b"type2".as_slice()) => b"type3".to_vec(),
            _ => {
                return Err(AuthError::Native(format!(
                    "unexpected mock auth step {} with challenge {challenge:?}",
                    self.step
                )));
            }
        };
        self.step += 1;
        Ok(token)
    }
}
