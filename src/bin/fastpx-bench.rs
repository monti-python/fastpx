use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use clap::Parser;
use fastpx::{
    AuthContext, AuthError, AuthFactory, AuthMode, AuthScheme, Endpoint, Proxy, ProxyConfig,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinSet,
};

#[derive(Debug, Parser)]
#[command(about = "Loopback CONNECT throughput smoke benchmark")]
struct Cli {
    /// Total number of CONNECT tunnels to establish.
    #[arg(long, default_value_t = 5_000)]
    connections: usize,

    /// Number of benchmark clients running concurrently.
    #[arg(long, default_value_t = 200)]
    concurrency: usize,

    /// Bytes echoed through every established tunnel.
    #[arg(long, default_value_t = 32)]
    payload_bytes: usize,

    /// Simulate a two-token NTLM handshake before every tunnel.
    #[arg(long)]
    mock_ntlm: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.connections == 0 || cli.concurrency == 0 {
        bail!("connections and concurrency must be greater than zero");
    }

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_address = upstream_listener.local_addr()?;
    let upstream_task = tokio::spawn(run_mock_upstream(upstream_listener, cli.mock_ntlm));

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_address = proxy_listener.local_addr()?;
    let config = ProxyConfig {
        listen: proxy_address,
        upstream: Endpoint::new(upstream_address.ip().to_string(), upstream_address.port()),
        auth: if cli.mock_ntlm {
            AuthMode::Ntlm
        } else {
            AuthMode::None
        },
        connect_timeout: Duration::from_secs(5),
        idle_timeout: Some(Duration::from_secs(5)),
        max_header_bytes: 32 * 1024,
        max_connections: cli.concurrency * 2,
    };
    let proxy = if cli.mock_ntlm {
        Proxy::with_auth_factory(config, Arc::new(MockFactory))
    } else {
        Proxy::new(config)
    };
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let proxy_task = tokio::spawn(async move {
        proxy
            .serve_until(proxy_listener, async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    let next = Arc::new(AtomicUsize::new(0));
    let payload = Arc::new(vec![0x5a; cli.payload_bytes]);
    let started = Instant::now();
    let mut workers = JoinSet::new();
    for _ in 0..cli.concurrency {
        let next = next.clone();
        let payload = payload.clone();
        workers.spawn(async move {
            let mut latencies = Vec::new();
            loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= cli.connections {
                    break;
                }
                latencies.push(run_client(proxy_address, &payload).await?);
            }
            Ok::<_, io::Error>(latencies)
        });
    }

    let mut latencies = Vec::with_capacity(cli.connections);
    while let Some(result) = workers.join_next().await {
        latencies.extend(result??);
    }
    let elapsed = started.elapsed();
    latencies.sort_unstable();

    let _ = shutdown_tx.send(());
    proxy_task.await??;
    upstream_task.abort();

    let Ok(connection_count) = u32::try_from(cli.connections) else {
        bail!("connection count is too large to report");
    };
    let rate = f64::from(connection_count) / elapsed.as_secs_f64();
    println!("connections: {}", cli.connections);
    println!("concurrency: {}", cli.concurrency);
    println!("mock NTLM: {}", cli.mock_ntlm);
    println!("elapsed: {:.3}s", elapsed.as_secs_f64());
    println!("CONNECT/s: {rate:.0}");
    println!(
        "p50: {:.3}ms",
        percentile(&latencies, 50).as_secs_f64() * 1_000.0
    );
    println!(
        "p95: {:.3}ms",
        percentile(&latencies, 95).as_secs_f64() * 1_000.0
    );
    println!(
        "p99: {:.3}ms",
        percentile(&latencies, 99).as_secs_f64() * 1_000.0
    );
    Ok(())
}

async fn run_mock_upstream(listener: TcpListener, mock_ntlm: bool) -> io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let _ = handle_mock_upstream(stream, mock_ntlm).await;
        });
    }
}

async fn handle_mock_upstream(mut stream: TcpStream, mock_ntlm: bool) -> io::Result<()> {
    let _ = read_head(&mut stream).await?;
    if mock_ntlm {
        stream
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: NTLM\r\n\
                  Content-Length: 0\r\n\r\n",
            )
            .await?;
        let _ = read_head(&mut stream).await?;
        stream
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: NTLM dHlwZTI=\r\n\
                  Content-Length: 0\r\n\r\n",
            )
            .await?;
        let _ = read_head(&mut stream).await?;
    }
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    let mut payload = Vec::new();
    stream.read_to_end(&mut payload).await?;
    stream.write_all(&payload).await?;
    stream.shutdown().await
}

async fn run_client(proxy_address: SocketAddr, payload: &[u8]) -> io::Result<Duration> {
    let started = Instant::now();
    let mut stream = TcpStream::connect(proxy_address).await?;
    stream
        .write_all(
            b"CONNECT benchmark.test:443 HTTP/1.1\r\n\
              Host: benchmark.test:443\r\n\r\n",
        )
        .await?;
    let remaining = read_head(&mut stream).await?;
    if !remaining.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected bytes after CONNECT response",
        ));
    }

    stream.write_all(payload).await?;
    stream.shutdown().await?;
    let mut echoed = Vec::new();
    stream.read_to_end(&mut echoed).await?;
    if echoed != payload {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tunnel echo mismatch",
        ));
    }
    Ok(started.elapsed())
}

async fn read_head(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            return Ok(bytes.split_off(position + 4));
        }
        if bytes.len() >= 32 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP head exceeds benchmark limit",
            ));
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before HTTP head completed",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
}

fn percentile(values: &[Duration], percentile: usize) -> Duration {
    let index = (values.len() - 1) * percentile / 100;
    values[index]
}

#[derive(Debug)]
struct MockFactory;

impl AuthFactory for MockFactory {
    fn create(
        &self,
        _scheme: AuthScheme,
        _target_name: &str,
    ) -> Result<Box<dyn AuthContext>, AuthError> {
        Ok(Box::new(MockContext { step: 0 }))
    }
}

struct MockContext {
    step: usize,
}

impl AuthContext for MockContext {
    fn step(&mut self, _challenge: Option<&[u8]>) -> Result<Vec<u8>, AuthError> {
        let token = if self.step == 0 { b"type1" } else { b"type3" };
        self.step += 1;
        Ok(token.to_vec())
    }
}
