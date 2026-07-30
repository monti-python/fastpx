use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result, bail};
use clap::Parser;
use fastpx::{AuthMode, Endpoint, Proxy, ProxyConfig};
use tokio::{net::TcpListener, signal};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Local address on which applications connect.
    #[arg(long, default_value = "127.0.0.1:3128")]
    listen: SocketAddr,

    /// Corporate proxy endpoint.
    #[arg(long, env = "FASTPX_PROXY")]
    upstream: Endpoint,

    /// Upstream authentication mode.
    #[arg(long, value_enum, default_value = "auto")]
    auth: AuthMode,

    /// Timeout for connecting to the corporate proxy.
    #[arg(long, default_value_t = 10)]
    connect_timeout_seconds: u64,

    /// Close tunnels after this many idle seconds; zero disables the timeout.
    #[arg(long, default_value_t = 300)]
    idle_timeout_seconds: u64,

    /// Maximum accepted HTTP request or response header size.
    #[arg(long, default_value_t = 32 * 1024)]
    max_header_bytes: usize,

    /// Maximum number of simultaneous client connections.
    #[arg(long, default_value_t = 4096)]
    max_connections: usize,

    /// Logging filter, such as `info` or `fastpx=debug`.
    #[arg(long, env = "FASTPX_LOG", default_value = "info")]
    log: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let filter = EnvFilter::try_new(&cli.log)
        .with_context(|| format!("invalid log filter {:?}", cli.log))?;
    tracing_subscriber::fmt().with_env_filter(filter).init();

    if cli.max_header_bytes < 1024 {
        bail!("--max-header-bytes must be at least 1024");
    }
    if cli.max_connections == 0 {
        bail!("--max-connections must be greater than zero");
    }
    if !cfg!(windows) && cli.auth != AuthMode::None {
        bail!("native SSPI requires Windows; use --auth none on this platform");
    }
    if !cli.listen.ip().is_loopback() {
        warn!(
            listen = %cli.listen,
            "non-loopback listener exposes your authenticated proxy to the network"
        );
    }

    let config = ProxyConfig {
        listen: cli.listen,
        upstream: cli.upstream,
        auth: cli.auth,
        connect_timeout: Duration::from_secs(cli.connect_timeout_seconds),
        idle_timeout: (cli.idle_timeout_seconds != 0)
            .then(|| Duration::from_secs(cli.idle_timeout_seconds)),
        max_header_bytes: cli.max_header_bytes,
        max_connections: cli.max_connections,
    };
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("failed to bind {}", config.listen))?;
    info!(
        listen = %config.listen,
        upstream = %config.upstream,
        auth = ?config.auth,
        "fastpx is ready"
    );

    Proxy::new(config)
        .serve_until(listener, async {
            let _ = signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
