use std::{fmt, net::SocketAddr, num::ParseIntError, str::FromStr, time::Duration};

use clap::ValueEnum;
use thiserror::Error;

/// Upstream authentication behavior.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum AuthMode {
    /// Prefer Negotiate and fall back to NTLM based on the proxy challenge.
    #[default]
    Auto,
    /// Require the Negotiate authentication scheme.
    Negotiate,
    /// Require the NTLM authentication scheme.
    Ntlm,
    /// Forward CONNECT without upstream authentication.
    None,
}

/// A validated `host:port` endpoint.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Endpoint {
    host: String,
    port: u16,
}

impl Endpoint {
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(formatter, "[{}]:{}", self.host, self.port)
        } else {
            write!(formatter, "{}:{}", self.host, self.port)
        }
    }
}

impl FromStr for Endpoint {
    type Err = EndpointParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.is_empty() {
            return Err(EndpointParseError::Empty);
        }

        let (host, port) = if let Some(bracketed) = input.strip_prefix('[') {
            let closing = bracketed.find(']').ok_or(EndpointParseError::InvalidIpv6)?;
            let host = &bracketed[..closing];
            let suffix = &bracketed[closing + 1..];
            let port = suffix
                .strip_prefix(':')
                .ok_or(EndpointParseError::MissingPort)?;
            (host, port)
        } else {
            let (host, port) = input
                .rsplit_once(':')
                .ok_or(EndpointParseError::MissingPort)?;
            if host.contains(':') {
                return Err(EndpointParseError::UnbracketedIpv6);
            }
            (host, port)
        };

        if host.is_empty() {
            return Err(EndpointParseError::EmptyHost);
        }
        if host
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'/' | b'@' | b'\r' | b'\n'))
        {
            return Err(EndpointParseError::InvalidHost);
        }

        let port = port.parse::<u16>()?;
        if port == 0 {
            return Err(EndpointParseError::ZeroPort);
        }

        Ok(Self::new(host, port))
    }
}

#[derive(Debug, Error)]
pub enum EndpointParseError {
    #[error("endpoint is empty")]
    Empty,
    #[error("endpoint host is empty")]
    EmptyHost,
    #[error("endpoint host contains invalid characters")]
    InvalidHost,
    #[error("endpoint is missing a port")]
    MissingPort,
    #[error("IPv6 addresses must be enclosed in brackets")]
    UnbracketedIpv6,
    #[error("invalid bracketed IPv6 endpoint")]
    InvalidIpv6,
    #[error("port must not be zero")]
    ZeroPort,
    #[error("invalid port: {0}")]
    InvalidPort(#[from] ParseIntError),
}

/// Runtime settings for a proxy instance.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub upstream: Endpoint,
    pub auth: AuthMode,
    pub connect_timeout: Duration,
    pub idle_timeout: Option<Duration>,
    pub max_header_bytes: usize,
    pub max_connections: usize,
}

#[cfg(test)]
mod tests {
    use super::Endpoint;

    #[test]
    fn parses_dns_and_ipv6_endpoints() {
        let dns: Endpoint = "proxy.example:8080".parse().unwrap();
        assert_eq!(dns.host(), "proxy.example");
        assert_eq!(dns.port(), 8080);

        let ipv6: Endpoint = "[2001:db8::1]:3128".parse().unwrap();
        assert_eq!(ipv6.host(), "2001:db8::1");
        assert_eq!(ipv6.to_string(), "[2001:db8::1]:3128");
    }

    #[test]
    fn rejects_unsafe_or_ambiguous_endpoints() {
        for invalid in [
            "",
            "proxy",
            "proxy:0",
            "user@proxy:80",
            "proxy\r\nInjected: yes:80",
            "2001:db8::1:3128",
        ] {
            assert!(invalid.parse::<Endpoint>().is_err(), "{invalid}");
        }
    }
}
