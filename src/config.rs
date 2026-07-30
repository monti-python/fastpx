use std::{
    fmt,
    net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::ParseIntError,
    str::FromStr,
    time::Duration,
};

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

/// How CONNECT destinations are routed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum RoutingMode {
    /// Resolve destinations locally and connect directly to internal addresses.
    #[default]
    Auto,
    /// Send every destination through the configured upstream proxy.
    ProxyOnly,
}

/// An IPv4 or IPv6 network used by automatic direct routing.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

impl IpCidr {
    #[must_use]
    pub fn contains(self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => mask_v4(address, self.prefix) == network,
            (IpAddr::V6(network), IpAddr::V6(address)) => mask_v6(address, self.prefix) == network,
            _ => false,
        }
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.prefix)
    }
}

impl FromStr for IpCidr {
    type Err = IpCidrParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = input
            .split_once('/')
            .ok_or(IpCidrParseError::MissingPrefix)?;
        let address = address.parse::<IpAddr>()?;
        let prefix = prefix.parse::<u8>()?;
        let network = match address {
            IpAddr::V4(address) if prefix <= 32 => IpAddr::V4(mask_v4(address, prefix)),
            IpAddr::V6(address) if prefix <= 128 => IpAddr::V6(mask_v6(address, prefix)),
            IpAddr::V4(_) => return Err(IpCidrParseError::PrefixTooLong(32)),
            IpAddr::V6(_) => return Err(IpCidrParseError::PrefixTooLong(128)),
        };
        Ok(Self { network, prefix })
    }
}

fn mask_v4(address: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(u32::from(address) & mask)
}

fn mask_v6(address: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    Ipv6Addr::from(u128::from(address) & mask)
}

#[derive(Debug, Error)]
pub enum IpCidrParseError {
    #[error("CIDR is missing a prefix length")]
    MissingPrefix,
    #[error("invalid IP address: {0}")]
    InvalidAddress(#[from] AddrParseError),
    #[error("invalid prefix length: {0}")]
    InvalidPrefix(#[from] ParseIntError),
    #[error("prefix length exceeds the {0}-bit address size")]
    PrefixTooLong(u8),
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
    pub routing: RoutingMode,
    pub direct_cidrs: Vec<IpCidr>,
    pub dns_timeout: Duration,
    pub connect_timeout: Duration,
    pub idle_timeout: Option<Duration>,
    pub max_header_bytes: usize,
    pub max_connections: usize,
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{Endpoint, IpCidr};

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

    #[test]
    fn cidr_normalizes_and_matches_addresses() {
        let ipv4: IpCidr = "10.20.30.40/12".parse().unwrap();
        assert_eq!(ipv4.to_string(), "10.16.0.0/12");
        assert!(ipv4.contains("10.31.255.255".parse::<IpAddr>().unwrap()));
        assert!(!ipv4.contains("10.32.0.0".parse::<IpAddr>().unwrap()));

        let ipv6: IpCidr = "fd12:3456::abcd/48".parse().unwrap();
        assert_eq!(ipv6.to_string(), "fd12:3456::/48");
        assert!(ipv6.contains("fd12:3456::1".parse::<IpAddr>().unwrap()));
        assert!(!ipv6.contains("fd12:3457::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn rejects_invalid_cidrs() {
        for invalid in ["10.0.0.0", "10.0.0.0/33", "fd00::/129", "host/24"] {
            assert!(invalid.parse::<IpCidr>().is_err(), "{invalid}");
        }
    }
}
