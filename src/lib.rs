//! Core library for the `fastpx` authenticated CONNECT proxy.

mod auth;
mod config;
mod http1;
mod relay;
mod routing;
mod server;

pub use auth::{AuthContext, AuthError, AuthFactory, AuthScheme, NativeAuthFactory};
pub use config::{AuthMode, Endpoint, IpCidr, ProxyConfig, RoutingMode};
pub use server::Proxy;
