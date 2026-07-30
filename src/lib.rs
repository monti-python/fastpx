//! Core library for the `fastpx` authenticated CONNECT proxy.

mod auth;
mod config;
mod http1;
mod relay;
mod server;

pub use auth::{AuthContext, AuthError, AuthFactory, AuthScheme, NativeAuthFactory};
pub use config::{AuthMode, Endpoint, ProxyConfig};
pub use server::Proxy;
