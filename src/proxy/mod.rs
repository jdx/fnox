//! The credential proxy behind `fnox proxy run`: it hands the child
//! placeholders and injects real values into approved HTTPS requests.

use crate::config::{ProxyConfig, ProxyEgress, ProxyRule};
use crate::error::{FnoxError, Result};
use base64::Engine;
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use indexmap::IndexMap;
use ipnet::IpNet;
use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, Issuer, KeyPair};
use reqwest::Method;
use rustls::ServerConfig;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, LazyLock};
use tempfile::NamedTempFile;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

use crate::local_http::{
    HttpRequest, MAX_HEADER_BYTES, constant_time_eq, read_http_request_limited, read_line_limited,
};

const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
const DEFAULT_HEADER: &str = "authorization";
/// Clients such as git first connect without credentials and retry after a
/// 407 on the same connection; give up after this many unauthenticated tries.
const MAX_AUTH_ATTEMPTS: usize = 3;

mod ca;
mod destination;
mod handle;
mod leases;
mod plan;
mod policy;
mod server;
#[cfg(test)]
mod tests;
mod values;

use ca::*;
use destination::*;
use handle::*;
use policy::*;
use values::*;

pub use handle::{
    ClientStream, MCP_HOST, MCP_RELAY_ENV, MCP_RELAY_PROFILE_ENV, McpService, ProxyHandle, RuleInfo,
};
pub use leases::{LeaseMinter, MintFuture, ProxyLeases};
pub use plan::{ProxyPlan, deny_inspection, validate_config};
pub use policy::target_label;
pub use server::{ProxyListener, RunningProxy};

fn proxy_error(message: impl Into<String>) -> FnoxError {
    FnoxError::Config(format!("proxy: {}", message.into()))
}
