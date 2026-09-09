//! Fail-closed HTTP client constructor — the single chokepoint through which
//! every outbound request in this module is built.
//!
//! This is an inlined copy of the canonical `logos-net-proxy` crate
//! (`repos/logos-net-proxy`), vendored here because the module builder only
//! stages a module's `rust-lib` directory (a sibling Cargo `path` dep would not
//! be visible in the nix sandbox). The canonical crate remains the audited
//! reference + standalone test harness; keep the two in sync. There is
//! deliberately no other constructor of a `reqwest::Client` in this crate — a
//! unit test asserts `reqwest::blocking::Client::builder` appears only here.

use std::time::Duration;
use thiserror::Error;

/// Outbound network policy for the client we are about to build.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProxyConfig {
    /// Proxy URL, e.g. `socks5h://127.0.0.1:9050` (`socks5h` resolves DNS through
    /// the proxy — the privacy-preferred scheme for Tor). `None` = no proxy.
    pub proxy: Option<String>,
    /// When `true`, a request MUST traverse a proxy; if none is usable,
    /// [`build_client`] fails closed instead of building a clear-net client.
    pub proxy_required: bool,
    /// Per-request timeout in seconds. `0` leaves reqwest's default.
    pub timeout_secs: u64,
}

impl ProxyConfig {
    pub fn new(proxy: Option<String>, proxy_required: bool, timeout_secs: u64) -> Self {
        Self { proxy, proxy_required, timeout_secs }
    }
}

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("proxy required but none configured (fail-closed: refusing to send in the clear)")]
    ProxyRequiredButUnset,
    #[error("proxy URL is invalid or unsupported: {0}")]
    ProxyUnusable(String),
    #[error("failed to build HTTP client: {0}")]
    Build(String),
}

fn validate_proxy_url(p: &str) -> Result<(), ProxyError> {
    let parsed = url::Url::parse(p).map_err(|e| ProxyError::ProxyUnusable(format!("{p}: {e}")))?;
    match parsed.scheme() {
        "socks5h" | "socks5" | "http" | "https" => Ok(()),
        other => Err(ProxyError::ProxyUnusable(format!("unsupported proxy scheme: {other}"))),
    }
}

/// Build a blocking client honoring `cfg`. The ONLY client constructor in this
/// crate. Fails closed when a proxy is required but unusable.
pub fn build_client(cfg: &ProxyConfig) -> Result<reqwest::blocking::Client, ProxyError> {
    let mut builder = reqwest::blocking::Client::builder();

    let has_proxy = cfg.proxy.as_deref().is_some_and(|p| !p.trim().is_empty());
    if has_proxy {
        let p = cfg.proxy.as_deref().unwrap().trim();
        validate_proxy_url(p)?;
        let proxy = reqwest::Proxy::all(p).map_err(|e| ProxyError::ProxyUnusable(e.to_string()))?;
        builder = builder.proxy(proxy);
    } else {
        if cfg.proxy_required {
            return Err(ProxyError::ProxyRequiredButUnset);
        }
        builder = builder.no_proxy();
    }

    if cfg.timeout_secs > 0 {
        builder = builder.timeout(Duration::from_secs(cfg.timeout_secs));
    }

    builder.build().map_err(|e| ProxyError::Build(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_closed_when_required_and_unset() {
        assert!(matches!(
            build_client(&ProxyConfig::new(None, true, 30)),
            Err(ProxyError::ProxyRequiredButUnset)
        ));
    }

    #[test]
    fn ok_when_not_required_and_unset() {
        assert!(build_client(&ProxyConfig::new(None, false, 30)).is_ok());
    }

    #[test]
    fn rejects_unsupported_scheme() {
        assert!(matches!(
            build_client(&ProxyConfig::new(Some("ftp://1.2.3.4:21".into()), true, 30)),
            Err(ProxyError::ProxyUnusable(_))
        ));
    }
}
