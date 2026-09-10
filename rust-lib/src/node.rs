//! Proxyable monerod RPC client core.
//!
//! Per-network config (endpoint + proxy policy), persisted to disk, keyed by network name
//! (`mainnet`/`stagenet`/`testnet`/`regtest`) rather than an EVM chainId. Every outbound
//! request is built through the fail-closed [`crate::proxy`] chokepoint, so a network
//! configured `proxyRequired` with no usable proxy refuses to call rather than leaking in the
//! clear. Pure (no Logos deps) and unit-testable with `cargo test --no-default-features`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::proxy::{build_client, ProxyConfig};

/// The networks a wallet may talk to. Fixed set: a monerod is one of these, and an
/// unrecognised name is a configuration error, not a new network.
pub const NETWORKS: &[&str] = &["mainnet", "stagenet", "testnet", "regtest"];

pub fn is_network(name: &str) -> bool {
    NETWORKS.contains(&name)
}

fn default_timeout() -> u64 {
    // Well under the 20s Logos RPC deadline, matching eth_rpc_module's reasoning: a single
    // dead endpoint must surface as "unreachable" before the protocol timeout fires.
    8
}

/// One network's transport config. camelCase on the wire to match `chains.json` conventions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeConfig {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    #[serde(default, rename = "proxyRequired")]
    pub proxy_required: bool,
    #[serde(default = "default_timeout", rename = "timeoutSecs")]
    pub timeout_secs: u64,
    /// Loopback nodes may be trusted; a remote node must not be (it gates wallet2 commands
    /// that leak on an untrusted daemon). Advisory here — the wallet module enforces it.
    #[serde(default)]
    pub trusted: bool,
    /// "default" (seeded by init_defaults) or "external" (a UI wrote it).
    #[serde(default = "source_default")]
    pub source: String,
}

fn source_default() -> String { "external".into() }

impl NodeConfig {
    fn proxy_cfg(&self) -> ProxyConfig {
        ProxyConfig::new(self.proxy.clone(), self.proxy_required, self.timeout_secs)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("unknown network: {0}")]
    UnknownNetwork(String),
    #[error("network not configured: {0}")]
    NotConfigured(String),
    #[error("proxy: {0}")]
    Proxy(String),
    #[error("http: {0}")]
    Http(String),
    #[error("rpc error {code}: {message}")]
    Rpc { code: i64, message: String },
    #[error("parse: {0}")]
    Parse(String),
}

type Result<T> = std::result::Result<T, NodeError>;

/// The persisted, per-network registry. `path` is `None` in pure tests.
pub struct Nodes {
    map: BTreeMap<String, NodeConfig>,
    path: Option<PathBuf>,
}

impl Nodes {
    pub fn new(path: Option<PathBuf>) -> Self {
        let map = path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str::<BTreeMap<String, NodeConfig>>(&s).ok())
            .unwrap_or_default();
        Self { map, path }
    }

    fn persist(&self) -> Result<()> {
        let Some(p) = self.path.as_ref() else { return Ok(()) };
        let body = serde_json::to_string_pretty(&self.map)
            .map_err(|e| NodeError::Parse(e.to_string()))?;
        // Atomic: stage under a sibling name, then rename. A half-written registry that a
        // reader then parses as "no networks" is exactly the silent failure to avoid.
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, body.as_bytes()).map_err(|e| NodeError::Http(e.to_string()))?;
        std::fs::rename(&tmp, p).map_err(|e| NodeError::Http(e.to_string()))
    }

    pub fn get(&self, network: &str) -> Option<&NodeConfig> {
        self.map.get(network)
    }

    pub fn list(&self) -> Vec<String> {
        self.map.keys().cloned().collect()
    }

    /// Replace one network's config from a full object. Refuses an unknown network.
    ///
    /// The URL is normalised on the way in. `post()` builds `{url}/{path}` by concatenation, so
    /// a schemeless `host:port` — which is exactly what the wallet's own field used to ask for —
    /// produces `host:port/json_rpc`, and reqwest rejects that as having no base. Storing it
    /// verbatim turned a typo-shaped input into an obscure transport error much later.
    pub fn set(&mut self, network: &str, mut cfg: NodeConfig) -> Result<()> {
        if !is_network(network) {
            return Err(NodeError::UnknownNetwork(network.into()));
        }
        cfg.url = normalise_url(&cfg.url);
        self.map.insert(network.into(), cfg);
        self.persist()
    }

    pub fn remove(&mut self, network: &str) -> Result<bool> {
        let removed = self.map.remove(network).is_some();
        if removed { self.persist()?; }
        Ok(removed)
    }

    /// Seed defaults PER FIELD where absent, never per record — the EVM review's B3 lesson: a
    /// whole-record `ensure` silently hands a second consumer the first one's transport config.
    /// Returns the list of `(network, field)` pairs it actually seeded.
    pub fn init_defaults(&mut self) -> Result<Vec<String>> {
        let mut applied = Vec::new();
        for (net, url, trusted) in DEFAULT_ENDPOINTS {
            let entry = self.map.entry((*net).into()).or_insert_with(|| {
                applied.push(format!("{net}.endpoint"));
                NodeConfig {
                    url: (*url).into(),
                    username: None,
                    password: None,
                    proxy: None,
                    proxy_required: false,
                    timeout_secs: default_timeout(),
                    trusted: *trusted,
                    source: "default".into(),
                }
            });
            // Fill only genuinely-empty fields on an existing record.
            if entry.url.is_empty() {
                entry.url = (*url).into();
                applied.push(format!("{net}.endpoint"));
            }
        }
        if !applied.is_empty() { self.persist()?; }
        Ok(applied)
    }

    /// `{ ok, state, source, networks }`. Only `unconfigured` licenses a consumer write.
    pub fn config_status(&self) -> Value {
        let state = if self.map.is_empty() {
            "unconfigured"
        } else if self.map.values().all(|c| !c.url.is_empty()) {
            "configured"
        } else {
            "unready"
        };
        let source = if self.map.values().any(|c| c.source == "external") {
            "external"
        } else if self.map.is_empty() {
            "none"
        } else {
            "default"
        };
        json!({ "ok": true, "state": state, "source": source, "networks": self.list() })
    }

    fn client(&self, network: &str) -> Result<(reqwest::blocking::Client, NodeConfig)> {
        let c = self.get(network).ok_or_else(|| NodeError::NotConfigured(network.into()))?.clone();
        let client = build_client(&c.proxy_cfg()).map_err(|e| NodeError::Proxy(e.to_string()))?;
        Ok((client, c))
    }

    fn route(cfg: &NodeConfig) -> &'static str {
        if cfg.proxy.as_deref().is_some_and(|p| !p.trim().is_empty()) { "proxied" } else { "direct" }
    }

    /// A monerod JSON-RPC call: POST `<url>/json_rpc`. Returns `(result, route)`.
    pub fn json_rpc(&self, network: &str, method: &str, params: Value) -> Result<(Value, &'static str)> {
        let (client, cfg) = self.client(network)?;
        let body = json!({ "jsonrpc": "2.0", "id": "0", "method": method, "params": params });
        let v = self.post(&client, &cfg, "json_rpc", body)?;
        if let Some(err) = v.get("error") {
            return Err(NodeError::Rpc {
                code: err.get("code").and_then(Value::as_i64).unwrap_or(0),
                message: err.get("message").and_then(Value::as_str).unwrap_or("").into(),
            });
        }
        let result = v.get("result").cloned()
            .ok_or_else(|| NodeError::Parse("response had no `result`".into()))?;
        Ok((result, Self::route(&cfg)))
    }

    /// A non-JSON-RPC ("other") endpoint: POST `<url>/<path>`. Returns the whole body + route.
    pub fn other(&self, network: &str, path: &str, body: Value) -> Result<(Value, &'static str)> {
        let (client, cfg) = self.client(network)?;
        let v = self.post(&client, &cfg, path, body)?;
        Ok((v, Self::route(&cfg)))
    }

    fn post(&self, client: &reqwest::blocking::Client, cfg: &NodeConfig, path: &str, body: Value)
        -> Result<Value>
    {
        let base = cfg.url.trim_end_matches('/');
        let url = format!("{base}/{path}");
        let mut req = client.post(&url).json(&body);
        if let (Some(u), Some(p)) = (cfg.username.as_deref(), cfg.password.as_deref()) {
            // Basic auth covers the common self-hosted case. monerod's --rpc-login uses HTTP
            // Digest; a digest challenge is surfaced as an error rather than silently failing
            // (see health()'s 401 note). Digest is a deferred follow-up.
            if !u.is_empty() { req = req.basic_auth(u, Some(p)); }
        }
        let resp = req.send().map_err(|e| NodeError::Http(e.to_string()))?;
        resp.json::<Value>().map_err(|e| NodeError::Http(e.to_string()))
    }

    // ── Typed reads ───────────────────────────────────────────────────────────

    pub fn get_info(&self, network: &str) -> Result<(Value, &'static str)> {
        self.json_rpc(network, "get_info", json!({}))
    }

    pub fn get_fee_estimate(&self, network: &str) -> Result<(Value, &'static str)> {
        self.json_rpc(network, "get_fee_estimate", json!({}))
    }

    pub fn get_version(&self, network: &str) -> Result<(Value, &'static str)> {
        self.json_rpc(network, "get_version", json!({}))
    }

    pub fn hard_fork_info(&self, network: &str) -> Result<(Value, &'static str)> {
        self.json_rpc(network, "hard_fork_info", json!({}))
    }

    /// `/send_raw_transaction` — the broadcast path. `tx_as_hex` is the signed blob.
    pub fn send_raw_transaction(&self, network: &str, tx_as_hex: &str, do_not_relay: bool)
        -> Result<(Value, &'static str)>
    {
        self.other(network, "send_raw_transaction",
            json!({ "tx_as_hex": tx_as_hex, "do_not_relay": do_not_relay }))
    }

    /// regtest only: mine blocks to an address. The Anvil-analogue for fast tests.
    pub fn generateblocks(&self, network: &str, address: &str, amount: u64)
        -> Result<(Value, &'static str)>
    {
        self.json_rpc(network, "generateblocks",
            json!({ "amount_of_blocks": amount, "wallet_address": address, "starting_nonce": 0 }))
    }

    /// `{ reachable, height, targetHeight, synced, restricted, rttMs }` — for a settings UI
    /// and the wallet's sync chip. Never errors on an unreachable node: it reports it.
    pub fn node_health(&self, network: &str) -> Value {
        if !is_network(network) {
            return json!({ "ok": false, "error": format!("unknown network: {network}") });
        }
        let started = Instant::now();
        match self.get_info(network) {
            Ok((info, route)) => {
                let rtt = started.elapsed().as_millis() as u64;
                json!({
                    "ok": true,
                    "reachable": true,
                    "height": info.get("height").and_then(Value::as_u64),
                    "targetHeight": info.get("target_height").and_then(Value::as_u64),
                    "synced": info.get("synchronized").and_then(Value::as_bool),
                    "restricted": info.get("restricted").and_then(Value::as_bool),
                    "rttMs": rtt,
                    "route": route,
                })
            }
            Err(e) => json!({ "ok": true, "reachable": false, "error": e.to_string() }),
        }
    }
}

/// Give a URL a scheme if it has none: `node.example:38089` -> `http://node.example:38089`.
/// Left alone otherwise, including `https://` and any scheme a proxy setup might need.
fn normalise_url(url: &str) -> String {
    let u = url.trim();
    if u.is_empty() || u.contains("://") { u.to_string() } else { format!("http://{u}") }
}

/// Well-known defaults so a fresh device works before any settings app has run. Public nodes
/// for the live networks; loopback for a node the user runs themselves and for regtest.
///
/// These are somebody else's machines, and each daemon on them can wedge INDEPENDENTLY of the
/// host: on 2026-09-10 `node.monerodevs.org:38089` accepted TCP and then never answered HTTP,
/// while 18089 and 28089 on that same host served fine. So the stagenet default moved to node2,
/// which was measured serving all three ports. A default cannot be more than a starting point —
/// `set_node_config` is the answer, and the wallet's Wallets screen exposes it. Deliberately no
/// automatic failover: on a privacy coin, silently moving a user's queries to a different
/// operator is not a convenience.
/// (network, url, trusted)
pub const DEFAULT_ENDPOINTS: &[(&str, &str, bool)] = &[
    ("mainnet",  "http://node.monerodevs.org:18089",  false),
    ("stagenet", "http://node2.monerodevs.org:38089", false),
    ("testnet",  "http://node.monerodevs.org:28089",  false),
    ("regtest",  "http://127.0.0.1:18081",            true),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_schemeless_url_gets_a_scheme_before_it_is_stored() {
        let mut n = Nodes::new(None);
        n.set("stagenet", cfg("node2.monerodevs.org:38089")).unwrap();
        // Without this, post() would build "node2.monerodevs.org:38089/json_rpc".
        assert_eq!(n.get("stagenet").unwrap().url, "http://node2.monerodevs.org:38089");
        // A URL that already carries a scheme is left exactly as it was.
        n.set("stagenet", cfg("https://my.node:443")).unwrap();
        assert_eq!(n.get("stagenet").unwrap().url, "https://my.node:443");
    }

    fn cfg(url: &str) -> NodeConfig {
        NodeConfig { url: url.into(), username: None, password: None, proxy: None,
                     proxy_required: false, timeout_secs: 8, trusted: false, source: "external".into() }
    }

    #[test]
    fn unknown_network_is_refused() {
        let mut n = Nodes::new(None);
        assert!(matches!(n.set("mainet", cfg("http://x")), Err(NodeError::UnknownNetwork(_))));
    }

    #[test]
    fn init_defaults_seeds_all_four_then_is_idempotent() {
        let mut n = Nodes::new(None);
        let first = n.init_defaults().unwrap();
        assert_eq!(first.len(), 4, "all four networks seeded on a blank registry");
        let second = n.init_defaults().unwrap();
        assert!(second.is_empty(), "second run seeds nothing");
        assert_eq!(n.list().len(), 4);
    }

    #[test]
    fn init_defaults_does_not_clobber_an_external_endpoint() {
        let mut n = Nodes::new(None);
        n.set("mainnet", cfg("http://my.own.node:18081")).unwrap();
        n.init_defaults().unwrap();
        assert_eq!(n.get("mainnet").unwrap().url, "http://my.own.node:18081");
        assert_eq!(n.get("mainnet").unwrap().source, "external");
    }

    #[test]
    fn config_status_states() {
        let mut n = Nodes::new(None);
        assert_eq!(n.config_status()["state"], "unconfigured");
        n.init_defaults().unwrap();
        assert_eq!(n.config_status()["state"], "configured");
        assert_eq!(n.config_status()["source"], "default");
        n.set("mainnet", cfg("http://x")).unwrap();
        assert_eq!(n.config_status()["source"], "external");
    }

    #[test]
    fn proxy_required_without_proxy_fails_closed() {
        let mut n = Nodes::new(None);
        let mut c = cfg("http://node:18089");
        c.proxy_required = true;
        n.set("stagenet", c).unwrap();
        // Any call must refuse rather than build a clear-net client.
        let r = n.get_info("stagenet");
        assert!(matches!(r, Err(NodeError::Proxy(_))), "got {r:?}");
    }

    #[test]
    fn health_of_unreachable_node_reports_rather_than_errors() {
        let mut n = Nodes::new(None);
        // Reserved-TEST-net address, no server: connect fails fast under the 8s timeout.
        n.set("regtest", cfg("http://192.0.2.1:18081")).unwrap();
        let h = n.node_health("regtest");
        assert_eq!(h["ok"], true);
        assert_eq!(h["reachable"], false);
    }

    #[test]
    fn persistence_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("monero_nodes.json");
        {
            let mut n = Nodes::new(Some(p.clone()));
            n.init_defaults().unwrap();
        }
        let reloaded = Nodes::new(Some(p));
        assert_eq!(reloaded.list().len(), 4);
    }
}
