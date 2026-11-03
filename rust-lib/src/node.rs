//! Proxyable monerod RPC client core.
//!
//! Per-network config (endpoint + proxy policy), persisted to disk, keyed by network name
//! (`mainnet`/`stagenet`/`testnet`/`regtest`) rather than an EVM chainId. Every outbound
//! request is built through the fail-closed [`crate::proxy`] chokepoint, so a network
//! configured `proxyRequired` with no usable proxy refuses to call rather than leaking in the
//! clear. Pure (no Logos deps) and unit-testable with `cargo test --no-default-features`.
//!
//! A network in `local` mode dials the node `monerod_module` runs in-process instead of its
//! stored `url`, through the [`LocalNode`] seam.
//!
//! "Use Tor for" ([`TorUse`]) decides the route: `url` is the direct node, `onionUrl` the node
//! over Tor, and [`Nodes::plan`] picks between them. Tor routes never fall back to direct.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::proxy::{build_client, ProxyConfig};
use crate::tor::{is_onion, is_own_network, normalize_proxy, TorSettings, TorUse, TorView, BUILT_IN};

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

/// An onion service often takes 10-15 s to answer a first request.
const TOR_TIMEOUT: u64 = 15;

/// Where a network's calls go: its stored `url`, or the node `monerod_module` runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeMode {
    #[default]
    Remote,
    Local,
}

/// One network's transport config. camelCase on the wire to match `chains.json` conventions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeConfig {
    /// The direct node: everything in `none`, the catch-up in `identifying`.
    pub url: String,
    /// The node over Tor, in `all` and after the catch-up in `identifying`. Empty: `url` over Tor.
    #[serde(default, rename = "onionUrl", skip_serializing_if = "Option::is_none")]
    pub onion_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Which Tor: empty or `tor` is the one that comes with Logos, else your own `socks5h://`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    /// From before "Use Tor for": read only to migrate. Tor routes are always fail-closed.
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
    /// Absent from configs written before local mode existed, so those stay remote.
    #[serde(default)]
    pub mode: NodeMode,
}

fn source_default() -> String { "external".into() }

impl NodeConfig {
    fn proxy_cfg(&self) -> ProxyConfig {
        // monerod serves TLS with a certificate it made itself; wallet2 never checks it either.
        ProxyConfig::new(self.proxy.clone(), self.proxy_required, self.timeout_secs)
            .accept_self_signed(self.url.starts_with("https://"))
    }
}

/// Where one network's calls go under the current "Use Tor for".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub cfg: NodeConfig,
    pub tor_use: TorUse,
    pub url: String,
    pub via_tor: bool,
    /// `identifying`: the node a wallet catches up from directly before it moves to `url`.
    pub catch_up: Option<String>,
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
    #[error("local node: {0}")]
    Local(String),
    #[error("{0}")]
    Locked(String),
    #[error("{0}")]
    TorNotReady(String),
    #[error("this node is an onion service, reachable only over Tor, and Use Tor for is Nothing")]
    TorOff,
}

type Result<T> = std::result::Result<T, NodeError>;

/// The node `monerod_module` runs. A trait so the pure tests can stand one in.
pub trait LocalNode: Send + Sync {
    /// Its loopback RPC URL for `network`; empty if it cannot run that network.
    fn rpc_url(&self, network: &str) -> std::result::Result<String, String>;
    /// Its `status()`: state, network, height, peers, ...
    fn status(&self) -> std::result::Result<Value, String>;
}

/// The persisted, per-network registry. `path` is `None` in pure tests.
pub struct Nodes {
    map: BTreeMap<String, NodeConfig>,
    path: Option<PathBuf>,
    local: Option<Box<dyn LocalNode>>,
    tor_settings: TorSettings,
    /// The built-in Tor as tor_module last answered, written by the glue.
    tor: Arc<Mutex<Option<TorView>>>,
    /// A wallet asked for a route through the built-in Tor, so following it may start it.
    asked: Arc<AtomicBool>,
    /// Networks the wallet engine has a wallet open on: their settings are locked.
    wallet_open: BTreeSet<String>,
}

impl Nodes {
    pub fn new(path: Option<PathBuf>) -> Self {
        let map = path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str::<BTreeMap<String, NodeConfig>>(&s).ok())
            .unwrap_or_default();
        let saved = path.as_deref().and_then(|p| TorSettings::load(&TorSettings::path_beside(p)));
        let tor_settings = saved.clone().unwrap_or_else(|| {
            if map.is_empty() {
                TorSettings::fresh()
            } else {
                TorSettings::migrated(map.values().any(|c| c.proxy_required || c.proxy.as_deref().is_some_and(|p| !p.trim().is_empty())))
            }
        });
        let mut n = Self { map, path, local: None, tor_settings, tor: Arc::default(), asked: Arc::default(), wallet_open: BTreeSet::new() };
        if saved.is_none() {
            let _ = n.persist_tor();
        }
        if n.upgrade_defaults() {
            let _ = n.persist();
        }
        n
    }

    /// Moves records the module seeded onto today's defaults: TLS, and an onion node for Tor.
    fn upgrade_defaults(&mut self) -> bool {
        let mut changed = false;
        for (net, c) in self.map.iter_mut().filter(|(_, c)| c.source == "default") {
            let Some(d) = DEFAULT_ENDPOINTS.iter().find(|d| d.0 == net) else { continue };
            if OLD_DEFAULT_URLS.contains(&c.url.as_str()) && c.url != d.1 {
                c.url = d.1.into();
                changed = true;
            }
            if c.onion_url.is_none() && !d.2.is_empty() {
                c.onion_url = Some(d.2.into());
                changed = true;
            }
        }
        changed
    }

    fn persist_tor(&self) -> Result<()> {
        let Some(p) = self.path.as_ref() else { return Ok(()) };
        self.tor_settings.save(&TorSettings::path_beside(p)).map_err(|e| NodeError::Http(e.to_string()))
    }

    pub fn with_local(mut self, local: Box<dyn LocalNode>) -> Self {
        self.local = Some(local);
        self
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
        if self.wallet_open.contains(network) {
            return Err(NodeError::Locked("close the wallet before changing its node".into()));
        }
        if cfg.mode == NodeMode::Local && network == "regtest" {
            return Err(NodeError::Local("not available on regtest".into()));
        }
        cfg.url = normalise_url(&cfg.url);
        cfg.onion_url = cfg.onion_url.map(|u| normalise_url(&u)).filter(|u| !u.is_empty());
        cfg.proxy = match normalize_proxy(cfg.proxy.as_deref()).map_err(NodeError::Proxy)? {
            p if p == BUILT_IN => None,
            own => Some(own),
        };
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
        for (net, url, onion, trusted) in DEFAULT_ENDPOINTS {
            let entry = self.map.entry((*net).into()).or_insert_with(|| {
                applied.push(format!("{net}.endpoint"));
                NodeConfig {
                    url: (*url).into(),
                    onion_url: (!onion.is_empty()).then(|| (*onion).into()),
                    username: None,
                    password: None,
                    proxy: None,
                    proxy_required: false,
                    timeout_secs: default_timeout(),
                    trusted: *trusted,
                    source: "default".into(),
                    mode: NodeMode::Remote,
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

    /// Where `network`'s calls go. Local mode and your own network are direct in every mode; an
    /// onion service is Tor-only; in `identifying` a wallet first catches up from `url` directly.
    pub fn plan(&self, network: &str) -> Result<Plan> {
        let c = self.get(network).ok_or_else(|| NodeError::NotConfigured(network.into()))?;
        let tor_use = self.tor_settings.tor_use;
        let direct = |url: String| Plan { cfg: c.clone(), tor_use, url, via_tor: false, catch_up: None };
        if c.mode == NodeMode::Local {
            let local = self.local.as_ref()
                .ok_or_else(|| NodeError::Local("monerod_module is not available".into()))?;
            let url = local.rpc_url(network).map_err(NodeError::Local)?;
            if url.is_empty() {
                return Err(NodeError::Local(format!("no local node for {network}")));
            }
            return Ok(direct(url));
        }
        if tor_use == TorUse::None {
            if is_onion(&c.url) {
                return Err(NodeError::TorOff);
            }
            return Ok(direct(c.url.clone()));
        }
        let target = c.onion_url.clone().filter(|u| !u.trim().is_empty()).unwrap_or_else(|| c.url.clone());
        if is_own_network(&target) {
            return Ok(direct(target));
        }
        // The same node on both sides would see the catch-up and the sends together.
        let catch_up = (tor_use == TorUse::Identifying && !is_onion(&c.url) && c.url != target).then(|| c.url.clone());
        Ok(Plan { cfg: c.clone(), tor_use, url: target, via_tor: true, catch_up })
    }

    /// The SOCKS proxy for a Tor route: your own, or the built-in Tor once it is ready.
    fn socks(&self, cfg: &NodeConfig) -> Result<String> {
        let p = normalize_proxy(cfg.proxy.as_deref()).map_err(NodeError::Proxy)?;
        if p != BUILT_IN {
            return Ok(p);
        }
        self.asked.store(true, Ordering::Relaxed);
        match self.tor.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            Some(v) if v.usable_socks().is_some() => Ok(v.usable_socks().unwrap().to_string()),
            Some(v) if v.state == "ready" => Err(NodeError::TorNotReady("the Tor SOCKS port is off; turn it on in the Tor app".into())),
            Some(v) if v.state == "failed" && !v.answered => Err(NodeError::TorNotReady(format!("Tor is not available: {}", v.detail))),
            Some(v) => Err(NodeError::TorNotReady(format!("waiting for Tor ({}, {}%)", v.state, v.progress))),
            None => Err(NodeError::TorNotReady("waiting for Tor".into())),
        }
    }

    /// What a wallet dials: `{ url, proxy, proxyRequired, trusted, torUse, route, catchUp? }`.
    /// A Tor route the built-in Tor cannot carry yet has proxy `tor`, so the wallet waits for it.
    /// proxyRequired is set on every Tor route, so an older engine fails closed on it.
    pub fn effective(&self, network: &str) -> Result<Value> {
        let plan = self.plan(network)?;
        let c = &plan.cfg;
        let same = plan.url == c.url;
        let local = c.mode == NodeMode::Local;
        let (proxy, tor_ready) = if plan.via_tor {
            match self.socks(c) {
                Ok(p) => (Some(p), true),
                Err(NodeError::TorNotReady(_)) => (Some(BUILT_IN.to_string()), false),
                Err(e) => return Err(e),
            }
        } else {
            (None, false)
        };
        // No `proxy` key on a direct route: an older engine reads it as a string, never null.
        let mut v = json!({
            "url": plan.url,
            "proxyRequired": plan.via_tor,
            "trusted": local || (same && c.trusted && !plan.via_tor),
            "timeoutSecs": c.timeout_secs,
            "source": c.source,
            "mode": c.mode,
            "torUse": plan.tor_use,
            "route": if plan.via_tor { "proxied" } else { "direct" },
        });
        if let Some(p) = proxy {
            v["proxy"] = json!(p);
            v["torReady"] = json!(tor_ready);
        }
        if same && !local {
            if let Some(u) = &c.username { v["username"] = json!(u); }
            if let Some(p) = &c.password { v["password"] = json!(p); }
        }
        if let Some(u) = &plan.catch_up {
            v["catchUp"] = json!({ "url": u });
        }
        Ok(v)
    }

    /// The transport for this module's own calls: the plan's node, over Tor when it says so.
    fn dial(&self, network: &str) -> Result<NodeConfig> {
        let plan = self.plan(network)?;
        let c = &plan.cfg;
        let same = plan.url == c.url;
        let via_tor = plan.via_tor;
        Ok(NodeConfig {
            proxy: if via_tor { Some(self.socks(c)?) } else { None },
            proxy_required: via_tor,
            timeout_secs: if via_tor { c.timeout_secs.max(TOR_TIMEOUT) } else { c.timeout_secs },
            username: c.username.clone().filter(|_| same && c.mode == NodeMode::Remote),
            password: c.password.clone().filter(|_| same && c.mode == NodeMode::Remote),
            trusted: c.mode == NodeMode::Local || (same && c.trusted && !via_tor),
            onion_url: None,
            url: plan.url,
            ..c.clone()
        })
    }

    fn client(&self, network: &str) -> Result<(reqwest::blocking::Client, NodeConfig)> {
        let c = self.dial(network)?;
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

    /// `{ reachable, height, targetHeight, synced, restricted, rttMs, mode }`, plus `local` (the
    /// local node's status) in local mode. Never errors on an unreachable node: it reports it.
    pub fn node_health(&self, network: &str) -> Value {
        if !is_network(network) {
            return json!({ "ok": false, "error": format!("unknown network: {network}") });
        }
        let mode = self.get(network).map(|c| c.mode).unwrap_or_default();
        if mode == NodeMode::Remote {
            let mut h = self.remote_health(network);
            h["mode"] = json!(mode);
            h["torUse"] = json!(self.tor_settings.tor_use);
            h["torUseChosen"] = json!(self.tor_settings.chosen);
            return h;
        }
        // Ask the local node first: when it is absent that one bounded call is the whole cost,
        // which matters to a UI polling this every few seconds.
        let local = self.local_status();
        let mut h = if local["state"] == "unavailable" {
            json!({ "ok": true, "reachable": false,
                    "error": format!("local node: {}", local["error"].as_str().unwrap_or("unavailable")) })
        } else {
            self.dial_health(network)
        };
        h["mode"] = json!(mode);
        h["local"] = local;
        h["torUse"] = json!(self.tor_settings.tor_use);
        h["torUseChosen"] = json!(self.tor_settings.chosen);
        h
    }

    /// Health of the plan's node. A Tor route is not dialled until Tor can carry it, and a
    /// health poll alone never starts the built-in Tor.
    fn remote_health(&self, network: &str) -> Value {
        let plan = match self.plan(network) {
            Ok(p) => p,
            Err(e) => return json!({ "ok": true, "reachable": false, "error": e.to_string() }),
        };
        if !plan.via_tor {
            return self.dial_health(network);
        }
        let built_in = normalize_proxy(plan.cfg.proxy.as_deref()).is_ok_and(|p| p == BUILT_IN);
        let view = self.tor.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut h = if built_in && !view.as_ref().is_some_and(|v| v.usable_socks().is_some()) {
            let why = match &view {
                None => "Tor has not started yet".to_string(),
                Some(v) if v.state == "ready" => "the Tor SOCKS port is off".to_string(),
                Some(v) => format!("waiting for Tor ({}, {}%)", v.state, v.progress),
            };
            json!({ "ok": true, "reachable": false, "error": why, "route": "proxied" })
        } else {
            self.dial_health(network)
        };
        h["url"] = json!(plan.url);
        if let Some(u) = &plan.catch_up {
            h["catchUp"] = json!({ "url": u });
        }
        if built_in {
            h["tor"] = view.map(|v| v.json()).unwrap_or(json!({ "state": "idle", "answered": false }));
        }
        h
    }

    // ── Use Tor for ───────────────────────────────────────────────────────────

    /// `{ ok, torUse, torUseChosen, existing }`.
    pub fn tor_use(&self) -> Value {
        let mut v = self.tor_settings.json();
        v["ok"] = json!(true);
        v
    }

    /// Stores the user's choice. Refused while any wallet is open: it binds its node at open.
    pub fn set_tor_use(&mut self, mode: &str) -> Result<Value> {
        let tor_use = TorUse::parse(mode).ok_or_else(|| NodeError::Parse(format!("unknown mode: {mode} (all, identifying or none)")))?;
        if !self.wallet_open.is_empty() {
            return Err(NodeError::Locked("Close your open accounts to change this.".into()));
        }
        let before = self.tor_settings.clone();
        self.tor_settings.tor_use = tor_use;
        self.tor_settings.chosen = true;
        if let Err(e) = self.persist_tor() {
            self.tor_settings = before;
            return Err(e);
        }
        Ok(self.tor_use())
    }

    /// The wallet engine says a wallet opened or closed on `network`.
    pub fn set_wallet_open(&mut self, network: &str, open: bool) -> Result<Value> {
        if !is_network(network) {
            return Err(NodeError::UnknownNetwork(network.into()));
        }
        if open { self.wallet_open.insert(network.into()); } else { self.wallet_open.remove(network); }
        Ok(json!({ "ok": true, "network": network, "walletOpen": open }))
    }

    /// Whether `network` goes through the built-in Tor, so tor_module's status is needed.
    /// Local mode never does, and is skipped first: resolving it is an IPC call.
    pub fn wants_tor(&self, network: &str) -> bool {
        self.get(network).is_some_and(|c| c.mode == NodeMode::Remote)
            && self.plan(network).is_ok_and(|p| p.via_tor && normalize_proxy(p.cfg.proxy.as_deref()).is_ok_and(|x| x == BUILT_IN))
    }

    /// Whether a health poll may ask tor_module: once the user chose, or a wallet asked for Tor.
    /// Asking starts Tor, and a poll alone must not start it before the first-run choice.
    pub fn follows_tor(&self) -> bool {
        self.tor_settings.chosen || self.asked.load(Ordering::Relaxed)
    }

    /// Where the glue writes tor_module's status, without the registry's lock.
    pub fn tor_handle(&self) -> Arc<Mutex<Option<TorView>>> {
        self.tor.clone()
    }

    /// `{ ok, available, rpcUrl, status }`, whatever mode `network` is in: whether a settings UI
    /// can offer local mode, and what the local node is doing.
    pub fn local_node(&self, network: &str) -> Value {
        if !is_network(network) {
            return json!({ "ok": false, "error": format!("unknown network: {network}") });
        }
        let Some(local) = self.local.as_ref() else {
            return json!({ "ok": true, "available": false, "error": "monerod_module is not available" });
        };
        match local.rpc_url(network) {
            Ok(url) if !url.is_empty() =>
                json!({ "ok": true, "available": true, "rpcUrl": url, "status": self.local_status() }),
            Ok(_) => json!({ "ok": true, "available": false, "error": format!("no local node for {network}") }),
            Err(e) => json!({ "ok": true, "available": false, "error": e }),
        }
    }

    fn local_status(&self) -> Value {
        match self.local.as_ref().map(|l| l.status()) {
            Some(Ok(s)) => s,
            Some(Err(e)) => json!({ "state": "unavailable", "error": e }),
            None => json!({ "state": "unavailable", "error": "monerod_module is not available" }),
        }
    }

    fn dial_health(&self, network: &str) -> Value {
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
///
/// The direct node speaks TLS (monerod's own certificate); the node over Tor is an onion
/// service from Feather's list, run by someone other than the direct node's operator.
/// (network, url, onionUrl, trusted)
pub const DEFAULT_ENDPOINTS: &[(&str, &str, &str, bool)] = &[
    ("mainnet",  "https://node.monerodevs.org:18089",  "http://plowsof3t5hogddwabaeiyrno25efmzfxyro2vligremt7sxpsclfaid.onion:18089", false),
    ("stagenet", "https://node2.monerodevs.org:38089", "http://plowsof3t5hogddwabaeiyrno25efmzfxyro2vligremt7sxpsclfaid.onion:38089", false),
    ("testnet",  "https://node.monerodevs.org:28089",  "http://plowsoffjexmxalw73tkjmf422gq6575fc7vicuu4javzn2ynnte6tyd.onion:28089", false),
    ("regtest",  "http://127.0.0.1:18081",             "", true),
];

/// Plain-http defaults earlier builds seeded; a record still on one moves to TLS.
const OLD_DEFAULT_URLS: &[&str] = &[
    "http://node.monerodevs.org:18089", "http://node2.monerodevs.org:38089", "http://node.monerodevs.org:28089",
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
        NodeConfig { url: url.into(), onion_url: None, username: None, password: None, proxy: None,
                     proxy_required: false, timeout_secs: 8, trusted: false, source: "external".into(),
                     mode: NodeMode::Remote }
    }

    fn with_mode(mode: &str) -> Nodes {
        let mut n = Nodes::new(None);
        n.set_tor_use(mode).unwrap();
        n
    }

    fn ready_tor(n: &Nodes) {
        *n.tor_handle().lock().unwrap() = Some(TorView::from_reply(Ok(
            r#"{"ok":true,"state":"ready","progress":100,"socks":"socks5h://127.0.0.1:9250"}"#.into())));
    }

    const ONION: &str = "http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion:38089";

    fn both(url: &str) -> NodeConfig {
        NodeConfig { onion_url: Some(ONION.into()), ..cfg(url) }
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
        // A Tor route while the built-in Tor cannot carry traffic: refuse, never go direct.
        for mode in ["all", "identifying"] {
            let mut n = with_mode(mode);
            n.set("stagenet", both("http://node:18089")).unwrap();
            let r = n.get_info("stagenet");
            assert!(matches!(r, Err(NodeError::TorNotReady(_))), "{mode}: got {r:?}");
            let e = n.effective("stagenet").unwrap();
            assert_eq!((&e["proxy"], &e["proxyRequired"], &e["torReady"]), (&json!("tor"), &json!(true), &json!(false)));
        }
        // The SOCKS port off is the same refusal, with the reason.
        let mut n = with_mode("all");
        n.set("stagenet", both("http://node:18089")).unwrap();
        *n.tor_handle().lock().unwrap() = Some(TorView::from_reply(Ok(r#"{"ok":true,"state":"ready","socks":null}"#.into())));
        assert!(matches!(n.get_info("stagenet"), Err(NodeError::TorNotReady(e)) if e.contains("SOCKS port is off")));
    }

    #[test]
    fn each_mode_routes_the_wallet_where_it_says() {
        let mut n = with_mode("none");
        n.set("stagenet", both("https://clear.example:38089")).unwrap();
        let e = n.effective("stagenet").unwrap();
        assert_eq!((&e["url"], &e["proxyRequired"]), (&json!("https://clear.example:38089"), &json!(false)));
        assert!(e.get("proxy").is_none() && e.get("catchUp").is_none() && !n.wants_tor("stagenet"));

        n.set_tor_use("all").unwrap();
        ready_tor(&n);
        let e = n.effective("stagenet").unwrap();
        assert_eq!((&e["url"], &e["proxy"], &e["proxyRequired"]), (&json!(ONION), &json!("socks5h://127.0.0.1:9250"), &json!(true)));
        assert!(e.get("catchUp").is_none() && n.wants_tor("stagenet"));

        n.set_tor_use("identifying").unwrap();
        let e = n.effective("stagenet").unwrap();
        assert_eq!((&e["url"], &e["catchUp"]["url"], &e["torUse"]), (&json!(ONION), &json!("https://clear.example:38089"), &json!("identifying")));
    }

    #[test]
    fn onion_and_own_network_keep_their_route_in_every_mode() {
        // An onion service is reachable only over Tor: refused in none, never a catch-up.
        let mut n = with_mode("none");
        n.set("stagenet", cfg(ONION)).unwrap();
        assert!(matches!(n.effective("stagenet"), Err(NodeError::TorOff)));
        n.set_tor_use("identifying").unwrap();
        let e = n.effective("stagenet").unwrap();
        assert_eq!((&e["url"], &e["proxyRequired"]), (&json!(ONION), &json!(true)));
        assert!(e.get("catchUp").is_none());
        // This computer or its network: direct, and trusted only there.
        for mode in ["all", "identifying", "none"] {
            n.set_tor_use(mode).unwrap();
            let mut c = cfg("http://192.168.1.4:38081");
            c.trusted = true;
            n.set("stagenet", c).unwrap();
            let e = n.effective("stagenet").unwrap();
            assert_eq!((&e["proxy"], &e["proxyRequired"], &e["trusted"]), (&json!(null), &json!(false), &json!(true)), "{mode}");
        }
    }

    #[test]
    fn one_node_for_both_halves_means_no_catch_up_and_no_credentials_over_tor() {
        let mut n = with_mode("identifying");
        ready_tor(&n);
        // No onion node: the same node over Tor throughout, as a catch-up would tie the two together.
        n.set("stagenet", cfg("https://clear.example:38089")).unwrap();
        let e = n.effective("stagenet").unwrap();
        assert_eq!(e["url"], "https://clear.example:38089");
        assert!(e.get("catchUp").is_none());
        // The direct node's login is not sent to the onion node, nor trust carried over.
        let mut c = both("https://clear.example:38089");
        c.username = Some("u".into());
        c.password = Some("p".into());
        c.trusted = true;
        n.set("stagenet", c).unwrap();
        let e = n.effective("stagenet").unwrap();
        assert!(e.get("username").is_none() && e.get("password").is_none());
        assert_eq!(e["trusted"], false);
    }

    #[test]
    fn your_own_tor_is_used_as_it_is_and_never_asks_the_built_in_one() {
        let mut n = with_mode("all");
        let mut c = both("https://clear.example:38089");
        c.proxy = Some("socks5://127.0.0.1:9050".into());
        n.set("stagenet", c).unwrap();
        assert_eq!(n.get("stagenet").unwrap().proxy.as_deref(), Some("socks5h://127.0.0.1:9050"));
        assert_eq!(n.effective("stagenet").unwrap()["proxy"], "socks5h://127.0.0.1:9050");
        assert!(!n.wants_tor("stagenet"));
        let mut bad = cfg("http://x:1");
        bad.proxy = Some("http://127.0.0.1:8118".into());
        assert!(matches!(n.set("stagenet", bad), Err(NodeError::Proxy(_))));
    }

    #[test]
    fn a_health_poll_follows_tor_only_once_chosen_or_asked() {
        let mut n = Nodes::new(None);
        n.set("stagenet", both("https://clear.example:38089")).unwrap();
        assert!(n.wants_tor("stagenet") && !n.follows_tor());
        let h = n.node_health("stagenet");
        assert_eq!((&h["reachable"], &h["torUseChosen"]), (&json!(false), &json!(false)));
        assert_eq!(h["tor"]["state"], "idle");
        let _ = n.effective("stagenet");
        assert!(n.follows_tor(), "a wallet asked for the Tor route");
        assert!(with_mode("identifying").follows_tor());
    }

    #[test]
    fn settings_are_locked_while_a_wallet_is_open() {
        let mut n = with_mode("identifying");
        n.set("stagenet", both("https://clear.example:38089")).unwrap();
        n.set_wallet_open("stagenet", true).unwrap();
        assert!(matches!(n.set_tor_use("none"), Err(NodeError::Locked(_))));
        assert!(matches!(n.set("stagenet", cfg("http://other:1")), Err(NodeError::Locked(_))));
        n.set("mainnet", cfg("https://other.example:18089")).unwrap();
        n.set_wallet_open("stagenet", false).unwrap();
        assert_eq!(n.set_tor_use("none").unwrap()["torUse"], "none");
        assert!(n.set_tor_use("some").is_err());
    }

    #[test]
    fn a_fresh_install_asks_and_an_existing_one_keeps_its_routing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("monero_nodes.json");
        let fresh = Nodes::new(Some(p.clone()));
        assert_eq!(fresh.tor_use(), json!({ "ok": true, "torUse": "identifying", "torUseChosen": false, "existing": false }));
        std::fs::remove_file(dir.path().join("monero_tor.json")).unwrap();

        for (record, mode) in [
            (r#"{"stagenet":{"url":"http://n:38089","proxy":"socks5h://127.0.0.1:9050","proxyRequired":true}}"#, "all"),
            (r#"{"stagenet":{"url":"http://n:38089","proxyRequired":true}}"#, "all"),
            (r#"{"stagenet":{"url":"http://n:38089"}}"#, "none"),
        ] {
            std::fs::write(&p, record).unwrap();
            let _ = std::fs::remove_file(dir.path().join("monero_tor.json"));
            let n = Nodes::new(Some(p.clone()));
            assert_eq!(n.tor_use(), json!({ "ok": true, "torUse": mode, "torUseChosen": false, "existing": true }), "{record}");
            // Stored at once, so a later load does not migrate again.
            let mut n = Nodes::new(Some(p.clone()));
            n.set_tor_use("identifying").unwrap();
            assert_eq!(Nodes::new(Some(p.clone())).tor_use()["torUseChosen"], true);
        }
    }

    #[test]
    fn seeded_defaults_move_to_tls_and_gain_an_onion_node() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("monero_nodes.json");
        std::fs::write(&p, r#"{"stagenet":{"url":"http://node2.monerodevs.org:38089","source":"default"},
                              "mainnet":{"url":"http://node.monerodevs.org:18089","source":"external"}}"#).unwrap();
        let n = Nodes::new(Some(p.clone()));
        let s = n.get("stagenet").unwrap();
        assert_eq!(s.url, "https://node2.monerodevs.org:38089");
        assert!(s.onion_url.as_deref().is_some_and(|u| u.ends_with(".onion:38089")));
        // A node the user picked stays exactly as it was.
        let m = n.get("mainnet").unwrap();
        assert_eq!((m.url.as_str(), m.onion_url.is_none()), ("http://node.monerodevs.org:18089", true));
        assert_eq!(Nodes::new(Some(p)).get("stagenet").unwrap().url, "https://node2.monerodevs.org:38089");
        for (_, url, onion, _) in DEFAULT_ENDPOINTS {
            assert!(onion.is_empty() || (is_onion(onion) && !is_onion(url) && url.starts_with("https://")), "{url}");
        }
    }

    #[test]
    fn health_of_unreachable_node_reports_rather_than_errors() {
        let mut n = with_mode("none");
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

    struct FakeLocal(&'static str);
    impl LocalNode for FakeLocal {
        fn rpc_url(&self, _: &str) -> std::result::Result<String, String> { Ok(self.0.into()) }
        fn status(&self) -> std::result::Result<Value, String> {
            Ok(json!({ "state": "running", "network": "stagenet" }))
        }
    }

    fn local(url: &str) -> NodeConfig {
        NodeConfig { mode: NodeMode::Local, ..cfg(url) }
    }

    #[test]
    fn a_config_written_before_local_mode_stays_remote() {
        let c: NodeConfig = serde_json::from_str(r#"{"url":"http://n:38089"}"#).unwrap();
        assert_eq!(c.mode, NodeMode::Remote);
        assert!(serde_json::from_str::<NodeConfig>(r#"{"url":"x","mode":"Local"}"#).is_err());
    }

    #[test]
    fn remote_mode_dials_the_stored_record_even_with_a_local_node() {
        let mut n = with_mode("none").with_local(Box::new(FakeLocal("http://127.0.0.1:38081")));
        let mut c = cfg("http://node2:38089");
        c.username = Some("u".into());
        n.set("stagenet", c).unwrap();
        let e = n.effective("stagenet").unwrap();
        assert_eq!((&e["url"], &e["mode"], &e["username"]), (&json!("http://node2:38089"), &json!("remote"), &json!("u")));
    }

    #[test]
    fn local_mode_dials_loopback_trusted_unproxied_and_keeps_the_remote_half() {
        let mut n = with_mode("all").with_local(Box::new(FakeLocal("http://127.0.0.1:38081")));
        let mut c = local("http://node2:38089");
        c.proxy = Some("socks5h://127.0.0.1:9050".into());
        c.proxy_required = true;
        c.username = Some("u".into());
        c.password = Some("p".into());
        n.set("stagenet", c.clone()).unwrap();
        let e = n.effective("stagenet").unwrap();
        assert_eq!(e["url"], "http://127.0.0.1:38081");
        assert_eq!(e["trusted"], true);
        assert_eq!((&e["proxy"], &e["proxyRequired"]), (&json!(null), &json!(false)));
        assert!(e.get("username").is_none() && e.get("password").is_none());
        assert_eq!(n.get("stagenet").unwrap(), &c);
        assert!(!n.wants_tor("stagenet"));
    }

    #[test]
    fn a_required_proxy_does_not_fail_close_the_local_node() {
        // Nothing listens on port 1: the call must fail dialling loopback, not on the proxy rule.
        let mut n = Nodes::new(None).with_local(Box::new(FakeLocal("http://127.0.0.1:1")));
        let mut c = local("http://node:18089");
        c.proxy_required = true;
        n.set("stagenet", c).unwrap();
        let r = n.get_info("stagenet");
        assert!(matches!(r, Err(NodeError::Http(_))), "got {r:?}");
    }

    #[test]
    fn without_the_daemon_module_local_mode_refuses_rather_than_goes_remote() {
        let mut n = Nodes::new(None);
        n.set("stagenet", local("http://node2:38089")).unwrap();
        assert!(matches!(n.effective("stagenet"), Err(NodeError::Local(_))));
        let h = n.node_health("stagenet");
        assert_eq!((&h["reachable"], &h["mode"]), (&json!(false), &json!("local")));
        assert_eq!(h["local"]["state"], "unavailable");
        assert_eq!(n.local_node("stagenet")["available"], false);
    }

    #[test]
    fn an_absent_daemon_module_costs_one_call_per_health_poll() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        use std::sync::Arc;
        struct Absent(Arc<AtomicUsize>);
        impl LocalNode for Absent {
            fn rpc_url(&self, _: &str) -> std::result::Result<String, String> {
                self.0.fetch_add(1, SeqCst);
                Err("object_unavailable".into())
            }
            fn status(&self) -> std::result::Result<Value, String> {
                self.0.fetch_add(1, SeqCst);
                Err("object_unavailable".into())
            }
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let mut n = Nodes::new(None).with_local(Box::new(Absent(calls.clone())));
        n.set("stagenet", local("http://node2:38089")).unwrap();
        let h = n.node_health("stagenet");
        assert_eq!((&h["reachable"], &h["local"]["state"]), (&json!(false), &json!("unavailable")));
        assert_eq!(calls.load(SeqCst), 1);
    }

    #[test]
    fn local_mode_is_refused_on_regtest() {
        let mut n = Nodes::new(None);
        assert!(matches!(n.set("regtest", local("http://127.0.0.1:18081")), Err(NodeError::Local(_))));
    }

    #[test]
    fn a_local_node_that_cannot_run_the_network_is_not_offered() {
        let n = Nodes::new(None).with_local(Box::new(FakeLocal("")));
        assert_eq!(n.local_node("stagenet")["available"], false);
    }

    #[test]
    fn health_reports_the_mode_and_the_local_status() {
        let mut n = Nodes::new(None).with_local(Box::new(FakeLocal("http://127.0.0.1:1")));
        n.set("stagenet", local("http://node2:38089")).unwrap();
        let h = n.node_health("stagenet");
        assert_eq!(h["mode"], "local");
        assert_eq!(h["local"]["state"], "running");
        let v = n.local_node("stagenet");
        assert_eq!((&v["available"], &v["rpcUrl"]), (&json!(true), &json!("http://127.0.0.1:1")));
        n.set("stagenet", cfg("http://192.0.2.1:38089")).unwrap();
        let h = n.node_health("stagenet");
        assert_eq!(h["mode"], "remote");
        assert!(h.get("local").is_none());
    }
}
