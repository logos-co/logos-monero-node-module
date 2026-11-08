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
//!
//! A mainnet record the module seeded moves among the public nodes [`crate::pick`] lists, by health.
//!
//! A node you run (`own`) is routed by its address alone: your network direct, an onion over Tor,
//! anywhere else by `reachThroughTor`. "Use Tor for" does not apply to it, and it is never moved.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::pick::{self, Half, Job, Probe};
use crate::proxy::{build_client, ProxyConfig};
use crate::tor::{host_of, is_onion, is_own_network, normalize_proxy, TorFile, TorLoaded, TorSettings, TorUse, TorView, BUILT_IN};

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
    /// Absent when the app asks for the picked node; `set` fills it from the seed.
    #[serde(default)]
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
    /// "default": the node this module seeds and picks by health. Anything else is stored "external".
    #[serde(default = "source_default")]
    pub source: String,
    /// Absent from configs written before local mode existed, so those stay remote.
    #[serde(default)]
    pub mode: NodeMode,
    /// A node you run, at `url`: routed by its address, never by "Use Tor for".
    #[serde(default)]
    pub own: bool,
    /// Your own node at an internet address goes through Tor unless this is off.
    #[serde(default = "yes", rename = "reachThroughTor")]
    pub reach_through_tor: bool,
}

fn source_default() -> String { "external".into() }
fn yes() -> bool { true }

impl NodeConfig {
    pub(crate) fn proxy_cfg(&self) -> ProxyConfig {
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
    #[error("enter the node's address")]
    NoAddress,
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
    /// Each network's "Use Tor for".
    tor_file: TorFile,
    /// The built-in Tor as tor_module last answered, written by the glue.
    tor: Arc<Mutex<Option<TorView>>>,
    /// A wallet asked for a route through the built-in Tor, so following it may start it.
    asked: Arc<AtomicBool>,
    /// Networks the wallet engine has a wallet open on: their settings are locked.
    wallet_open: BTreeSet<String>,
    /// This run's checks of seeded records, per network and half. In memory: a new run checks again.
    checks: Mutex<BTreeMap<(String, Half), Check>>,
}

#[derive(Clone, Debug, Default)]
struct Check {
    at: Option<Instant>,
    ok: bool,
    busy: bool,
    /// The row the check stored, and how it measured.
    last: Option<(usize, Probe)>,
}

impl Nodes {
    pub fn new(path: Option<PathBuf>) -> Self {
        let map = path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str::<BTreeMap<String, NodeConfig>>(&s).ok())
            .unwrap_or_default();
        let saved = path.as_deref().and_then(|p| TorFile::load(&TorSettings::path_beside(p)));
        let per_network = matches!(saved, Some(TorLoaded::PerNetwork(_)));
        let tor_file = match saved {
            Some(TorLoaded::PerNetwork(f)) => f,
            Some(TorLoaded::Shared(old)) => TorFile { networks: NETWORKS.iter().map(|n| (n.to_string(), old.carried())).collect() },
            // Before the setting: each configured network keeps its routing, to be confirmed.
            None => TorFile { networks: map.iter()
                .map(|(net, c)| (net.clone(), TorSettings::migrated(c.proxy_required || c.proxy.as_deref().is_some_and(|p| !p.trim().is_empty()))))
                .collect() },
        };
        let mut n = Self { map, path, local: None, tor_file, tor: Arc::default(), asked: Arc::default(),
                           wallet_open: BTreeSet::new(), checks: Mutex::default() };
        if !per_network {
            let _ = n.persist_tor();
        }
        if n.upgrade_defaults() {
            let _ = n.persist();
        }
        n
    }

    /// Moves records the module seeded onto today's defaults: TLS, and an onion node for Tor.
    /// A node you set on your own network, with no onion beside it, is yours: it was direct in
    /// every mode, and stays so.
    fn upgrade_defaults(&mut self) -> bool {
        let mut changed = false;
        for c in self.map.values_mut().filter(|c| c.source != "default" && c.mode == NodeMode::Remote && !c.own) {
            if is_own_network(&c.url) && c.onion_url.as_deref().unwrap_or("").trim().is_empty() {
                c.own = true;
                changed = true;
            }
        }
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
            changed |= split_operators(net, c, Half::Direct);
        }
        changed
    }

    fn persist_tor(&self) -> Result<()> {
        let Some(p) = self.path.as_ref() else { return Ok(()) };
        self.tor_file.save(&TorSettings::path_beside(p)).map_err(|e| NodeError::Http(e.to_string()))
    }

    /// `network`'s "Use Tor for"; a network never set up starts fresh.
    pub fn tor_of(&self, network: &str) -> TorSettings {
        self.tor_file.networks.get(network).cloned().unwrap_or_else(TorSettings::fresh)
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
    ///
    /// `source: "default"` asks for the node the module picks: the stored seeded pair if there is
    /// one, else the seed, and its address fields are not the caller's. Any other record is yours.
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
        cfg.proxy = match normalize_proxy(cfg.proxy.as_deref()).map_err(NodeError::Proxy)? {
            p if p == BUILT_IN => None,
            own => Some(own),
        };
        let was_seeded = self.map.get(network).is_some_and(|c| c.source == "default");
        if cfg.source == "default" && !cfg.own {
            let seeded = self.map.get(network).filter(|_| was_seeded).map(|c| (c.url.clone(), c.onion_url.clone(), c.trusted));
            let (url, onion, trusted) = seeded.or_else(|| DEFAULT_ENDPOINTS.iter().find(|d| d.0 == network)
                .map(|d| (d.1.to_string(), (!d.2.is_empty()).then(|| d.2.to_string()), d.3)))
                .ok_or_else(|| NodeError::NotConfigured(network.into()))?;
            cfg = NodeConfig { url, onion_url: onion, username: None, password: None, trusted, reach_through_tor: true, ..cfg };
            if !was_seeded {
                // A pick made before the record was yours says nothing about the seed.
                self.checks.lock().unwrap_or_else(|e| e.into_inner()).retain(|(n, _), _| n != network);
            }
        } else {
            cfg.source = "external".into();
            cfg.url = normalise_url(&cfg.url);
            cfg.onion_url = cfg.onion_url.map(|u| normalise_url(&u)).filter(|u| !u.is_empty());
            if cfg.mode == NodeMode::Remote && cfg.url.is_empty() { return Err(NodeError::NoAddress); }
            // With an onion beside it the record is a pair, which Tor reaches at the onion.
            cfg.own |= cfg.mode == NodeMode::Remote && is_own_network(&cfg.url) && cfg.onion_url.is_none();
        }
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
                    own: false,
                    reach_through_tor: true,
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
    /// A node you run at an address follows its address and `reachThroughTor`, never the mode.
    pub fn plan(&self, network: &str) -> Result<Plan> {
        let c = self.get(network).ok_or_else(|| NodeError::NotConfigured(network.into()))?;
        let tor_use = self.tor_of(network).tor_use;
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
        if c.own {
            let via_tor = is_onion(&c.url) || (!is_own_network(&c.url) && c.reach_through_tor);
            return Ok(Plan { cfg: c.clone(), tor_use, url: c.url.clone(), via_tor, catch_up: None });
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

    /// The SOCKS port a Tor route can use now, without asking for the built-in Tor.
    fn ready_socks(&self, cfg: &NodeConfig) -> Option<String> {
        let p = normalize_proxy(cfg.proxy.as_deref()).ok()?;
        if p != BUILT_IN {
            return Some(p);
        }
        self.tor.lock().unwrap_or_else(|e| e.into_inner()).as_ref().and_then(|v| v.usable_socks().map(str::to_string))
    }

    /// The half of `network`'s seeded record a wallet dials next, when its check is due. Marks it busy.
    pub(crate) fn begin_pick(&self, network: &str) -> Option<Job> {
        let c = self.get(network).filter(|c| c.source == "default" && c.mode == NodeMode::Remote)?;
        let listed = pick::listed(network);
        if listed.len() < 2 {
            return None;
        }
        let open = self.wallet_open.contains(network);
        // With a wallet open only the onion node is still to be dialled, on the move to Tor.
        let half = match (self.tor_of(network).tor_use, open) {
            (TorUse::None | TorUse::Identifying, false) => Half::Direct,
            (TorUse::All, _) | (TorUse::Identifying, true) => Half::Tor,
            (TorUse::None, true) => return None,
        };
        let socks = match half {
            Half::Tor => Some(self.ready_socks(c)?),
            Half::Direct => None,
        };
        let (stored, other) = match half {
            Half::Direct => (Some(c.url.as_str()), c.onion_url.as_deref()),
            Half::Tor => (c.onion_url.as_deref(), Some(c.url.as_str())),
        };
        // The other half has been dialled: the catch-up node's operator never gets the onion half.
        let exclude = other.filter(|_| open).and_then(|u| pick::operator_of(network, u));
        let rows: Vec<usize> = (0..listed.len()).filter(|&i| Some(listed[i].0) != exclude).collect();
        let current = stored.and_then(|u| rows.iter().copied().find(|&i| host_of(half.url(i, network)) == host_of(u)));
        let mut checks = self.checks.lock().unwrap_or_else(|e| e.into_inner());
        let k = checks.entry((network.to_string(), half)).or_default();
        let wait = if k.ok { pick::STALE } else { pick::RETRY };
        if k.busy || k.at.is_some_and(|t| t.elapsed() < wait) {
            return None;
        }
        k.busy = true;
        Some(Job { network: network.into(), half, current, rows, socks })
    }

    /// Stores what a pick chose, unless the record stopped being a seeded one meanwhile.
    pub(crate) fn finish_pick(&mut self, job: &Job, probes: &[(usize, Probe)]) {
        let chosen = pick::choose(&job.network, job.half, job.current, probes);
        let measured = |i: usize| probes.iter().find(|(j, _)| *j == i).cloned();
        {
            let mut checks = self.checks.lock().unwrap_or_else(|e| e.into_inner());
            let k = checks.entry((job.network.clone(), job.half)).or_default();
            *k = Check {
                at: Some(Instant::now()),
                ok: chosen.is_some_and(|(_, pass)| pass),
                busy: false,
                last: chosen.map(|(i, _)| i).or(job.current).and_then(measured),
            };
        }
        let Some((i, _)) = chosen else { return };
        let open = self.wallet_open.contains(&job.network);
        let Some(mut c) = self.get(&job.network).filter(|c| c.source == "default" && c.mode == NodeMode::Remote).cloned() else { return };
        if job.half == Half::Direct && open {
            return;
        }
        let url = job.half.url(i, &job.network).to_string();
        match job.half {
            Half::Direct => c.url = url,
            Half::Tor => c.onion_url = Some(url),
        }
        // The other half moves off this operator; with a wallet open it was excluded instead.
        if !open && split_operators(&job.network, &mut c, job.half) {
            let other = if job.half == Half::Direct { Half::Tor } else { Half::Direct };
            self.checks.lock().unwrap_or_else(|e| e.into_inner()).remove(&(job.network.clone(), other));
        }
        if self.map.get(&job.network) != Some(&c) {
            self.map.insert(job.network.clone(), c);
            let _ = self.persist();
        }
    }

    /// node_health on a seeded record: who runs the node, this run's checks, and a node that
    /// stopped answering is checked again at the next resolve.
    fn note_health(&self, network: &str, plan: &Plan, dialled: bool, h: &mut Value) {
        if plan.cfg.source != "default" || pick::listed(network).len() < 2 {
            return;
        }
        if let Some(op) = pick::operator_of(network, &plan.url) {
            h["operator"] = json!(op);
        }
        let half = if plan.via_tor { Half::Tor } else { Half::Direct };
        let mut checks = self.checks.lock().unwrap_or_else(|e| e.into_inner());
        if dialled && h["reachable"] == false {
            if let Some(k) = checks.get_mut(&(network.to_string(), half)) {
                k.ok = false;
            }
        }
        let report: serde_json::Map<String, Value> = checks.iter()
            .filter(|((n, _), _)| n == network)
            .filter_map(|((_, half), k)| {
                let (i, p) = k.last.as_ref()?;
                let mut v = p.json();
                v["operator"] = json!(pick::listed(network)[*i].0);
                v["url"] = json!(half.url(*i, network));
                v["ok"] = json!(k.ok);
                v["agoSecs"] = json!(k.at.map(|t| t.elapsed().as_secs()));
                Some((half.name().to_string(), v))
            })
            .collect();
        if !report.is_empty() {
            h["pick"] = Value::Object(report);
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
            let t = self.tor_of(network);
            (h["torUse"], h["torUseChosen"]) = (json!(t.tor_use), json!(t.chosen));
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
        let t = self.tor_of(network);
        (h["torUse"], h["torUseChosen"]) = (json!(t.tor_use), json!(t.chosen));
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
            let mut h = self.dial_health(network);
            self.note_health(network, &plan, true, &mut h);
            return h;
        }
        let built_in = normalize_proxy(plan.cfg.proxy.as_deref()).is_ok_and(|p| p == BUILT_IN);
        let view = self.tor.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let waiting = built_in && !view.as_ref().is_some_and(|v| v.usable_socks().is_some());
        let mut h = if waiting {
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
        self.note_health(network, &plan, !waiting, &mut h);
        h
    }

    // ── Use Tor for ───────────────────────────────────────────────────────────

    /// `{ ok, network, torUse, torUseChosen, existing }`.
    pub fn tor_use(&self, network: &str) -> Result<Value> {
        if !is_network(network) {
            return Err(NodeError::UnknownNetwork(network.into()));
        }
        let mut v = self.tor_of(network).json();
        (v["ok"], v["network"]) = (json!(true), json!(network));
        Ok(v)
    }

    /// Stores the user's choice for `network`. Refused while any wallet is open: it binds its
    /// node at open.
    pub fn set_tor_use(&mut self, network: &str, mode: &str) -> Result<Value> {
        if !is_network(network) {
            return Err(NodeError::UnknownNetwork(network.into()));
        }
        let tor_use = TorUse::parse(mode).ok_or_else(|| NodeError::Parse(format!("unknown mode: {mode} (all, identifying or none)")))?;
        if !self.wallet_open.is_empty() {
            return Err(NodeError::Locked("Close your open accounts to change this.".into()));
        }
        let before = self.tor_file.clone();
        let existing = self.tor_of(network).existing;
        self.tor_file.networks.insert(network.into(), TorSettings { tor_use, chosen: true, existing });
        if let Err(e) = self.persist_tor() {
            self.tor_file = before;
            return Err(e);
        }
        self.tor_use(network)
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

    /// Whether a health poll on `network` may ask tor_module: once the user chose there, or a
    /// wallet asked for Tor. Asking starts Tor, and a poll alone must not start it before the
    /// first-run choice.
    pub fn follows_tor(&self, network: &str) -> bool {
        self.tor_of(network).chosen || self.asked.load(Ordering::Relaxed)
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
/// These are somebody else's machines, and each daemon on them can wedge independently of the
/// host: on 2026-09-10 `node.monerodevs.org:38089` accepted TCP and never answered HTTP, and on
/// 2026-11-03 its 18089 served ~4 KB/s for hours. So mainnet's pair is only a seed, which
/// [`crate::pick`] moves among three operators by health. Only a record the module seeded moves:
/// a node you set stays where you put it, and `set_node_config` stays the answer to a bad one.
///
/// The direct node speaks TLS (monerod's own certificate); the node over Tor is an onion service.
/// Mainnet's two are two operators', so the catch-up node never sees the sends. Stagenet's and
/// testnet's are still both plowsof's.
/// (network, url, onionUrl, trusted)
pub const DEFAULT_ENDPOINTS: &[(&str, &str, &str, bool)] = &[
    ("mainnet",  "https://xmr-node.cakewallet.com:18081", "http://plowsof3t5hogddwabaeiyrno25efmzfxyro2vligremt7sxpsclfaid.onion:18089", false),
    ("stagenet", "https://node2.monerodevs.org:38089", "http://plowsof3t5hogddwabaeiyrno25efmzfxyro2vligremt7sxpsclfaid.onion:38089", false),
    ("testnet",  "https://node.monerodevs.org:28089",  "http://plowsoffjexmxalw73tkjmf422gq6575fc7vicuu4javzn2ynnte6tyd.onion:28089", false),
    ("regtest",  "http://127.0.0.1:18081",             "", true),
];

/// When both halves of a record are one listed operator's, the half other than `keep` moves to
/// the first other operator: one operator seeing the catch-up and the sends could tie them.
fn split_operators(network: &str, c: &mut NodeConfig, keep: Half) -> bool {
    let a = pick::operator_of(network, &c.url);
    let b = c.onion_url.as_deref().and_then(|u| pick::operator_of(network, u));
    let (Some(a), true) = (a, a == b) else { return false };
    let Some(i) = pick::listed(network).iter().position(|n| n.0 != a) else { return false };
    match keep {
        Half::Direct => c.onion_url = Some(Half::Tor.url(i, network).into()),
        Half::Tor => c.url = Half::Direct.url(i, network).into(),
    }
    true
}

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
                     mode: NodeMode::Remote, own: false, reach_through_tor: true }
    }

    fn with_mode(mode: &str) -> Nodes {
        let mut n = Nodes::new(None);
        for net in NETWORKS {
            n.set_tor_use(net, mode).unwrap();
        }
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

        n.set_tor_use("stagenet", "all").unwrap();
        ready_tor(&n);
        let e = n.effective("stagenet").unwrap();
        assert_eq!((&e["url"], &e["proxy"], &e["proxyRequired"]), (&json!(ONION), &json!("socks5h://127.0.0.1:9250"), &json!(true)));
        assert!(e.get("catchUp").is_none() && n.wants_tor("stagenet"));

        n.set_tor_use("stagenet", "identifying").unwrap();
        let e = n.effective("stagenet").unwrap();
        assert_eq!((&e["url"], &e["catchUp"]["url"], &e["torUse"]), (&json!(ONION), &json!("https://clear.example:38089"), &json!("identifying")));
    }

    #[test]
    fn onion_and_own_network_keep_their_route_in_every_mode() {
        // An onion service is reachable only over Tor: refused in none, never a catch-up.
        let mut n = with_mode("none");
        n.set("stagenet", cfg(ONION)).unwrap();
        assert!(matches!(n.effective("stagenet"), Err(NodeError::TorOff)));
        n.set_tor_use("stagenet", "identifying").unwrap();
        let e = n.effective("stagenet").unwrap();
        assert_eq!((&e["url"], &e["proxyRequired"]), (&json!(ONION), &json!(true)));
        assert!(e.get("catchUp").is_none());
        // This computer or its network: direct, and trusted only there.
        for mode in ["all", "identifying", "none"] {
            n.set_tor_use("stagenet", mode).unwrap();
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
        assert!(n.wants_tor("stagenet") && !n.follows_tor("stagenet"));
        let h = n.node_health("stagenet");
        assert_eq!((&h["reachable"], &h["torUseChosen"]), (&json!(false), &json!(false)));
        assert_eq!(h["tor"]["state"], "idle");
        let _ = n.effective("stagenet");
        assert!(n.follows_tor("stagenet"), "a wallet asked for the Tor route");
        let mut chosen = Nodes::new(None);
        chosen.set_tor_use("mainnet", "identifying").unwrap();
        assert!(chosen.follows_tor("mainnet") && !chosen.follows_tor("stagenet"), "chosen per network");
    }

    #[test]
    fn settings_are_locked_while_a_wallet_is_open() {
        let mut n = with_mode("identifying");
        n.set("stagenet", both("https://clear.example:38089")).unwrap();
        n.set_wallet_open("stagenet", true).unwrap();
        assert!(matches!(n.set_tor_use("mainnet", "none"), Err(NodeError::Locked(_))));
        assert!(matches!(n.set("stagenet", cfg("http://other:1")), Err(NodeError::Locked(_))));
        n.set("mainnet", cfg("https://other.example:18089")).unwrap();
        n.set_wallet_open("stagenet", false).unwrap();
        assert_eq!(n.set_tor_use("stagenet", "none").unwrap()["torUse"], "none");
        assert!(n.set_tor_use("stagenet", "some").is_err());
        assert!(matches!(n.set_tor_use("moon", "none"), Err(NodeError::UnknownNetwork(_))));
    }

    #[test]
    fn a_fresh_install_asks_and_an_existing_one_keeps_its_routing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("monero_nodes.json");
        let fresh = Nodes::new(Some(p.clone()));
        assert_eq!(fresh.tor_use("mainnet").unwrap(), json!({ "ok": true, "network": "mainnet", "torUse": "identifying", "torUseChosen": false, "existing": false }));
        std::fs::remove_file(dir.path().join("monero_tor.json")).unwrap();

        for (record, mode) in [
            (r#"{"stagenet":{"url":"http://n:38089","proxy":"socks5h://127.0.0.1:9050","proxyRequired":true}}"#, "all"),
            (r#"{"stagenet":{"url":"http://n:38089","proxyRequired":true}}"#, "all"),
            (r#"{"stagenet":{"url":"http://n:38089"}}"#, "none"),
        ] {
            std::fs::write(&p, record).unwrap();
            let _ = std::fs::remove_file(dir.path().join("monero_tor.json"));
            let n = Nodes::new(Some(p.clone()));
            assert_eq!(n.tor_use("stagenet").unwrap(), json!({ "ok": true, "network": "stagenet", "torUse": mode, "torUseChosen": false, "existing": true }), "{record}");
            assert_eq!(n.tor_use("mainnet").unwrap()["existing"], false, "a network never set up starts fresh");
            // Stored at once, so a later load does not migrate again.
            let mut n = Nodes::new(Some(p.clone()));
            n.set_tor_use("stagenet", "identifying").unwrap();
            let again = Nodes::new(Some(p.clone()));
            assert_eq!(again.tor_use("stagenet").unwrap()["torUseChosen"], true);
            assert_eq!(again.tor_use("mainnet").unwrap()["torUseChosen"], false);
        }

        // A build with one setting for every network: each network keeps it, and asks again.
        std::fs::write(dir.path().join("monero_tor.json"), r#"{"torUse":"all","torUseChosen":true,"existing":false}"#).unwrap();
        let n = Nodes::new(Some(p.clone()));
        for net in NETWORKS {
            assert_eq!(n.tor_use(net).unwrap(), json!({ "ok": true, "network": net, "torUse": "all", "torUseChosen": false, "existing": true }));
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

    // ── Picking among mainnet's public nodes ─────────────────────────────────

    use crate::pick::{tend, Prober, MAINNET_NODES};
    use std::sync::RwLock;
    use std::time::Duration;

    const CAKE: usize = 0;
    const SETH: usize = 1;
    const PLOWSOF: usize = 2;

    fn direct(i: usize) -> &'static str { MAINNET_NODES[i].1 }
    fn onion(i: usize) -> &'static str { MAINNET_NODES[i].2 }

    /// Answers by URL; anything else does not answer. Records what was asked, `tor:` over Tor.
    #[derive(Default)]
    struct Fake { by_url: BTreeMap<String, Probe>, asked: Mutex<Vec<String>> }

    impl Fake {
        fn with(mut self, url: &str, p: Probe) -> Self { self.by_url.insert(url.into(), p); self }
        fn asked(&self) -> Vec<String> { std::mem::take(&mut *self.asked.lock().unwrap()) }
    }

    impl Prober for Fake {
        fn probe(&self, _: &str, dial: &NodeConfig, _: Instant) -> Probe {
            let via = if dial.proxy.is_some() { "tor:" } else { "" };
            self.asked.lock().unwrap().push(format!("{via}{}", dial.url));
            self.by_url.get(&dial.url).cloned().unwrap_or_else(|| Probe::failed("no answer"))
        }
    }

    fn serving(kib_per_sec: u64) -> Probe {
        Probe { reachable: true, nettype: "mainnet".into(), height: 3_799_000, synced: true, rtt_ms: 700,
                bytes_per_sec: kib_per_sec * 1024, error: None }
    }

    fn seeded(mode: &str, url: usize, onion_row: usize) -> RwLock<Nodes> {
        let mut n = with_mode(mode);
        n.init_defaults().unwrap();
        let c = n.map.get_mut("mainnet").unwrap();
        c.url = direct(url).into();
        c.onion_url = Some(onion(onion_row).into());
        RwLock::new(n)
    }

    fn stored(n: &RwLock<Nodes>) -> (String, String) {
        let c = n.read().unwrap().get("mainnet").unwrap().clone();
        (c.url, c.onion_url.unwrap_or_default())
    }

    fn age(n: &RwLock<Nodes>, by: Duration) {
        for k in n.read().unwrap().checks.lock().unwrap().values_mut() {
            k.at = k.at.and_then(|t| t.checked_sub(by));
        }
    }

    #[test]
    fn mainnet_lists_three_operators_each_with_tls_and_its_own_onion() {
        let ops: BTreeSet<_> = MAINNET_NODES.iter().map(|n| n.0).collect();
        assert_eq!(ops.len(), MAINNET_NODES.len());
        for (op, url, onion) in MAINNET_NODES {
            assert!(url.starts_with("https://") && !is_onion(url) && is_onion(onion), "{op}");
            assert_eq!((pick::operator_of("mainnet", url), pick::operator_of("mainnet", onion)), (Some(*op), Some(*op)));
        }
        // The seed is two of them, run by two operators.
        let (_, url, onion, _) = DEFAULT_ENDPOINTS.iter().find(|d| d.0 == "mainnet").unwrap();
        let (a, b) = (pick::operator_of("mainnet", url), pick::operator_of("mainnet", onion));
        assert!(a.is_some() && b.is_some() && a != b);
        assert!(pick::listed("stagenet").is_empty() && pick::operator_of("stagenet", url).is_none());
    }

    #[test]
    fn a_seeded_node_that_serves_stays_and_only_its_operator_is_asked() {
        let n = seeded("none", CAKE, PLOWSOF);
        let fake = Fake::default().with(direct(CAKE), serving(170)).with(direct(SETH), serving(300));
        tend(&n, "mainnet", &fake);
        assert_eq!(fake.asked(), [direct(CAKE)]);
        assert_eq!(stored(&n).0, direct(CAKE));
        // Checked once a run; again once the check is stale.
        tend(&n, "mainnet", &fake);
        assert!(fake.asked().is_empty());
        age(&n, pick::STALE);
        tend(&n, "mainnet", &fake);
        assert_eq!(fake.asked(), [direct(CAKE)]);
    }

    #[test]
    fn a_slow_seeded_node_moves_to_the_best_listed_one() {
        // 2026-11-03: the seeded node served ~4 KB/s; Cake 80 KB/s, Seth 149 KB/s.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("monero_nodes.json");
        let mut n = Nodes::new(Some(p.clone()));
        n.init_defaults().unwrap();
        n.map.get_mut("mainnet").unwrap().url = direct(PLOWSOF).into();
        n.map.get_mut("mainnet").unwrap().onion_url = Some(onion(CAKE).into());
        let n = RwLock::new(n);
        let fake = Fake::default().with(direct(PLOWSOF), serving(4)).with(direct(CAKE), serving(80)).with(direct(SETH), serving(149));
        tend(&n, "mainnet", &fake);
        let asked = fake.asked();
        assert_eq!(asked[0], direct(PLOWSOF), "the stored node first, alone");
        assert_eq!(asked[1..].iter().cloned().collect::<BTreeSet<_>>(), [direct(CAKE).to_string(), direct(SETH).to_string()].into());
        assert_eq!(stored(&n), (direct(SETH).to_string(), onion(CAKE).to_string()));
        // What a wallet dials follows: the catch-up from Seth's node, then Cake's onion.
        n.write().unwrap().set_tor_use("mainnet", "identifying").unwrap();
        let e = n.read().unwrap().effective("mainnet").unwrap();
        assert_eq!((&e["catchUp"]["url"], &e["url"], &e["source"]), (&json!(direct(SETH)), &json!(onion(CAKE)), &json!("default")));
        assert_eq!(Nodes::new(Some(p)).get("mainnet").unwrap().url, direct(SETH));
    }

    #[test]
    fn only_a_node_that_answers_synced_on_mainnet_at_the_top_is_picked() {
        let behind = Probe { height: 3_798_990, ..serving(900) };
        let syncing = Probe { synced: false, ..serving(900) };
        let other_net = Probe { nettype: "stagenet".into(), height: 4_000_000, ..serving(900) };
        let slow = serving(2);
        for (probes, want) in [
            (vec![(0, behind.clone()), (1, serving(40)), (2, syncing.clone())], Some((1, true))),
            (vec![(0, other_net.clone()), (1, Probe::failed("x")), (2, serving(40))], Some((2, true))),
            // Nothing passes: the best that answers, marked as not passing.
            (vec![(0, slow.clone()), (1, Probe { rtt_ms: 5000, ..slow.clone() }), (2, syncing)], Some((0, false))),
            (vec![(0, Probe::failed("x")), (1, other_net)], None),
        ] {
            assert_eq!(pick::choose("mainnet", Half::Direct, None, &probes), want, "{probes:?}");
        }
        // Latency counts: the same throughput a second slower loses.
        let probes = [(0, Probe { rtt_ms: 2000, ..serving(100) }), (1, serving(100))];
        assert_eq!(pick::choose("mainnet", Half::Direct, None, &probes), Some((1, true)));
        // The stored node stays while it passes, even beside a faster one.
        let probes = [(0, serving(900)), (2, serving(40))];
        assert_eq!(pick::choose("mainnet", Half::Tor, Some(2), &probes), Some((2, true)));
    }

    #[test]
    fn when_nothing_answers_the_stored_node_stays_and_is_retried() {
        let n = seeded("none", PLOWSOF, CAKE);
        let fake = Fake::default();
        tend(&n, "mainnet", &fake);
        assert_eq!(fake.asked().len(), 3);
        assert_eq!(stored(&n).0, direct(PLOWSOF));
        tend(&n, "mainnet", &fake);
        assert!(fake.asked().is_empty(), "not again before RETRY");
        age(&n, pick::RETRY);
        tend(&n, "mainnet", &fake);
        assert_eq!(fake.asked().len(), 3);
    }

    #[test]
    fn a_node_you_set_is_never_probed_or_moved() {
        for mode in ["none", "identifying", "all"] {
            let n = seeded(mode, PLOWSOF, CAKE);
            ready_tor(&n.read().unwrap());
            n.write().unwrap().set("mainnet", both(direct(PLOWSOF))).unwrap();
            let fake = Fake::default().with(direct(SETH), serving(900));
            tend(&n, "mainnet", &fake);
            assert!(fake.asked().is_empty(), "{mode}");
            assert_eq!(stored(&n), (direct(PLOWSOF).to_string(), ONION.to_string()));
        }
        // Local mode keeps its seeded remote half as it is too.
        let n = seeded("none", PLOWSOF, CAKE);
        n.write().unwrap().map.get_mut("mainnet").unwrap().mode = NodeMode::Local;
        let fake = Fake::default();
        tend(&n, "mainnet", &fake);
        assert!(fake.asked().is_empty());
    }

    #[test]
    fn with_a_wallet_open_only_the_onion_half_moves_and_never_to_the_catch_up_operator() {
        let n = seeded("identifying", CAKE, SETH);
        n.write().unwrap().set_wallet_open("mainnet", true).unwrap();
        // The move to Tor waits for Tor, and asks nobody before it is ready.
        let fake = Fake::default().with(onion(CAKE), serving(900)).with(onion(PLOWSOF), serving(20)).with(direct(SETH), serving(900));
        tend(&n, "mainnet", &fake);
        assert!(fake.asked().is_empty());
        ready_tor(&n.read().unwrap());
        tend(&n, "mainnet", &fake);
        let asked = fake.asked();
        assert_eq!(asked.iter().cloned().collect::<BTreeSet<_>>(), [format!("tor:{}", onion(SETH)), format!("tor:{}", onion(PLOWSOF))].into(),
                   "every onion but the catch-up operator's, over Tor");
        assert_eq!(stored(&n), (direct(CAKE).to_string(), onion(PLOWSOF).to_string()));
        let e = n.read().unwrap().effective("mainnet").unwrap();
        assert_eq!((&e["catchUp"]["url"], &e["url"], &e["proxy"]), (&json!(direct(CAKE)), &json!(onion(PLOWSOF)), &json!("socks5h://127.0.0.1:9250")));
    }

    #[test]
    fn all_never_dials_a_direct_node_and_none_never_asks_for_tor() {
        let n = seeded("all", PLOWSOF, SETH);
        let fake = Fake::default().with(onion(CAKE), serving(50)).with(direct(CAKE), serving(900));
        tend(&n, "mainnet", &fake);
        assert!(fake.asked().is_empty(), "no Tor yet");
        ready_tor(&n.read().unwrap());
        tend(&n, "mainnet", &fake);
        let asked = fake.asked();
        assert!(asked.len() == 3 && asked.iter().all(|u| u.starts_with("tor:") && u.contains(".onion")), "{asked:?}");
        assert_eq!(stored(&n).1, onion(CAKE));

        let n = seeded("none", PLOWSOF, SETH);
        let fake = Fake::default().with(direct(PLOWSOF), serving(1));
        tend(&n, "mainnet", &fake);
        assert!(fake.asked().iter().all(|u| !u.starts_with("tor:") && !u.contains(".onion")));
        assert!(!n.read().unwrap().asked.load(Ordering::Relaxed), "nothing asked for the built-in Tor");
        // With a wallet open in none, the node it dialled stays.
        let n = seeded("none", PLOWSOF, SETH);
        n.write().unwrap().set_wallet_open("mainnet", true).unwrap();
        tend(&n, "mainnet", &fake);
        assert!(fake.asked().is_empty());
    }

    #[test]
    fn a_pick_moves_the_other_half_off_its_operator() {
        // Direct: Cake wins while Cake's onion is stored, so the onion moves to another operator.
        let n = seeded("identifying", PLOWSOF, CAKE);
        let fake = Fake::default().with(direct(PLOWSOF), serving(4)).with(direct(CAKE), serving(170)).with(direct(SETH), serving(60));
        tend(&n, "mainnet", &fake);
        let (url, on) = stored(&n);
        assert_eq!(url, direct(CAKE));
        assert_ne!(pick::operator_of("mainnet", &on), Some("cakewallet"));
        // Over Tor with no wallet open: Seth's onion wins, so the direct node leaves Seth.
        let n = seeded("all", SETH, PLOWSOF);
        ready_tor(&n.read().unwrap());
        let fake = Fake::default().with(onion(SETH), serving(90)).with(onion(PLOWSOF), serving(1));
        tend(&n, "mainnet", &fake);
        let (url, on) = stored(&n);
        assert_eq!(on, onion(SETH));
        assert_ne!(pick::operator_of("mainnet", &url), Some("sethforprivacy"));
    }

    #[test]
    fn a_seeded_pair_run_by_one_operator_is_split_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("monero_nodes.json");
        // What 0.1.1 seeded: plowsof's node and plowsof's onion. And the plain-http one before it.
        std::fs::write(&p, format!(r#"{{"mainnet":{{"url":"{}","onionUrl":"{}","source":"default"}}}}"#, direct(PLOWSOF), onion(PLOWSOF))).unwrap();
        let c = Nodes::new(Some(p.clone())).get("mainnet").unwrap().clone();
        assert_eq!(c.url, direct(PLOWSOF));
        assert_eq!(pick::operator_of("mainnet", c.onion_url.as_deref().unwrap()), Some("cakewallet"));
        std::fs::write(&p, r#"{"mainnet":{"url":"http://node.monerodevs.org:18089","source":"default"}}"#).unwrap();
        let c = Nodes::new(Some(p.clone())).get("mainnet").unwrap().clone();
        assert_eq!((c.url.as_str(), c.onion_url.as_deref()), (direct(CAKE), Some(onion(PLOWSOF))));
        // Yours stays as you set it.
        std::fs::write(&p, format!(r#"{{"mainnet":{{"url":"{}","onionUrl":"{}","source":"external"}}}}"#, direct(PLOWSOF), onion(PLOWSOF))).unwrap();
        assert_eq!(Nodes::new(Some(p)).get("mainnet").unwrap().onion_url.as_deref(), Some(onion(PLOWSOF)));
    }

    #[test]
    fn node_health_names_the_operator_and_an_unanswered_node_is_checked_again() {
        let n = seeded("none", CAKE, PLOWSOF);
        let fake = Fake::default().with(direct(CAKE), serving(170));
        tend(&n, "mainnet", &fake);
        fake.asked();
        let g = n.read().unwrap();
        let plan = g.plan("mainnet").unwrap();
        let mut h = json!({ "ok": true, "reachable": false, "error": "timed out" });
        g.note_health("mainnet", &plan, true, &mut h);
        assert_eq!((&h["operator"], &h["pick"]["direct"]["operator"], &h["pick"]["direct"]["ok"]), (&json!("cakewallet"), &json!("cakewallet"), &json!(false)));
        assert_eq!(h["pick"]["direct"]["bytesPerSec"], 170 * 1024);
        drop(g);
        // Failed: due again after RETRY, not STALE.
        age(&n, pick::RETRY);
        tend(&n, "mainnet", &fake);
        assert_eq!(fake.asked(), [direct(CAKE)]);
        // Not dialled (Tor not ready) is not a failure.
        let n = seeded("all", CAKE, PLOWSOF);
        let g = n.read().unwrap();
        let mut h = json!({ "reachable": false });
        g.note_health("mainnet", &g.plan("mainnet").unwrap(), false, &mut h);
        assert_eq!(h["operator"], "plowsof");
        assert!(h.get("pick").is_none());
    }

    // ── A node you run ───────────────────────────────────────────────────────

    fn own(url: &str, through_tor: bool) -> NodeConfig {
        NodeConfig { own: true, reach_through_tor: through_tor, ..cfg(url) }
    }

    #[test]
    fn your_own_node_is_routed_by_its_address_whatever_use_tor_for_says() {
        for mode in ["all", "identifying", "none"] {
            let mut n = with_mode(mode);
            ready_tor(&n);
            // Your network: direct, even with the switch on, and trusted there.
            let mut lan = own("http://192.168.1.4:18081", true);
            lan.trusted = true;
            n.set("stagenet", lan).unwrap();
            let e = n.effective("stagenet").unwrap();
            assert_eq!((&e["url"], &e["route"], &e["proxyRequired"], &e["trusted"]),
                       (&json!("http://192.168.1.4:18081"), &json!("direct"), &json!(false), &json!(true)), "{mode}");
            assert!(e.get("proxy").is_none() && e.get("catchUp").is_none(), "{mode}");
            // An onion: through Tor, in none too.
            n.set("stagenet", own(ONION, false)).unwrap();
            let e = n.effective("stagenet").unwrap();
            assert_eq!((&e["url"], &e["proxy"], &e["proxyRequired"]), (&json!(ONION), &json!("socks5h://127.0.0.1:9250"), &json!(true)), "{mode}");
            assert!(e.get("catchUp").is_none(), "{mode}");
            // Anywhere else: by the switch, to its own address with its login, never a catch-up.
            let mut far = own("https://my.node.example:18081", true);
            far.onion_url = Some(ONION.into());
            far.username = Some("u".into());
            far.password = Some("p".into());
            n.set("stagenet", far.clone()).unwrap();
            let e = n.effective("stagenet").unwrap();
            assert_eq!((&e["url"], &e["route"], &e["proxyRequired"], &e["username"]),
                       (&json!("https://my.node.example:18081"), &json!("proxied"), &json!(true), &json!("u")), "{mode}");
            assert!(e.get("catchUp").is_none() && n.wants_tor("stagenet"), "{mode}");
            far.reach_through_tor = false;
            n.set("stagenet", far).unwrap();
            let e = n.effective("stagenet").unwrap();
            assert_eq!((&e["url"], &e["route"], &e["proxyRequired"]), (&json!("https://my.node.example:18081"), &json!("direct"), &json!(false)), "{mode}");
            assert!(e.get("proxy").is_none() && !n.wants_tor("stagenet"), "{mode}");
        }
    }

    #[test]
    fn your_own_node_is_never_probed_or_moved_even_on_a_listed_address() {
        for mode in ["none", "identifying", "all"] {
            let n = seeded(mode, PLOWSOF, CAKE);
            ready_tor(&n.read().unwrap());
            // Asking for both: yours wins, so the module never takes it for its own pick.
            n.write().unwrap().set("mainnet", NodeConfig { source: "default".into(), ..own(direct(PLOWSOF), true) }).unwrap();
            let fake = Fake::default().with(direct(SETH), serving(900)).with(onion(SETH), serving(900));
            tend(&n, "mainnet", &fake);
            assert!(fake.asked().is_empty(), "{mode}");
            let c = n.read().unwrap().get("mainnet").unwrap().clone();
            assert_eq!((c.url.as_str(), c.source.as_str(), c.own), (direct(PLOWSOF), "external", true), "{mode}");
        }
    }

    #[test]
    fn the_picked_node_saves_from_the_apps_json_without_an_address() {
        // What the app sends for "A node picked for you"; a node you choose still needs one.
        let n = seeded("none", SETH, CAKE);
        let picked: NodeConfig = serde_json::from_str(r#"{"mode":"remote","source":"default","proxy":""}"#).unwrap();
        n.write().unwrap().set("mainnet", picked).unwrap();
        assert_eq!(n.read().unwrap().get("mainnet").unwrap().source, "default");
        let chosen: NodeConfig = serde_json::from_str(r#"{"mode":"remote","url":" ","proxy":""}"#).unwrap();
        assert!(matches!(n.write().unwrap().set("mainnet", chosen), Err(NodeError::NoAddress)));
    }

    #[test]
    fn choosing_the_picked_node_brings_back_the_seed_and_keeps_a_pick() {
        let n = seeded("none", SETH, CAKE);
        let fake = Fake::default().with(direct(SETH), serving(300)).with(direct(CAKE), serving(2)).with(direct(PLOWSOF), serving(100));
        tend(&n, "mainnet", &fake);
        assert_eq!(fake.asked(), [direct(SETH)]);
        // Yours for a while, then the picked node again: the seed, whatever address came with it.
        n.write().unwrap().set("mainnet", own("http://192.168.1.4:18081", true)).unwrap();
        let back = NodeConfig { source: "default".into(), username: Some("u".into()), ..cfg("http://ignored.example:1") };
        n.write().unwrap().set("mainnet", back.clone()).unwrap();
        let (_, url, onion_seed, _) = DEFAULT_ENDPOINTS.iter().find(|d| d.0 == "mainnet").unwrap();
        let c = n.read().unwrap().get("mainnet").unwrap().clone();
        assert_eq!((c.url.as_str(), c.onion_url.as_deref(), c.source.as_str(), c.own, c.username), (*url, Some(*onion_seed), "default", false, None));
        // Checked again at once, not when the earlier pick goes stale, and moved by health.
        tend(&n, "mainnet", &fake);
        assert_eq!(fake.asked()[0], direct(CAKE));
        assert_eq!(stored(&n).0, direct(SETH));
        // Saving the picked node again, through local mode and back, keeps where the pick put it.
        n.write().unwrap().set("mainnet", NodeConfig { mode: NodeMode::Local, ..back.clone() }).unwrap();
        n.write().unwrap().set("mainnet", back).unwrap();
        assert_eq!(stored(&n).0, direct(SETH));
    }

    #[test]
    fn a_node_you_set_on_your_network_is_yours_on_load_and_on_save() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("monero_nodes.json");
        std::fs::write(&p, r#"{"stagenet":{"url":"http://192.168.1.4:38081","source":"external"},
                              "mainnet":{"url":"https://far.example:18081","source":"external"}}"#).unwrap();
        let n = Nodes::new(Some(p.clone()));
        assert_eq!((n.get("stagenet").unwrap().own, n.get("mainnet").unwrap().own), (true, false));
        assert!(n.get("mainnet").unwrap().reach_through_tor, "absent reads as on");
        assert!(Nodes::new(Some(p)).get("stagenet").unwrap().own, "and is stored");
        let mut n = Nodes::new(None);
        n.set("stagenet", cfg("http://node.lan:38081")).unwrap();
        assert!(n.get("stagenet").unwrap().own);
    }

    #[test]
    fn a_pair_whose_direct_half_is_on_your_network_stays_a_pair() {
        // The wallet core's Tor-modes test: a loopback relay as the direct half, an onion beside it.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("monero_nodes.json");
        std::fs::write(&p, format!(r#"{{"stagenet":{{"url":"http://127.0.0.1:38081","onionUrl":"{ONION}","source":"external"}}}}"#)).unwrap();
        assert!(!Nodes::new(Some(p)).get("stagenet").unwrap().own, "on load");
        for mode in ["all", "identifying"] {
            let mut n = with_mode(mode);
            let pair = NodeConfig { proxy: Some("socks5h://127.0.0.1:9050".into()), ..both("http://127.0.0.1:38081") };
            n.set("stagenet", pair).unwrap();
            assert!(!n.get("stagenet").unwrap().own, "{mode}");
            let e = n.effective("stagenet").unwrap();
            assert_eq!((&e["url"], &e["route"]), (&json!(ONION), &json!("proxied")), "{mode}");
            let catch_up = e.get("catchUp").map(|c| c["url"].clone());
            assert_eq!(catch_up, (mode == "identifying").then(|| json!("http://127.0.0.1:38081")), "{mode}");
        }
    }
}
