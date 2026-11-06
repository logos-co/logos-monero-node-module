//! Logos module glue for `monero_node_module` (rust-first authoring).
//!
//! The builder derives the `.lidl` from the `MoneroNodeModule` trait below. Config is keyed +
//! persisted per network (`monero_nodes.json` under the instance persistence path); every
//! method takes a network name. Structured values cross as JSON strings —
//! `{ "ok": true, "result": …, "route": "proxied"|"direct" }` (proxied = over Tor) or `{ "ok": false, "error": … }`.
//!
//! `concurrency: "multi"`: every method is a blocking network round-trip, so the module opts
//! into concurrent dispatch. The trait takes `&self` + `Send + Sync`, so state lives behind a
//! `RwLock`: the reads take the read lock and run concurrently; the rare config mutators take
//! the write lock.
//!
//! The built-in Tor's status is asked of tor_module on the calls that need it, at most every
//! 2 s until it is ready and every 30 s after. Asking starts Tor, so `none` never asks.

use std::sync::RwLock;
use std::time::{Duration, Instant};

use logos_rust_sdk::LogosCaller;
use serde_json::{json, Value};

use crate::gate::{Access, Caller, Callers};
use crate::node::{is_network, LocalNode, NodeConfig, Nodes};
use crate::tor::TorView;

pub trait MoneroNodeModule: Send + Sync + 'static {
    /// Store one network's config from `{ url, onionUrl?, username?, password?, proxy?, timeoutSecs?, trusted?, mode?,
    /// own?, reachThroughTor?, source? }`. A full replace: `mode` is `remote` unless the config says `local`. `proxy` is
    /// which Tor: empty or `tor` for the built-in one, else `socks5h://host:port`. `own`: a node you run, routed by its
    /// address and `reachThroughTor`. `source: "default"`: the node this module picks. Refused while a wallet is open on it.
    fn set_node_config(&self, network: String, config_json: String) -> String;
    fn get_node_config(&self, network: String) -> String;
    /// What a wallet dials under "Use Tor for": `{ ok, result: { url, proxy, proxyRequired,
    /// trusted, torUse, route, torReady?, catchUp?: { url }, localSends?, send?: { url, proxy } } }`.
    /// proxy is `tor` while the built-in Tor cannot carry traffic yet. In local mode, monerod_module's
    /// loopback URL. `send`: with your own node, the public node payments go to over Tor.
    /// On a seeded mainnet record it first checks the node to be dialled, and may move it.
    fn effective_node(&self, network: String) -> String;
    /// `network`'s setting: `{ ok, network, torUse: "all"|"identifying"|"none", torUseChosen, existing,
    /// sends? }`. `sends`, with your own node: as `set_local_sends` answers.
    fn tor_use(&self, network: String) -> String;
    /// The wallet backend only: store the user's choice for `network`. `{ ok:false, error }`
    /// while a wallet is open.
    fn set_tor_use(&self, network: String, mode: String) -> String;
    /// The wallet backend only: with your own node, where `network`'s payments go: `servers` (a
    /// public node over Tor) or `node`. `{ ok, network, localSends, localSendsChosen,
    /// localSendsRecommended, sendNode? }`, or `{ ok:false, error }` while a wallet is open.
    fn set_local_sends(&self, network: String, via: String) -> String;
    /// The wallet core only: a wallet opened or closed on `network`, locking its settings.
    fn set_wallet_open(&self, network: String, open: bool) -> String;
    /// `{ ok, available, rpcUrl?, status?, error? }`: whether monerod_module can serve `network`.
    fn local_node(&self, network: String) -> String;
    fn remove_node_config(&self, network: String) -> bool;
    /// `{ ok, networks: [name, ...] }`.
    fn list_networks(&self) -> String;

    /// `{ ok, state: "unready"|"unconfigured"|"configured", source, networks }`.
    fn config_status(&self) -> String;
    /// Seed well-known defaults per-field-if-absent. `{ ok, applied: [...] }`.
    fn init_defaults(&self) -> String;

    /// `{ reachable, height, targetHeight, synced, restricted, rttMs, mode, torUse, torUseChosen,
    /// url?, catchUp?, tor?, local?, operator?, pick?, sends? }`. A Tor route is not dialled while Tor is
    /// not ready. `operator` and `pick` (this run's checks) are for a seeded mainnet record.
    fn node_health(&self, network: String) -> String;

    fn get_info(&self, network: String) -> String;
    fn get_fee_estimate(&self, network: String) -> String;
    fn get_version(&self, network: String) -> String;
    fn hard_fork_info(&self, network: String) -> String;
    /// Broadcast a signed tx blob via `/send_raw_transaction`.
    fn send_raw_transaction(&self, network: String, tx_as_hex: String) -> String;
    /// regtest only: mine `amount` blocks to `address`.
    fn generateblocks(&self, network: String, address: String, amount: i64) -> String;

    /// Escape hatch: an arbitrary `/json_rpc` method. `params_json` is a JSON value.
    fn raw_json_rpc(&self, network: String, method: String, params_json: String) -> String;
    /// Escape hatch: an arbitrary "other" endpoint (POST `<url>/<path>`).
    fn raw_endpoint(&self, network: String, path: String, body_json: String) -> String;

    fn on_context_ready(&self, _ctx: &RustModuleContext) {}
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

struct MoneroNodeModuleImpl {
    nodes: RwLock<Nodes>,
    callers: std::sync::Mutex<Callers>,
    /// When tor_module was last asked.
    tor_asked: std::sync::Mutex<Option<Instant>>,
    tor: std::sync::OnceLock<tor_module::TorModuleClient>,
}

/// One status() call to tor_module, which answers at once.
const TOR_BUDGET: Duration = Duration::from_millis(1000);

/// Bounded so an absent monerod_module costs 1.5 s, not the 20 s protocol deadline.
const LOCAL_BUDGET: Duration = Duration::from_millis(1500);

/// monerod_module, an OPTIONAL dependency: when it is not loaded, local mode reports it.
struct MonerodLocal;

impl LocalNode for MonerodLocal {
    fn rpc_url(&self, network: &str) -> std::result::Result<String, String> {
        monerod_module::MonerodModuleClient::new()
            .rpc_endpoint_with_timeout(network, LOCAL_BUDGET)
            .map_err(why)
    }

    fn status(&self) -> std::result::Result<Value, String> {
        monerod_module::MonerodModuleClient::new()
            .status_with_timeout(LOCAL_BUDGET)
            .map_err(why)
    }

    fn config(&self, network: &str) -> std::result::Result<Value, String> {
        monerod_module::MonerodModuleClient::new()
            .get_config_with_timeout(network, LOCAL_BUDGET)
            .map_err(why)
    }
}

/// The SDK's error text ends in a `{ "code", ... }` object; name the absent case plainly.
fn why(e: impl std::fmt::Display) -> String {
    let s = e.to_string();
    let code = s.find('{')
        .and_then(|i| serde_json::from_str::<Value>(&s[i..]).ok())
        .and_then(|v| v.get("code").and_then(Value::as_str).map(str::to_owned));
    match code.as_deref() {
        Some("object_unavailable") => "monerod_module is not loaded".into(),
        _ => format!("monerod_module: {s}"),
    }
}

impl Default for MoneroNodeModuleImpl {
    fn default() -> Self {
        Self {
            nodes: RwLock::new(Nodes::new(None)),
            callers: Default::default(),
            tor_asked: Default::default(),
            tor: Default::default(),
        }
    }
}

fn ok(result: Value, route: &str) -> String {
    json!({ "ok": true, "result": result, "route": route }).to_string()
}

fn err(msg: impl std::fmt::Display) -> String {
    json!({ "ok": false, "error": msg.to_string() }).to_string()
}

impl MoneroNodeModuleImpl {
    fn admits(&self, access: Access) -> bool {
        let caller = match logos_rust_sdk::current_caller() {
            LogosCaller::Module { name, .. } => Caller::Module(name),
            LogosCaller::HostAnchor => Caller::Host,
            _ => Caller::Unknown,
        };
        self.callers.lock().unwrap().admits(access, &caller)
    }

    /// Asks tor_module for its status when `network` goes through the built-in Tor and the
    /// last answer is stale. `poll`: a health poll, which may ask only once Tor is followed.
    fn refresh_tor(&self, network: &str, poll: bool) {
        let handle = {
            let n = self.nodes.read().unwrap();
            if !n.wants_tor(network) || (poll && !n.follows_tor(network)) {
                return;
            }
            n.tor_handle()
        };
        let ready = handle.lock().unwrap().as_ref().is_some_and(|v| v.usable_socks().is_some());
        {
            let mut at = self.tor_asked.lock().unwrap();
            let every = Duration::from_secs(if ready { 30 } else { 2 });
            if at.is_some_and(|t| t.elapsed() < every) {
                return;
            }
            *at = Some(Instant::now());
        }
        // Async, then waited for here: a blocking call nests in the main thread's event loop.
        let (tx, rx) = std::sync::mpsc::channel();
        self.tor.get_or_init(tor_module::TorModuleClient::new).status_async_with_timeout(TOR_BUDGET, move |r| {
            let _ = tx.send(r.map_err(|e| e.to_string()));
        });
        let reply = rx.recv_timeout(TOR_BUDGET + Duration::from_millis(200))
            .unwrap_or_else(|_| Err("tor_module did not answer".into()));
        *handle.lock().unwrap() = Some(TorView::from_reply(reply));
    }

    fn call<F>(&self, network: &str, f: F) -> String
    where
        F: FnOnce(&Nodes) -> std::result::Result<(Value, &'static str), crate::node::NodeError>,
    {
        self.refresh_tor(network, false);
        let guard = self.nodes.read().unwrap();
        match f(&guard) {
            Ok((v, route)) => ok(v, route),
            Err(e) => err(e),
        }
    }
}

impl MoneroNodeModule for MoneroNodeModuleImpl {
    fn on_context_ready(&self, ctx: &RustModuleContext) {
        let dir = std::path::Path::new(&ctx.instance_persistence_path);
        *self.callers.lock().unwrap() = Callers::from_file(std::fs::read_to_string(dir.join("callers.json")).ok().as_deref());
        *self.nodes.write().unwrap() = Nodes::new(Some(dir.join("monero_nodes.json"))).with_local(Box::new(MonerodLocal));
    }

    fn set_node_config(&self, network: String, config_json: String) -> String {
        let cfg: NodeConfig = match serde_json::from_str(&config_json) {
            Ok(c) => c,
            Err(e) => return err(format!("bad config: {e}")),
        };
        match self.nodes.write().unwrap().set(&network, cfg) {
            Ok(()) => json!({ "ok": true }).to_string(),
            Err(e) => err(e),
        }
    }

    fn get_node_config(&self, network: String) -> String {
        match self.nodes.read().unwrap().get(&network) {
            Some(c) => json!({ "ok": true, "result": c }).to_string(),
            None => err(format!("network not configured: {network}")),
        }
    }

    fn effective_node(&self, network: String) -> String {
        self.refresh_tor(&network, false);
        // A wallet binds what this returns, so a seeded record is checked here, within 14 s.
        crate::pick::tend(&self.nodes, &network, &crate::pick::HttpProber);
        match self.nodes.read().unwrap().effective(&network) {
            Ok(c) => json!({ "ok": true, "result": c }).to_string(),
            Err(e) => err(e),
        }
    }

    fn tor_use(&self, network: String) -> String {
        match self.nodes.read().unwrap().tor_use(&network) {
            Ok(v) => v.to_string(),
            Err(e) => err(e),
        }
    }

    fn set_tor_use(&self, network: String, mode: String) -> String {
        if !self.admits(Access::Backend) {
            return err("not authorized");
        }
        match self.nodes.write().unwrap().set_tor_use(&network, &mode) {
            Ok(v) => v.to_string(),
            Err(e) => err(e),
        }
    }

    fn set_local_sends(&self, network: String, via: String) -> String {
        if !self.admits(Access::Backend) {
            return err("not authorized");
        }
        match self.nodes.write().unwrap().set_local_sends(&network, &via) {
            Ok(v) => v.to_string(),
            Err(e) => err(e),
        }
    }

    fn set_wallet_open(&self, network: String, open: bool) -> String {
        if !self.admits(Access::Core) {
            return err("not authorized");
        }
        match self.nodes.write().unwrap().set_wallet_open(&network, open) {
            Ok(v) => v.to_string(),
            Err(e) => err(e),
        }
    }

    fn local_node(&self, network: String) -> String {
        self.nodes.read().unwrap().local_node(&network).to_string()
    }

    fn remove_node_config(&self, network: String) -> bool {
        self.nodes.write().unwrap().remove(&network).unwrap_or(false)
    }

    fn list_networks(&self) -> String {
        json!({ "ok": true, "networks": self.nodes.read().unwrap().list() }).to_string()
    }

    fn config_status(&self) -> String {
        self.nodes.read().unwrap().config_status().to_string()
    }

    fn init_defaults(&self) -> String {
        match self.nodes.write().unwrap().init_defaults() {
            Ok(applied) => json!({ "ok": true, "applied": applied }).to_string(),
            Err(e) => err(e),
        }
    }

    fn node_health(&self, network: String) -> String {
        self.refresh_tor(&network, true);
        self.nodes.read().unwrap().node_health(&network).to_string()
    }

    fn get_info(&self, network: String) -> String { self.call(&network, |n| n.get_info(&network)) }
    fn get_fee_estimate(&self, network: String) -> String { self.call(&network, |n| n.get_fee_estimate(&network)) }
    fn get_version(&self, network: String) -> String { self.call(&network, |n| n.get_version(&network)) }
    fn hard_fork_info(&self, network: String) -> String { self.call(&network, |n| n.hard_fork_info(&network)) }

    fn send_raw_transaction(&self, network: String, tx_as_hex: String) -> String {
        self.call(&network, |n| n.send_raw_transaction(&network, &tx_as_hex, false))
    }

    fn generateblocks(&self, network: String, address: String, amount: i64) -> String {
        if network != "regtest" {
            return err("generateblocks is regtest-only");
        }
        self.call(&network, |n| n.generateblocks(&network, &address, amount.max(0) as u64))
    }

    fn raw_json_rpc(&self, network: String, method: String, params_json: String) -> String {
        let params: Value = serde_json::from_str(&params_json).unwrap_or(Value::Null);
        self.call(&network, |n| n.json_rpc(&network, &method, params))
    }

    fn raw_endpoint(&self, network: String, path: String, body_json: String) -> String {
        if !is_network(&network) {
            return err(format!("unknown network: {network}"));
        }
        let body: Value = serde_json::from_str(&body_json).unwrap_or(json!({}));
        self.call(&network, |n| n.other(&network, &path, body))
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<MoneroNodeModuleImpl>();
}
