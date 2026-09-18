//! Logos module glue for `monero_node_module` (rust-first authoring).
//!
//! The builder derives the `.lidl` from the `MoneroNodeModule` trait below. Config is keyed +
//! persisted per network (`monero_nodes.json` under the instance persistence path); every
//! method takes a network name. Structured values cross as JSON strings —
//! `{ "ok": true, "result": …, "route": "proxied"|"direct" }` or `{ "ok": false, "error": … }`.
//!
//! `concurrency: "multi"`: every method is a blocking network round-trip, so the module opts
//! into concurrent dispatch. The trait takes `&self` + `Send + Sync`, so state lives behind a
//! `RwLock`: the reads take the read lock and run concurrently; the rare config mutators take
//! the write lock.

use std::sync::RwLock;
use std::time::Duration;

use serde_json::{json, Value};

use crate::node::{is_network, LocalNode, NodeConfig, Nodes};

pub trait MoneroNodeModule: Send + Sync + 'static {
    /// Store one network's config from `{ url, username?, password?, proxy?, proxyRequired?, timeoutSecs?, trusted?, mode? }`.
    /// A full replace: `mode` is `remote` unless the config says `local`.
    fn set_node_config(&self, network: String, config_json: String) -> String;
    fn get_node_config(&self, network: String) -> String;
    /// What a wallet dials: the stored config, or in local mode monerod_module's loopback URL,
    /// trusted and unproxied. `{ ok, result }` like get_node_config.
    fn effective_node(&self, network: String) -> String;
    /// `{ ok, available, rpcUrl?, status?, error? }`: whether monerod_module can serve `network`.
    fn local_node(&self, network: String) -> String;
    fn remove_node_config(&self, network: String) -> bool;
    /// `{ ok, networks: [name, ...] }`.
    fn list_networks(&self) -> String;

    /// `{ ok, state: "unready"|"unconfigured"|"configured", source, networks }`.
    fn config_status(&self) -> String;
    /// Seed well-known defaults per-field-if-absent. `{ ok, applied: [...] }`.
    fn init_defaults(&self) -> String;

    /// `{ reachable, height, targetHeight, synced, restricted, rttMs, mode, local? }`.
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
}

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
        Self { nodes: RwLock::new(Nodes::new(None)) }
    }
}

fn ok(result: Value, route: &str) -> String {
    json!({ "ok": true, "result": result, "route": route }).to_string()
}

fn err(msg: impl std::fmt::Display) -> String {
    json!({ "ok": false, "error": msg.to_string() }).to_string()
}

impl MoneroNodeModuleImpl {
    fn call<F>(&self, f: F) -> String
    where
        F: FnOnce(&Nodes) -> std::result::Result<(Value, &'static str), crate::node::NodeError>,
    {
        let guard = self.nodes.read().unwrap();
        match f(&guard) {
            Ok((v, route)) => ok(v, route),
            Err(e) => err(e),
        }
    }
}

impl MoneroNodeModule for MoneroNodeModuleImpl {
    fn on_context_ready(&self, ctx: &RustModuleContext) {
        let path = std::path::Path::new(&ctx.instance_persistence_path).join("monero_nodes.json");
        *self.nodes.write().unwrap() = Nodes::new(Some(path)).with_local(Box::new(MonerodLocal));
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
        match self.nodes.read().unwrap().effective(&network) {
            Ok(c) => json!({ "ok": true, "result": c }).to_string(),
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
        self.nodes.read().unwrap().node_health(&network).to_string()
    }

    fn get_info(&self, network: String) -> String { self.call(|n| n.get_info(&network)) }
    fn get_fee_estimate(&self, network: String) -> String { self.call(|n| n.get_fee_estimate(&network)) }
    fn get_version(&self, network: String) -> String { self.call(|n| n.get_version(&network)) }
    fn hard_fork_info(&self, network: String) -> String { self.call(|n| n.hard_fork_info(&network)) }

    fn send_raw_transaction(&self, network: String, tx_as_hex: String) -> String {
        self.call(|n| n.send_raw_transaction(&network, &tx_as_hex, false))
    }

    fn generateblocks(&self, network: String, address: String, amount: i64) -> String {
        if network != "regtest" {
            return err("generateblocks is regtest-only");
        }
        self.call(|n| n.generateblocks(&network, &address, amount.max(0) as u64))
    }

    fn raw_json_rpc(&self, network: String, method: String, params_json: String) -> String {
        let params: Value = serde_json::from_str(&params_json).unwrap_or(Value::Null);
        self.call(|n| n.json_rpc(&network, &method, params))
    }

    fn raw_endpoint(&self, network: String, path: String, body_json: String) -> String {
        if !is_network(&network) {
            return err(format!("unknown network: {network}"));
        }
        let body: Value = serde_json::from_str(&body_json).unwrap_or(json!({}));
        self.call(|n| n.other(&network, &path, body))
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<MoneroNodeModuleImpl>();
}
