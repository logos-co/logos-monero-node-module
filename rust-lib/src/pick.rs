//! Mainnet's public nodes, and keeping a record the module seeded on one that serves.
//!
//! Only a seeded record (`source: "default"`, remote) is checked or moved. When a wallet resolves
//! it ([`tend`], from `effective_node`), the half it dials next is checked once per run, and again
//! after a failure or when the check is stale. One that passes stays. Otherwise every listed node
//! for that half is measured and the best is stored.

use std::io::Read;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::node::{NodeConfig, Nodes};
use crate::proxy::build_client;
use crate::tor::host_of;

/// `(operator, direct node, onion node)`. Each operator runs both of its nodes, so a catch-up node
/// and an onion node from two different rows are two operators.
pub const MAINNET_NODES: &[(&str, &str, &str)] = &[
    // cake-tech/cake_wallet assets/node_list.yml at c8cad83: "Cake Wallet" and "Cake Wallet (Tor)".
    ("cakewallet", "https://xmr-node.cakewallet.com:18081", "http://cakexmrkbd7ptshw7vfzhzqgg77xgeavdrxm6zbu57lppfkj3fczbrqd.onion:18081"),
    // https://sethforprivacy.com/about/ "High-Performance Monero Nodes": RPC on 18089, and its onion.
    ("sethforprivacy", "https://node.sethforprivacy.com:18089", "http://sfprpc5klzs5vyitq2mrooicgk2wcs5ho2nm3niqduvzn5o6ylaslaqd.onion:18089"),
    // feather-wallet/feather-nodes nodes.yaml at 5a1bd38 lists both under "plowsof".
    ("plowsof", "https://node.monerodevs.org:18089", "http://plowsof3t5hogddwabaeiyrno25efmzfxyro2vligremt7sxpsclfaid.onion:18089"),
];

/// The listed nodes of `network`; only mainnet has more than one.
pub fn listed(network: &str) -> &'static [(&'static str, &'static str, &'static str)] {
    if network == "mainnet" { MAINNET_NODES } else { &[] }
}

/// Which listed operator runs `url`, by host.
pub fn operator_of(network: &str, url: &str) -> Option<&'static str> {
    let host = host_of(url);
    listed(network).iter().find(|n| host_of(n.1) == host || host_of(n.2) == host).map(|n| n.0)
}

/// The direct node or the node over Tor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Half {
    Direct,
    Tor,
}

impl Half {
    pub fn name(self) -> &'static str {
        match self { Half::Direct => "direct", Half::Tor => "tor" }
    }

    /// The listed node of this half in row `i`.
    pub fn url(self, i: usize, network: &str) -> &'static str {
        let n = listed(network)[i];
        match self { Half::Direct => n.1, Half::Tor => n.2 }
    }

    /// Slower than this is what stalled wallets: ~4 KB/s for hours on 2026-11-03.
    fn floor(self) -> u64 {
        match self { Half::Direct => 32 * 1024, Half::Tor => 8 * 1024 }
    }

    fn info_cap(self) -> Duration {
        Duration::from_secs(match self { Half::Direct => 5, Half::Tor => 9 })
    }

    fn window(self) -> Duration {
        Duration::from_secs(match self { Half::Direct => 3, Half::Tor => 5 })
    }
}

/// All the checking one `effective_node` may do, well under the 20 s Logos RPC deadline.
const BUDGET: Duration = Duration::from_secs(14);
/// A check that passed stands this long; one that failed is retried after RETRY.
pub const STALE: Duration = Duration::from_secs(30 * 60);
pub const RETRY: Duration = Duration::from_secs(5 * 60);
/// Blocks a node may trail the highest one measured beside it.
const HEIGHT_SLACK: u64 = 3;
/// Headers in the throughput sample, ~134 KB.
const SAMPLE: u64 = 150;

/// One node, measured the way a wallet reaches it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Probe {
    pub reachable: bool,
    pub nettype: String,
    pub height: u64,
    pub synced: bool,
    pub rtt_ms: u64,
    /// Over a header sample, from request to last byte: the shape of a wallet's block request.
    pub bytes_per_sec: u64,
    pub error: Option<String>,
}

impl Probe {
    pub fn failed(e: impl std::fmt::Display) -> Self {
        Self { error: Some(e.to_string()), ..Self::default() }
    }

    fn usable(&self, network: &str, top: u64) -> bool {
        self.reachable && self.synced && self.nettype == network && self.height + HEIGHT_SLACK >= top
    }

    fn passes(&self, network: &str, top: u64, half: Half) -> bool {
        self.usable(network, top) && self.bytes_per_sec >= half.floor()
    }

    /// Seconds a 100 KB request would take: latency and throughput in one number.
    fn cost(&self) -> f64 {
        self.rtt_ms as f64 / 1000.0 + 100_000.0 / self.bytes_per_sec.max(1) as f64
    }

    pub fn json(&self) -> Value {
        json!({ "reachable": self.reachable, "height": self.height, "synced": self.synced,
                "rttMs": self.rtt_ms, "bytesPerSec": self.bytes_per_sec, "error": self.error })
    }
}

/// Measures nodes. A trait so the pure tests can stand one in.
pub trait Prober: Send + Sync {
    fn probe(&self, network: &str, dial: &NodeConfig, deadline: Instant) -> Probe;
}

/// `get_info`, then the last SAMPLE block headers, read until the window closes.
pub struct HttpProber;

impl Prober for HttpProber {
    fn probe(&self, network: &str, dial: &NodeConfig, deadline: Instant) -> Probe {
        let half = if dial.proxy.is_some() { Half::Tor } else { Half::Direct };
        let left = |cap: Duration| cap.min(deadline.saturating_duration_since(Instant::now()));
        let client = match build_client(&dial.proxy_cfg()) {
            Ok(c) => c,
            Err(e) => return Probe::failed(e),
        };
        let url = format!("{}/json_rpc", dial.url.trim_end_matches('/'));
        let rpc = |method: &str, params: Value| json!({ "jsonrpc": "2.0", "id": "0", "method": method, "params": params });
        let started = Instant::now();
        let info = client.post(&url).timeout(left(half.info_cap())).json(&rpc("get_info", json!({}))).send()
            .and_then(|r| r.json::<Value>());
        let info = match info {
            Ok(v) if v["result"].is_object() => v["result"].clone(),
            Ok(_) => return Probe::failed("get_info had no result"),
            Err(e) => return Probe::failed(e),
        };
        let rtt_ms = started.elapsed().as_millis() as u64;
        let height = info["height"].as_u64().unwrap_or(0);
        let target = info["target_height"].as_u64().unwrap_or(0);
        let synced = info["synchronized"].as_bool() == Some(true) && info["busy_syncing"].as_bool() != Some(true) && target <= height;
        let mut p = Probe {
            reachable: true,
            nettype: info["nettype"].as_str().unwrap_or(network).to_string(),
            height,
            synced,
            rtt_ms,
            ..Probe::default()
        };
        let window = left(half.window());
        if height <= SAMPLE + 2 || window.is_zero() {
            return p;
        }
        let t0 = Instant::now();
        let mut bytes = 0u64;
        let params = json!({ "start_height": height - SAMPLE - 1, "end_height": height - 2 });
        match client.post(&url).timeout(window).json(&rpc("get_block_headers_range", params)).send() {
            Ok(mut r) => {
                let mut buf = [0u8; 16 * 1024];
                while t0.elapsed() < window {
                    match r.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => bytes += n as u64,
                    }
                }
            }
            Err(e) => p.error = Some(e.to_string()),
        }
        p.bytes_per_sec = (bytes as f64 / t0.elapsed().as_secs_f64().max(0.001)) as u64;
        p
    }
}

/// What to measure: one half of one seeded record, the rows it may move to, and how to reach them.
pub struct Job {
    pub network: String,
    pub half: Half,
    /// The row stored now, if it may stay.
    pub current: Option<usize>,
    pub rows: Vec<usize>,
    pub socks: Option<String>,
}

impl Job {
    pub fn dial(&self, i: usize) -> NodeConfig {
        NodeConfig {
            url: self.half.url(i, &self.network).into(),
            onion_url: None,
            username: None,
            password: None,
            proxy: self.socks.clone(),
            proxy_required: self.half == Half::Tor,
            timeout_secs: self.half.info_cap().as_secs(),
            trusted: false,
            source: "default".into(),
            mode: crate::node::NodeMode::Remote,
            own: false,
            reach_through_tor: true,
        }
    }
}

/// The row to store: one that passes, else the best that is usable, else none (keep what is stored).
/// The stored row stays while it passes.
pub fn choose(network: &str, half: Half, current: Option<usize>, probes: &[(usize, Probe)]) -> Option<(usize, bool)> {
    let top = probes.iter().filter(|(_, p)| p.reachable && p.synced && p.nettype == network).map(|(_, p)| p.height).max()?;
    if let Some((i, _)) = probes.iter().find(|(i, p)| Some(*i) == current && p.passes(network, top, half)) {
        return Some((*i, true));
    }
    let best = |pass: bool| probes.iter()
        .filter(|(_, p)| p.usable(network, top) && (!pass || p.passes(network, top, half)))
        .min_by(|a, b| a.1.cost().total_cmp(&b.1.cost()))
        .map(|(i, _)| *i);
    best(true).map(|i| (i, true)).or_else(|| best(false).map(|i| (i, false)))
}

/// Keeps `network`'s seeded record on a node that serves. Probes run without the registry lock.
/// The direct half asks the stored node first, so one operator sees you while it serves; over Tor
/// every row is asked at once, as no answer there carries your address.
pub fn tend(nodes: &RwLock<Nodes>, network: &str, prober: &dyn Prober) {
    let Some(job) = nodes.read().unwrap_or_else(|e| e.into_inner()).begin_pick(network) else { return };
    let deadline = Instant::now() + BUDGET;
    let mut probes = Vec::new();
    if job.half == Half::Direct {
        if let Some(c) = job.current {
            let p = prober.probe(network, &job.dial(c), deadline);
            let top = p.height;
            let pass = p.passes(network, top, job.half);
            probes.push((c, p));
            if pass {
                nodes.write().unwrap_or_else(|e| e.into_inner()).finish_pick(&job, &probes);
                return;
            }
        }
    }
    let rest: Vec<usize> = job.rows.iter().copied().filter(|i| !probes.iter().any(|(j, _)| j == i)).collect();
    let more: Vec<(usize, Probe)> = std::thread::scope(|s| {
        let handles: Vec<_> = rest.iter().map(|&i| {
            let dial = job.dial(i);
            (i, s.spawn(move || prober.probe(network, &dial, deadline)))
        }).collect();
        handles.into_iter().map(|(i, h)| (i, h.join().unwrap_or_else(|_| Probe::failed("probe panicked")))).collect()
    });
    probes.extend(more);
    nodes.write().unwrap_or_else(|e| e.into_inner()).finish_pick(&job, &probes);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live: measures every listed direct node from here. `cargo test -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn the_listed_mainnet_nodes_answer() {
        let job = Job { network: "mainnet".into(), half: Half::Direct, current: None, rows: vec![0, 1, 2], socks: None };
        for i in job.rows.clone() {
            let p = HttpProber.probe("mainnet", &job.dial(i), Instant::now() + BUDGET);
            println!("{:<15} {:<40} {:?}", MAINNET_NODES[i].0, MAINNET_NODES[i].1, p);
            assert!(p.reachable && p.synced && p.nettype == "mainnet" && p.bytes_per_sec > 0, "{p:?}");
        }
    }
}
