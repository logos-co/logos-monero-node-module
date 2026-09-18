//! monero_node_module — proxyable, fail-closed monerod JSON-RPC client.
//!
//! One job: give the Monero wallet family chain data (height, fee estimate, node health, tx
//! lookup, broadcast) from a public or user-supplied node, keyed by network name, with every
//! outbound request built through the single fail-closed [`proxy`] chokepoint. It never runs a
//! node itself (local mode dials the one `monerod_module` runs) and holds no key material.
//!
//! The client core ([`node`]) is pure and unit-tested with `cargo test --no-default-features`;
//! the Logos glue is behind the default `logos_module` feature.
mod proxy;
mod node;

pub use node::{is_network, LocalNode, NodeConfig, NodeMode, Nodes, NETWORKS};

#[cfg(feature = "logos_module")]
mod glue;
