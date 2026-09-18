# logos-monero-node-module

`monero_node_module` — a proxyable, **fail-closed** monerod JSON-RPC client for the Logos
Monero wallet family. Per-network config (endpoint + proxy policy), persisted device-wide, keyed
by network name (`mainnet` / `stagenet` / `testnet` / `regtest`). It **never runs a node** itself
and holds no key material.

Every outbound request is built through the single fail-closed chokepoint (`src/proxy.rs`, an
inlined copy of `logos-net-proxy`): a network configured `proxyRequired` with no usable proxy
**refuses to call** rather than leaking in the clear. `socks5h` is the preferred scheme (remote
DNS, Tor-ready).

## Contract

Every method returns a JSON string: `{ "ok": true, "result": …, "route": "proxied"|"direct" }`
or `{ "ok": false, "error": … }`. Config: `set_node_config` / `get_node_config` /
`remove_node_config` / `list_networks` / `config_status` / `init_defaults`. Reads: `node_health`,
`get_info`, `get_fee_estimate`, `get_version`, `hard_fork_info`, `send_raw_transaction`,
`generateblocks` (regtest only), plus `raw_json_rpc` / `raw_endpoint` escape hatches. Local mode:
`effective_node`, `local_node`.

## Local mode

A network set to `"mode": "local"` dials the node that
[`monerod_module`](../logos-monerod-module) runs in-process, instead of its stored `url`.
`monerod_module` is an **optional** dependency: never bundled, never auto-loaded.

- `effective_node(network)` is what a wallet dials: in local mode, the daemon's loopback URL,
  `trusted`, with no proxy or credentials. A required proxy cannot fail-close a loopback call.
- The stored remote fields stay on the record, so switching back to `remote` restores them.
- `node_health` adds `mode`, plus `local` (the daemon's `status()`) in local mode.
  `local_node(network)` says whether local mode can be offered at all.
- With `monerod_module` absent, local mode fails within 1.5 s and never falls back to a remote
  node. Local mode is refused on `regtest`, which the daemon does not run.

`set_node_config` replaces the whole record, so a config without `mode` is `remote`.

Auth: unauthenticated public nodes and HTTP **Basic** auth (a simple self-hosted node) are
supported. monerod's `--rpc-login` uses HTTP **Digest**; digest support is a deferred follow-up
and a digest challenge currently surfaces as an error rather than silently failing.

## Build & test

```bash
cargo test --manifest-path rust-lib/Cargo.toml --no-default-features --locked   # pure core
nix build                                                                        # the module
```
