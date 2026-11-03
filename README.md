# logos-monero-node-module

`monero_node_module` — a proxyable, **fail-closed** monerod JSON-RPC client for the Logos
Monero wallet family. Per-network config (endpoint + proxy policy), persisted device-wide, keyed
by network name (`mainnet` / `stagenet` / `testnet` / `regtest`). It **never runs a node** itself
and holds no key material.

Every outbound request is built through the single fail-closed chokepoint (`src/proxy.rs`, an
inlined copy of `logos-net-proxy`): a route through Tor with no usable proxy **refuses to call**
rather than leaking in the clear.

## Contract

Every method returns a JSON string: `{ "ok": true, "result": …, "route": "proxied"|"direct" }`
or `{ "ok": false, "error": … }`. Config: `set_node_config` / `get_node_config` /
`remove_node_config` / `list_networks` / `config_status` / `init_defaults`. Reads: `node_health`,
`get_info`, `get_fee_estimate`, `get_version`, `hard_fork_info`, `send_raw_transaction`,
`generateblocks` (regtest only), plus `raw_json_rpc` / `raw_endpoint` escape hatches. Tor:
`tor_use`, `set_tor_use`, `set_wallet_open`. Local mode: `effective_node`, `local_node`.

## Use Tor for

One setting for all networks, the same three values as the other Logos wallets. It is stored in
`monero_tor.json` beside the node registry, with `torUseChosen`.

| `torUse` | What a wallet dials (`effective_node`) |
|---|---|
| `all` | the onion node (`onionUrl`), over Tor |
| `identifying` (default) | the onion node over Tor, plus `catchUp: { url }`: the direct node (`url`) to catch up from first. The wallet core switches to the onion node once caught up, and sends only after the switch. |
| `none` | the direct node (`url`); Tor is never started |

- **Which Tor:** `proxy` empty or `tor` is the Tor that comes with Logos (`tor_module`'s SOCKS
  port, read from its `status()`), else your own `socks5h://host:port`. `socks5://` is stored
  as `socks5h://`; names are always resolved by Tor.
- **Fail-closed:** a Tor route has `proxyRequired: true`. While the built-in Tor is joining, its
  proxy reads `tor` and `torReady: false`: a wallet waits, and a wallet core from before this
  setting refuses it. Calls of this module's own (`get_info`, `node_health`, ...) on a Tor route
  answer an error, or `reachable: false` with the reason, until Tor is ready.
- **Onion and LAN:** an onion `url` is Tor-only in every mode, and refused in `none`. A node on
  this computer or its network (loopback, private and link-local addresses, `.local`, `.lan`,
  `.home.arpa`) is dialled directly in every mode. Local mode is always direct.
- **No onion node:** `url` itself is used over Tor, and `identifying` gives no `catchUp`: one node
  seeing both the catch-up and the sends would tie them together. Credentials and `trusted` go
  only to `url`, never to a different onion node.
- **Starting Tor:** tor_module starts when asked. This module asks only for a Tor route through
  the built-in Tor: on a wallet's `effective_node` and on calls, and on a `node_health` poll once
  the user chose or a wallet asked. At most every 2 s until ready, every 30 s after.
- **Locked while a wallet is open:** the wallet core reports `set_wallet_open(network, open)`;
  while any wallet is open `set_tor_use` answers "Close your open accounts to change this.", and
  `set_node_config` on that network is refused too. `set_tor_use` takes the wallet backend
  (`monero_wallet_backend`) and `set_wallet_open` the wallet core; a `callers.json` in the
  instance directory, `{"modules": [...], "allowHost": true}`, admits more, for tests.
- **Upgrading:** an install from before this setting keeps its routing: a saved proxy (or
  `proxyRequired`) loads as `all` with that proxy as your own Tor, none as `none`, both with
  `torUseChosen: false` and `existing: true`, for the wallet to confirm. A fresh install is
  `identifying`, not chosen. `proxyRequired` on a stored record is read only for this.
- **Defaults:** the direct nodes are monerodevs.org's over TLS (monerod's own certificate, which
  neither wallet2 nor this module checks), the onion nodes plowsof's, from Feather's list: two
  operators, so the catch-up node never sees the sends. Records seeded on the old plain-http
  defaults move to these on load; a node you picked is left alone.

`node_health` adds `torUse`, `torUseChosen`, and on a Tor route `url`, `catchUp` and `tor` (the
built-in Tor's `{ state, progress, detail, socks, answered }`).

## Local mode

A network set to `"mode": "local"` dials the node that
[`monerod_module`](https://github.com/logos-co/logos-monerod-module) runs in-process, instead of its stored `url`.
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

Plain `cargo` reads the optional SDK path dependency's manifest, so check out logos-rust-sdk at
the revision `flake.lock` pins into `logos-rust-sdk-src/` first, as the unit-test workflow does.
The doctest (`doctests/monero-node-stagenet.test.yaml`) stages `tor_module` beside this module
and dials a public stagenet node directly and over Tor through the onion default.
