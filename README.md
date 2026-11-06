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
`tor_use`, `set_tor_use`, `set_wallet_open`. Sending payments: `set_local_sends`. Local mode:
`effective_node`, `local_node`.

## Use Tor for

One setting per network, the same three values as the other Logos wallets: `tor_use(network)`,
`set_tor_use(network, mode)`. It is stored in `monero_tor.json` beside the node registry, as
`{ "networks": { "<network>": { "torUse", "torUseChosen", "existing" } } }`.

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
  the user chose for that network or a wallet asked. At most every 2 s until ready, every 30 s after.
- **Locked while a wallet is open:** the wallet core reports `set_wallet_open(network, open)`;
  while any wallet is open `set_tor_use` answers "Close your open accounts to change this.", and
  `set_node_config` on that network is refused too. `set_tor_use` takes the wallet backend
  (`monero_wallet_backend`) and `set_wallet_open` the wallet core; a `callers.json` in the
  instance directory, `{"modules": [...], "allowHost": true}`, admits more, for tests.
- **Upgrading:** an install from before this setting keeps its routing: a saved proxy (or
  `proxyRequired`) loads as `all` with that proxy as your own Tor, none as `none`, both with
  `torUseChosen: false` and `existing: true`, for the wallet to confirm. A fresh install is
  `identifying`, not chosen. `proxyRequired` on a stored record is read only for this. A
  `monero_tor.json` from a build with one setting for every network gives each network that
  value, not chosen, so the wallet asks again on each network.
- **Defaults:** the direct nodes speak TLS (this module accepts monerod's own certificate), the
  onion nodes are onion services. Mainnet's seed is Cake Wallet's node and plowsof's onion: two
  operators, so the catch-up node never sees the sends. Stagenet's and testnet's are both
  plowsof's (`node*.monerodevs.org` and the `plowsof*` onions). Records seeded on the old
  plain-http defaults move to these on load; a node you picked is left alone.

`node_health` adds `torUse`, `torUseChosen`, and on a Tor route `url`, `catchUp` and `tor` (the
built-in Tor's `{ state, progress, detail, socks, answered }`).

## Mainnet's public nodes

A mainnet record the module seeded (`source: "default"`, remote) moves among three operators'
nodes by health (`rust-lib/src/pick.rs`, each with its source):

| Operator | Direct node | Onion node |
|---|---|---|
| Cake Wallet | `xmr-node.cakewallet.com:18081` | `cakexmrkbd7…qd.onion:18081` |
| Seth For Privacy | `node.sethforprivacy.com:18089` | `sfprpc5klz…qd.onion:18089` |
| plowsof | `node.monerodevs.org:18089` | `plowsof3t5…id.onion:18089` |

- **When:** in `effective_node`, the call a wallet makes before it dials. Only the half it dials
  next is checked: the direct node at open in `none` and `identifying`, the onion node at open in
  `all` and on the move to Tor in `identifying` (once Tor is ready). Once a run; again 30 min
  after a check passed, or 5 min after one failed or `node_health` found the node not answering.
- **How:** `get_info` (answers, `nettype` mainnet, synchronized, within 3 blocks of the highest
  measured), then the last 150 block headers (~134 KB) read for up to 3 s (5 s over Tor). It
  must serve 32 KB/s directly, 8 KB/s over Tor. They are ranked by the seconds a 100 KB
  request would take: latency plus size over throughput. A check takes at most 14 s.
- **Sticky:** the stored node is asked first, alone, and stays while it passes, so one operator
  sees your address. Only when it fails are the other two asked, at once, and the best stored.
  Over Tor all three are asked at once, as none of them learns your address. When nothing
  answers, the stored node stays.
- **Two operators:** a pick that lands on the other half's operator moves that half to another
  operator. With a wallet open the direct node never moves, and the onion pick leaves out the
  catch-up node's operator. A 0.1.1 record with plowsof on both halves is split on load.
- **Never yours:** a node you set (`source` is not `default`), and local mode, are never probed
  or moved. It stays where you put it.
- **Back to the picked node:** `set_node_config` with `source: "default"` stores the stored seeded
  pair again, or the seed if the record was yours, and ignores the address fields that came with it.
  A seed that replaces your node is checked at the next `effective_node`.
- **What changes:** the record's `url` / `onionUrl`, so `get_node_config`, `effective_node` (its
  `url` and `catchUp.url`) and `node_health` follow, in the same shape. `node_health` on such a
  record adds `operator` (who runs the node it dialled) and `pick`: this run's checks,
  `{ direct?, tor?: { operator, url, ok, reachable, height, synced, rttMs, bytesPerSec, agoSecs } }`.

## Your own node at an address

A record with `"own": true` is a node you run, dialled at its `url` (`onionUrl` is not used).
Its address decides the route, and "Use Tor for" does not apply:

| `url` | Route |
|---|---|
| this computer or its network | direct; `reachThroughTor` is ignored, as Tor can't reach it |
| an onion service | over Tor, in `none` too |
| anywhere else | over Tor when `reachThroughTor` (the default), else direct |

There is never a `catchUp`, and the login goes to `url` over Tor too. It is never probed or moved.
A record you set on your own network, with no onion address beside it, is marked `own`, on save
and on load: it was direct in every mode, and stays so. With an onion beside it, it stays a pair.

## Sending payments with your own node

With your own node, in Logos (local mode) or at an address (`own`), a wallet syncs from it, and
`set_local_sends(network, via)` says where its payments go:

| `localSends` | Payments go | `effective_node` adds |
|---|---|---|
| `servers` | to a public node over Tor | `send: { url, proxy }`: the network's onion node, through the network's Tor |
| `node` | through your node, which passes them to its peers from its IP address, or over Tor when the node in Logos runs with `txProxy` | nothing |

- **Default:** `node` for the node in Logos while `monerod_module` sends over Tor itself (the
  running node's `status().txProxy` is `on`, or, while it runs no node for this network, its
  `getConfig(network).txProxy` is true); `servers` otherwise, and always for a node at an
  address, whose flags we can't see. It is stored in `monero_tor.json` as `localSends` only once
  picked, so until then it follows the node.
- **Never your node in its place:** while Tor can't carry the send, `send.proxy` is `tor`, and the
  wallet core waits. There is no fallback either way.
- `regtest` lists no public node, so its payments go through your node.
- `effective_node` also gives `localSends`, the route in effect. `tor_use` and `node_health` add
  `sends: { localSends, localSendsChosen, localSendsRecommended, sendNode: { url, operator } }`.
- `set_local_sends` takes the wallet backend only, and is refused while any wallet is open, as
  `set_tor_use` is.
- A public route asks tor_module for its port as a Tor route does: Logos' Tor starts for it.

An older wallet core ignores `send` and sends through your node.

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
