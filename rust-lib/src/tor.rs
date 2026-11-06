//! "Use Tor for": the setting, its store beside the node registry, the built-in Tor's status,
//! and how an address is classed (onion, own network, or anywhere else).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The value proxy takes for the Tor that comes with Logos (tor_module's SOCKS port).
pub const BUILT_IN: &str = "tor";

/// What goes over Tor. The same three values in every Logos wallet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TorUse {
    /// Every connection goes through Tor.
    All,
    /// Catch up directly, then everything over Tor: refresh, decoys, sends.
    #[default]
    Identifying,
    /// Everything is direct; onion services are off and Tor is never started.
    None,
}

impl TorUse {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "all" => Some(Self::All),
            "identifying" => Some(Self::Identifying),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Identifying => "identifying",
            Self::None => "none",
        }
    }
}

/// One network's "Use Tor for".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TorSettings {
    #[serde(rename = "torUse")]
    pub tor_use: TorUse,
    /// The user picked it, on the first-run screen or in Settings.
    #[serde(rename = "torUseChosen", default)]
    pub chosen: bool,
    /// The value was carried over from an install that predates the setting.
    #[serde(default)]
    pub existing: bool,
}

impl TorSettings {
    pub fn fresh() -> Self {
        Self { tor_use: TorUse::Identifying, chosen: false, existing: false }
    }

    /// Today's routing, nearest mode: a saved proxy is `all` (with that proxy as the user's own
    /// Tor), none is `none`. Never weaker than before, and still to be confirmed by the user.
    pub fn migrated(any_proxy: bool) -> Self {
        Self { tor_use: if any_proxy { TorUse::All } else { TorUse::None }, chosen: false, existing: true }
    }

    /// An earlier build's one setting for every network: each network keeps its routing, to be
    /// confirmed there.
    pub fn carried(&self) -> Self {
        Self { tor_use: self.tor_use, chosen: false, existing: true }
    }

    pub fn path_beside(registry: &Path) -> PathBuf {
        registry.with_file_name("monero_tor.json")
    }

    pub fn json(&self) -> Value {
        json!({ "torUse": self.tor_use, "torUseChosen": self.chosen, "existing": self.existing })
    }
}

/// `monero_tor.json`: each network's setting. A separate file, so an older build keeps reading
/// the registry as it was.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TorFile {
    pub networks: BTreeMap<String, TorSettings>,
}

/// What `monero_tor.json` held.
#[derive(Debug, PartialEq, Eq)]
pub enum TorLoaded {
    PerNetwork(TorFile),
    /// Written by a build that kept one setting for every network.
    Shared(TorSettings),
}

impl TorFile {
    pub fn load(path: &Path) -> Option<TorLoaded> {
        let text = std::fs::read_to_string(path).ok()?;
        if let Ok(f) = serde_json::from_str::<TorFile>(&text) {
            return Some(TorLoaded::PerNetwork(f));
        }
        serde_json::from_str::<TorSettings>(&text).ok().map(TorLoaded::Shared)
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(self).unwrap_or_default())?;
        std::fs::rename(&tmp, path)
    }
}

/// The built-in Tor as tor_module last reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorView {
    /// connecting, ready, blocked or failed.
    pub state: String,
    pub progress: u8,
    /// Why it is blocked or failed; empty otherwise.
    pub detail: String,
    /// Its SOCKS port, `socks5h://IP:PORT`; none while the user has it off.
    pub socks: Option<String>,
    /// tor_module answered; false when it is not loaded or did not answer.
    pub answered: bool,
}

impl TorView {
    /// tor_module's status() reply, or why there was none.
    pub fn from_reply(reply: Result<String, String>) -> Self {
        let failed = |detail: String| Self { state: "failed".into(), progress: 0, detail, socks: None, answered: false };
        let v: Value = match reply.and_then(|t| serde_json::from_str(&t).map_err(|e| format!("tor_module: {e}"))) {
            Ok(v) => v,
            Err(e) => return failed(e),
        };
        match v["error"].as_str() {
            _ if v["ok"] == true => {}
            Some("starting") => return Self { state: "connecting".into(), progress: 0, detail: String::new(), socks: None, answered: false },
            e => return failed(e.unwrap_or("tor_module answered without ok").into()),
        }
        // Asking starts an idle Tor, so idle is only ever a moment's answer.
        let state = match v["state"].as_str() {
            None | Some("idle") => "connecting".to_string(),
            Some(s) => s.to_string(),
        };
        let detail = match state.as_str() {
            "blocked" | "failed" => v["detail"].as_str().unwrap_or("").to_string(),
            _ => String::new(),
        };
        let progress = v["progress"].as_u64().unwrap_or(0).min(100) as u8;
        let socks = v["socks"].as_str().filter(|s| s.starts_with("socks5h://")).map(str::to_string);
        Self { state, progress, detail, socks, answered: true }
    }

    /// The port to dial, once Tor can carry traffic.
    pub fn usable_socks(&self) -> Option<&str> {
        if self.state == "ready" { self.socks.as_deref() } else { None }
    }

    pub fn json(&self) -> Value {
        json!({ "state": self.state, "progress": self.progress, "detail": self.detail,
                "socks": self.socks, "answered": self.answered })
    }
}

/// Normalises a stored proxy to `tor` or `socks5h://host:port`; empty is the built-in Tor.
/// `socks5://` reads as socks5h: names are never resolved here.
pub fn normalize_proxy(p: Option<&str>) -> Result<String, String> {
    let s = p.unwrap_or("").trim().to_ascii_lowercase();
    if s.is_empty() || s == BUILT_IN {
        return Ok(BUILT_IN.into());
    }
    let rest = s.strip_prefix("socks5h://").or_else(|| s.strip_prefix("socks5://"))
        .ok_or("your own Tor must be socks5h://host:port")?;
    let rest = rest.trim_end_matches('/');
    if rest.is_empty() || rest.contains(['@', '/', '?', '#']) || !rest.rsplit_once(':').is_some_and(|(h, p)| !h.is_empty() && p.parse::<u16>().is_ok_and(|p| p > 0)) {
        return Err("your own Tor must be socks5h://host:port".into());
    }
    Ok(format!("socks5h://{rest}"))
}

/// The host of `http(s)://host:port/...`, lowercased, without IPv6 brackets.
pub fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map(|(_, a)| a).unwrap_or(authority);
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        authority.rsplit_once(':').map(|(h, _)| h).unwrap_or(authority)
    };
    host.to_ascii_lowercase()
}

pub fn is_onion(url: &str) -> bool {
    host_of(url).ends_with(".onion")
}

/// This computer or its network: direct in every mode, as Tor could not reach it anyway.
pub fn is_own_network(url: &str) -> bool {
    let host = host_of(url);
    if host == "localhost" || host.ends_with(".localhost") || host.ends_with(".local") || host.ends_with(".lan")
        || host.ends_with(".home.arpa")
    {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified(),
        Ok(IpAddr::V6(ip)) => {
            let s = ip.segments()[0];
            ip.is_loopback() || ip.is_unspecified() || (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80
                || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback() || v4.is_private())
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_classed_by_host() {
        assert!(is_onion("http://abc.onion:18089"));
        assert!(!is_onion("https://node.monerodevs.org:18089"));
        for own in ["http://127.0.0.1:18081", "http://localhost:18081", "http://192.168.1.4:18089", "http://10.0.0.2:18089",
                    "http://[::1]:18081", "http://node.lan:18089", "http://[fd00::4]:18081", "http://169.254.3.3:1"] {
            assert!(is_own_network(own), "{own}");
        }
        for far in ["https://node.monerodevs.org:18089", "http://8.8.8.8:18089", "http://abc.onion:18089", "http://[2001:db8::1]:1"] {
            assert!(!is_own_network(far), "{far}");
        }
        assert_eq!(host_of("http://user:pw@Node.Example:1/x"), "node.example");
    }

    #[test]
    fn a_proxy_is_the_built_in_tor_or_your_own_socks5h() {
        assert_eq!(normalize_proxy(None).unwrap(), BUILT_IN);
        assert_eq!(normalize_proxy(Some(" TOR ")).unwrap(), BUILT_IN);
        assert_eq!(normalize_proxy(Some("socks5h://127.0.0.1:9050/")).unwrap(), "socks5h://127.0.0.1:9050");
        assert_eq!(normalize_proxy(Some("socks5://127.0.0.1:9050")).unwrap(), "socks5h://127.0.0.1:9050");
        for bad in ["http://127.0.0.1:8118", "127.0.0.1:9050", "socks5h://127.0.0.1", "socks5h://u:p@h:1", "socks5h://h:0"] {
            assert!(normalize_proxy(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn tor_modules_status_reply() {
        let ok = |s: &str| TorView::from_reply(Ok(s.into()));
        let ready = ok(r#"{"ok":true,"state":"ready","progress":100,"socks":"socks5h://127.0.0.1:9250"}"#);
        assert_eq!(ready.usable_socks(), Some("socks5h://127.0.0.1:9250"));
        let joining = ok(r#"{"ok":true,"state":"connecting","progress":40,"socks":"socks5h://127.0.0.1:9250"}"#);
        assert_eq!(joining.usable_socks(), None);
        assert_eq!(ok(r#"{"ok":true,"state":"idle"}"#).state, "connecting");
        assert_eq!(ok(r#"{"ok":true,"state":"ready","socks":null}"#).usable_socks(), None);
        let missing = TorView::from_reply(Err("object_unavailable".into()));
        assert!(!missing.answered && missing.state == "failed");
    }

    #[test]
    fn settings_round_trip_and_migrate() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("monero_tor.json");
        let mut file = TorFile::default();
        file.networks.insert("mainnet".into(), TorSettings::migrated(true));
        file.networks.insert("stagenet".into(), TorSettings::fresh());
        file.save(&p).unwrap();
        assert_eq!(TorFile::load(&p).unwrap(), TorLoaded::PerNetwork(file));
        assert_eq!(TorSettings::migrated(false).tor_use, TorUse::None);
        assert_eq!(TorSettings::fresh().tor_use, TorUse::Identifying);

        // An earlier build's single setting is read as shared, then carried to each network.
        std::fs::write(&p, r#"{"torUse":"none","torUseChosen":true,"existing":false}"#).unwrap();
        let Some(TorLoaded::Shared(old)) = TorFile::load(&p) else { panic!("not read as shared") };
        assert_eq!(old.carried(), TorSettings { tor_use: TorUse::None, chosen: false, existing: true });
    }
}
