//! Who may change "Use Tor for" (the wallet backend) and report open wallets (the wallet
//! core). Everything else stays open. callers.json in the instance directory widens it.

use serde::Deserialize;

pub const BACKEND: &str = "monero_wallet_backend";
pub const CORE: &str = "monero_wallet_core_module";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Backend,
    Core,
}

/// The caller as the host reported it, mirrored so this file needs no SDK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    Unknown,
    Host,
    Module(String),
}

/// Callers admitted beyond the defaults, for tests: `{"modules": [...], "allowHost": true}`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Callers {
    #[serde(default)]
    pub modules: Vec<String>,
    #[serde(default)]
    pub allow_host: bool,
}

impl Callers {
    /// Absent or unreadable file: the defaults only, so a typo never opens the door.
    pub fn from_file(contents: Option<&str>) -> Self {
        contents.and_then(|t| serde_json::from_str(t).ok()).unwrap_or_default()
    }

    pub fn admits(&self, access: Access, caller: &Caller) -> bool {
        match caller {
            Caller::Module(name) if !name.is_empty() => {
                let named = match access {
                    Access::Backend => name == BACKEND,
                    Access::Core => name == CORE,
                };
                named || self.modules.iter().any(|m| m == name)
            }
            Caller::Host => self.allow_host,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(name: &str) -> Caller {
        Caller::Module(name.into())
    }

    #[test]
    fn only_the_backend_sets_tor_use_and_only_the_core_reports_wallets() {
        let c = Callers::default();
        assert!(c.admits(Access::Backend, &m(BACKEND)) && !c.admits(Access::Backend, &m(CORE)));
        assert!(c.admits(Access::Core, &m(CORE)) && !c.admits(Access::Core, &m(BACKEND)));
        for who in [m("monero_wallet_ui"), m(""), Caller::Host, Caller::Unknown] {
            assert!(!c.admits(Access::Backend, &who) && !c.admits(Access::Core, &who), "{who:?}");
        }
        let wide = Callers::from_file(Some(r#"{"modules":["t"],"allowHost":true}"#));
        assert!(wide.admits(Access::Backend, &m("t")) && wide.admits(Access::Core, &Caller::Host));
        assert_eq!(Callers::from_file(Some(r#"{"allowhost":true}"#)), Callers::default());
    }
}
