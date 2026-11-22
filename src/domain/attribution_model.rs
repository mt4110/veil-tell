//! Pure domain value types for package attribution (`Attribution`, `Confidence`, `Package`).

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::PathBuf;

pub const CODEC: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Observe,
    Restrict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Proxy,
    Isolated,
}

pub struct Options {
    pub mode: Mode,
    pub backend: Backend,
    pub policy: Option<PathBuf>,
    pub report: Option<PathBuf>,
    pub emit_policy: Option<PathBuf>,
    pub fail_on_unknown: bool,
    pub command: Vec<OsString>,
    pub attribute_npm: bool,
    pub no_attribute: bool,
    pub log: bool,
    pub json: bool,
    pub shorthand: bool,
    pub shim: bool,
    pub save_baseline: bool,
    pub comparison: crate::domain::baseline::Options,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Attribution {
    pub confidence: Confidence,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub package: Option<Package>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub manager: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub phase: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Inferred,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub script: String,
    pub path: String,
}

pub type Sources = BTreeSet<Attribution>;

pub fn record(sources: &mut Sources, source: Attribution) {
    // Keep the smallest four distinct inferred labels, plus any unknown label.
    sources.insert(source);
    if sources.iter().filter(|a| a.package.is_some()).count() > 4
        && let Some(last) = sources.iter().rev().find(|a| a.package.is_some()).cloned()
    {
        sources.remove(&last);
        sources.insert(Attribution::unknown());
    }
}

impl Attribution {
    pub fn unknown() -> Self {
        Self {
            confidence: Confidence::Unknown,
            package: None,
            manager: None,
            phase: None,
        }
    }

    pub fn decode(payload: Option<&str>) -> Self {
        payload
            .filter(|s| s.len() <= 2048)
            .and_then(|s| CODEC.decode(s).ok())
            .and_then(|bytes| serde_json::from_slice::<Package>(&bytes).ok())
            .filter(Package::valid)
            .map_or_else(Self::unknown, |package| Self {
                confidence: Confidence::Inferred,
                package: Some(package),
                manager: None,
                phase: None,
            })
    }

    pub fn valid(&self) -> bool {
        if self.manager.is_some() || self.phase.is_some() {
            return self.manager.as_deref() == Some("npm")
                && self.phase.as_deref() == Some("fetch")
                && self.package.is_none()
                && self.confidence == Confidence::Inferred;
        }
        match (&self.confidence, &self.package) {
            (Confidence::Unknown, None) => true,
            (Confidence::Inferred, Some(package)) => package.valid(),
            _ => false,
        }
    }
}

fn identifier(s: &str, max: usize, punctuation: &[u8]) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || punctuation.contains(&b))
}

impl Package {
    pub fn valid(&self) -> bool {
        identifier(&self.name, 214, b"@/_.-")
            && identifier(&self.version, 80, b".-+")
            && identifier(&self.script, 64, b"_.:-")
            && self.path.len() <= 500
            && (self.path == "."
                || self
                    .path
                    .split('/')
                    .all(|s| s != "." && s != ".." && identifier(s, 255, b" @_.-+")))
    }
}
