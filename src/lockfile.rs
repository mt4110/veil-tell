use crate::attribution::Package;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const INPUT_LIMIT: u64 = 16 * 1024 * 1024;
const SUMMARY_LIMIT: usize = 128 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub ecosystem: Ecosystem,
    pub packages: BTreeSet<Entry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ecosystem {
    Npm,
    Cargo,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Changes {
    pub added: Vec<Entry>,
    pub updated: Vec<Update>,
    pub removed: Vec<Entry>,
}

#[derive(Debug, Serialize)]
pub struct Update {
    pub before: Entry,
    pub after: Entry,
}

// A damaged optional summary must not prevent destination comparison.
pub fn optional_summary<'de, D: serde::Deserializer<'de>>(
    input: D,
) -> Result<Option<Summary>, D::Error> {
    let value = serde_json::Value::deserialize(input)?;
    Ok(serde_json::from_value::<Summary>(value)
        .ok()
        .filter(Summary::usable))
}

impl Summary {
    pub fn read(root: &Path, ecosystem: Ecosystem) -> Option<Self> {
        let filename = match ecosystem {
            Ecosystem::Npm => "package-lock.json",
            Ecosystem::Cargo => "Cargo.lock",
        };
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(root.join(filename))
            .ok()?;
        if !file.metadata().ok()?.is_file() {
            return None;
        }
        let mut bytes = Vec::new();
        file.take(INPUT_LIMIT + 1).read_to_end(&mut bytes).ok()?;
        if bytes.len() as u64 > INPUT_LIMIT {
            return None;
        }
        let packages = match ecosystem {
            Ecosystem::Npm => npm(&serde_json::from_slice(&bytes).ok()?)?,
            Ecosystem::Cargo => cargo(std::str::from_utf8(&bytes).ok()?)?,
        };
        let summary = Self {
            ecosystem,
            packages,
        };
        summary.usable().then_some(summary)
    }

    pub fn usable(&self) -> bool {
        self.packages.iter().all(|e| {
            safe(&e.name, 214)
                && safe(&e.version, 80)
                && e.integrity
                    .as_ref()
                    .is_none_or(|s| s.len() <= 1024 && s.bytes().all(|b| b.is_ascii_graphic()))
        }) && serde_json::to_vec_pretty(self).is_ok_and(|s| s.len() <= SUMMARY_LIMIT)
    }

    pub fn compare(&self, current: &Self) -> Option<Changes> {
        if self.ecosystem != current.ecosystem || !self.usable() || !current.usable() {
            return None;
        }
        let mut gone: BTreeMap<&str, Vec<&Entry>> = BTreeMap::new();
        let mut new: BTreeMap<&str, Vec<&Entry>> = BTreeMap::new();
        for e in self.packages.difference(&current.packages) {
            gone.entry(&e.name).or_default().push(e);
        }
        for e in current.packages.difference(&self.packages) {
            new.entry(&e.name).or_default().push(e);
        }
        let mut changes = Changes {
            added: vec![],
            updated: vec![],
            removed: vec![],
        };
        for (name, entries) in new {
            if entries.len() == 1 && gone.get(name).is_some_and(|old| old.len() == 1) {
                changes.updated.push(Update {
                    before: gone.remove(name).unwrap()[0].clone(),
                    after: entries[0].clone(),
                });
            } else {
                changes.added.extend(entries.into_iter().cloned());
            }
        }
        changes
            .removed
            .extend(gone.into_values().flatten().cloned());
        Some(changes)
    }
}

#[derive(Serialize)]
pub struct Evidence {
    pub status: &'static str,
    pub label: String,
}

impl Evidence {
    fn new(status: &'static str, label: impl Into<String>) -> Self {
        Self {
            status,
            label: label.into(),
        }
    }
}

impl Changes {
    pub fn label(&self, package: Option<&Package>, current: &Summary) -> Option<Evidence> {
        let changed = self.updated.iter().map(|u| &u.after).chain(&self.added);
        if let Some(pkg) = package {
            let matches = |e: &Entry| e.name == pkg.name && e.version == pkg.version;
            let mut identities = current.packages.iter().filter(|e| matches(e));
            identities.next()?;
            if identities.next().is_some() {
                return None;
            }
            if let Some(update) = self.updated.iter().find(|u| matches(&u.after)) {
                let transition = if update.before.version == update.after.version {
                    format!("{} integrity changed", update.after.version)
                } else {
                    format!("{}→{}", update.before.version, update.after.version)
                };
                return Some(Evidence::new(
                    "corroborated",
                    format!("lockfile: {transition} / 裏づけあり"),
                ));
            }
            if self.added.iter().any(matches) {
                return Some(Evidence::new(
                    "corroborated",
                    "lockfile: added / 裏づけあり",
                ));
            }
            return Some(Evidence::new("unchanged", "lockfile: unchanged / 要注意"));
        }
        let candidates: Vec<_> = changed
            .chain(&self.removed)
            .map(|e| format!("{}@{}", e.name, e.version))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        (!candidates.is_empty()).then(|| {
            Evidence::new(
                "candidates",
                format!(
                    "lockfile candidates / 変更候補: {}{}",
                    candidates
                        .iter()
                        .take(8)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", "),
                    if candidates.len() > 8 { ", …" } else { "" }
                ),
            )
        })
    }
}

fn safe(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@/_.+-".contains(&b))
}

fn npm(lock: &serde_json::Value) -> Option<BTreeSet<Entry>> {
    if !matches!(lock["lockfileVersion"].as_u64(), Some(2 | 3)) {
        return None;
    }
    Some(
        lock["packages"]
            .as_object()?
            .iter()
            .filter_map(|(path, data)| {
                if path.is_empty() || data["link"].as_bool() == Some(true) {
                    return None;
                }
                let name = data["name"]
                    .as_str()
                    .or_else(|| path.rsplit_once("node_modules/").map(|(_, name)| name))?;
                Some(Entry {
                    name: name.into(),
                    version: data["version"].as_str()?.into(),
                    integrity: data["integrity"].as_str().map(str::to_owned),
                })
            })
            .collect(),
    )
}

fn cargo(text: &str) -> Option<BTreeSet<Entry>> {
    #[derive(Deserialize)]
    struct CargoLock {
        version: u8,
        package: Vec<CargoPackage>,
    }
    #[derive(Deserialize)]
    struct CargoPackage {
        name: String,
        version: String,
        checksum: Option<String>,
    }
    let lock: CargoLock = toml::from_str(text).ok()?;
    if !matches!(lock.version, 3 | 4) {
        return None;
    }
    Some(
        lock.package
            .into_iter()
            .map(|p| Entry {
                name: p.name,
                version: p.version,
                integrity: p.checksum,
            })
            .collect(),
    )
}
