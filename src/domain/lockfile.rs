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
    Pnpm,
    Yarn,
    Bun,
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
            Ecosystem::Pnpm => "pnpm-lock.yaml",
            Ecosystem::Yarn => "yarn.lock",
            Ecosystem::Bun => "bun.lock",
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
            Ecosystem::Pnpm => pnpm(&serde_yaml_ng::from_slice(&bytes).ok()?)?,
            Ecosystem::Yarn => yarn(std::str::from_utf8(&bytes).ok()?)?,
            Ecosystem::Bun => bun(&json5::from_str(std::str::from_utf8(&bytes).ok()?).ok()?)?,
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

fn pnpm(lock: &serde_yaml_ng::Value) -> Option<BTreeSet<Entry>> {
    if lock["lockfileVersion"].as_str() != Some("9.0") {
        return None;
    }
    let Some(packages) = lock["packages"].as_mapping() else {
        return Some(BTreeSet::new());
    };
    Some(
        packages
            .iter()
            .filter_map(|(locator, value)| {
                let (name, version) = locator.as_str()?.rsplit_once('@')?;
                safe(version, 80).then(|| Entry {
                    name: name.into(),
                    version: version.into(),
                    integrity: value["resolution"]["integrity"].as_str().map(str::to_owned),
                })
            })
            .collect(),
    )
}

fn yarn(text: &str) -> Option<BTreeSet<Entry>> {
    if text.lines().any(|line| line == "__metadata:") {
        let lock: serde_yaml_ng::Value = serde_yaml_ng::from_str(text).ok()?;
        return Some(
            lock.as_mapping()?
                .values()
                .filter_map(|value| {
                    let locator = value["resolution"].as_str()?;
                    let (name, reference) = locator.trim_start_matches('@').split_once('@')?;
                    if reference.starts_with("workspace:") {
                        return None;
                    }
                    let name = if locator.starts_with('@') {
                        format!("@{name}")
                    } else {
                        name.into()
                    };
                    Some(Entry {
                        name,
                        version: value["version"].as_str()?.into(),
                        integrity: value["checksum"].as_str().map(str::to_owned),
                    })
                })
                .collect(),
        );
    }
    if !text.lines().any(|line| line == "# yarn lockfile v1") {
        return None;
    }
    let mut entries = BTreeSet::new();
    let mut current: Option<Entry> = None;
    for line in text.lines().chain(["# end"]) {
        if !line.is_empty() && !line.starts_with(' ') {
            if let Some(entry) = current.take().filter(|e| !e.version.is_empty()) {
                entries.insert(entry);
            }
            let name = line
                .trim_start_matches('"')
                .trim_start_matches('@')
                .split_once('@')
                .map(|(name, _)| name);
            if let Some(name) = name.filter(|_| !line.starts_with('#')) {
                current = Some(Entry {
                    name: if line.trim_start_matches('"').starts_with('@') {
                        format!("@{name}")
                    } else {
                        name.into()
                    },
                    version: String::new(),
                    integrity: None,
                });
            }
        } else if let Some(entry) = &mut current {
            if let Some(version) = line.strip_prefix("  version ") {
                entry.version = version.trim_matches('"').into();
            } else if let Some(integrity) = line.strip_prefix("  integrity ") {
                entry.integrity = Some(integrity.into());
            }
        }
    }
    Some(entries)
}

fn bun(lock: &serde_json::Value) -> Option<BTreeSet<Entry>> {
    if !matches!(lock["lockfileVersion"].as_u64(), Some(1 | 2)) {
        return None;
    }
    Some(
        lock["packages"]
            .as_object()?
            .values()
            .filter_map(|value| {
                let fields = value.as_array()?;
                let (name, version) = fields.first()?.as_str()?.rsplit_once('@')?;
                safe(version, 80).then(|| Entry {
                    name: name.into(),
                    version: version.into(),
                    integrity: fields
                        .last()
                        .and_then(|v| v.as_str())
                        .filter(|s| s.starts_with("sha"))
                        .map(str::to_owned),
                })
            })
            .collect(),
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_registry_lockfile_entries() {
        let pnpm = serde_yaml_ng::from_str(
            "lockfileVersion: '9.0'\npackages:\n  '@scope/pkg@1.2.3':\n    resolution: { integrity: sha512-test }\n",
        )
        .unwrap();
        let berry = "__metadata:\n  version: 8\n\"@scope/pkg@npm:^1\":\n  version: 1.2.3\n  resolution: \"@scope/pkg@npm:1.2.3\"\n  checksum: sha512-test\n";
        let classic = "# yarn lockfile v1\n\"@scope/pkg@^1\":\n  version \"1.2.3\"\n  integrity sha512-test\n";
        let bun = json5::from_str(
            r#"{lockfileVersion:2,packages:{"@scope/pkg":["@scope/pkg@1.2.3","",{},"sha512-test"],},}"#,
        )
        .unwrap();
        let expected = BTreeSet::from([Entry {
            name: "@scope/pkg".into(),
            version: "1.2.3".into(),
            integrity: Some("sha512-test".into()),
        }]);
        for parsed in [
            self::pnpm(&pnpm),
            yarn(berry),
            yarn(classic),
            self::bun(&bun),
        ] {
            assert_eq!(parsed.unwrap(), expected);
        }
    }

    #[test]
    fn validates_npm_and_pnpm_lock_evidence_boundaries() {
        let npm_v2 = serde_json::json!({
            "lockfileVersion": 2,
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/linked": {"link": true, "version": "1.0.0"},
                "node_modules/demo": {"version": "1.0.0", "integrity": "sha512-v1"}
            }
        });
        let npm_v3_updated = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/demo": {"version": "1.0.1", "integrity": "sha512-v2"}
            }
        });
        let npm_v3_tampered = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/demo": {"version": "1.0.0", "integrity": "sha512-tampered"}
            }
        });
        let npm_v3_missing = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {"": {"name": "app", "version": "1.0.0"}}
        });
        let npm_v3_multi = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/demo": {"version": "1.0.0", "integrity": "sha512-v1"},
                "node_modules/other/node_modules/demo": {"version": "2.0.0", "integrity": "sha512-v2"}
            }
        });
        let npm_v1_invalid = serde_json::json!({"lockfileVersion": 1, "dependencies": {}});

        let base = Summary {
            ecosystem: Ecosystem::Npm,
            packages: npm(&npm_v2).unwrap(),
        };
        assert_eq!(base.packages.len(), 1);
        assert!(npm(&npm_v1_invalid).is_none());

        let pkg_v2 = Package {
            name: "demo".into(),
            version: "1.0.1".into(),
            script: "postinstall".into(),
            path: "node_modules/demo".into(),
        };
        let pkg_v1 = Package {
            version: "1.0.0".into(),
            ..pkg_v2.clone()
        };

        // 1. Normal version update
        let updated = Summary {
            ecosystem: Ecosystem::Npm,
            packages: npm(&npm_v3_updated).unwrap(),
        };
        let diff_upd = base.compare(&updated).unwrap();
        let ev_upd = diff_upd.label(Some(&pkg_v2), &updated).unwrap();
        assert_eq!(ev_upd.status, "corroborated");
        assert!(ev_upd.label.contains("1.0.0→1.0.1"), "{}", ev_upd.label);

        // 2. Same version, changed integrity digest
        let tampered = Summary {
            ecosystem: Ecosystem::Npm,
            packages: npm(&npm_v3_tampered).unwrap(),
        };
        let diff_tamper = base.compare(&tampered).unwrap();
        let ev_tamper = diff_tamper.label(Some(&pkg_v1), &tampered).unwrap();
        assert_eq!(ev_tamper.status, "corroborated");
        assert!(ev_tamper.label.contains("1.0.0 integrity changed"), "{}", ev_tamper.label);

        // 3. Missing package in current lockfile -> None
        let missing = Summary {
            ecosystem: Ecosystem::Npm,
            packages: npm(&npm_v3_missing).unwrap(),
        };
        let diff_missing = base.compare(&missing).unwrap();
        assert!(diff_missing.label(Some(&pkg_v1), &missing).is_none());

        // 4. Multiple versions of the same package (e.g. demo@1.0.0 and demo@2.0.0) -> None (ambiguous)
        let multi = Summary {
            ecosystem: Ecosystem::Npm,
            packages: npm(&npm_v3_multi).unwrap(),
        };
        assert_eq!(multi.packages.len(), 2);
        let diff_multi = base.compare(&multi).unwrap();
        assert!(diff_multi.label(Some(&pkg_v1), &multi).is_some());
        let multi_same_ver_diff_integrity = Summary {
            ecosystem: Ecosystem::Npm,
            packages: BTreeSet::from([
                Entry {
                    name: "demo".into(),
                    version: "1.0.0".into(),
                    integrity: Some("sha512-a".into()),
                },
                Entry {
                    name: "demo".into(),
                    version: "1.0.0".into(),
                    integrity: Some("sha512-b".into()),
                },
            ]),
        };
        let diff_ambig = base.compare(&multi_same_ver_diff_integrity).unwrap();
        assert!(diff_ambig.label(Some(&pkg_v1), &multi_same_ver_diff_integrity).is_none());

        // 5. pnpm v9 boundaries (valid vs unsupported v6)
        let pnpm_v9 = serde_yaml_ng::from_str(
            "lockfileVersion: '9.0'\npackages:\n  'demo@1.0.0':\n    resolution: { integrity: sha512-v1 }\n  'demo@2.0.0':\n    resolution: { integrity: sha512-v2 }\n",
        )
        .unwrap();
        let pnpm_v6 = serde_yaml_ng::from_str("lockfileVersion: '6.0'\npackages: {}\n").unwrap();
        assert_eq!(self::pnpm(&pnpm_v9).unwrap().len(), 2);
        assert!(self::pnpm(&pnpm_v6).is_none());
    }

    #[test]
    fn validates_yarn_bun_and_cargo_lock_evidence_boundaries() {
        let pkg_v1 = Package {
            name: "demo".into(),
            version: "1.0.0".into(),
            script: "postinstall".into(),
            path: "node_modules/demo".into(),
        };
        let pkg_v2 = Package {
            version: "1.0.1".into(),
            ..pkg_v1.clone()
        };

        // Yarn Berry (checksum change & workspace exclusion)
        let berry_base = Summary {
            ecosystem: Ecosystem::Yarn,
            packages: yarn(
                "__metadata:\n  version: 8\n\"app@workspace:.\":\n  version: 0.0.0-use.local\n  resolution: \"app@workspace:.\"\n\"demo@npm:^1\":\n  version: 1.0.0\n  resolution: \"demo@npm:1.0.0\"\n  checksum: sha512-v1\n",
            )
            .unwrap(),
        };
        assert_eq!(berry_base.packages.len(), 1);
        let berry_tampered = Summary {
            ecosystem: Ecosystem::Yarn,
            packages: yarn(
                "__metadata:\n  version: 8\n\"demo@npm:^1\":\n  version: 1.0.0\n  resolution: \"demo@npm:1.0.0\"\n  checksum: sha512-evil\n",
            )
            .unwrap(),
        };
        let berry_diff = berry_base.compare(&berry_tampered).unwrap();
        let berry_ev = berry_diff.label(Some(&pkg_v1), &berry_tampered).unwrap();
        assert!(berry_ev.label.contains("1.0.0 integrity changed"));

        // Yarn Classic (v1 format vs invalid header)
        let classic_base = Summary {
            ecosystem: Ecosystem::Yarn,
            packages: yarn(
                "# yarn lockfile v1\n\ndemo@^1.0.0:\n  version \"1.0.0\"\n  integrity sha512-v1\n",
            )
            .unwrap(),
        };
        let classic_upd = Summary {
            ecosystem: Ecosystem::Yarn,
            packages: yarn(
                "# yarn lockfile v1\n\ndemo@^1.0.0:\n  version \"1.0.1\"\n  integrity sha512-v2\n",
            )
            .unwrap(),
        };
        let classic_ev = classic_base
            .compare(&classic_upd)
            .unwrap()
            .label(Some(&pkg_v2), &classic_upd)
            .unwrap();
        assert!(classic_ev.label.contains("1.0.0→1.0.1"));
        assert!(yarn("not a yarn lockfile\n").is_none());

        // Bun (v1/v2 vs unsupported binary/v0)
        let bun_v1 = json5::from_str(
            r#"{lockfileVersion:1,packages:{"demo":["demo@1.0.0","",{},"sha512-v1"],},}"#,
        )
        .unwrap();
        let bun_v2_tampered = json5::from_str(
            r#"{lockfileVersion:2,packages:{"demo":["demo@1.0.0","",{},"sha512-tampered"],},}"#,
        )
        .unwrap();
        let bun_v0 = json5::from_str(r#"{lockfileVersion:0,packages:{}}"#).unwrap();
        assert!(self::bun(&bun_v0).is_none());
        let bun_base = Summary {
            ecosystem: Ecosystem::Bun,
            packages: self::bun(&bun_v1).unwrap(),
        };
        let bun_curr = Summary {
            ecosystem: Ecosystem::Bun,
            packages: self::bun(&bun_v2_tampered).unwrap(),
        };
        assert!(
            bun_base
                .compare(&bun_curr)
                .unwrap()
                .label(Some(&pkg_v1), &bun_curr)
                .unwrap()
                .label
                .contains("1.0.0 integrity changed")
        );

        // Cargo (v3/v4, multiple versions, checksum change, unsupported v2)
        let cargo_v3 = cargo(
            "version = 3\n[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\nchecksum = \"abc\"\n",
        )
        .unwrap();
        let cargo_v4_multi = cargo(
            "version = 4\n[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\nchecksum = \"abc\"\n[[package]]\nname = \"demo\"\nversion = \"2.0.0\"\nchecksum = \"def\"\n",
        )
        .unwrap();
        let cargo_v4_tampered = cargo(
            "version = 4\n[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\nchecksum = \"evil\"\n",
        )
        .unwrap();
        assert!(cargo("version = 2\n").is_none());

        let cargo_base = Summary {
            ecosystem: Ecosystem::Cargo,
            packages: cargo_v3,
        };
        let cargo_multi = Summary {
            ecosystem: Ecosystem::Cargo,
            packages: cargo_v4_multi,
        };
        let cargo_tampered = Summary {
            ecosystem: Ecosystem::Cargo,
            packages: cargo_v4_tampered,
        };
        let cargo_pkg = Package {
            name: "demo".into(),
            version: "1.0.0".into(),
            script: "build.rs".into(),
            path: "demo".into(),
        };
        assert!(
            cargo_base
                .compare(&cargo_tampered)
                .unwrap()
                .label(Some(&cargo_pkg), &cargo_tampered)
                .unwrap()
                .label
                .contains("1.0.0 integrity changed")
        );
        assert_eq!(cargo_multi.packages.len(), 2);
    }
}
