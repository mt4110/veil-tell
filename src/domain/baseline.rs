use crate::domain::attribution_model::{self as attribution, Backend};
use crate::report::{Attempted, Destination};
use crate::{Result, error};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[path = "baseline_store.rs"]
mod store;
pub use store::{Session, accept, clean, migrate};

pub const NEW_DESTINATION: u8 = 21;
pub(super) const MAX_BYTES: u64 = 1024 * 1024;
pub(super) const MAX_PENDING_BYTES: u64 = 3 * MAX_BYTES;
const CAPTURE: &str = "http_connect_requests";

#[derive(Default)]
pub struct Options {
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub fail_on_new: bool,
    pub automatic: bool,
    pub ci: bool,
    pub no_attribute: bool,
}

impl Options {
    pub fn writes_pending(&self) -> bool {
        self.automatic || (self.ci && self.input.is_none())
    }

    pub fn requested(&self) -> bool {
        self.input.is_some()
            || self.output.is_some()
            || self.fail_on_new
            || self.automatic
            || self.ci
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    host: String,
    port: u16,
    attempts: u64,
    #[serde(default, skip_serializing_if = "attribution::Sources::is_empty")]
    attribution: attribution::Sources,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct Baseline {
    schema_version: u8,
    coverage: String,
    backend: Backend,
    #[serde(
        default,
        deserialize_with = "crate::lockfile::optional_summary",
        skip_serializing_if = "Option::is_none"
    )]
    lockfile: Option<crate::lockfile::Summary>,
    destinations: Vec<Endpoint>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    attempted: Vec<Attempted>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    volume: BTreeMap<String, crate::volume::Sample>,
}

impl Baseline {
    fn capture(backend: Backend, events: &[Destination]) -> Self {
        let mut volume = BTreeMap::<String, crate::volume::Sample>::new();
        let mut counts = BTreeMap::<_, Endpoint>::new();
        for event in events {
            if event.tunnel_established {
                volume.entry(event.host.clone()).or_default().record(event);
            }
            let endpoint = counts
                .entry((event.host.clone(), event.port))
                .or_insert_with(|| Endpoint {
                    host: event.host.clone(),
                    port: event.port,
                    attempts: 0,
                    attribution: Default::default(),
                });
            endpoint.attempts = endpoint.attempts.saturating_add(event.attempts);
            for source in &event.attribution {
                attribution::record(
                    &mut endpoint.attribution,
                    if source.manager.is_some() {
                        attribution::Attribution::unknown()
                    } else {
                        source.clone()
                    },
                );
            }
        }
        Self {
            schema_version: 1,
            coverage: CAPTURE.into(),
            backend,
            lockfile: None,
            destinations: counts.into_values().collect(),
            attempted: Vec::new(),
            volume,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != 1 || self.coverage != CAPTURE {
            return Err(error(
                "unsupported baseline version or coverage; create a fresh baseline with --baseline-out",
            ));
        }
        let key = |e: &Endpoint| (e.host.clone(), e.port);
        if self.destinations.iter().any(|e| {
            e.port != 443
                || e.attempts == 0
                || e.attribution.len() > 5
                || e.attribution.iter().any(|source| !source.valid())
                || crate::policy::normalize_host(&e.host).as_deref() != Some(&e.host)
        }) || self
            .destinations
            .windows(2)
            .any(|pair| key(&pair[0]) >= key(&pair[1]))
        {
            return Err(error(
                "invalid baseline destinations; use sorted unique canonical hosts on port 443 with positive counts",
            ));
        }
        if self.volume.iter().any(|(host, sample)| {
            self.destinations
                .binary_search_by(|entry| entry.host.cmp(host))
                .is_err()
                || sample.max_connection_bytes > sample.sent_bytes
                || sample.connections == 0
        }) {
            return Err(error("invalid baseline volume sample"));
        }
        if self.attempted.len() > 1024
            || self
                .attempted
                .windows(2)
                .any(|pair| pair[0].host >= pair[1].host)
            || self.attempted.iter().any(|entry| {
                entry.attempts == 0
                    || entry.attribution.len() > 5
                    || entry.attribution.iter().any(|source| !source.valid())
                    || crate::policy::normalize_host(&entry.host).as_deref() != Some(&entry.host)
            })
        {
            return Err(error(
                "invalid baseline DNS attempts; use sorted unique canonical hosts",
            ));
        }
        Ok(())
    }

    fn compare(&self, current: &Self) -> Comparison {
        let index: BTreeMap<_, _> = self
            .destinations
            .iter()
            .map(|e| ((e.host.as_str(), e.port), e.attempts))
            .collect();
        let current_index: BTreeMap<_, _> = current
            .destinations
            .iter()
            .map(|e| ((e.host.as_str(), e.port), e.attempts))
            .collect();
        let mut diff = Comparison::new("compared");
        diff.attempted_added.extend(
            current
                .attempted
                .iter()
                .filter(|entry| {
                    self.attempted
                        .binary_search_by(|old| old.host.cmp(&entry.host))
                        .is_err()
                })
                .cloned(),
        );
        diff.backend_changed = self.backend != current.backend;
        for e in &current.destinations {
            match index.get(&(e.host.as_str(), e.port)) {
                None => diff.added.push(e.clone()),
                Some(&before)
                    if before.abs_diff(e.attempts) >= 3
                        && before.max(e.attempts) / before.min(e.attempts) >= 2 =>
                {
                    diff.count_changes.push(CountChange {
                        host: e.host.clone(),
                        port: e.port,
                        before,
                        after: e.attempts,
                    });
                }
                _ => {}
            }
        }
        if let Some((changes, summary)) = self
            .lockfile
            .as_ref()
            .zip(current.lockfile.as_ref())
            .and_then(|(old, new)| Some((old.compare(new)?, new)))
        {
            let destinations = diff
                .added
                .iter()
                .map(|e| (&e.host, Some(e.port), &e.attribution));
            let attempts = diff
                .attempted_added
                .iter()
                .map(|e| (&e.host, None, &e.attribution));
            for (host, port, attribution) in destinations.chain(attempts) {
                let unknown = attribution::Attribution::unknown();
                let sources = attribution
                    .iter()
                    .chain(attribution.is_empty().then_some(&unknown));
                for source in sources {
                    if let Some(evidence) = changes.label(source.package.as_ref(), summary) {
                        diff.lockfile_evidence.push(LockEvidence {
                            host: host.clone(),
                            port,
                            source: source.clone(),
                            evidence,
                        });
                    }
                }
            }
            diff.lockfile_changes = Some(changes);
        }
        diff.removed.extend(
            self.destinations
                .iter()
                .filter(|e| !current_index.contains_key(&(e.host.as_str(), e.port)))
                .cloned(),
        );
        diff
    }
}

#[derive(Serialize)]
struct CountChange {
    host: String,
    port: u16,
    before: u64,
    after: u64,
}

#[derive(Serialize)]
struct LockEvidence {
    host: String,
    port: Option<u16>,
    source: attribution::Attribution,
    #[serde(flatten)]
    evidence: crate::lockfile::Evidence,
}

#[derive(Serialize)]
pub struct Comparison {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    lockfile_changes: Option<crate::lockfile::Changes>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    lockfile_evidence: Vec<LockEvidence>,
    backend_changed: bool,
    added: Vec<Endpoint>,
    removed: Vec<Endpoint>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    attempted_added: Vec<Attempted>,
    count_changes: Vec<CountChange>,
}

impl Comparison {
    fn new(status: &'static str) -> Self {
        Self {
            status,
            lockfile_changes: None,
            lockfile_evidence: vec![],
            backend_changed: false,
            added: vec![],
            removed: vec![],
            attempted_added: vec![],
            count_changes: vec![],
        }
    }

    pub fn skipped() -> Self {
        Self::new("skipped")
    }
    pub fn retain_additions(&mut self) {
        self.status = "new_destinations_only";
        self.removed.clear();
        self.count_changes.clear();
    }

    pub fn created(&self) -> bool {
        self.status == "created"
    }

    pub fn lock_evidence(
        &self,
        host: &str,
        port: u16,
        source: &attribution::Attribution,
    ) -> Option<&str> {
        self.lockfile_evidence
            .iter()
            .find(|e| e.host == host && e.port == Some(port) && &e.source == source)
            .map(|e| e.evidence.label.as_str())
    }

    pub fn added_host(&self, host: &str, dns: bool) -> bool {
        if dns {
            self.attempted_added.iter().any(|d| d.host == host)
        } else {
            self.added.iter().any(|d| d.host == host)
        }
    }

    pub fn has_new(&self) -> bool {
        !self.added.is_empty() || !self.attempted_added.is_empty()
    }

    pub fn display(&self, automatic: bool, volume_anomaly: bool, failure_hint: Option<&str>) {
        let message = match self.status {
            "new_destinations_only" => {
                "New destinations before command failure / コマンド失敗までに観測した新規宛先"
            }
            "created" => "Baseline saved / 基準を保存しました",
            "skipped" => "Comparison skipped / 比較を見送りました",
            _ if volume_anomaly => "Volume anomaly / 送信量の異常",
            _ if !self.has_new() => "No new destinations / 新しい送り先はありません",
            _ => "Destination changes / 宛先の変化",
        };
        eprintln!("veil-tell: {message}");
        if self.backend_changed {
            eprintln!(
                "veil-tell: backend changed; compare under matching conditions / 実行方式が変わりました。同じ条件で確認してください"
            );
        }
        for e in &self.added {
            eprintln!("  + {}:{} ({})", e.host, e.port, e.attempts);
            let unknown = attribution::Attribution::unknown();
            for source in e.attribution.iter().chain(
                (e.attribution.is_empty()
                    && self
                        .lockfile_evidence
                        .iter()
                        .any(|x| x.host == e.host && x.port == Some(e.port)))
                .then_some(&unknown),
            ) {
                let suffix = self
                    .lockfile_evidence
                    .iter()
                    .find(|x| x.host == e.host && x.port == Some(e.port) && x.source == *source)
                    .map(|x| format!(", {}", x.evidence.label))
                    .unwrap_or_default();
                if let Some(pkg) = &source.package {
                    eprintln!(
                        "    {}:{} ← {}@{} {} ({}) [inferred / 推定{suffix}]",
                        e.host, e.port, pkg.name, pkg.version, pkg.script, pkg.path
                    );
                } else {
                    eprintln!(
                        "    {}:{} ← unknown / 特定できません{suffix}",
                        e.host, e.port
                    );
                }
            }
        }
        for e in &self.attempted_added {
            eprintln!("  + attempted (blocked) / 名前解決の試み: {}", e.host);
            for evidence in self
                .lockfile_evidence
                .iter()
                .filter(|row| row.port.is_none() && row.host == e.host)
            {
                eprintln!("    {}", evidence.evidence.label);
            }
        }
        for e in &self.removed {
            eprintln!(
                "  not observed this run / 今回は未観測: {}:{}",
                e.host, e.port
            );
        }
        let next = if let Some(hint) = failure_hint {
            hint
        } else if self.created() && automatic {
            "commit the baseline: git add .veil-tell / 基準をコミット: git add .veil-tell"
        } else if automatic && self.has_new() {
            "review, then veil-tell accept / 調査後、承認するなら veil-tell accept"
        } else if volume_anomaly {
            "review volume_anomalies / レポートの送信量と上限を確認"
        } else if self.status == "skipped" {
            "fix the run and repeat the command / 実行を直して同じコマンドを再実行"
        } else if self.has_new() {
            "review the new destinations; to prepare a project approval, repeat locally against the project baseline / 新規宛先を調査し、承認候補を作る場合はプロジェクトの基準を使ってローカルで再実行"
        } else {
            "repeat the same check after the next dependency update / 次の依存更新後に同じチェックを実行"
        };
        eprintln!("Next / 次: {next}");
    }
}

#[cfg(test)]
mod tests {
    use super::store::{baseline, command_key, write_json};
    use super::*;
    use crate::report::OutputFile;
    use std::fs;

    fn event(host: &str, attempts: u64) -> Destination {
        Destination {
            host: host.into(),
            port: 443,
            decision: "allow",
            reason: "observe",
            result: "completed",
            resolver_hint: None,
            via_upstream_proxy: false,
            connected_ip: Some("192.0.2.1".parse().unwrap()),
            tunnel_established: true,
            attempts,
            sent_bytes: 0,
            max_connection_bytes: 0,
            received_bytes: 0,
            attribution: Default::default(),
        }
    }

    #[test]
    fn stable_round_trip_and_counts() {
        let first = Baseline::capture(
            Backend::Proxy,
            &[event("z.test", 2), event("a.test", 1), event("z.test", 3)],
        );
        let second = Baseline::capture(Backend::Proxy, &[event("a.test", 1), event("z.test", 5)]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        OutputFile::prepare(&path, "baseline")
            .unwrap()
            .save(|file| write_json(file, &first, MAX_BYTES))
            .unwrap();
        assert_eq!(baseline(&path).unwrap(), second);
        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&second).unwrap()
        );
        assert!(OutputFile::prepare(&path, "baseline").is_err());
    }

    #[test]
    fn differences_and_frequency_threshold() {
        let before = Baseline::capture(
            Backend::Proxy,
            &[
                event("a.test", 2),
                event("old.test", 1),
                event("same.test", 1),
            ],
        );
        let after = Baseline::capture(
            Backend::Isolated,
            &[
                event("a.test", 5),
                event("new.test", 1),
                event("same.test", 2),
            ],
        );
        let diff = before.compare(&after);
        assert!(diff.backend_changed && diff.has_new());
        assert_eq!(diff.added[0].host, "new.test");
        assert_eq!(diff.removed[0].host, "old.test");
        assert_eq!(diff.count_changes.len(), 1);
        assert_eq!(
            (diff.count_changes[0].before, diff.count_changes[0].after),
            (2, 5)
        );
        assert!(!before.compare(&before).has_new());
    }

    #[test]
    fn rejects_invalid_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        for contents in [
            "{",
            r#"{"schema_version":2,"coverage":"http_connect_requests","backend":"proxy","destinations":[]}"#,
            r#"{"schema_version":1,"coverage":"http_connect_requests","backend":"proxy","destinations":[{"host":"A.test","port":443,"attempts":1}]}"#,
            r#"{"schema_version":1,"coverage":"http_connect_requests","backend":"proxy","destinations":[{"host":"a.test","port":443,"attempts":0}]}"#,
            r#"{"schema_version":1,"coverage":"http_connect_requests","backend":"proxy","destinations":[{"host":"a.test","port":443,"attempts":1},{"host":"a.test","port":443,"attempts":1}]}"#,
        ] {
            fs::write(&path, contents).unwrap();
            assert!(baseline(&path).is_err(), "{contents}");
        }
    }

    #[test]
    fn command_key_keeps_the_persisted_sha256_format() {
        assert_eq!(
            command_key(&["ab".into(), "c".into()]),
            "43ee655579de01ca739b3f95c1c2d3f46d353b2c0df818064ea594506cdb2617"
        );
    }

    #[test]
    fn argument_boundaries_are_part_of_the_command_key() {
        assert_ne!(
            command_key(&["ab".into(), "c".into()]),
            command_key(&["a".into(), "bc".into()])
        );
    }
}
