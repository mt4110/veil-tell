use crate::cli::Backend;
use crate::report::{Destination, OutputFile};
use crate::{Result, error};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const NEW_DESTINATION: u8 = 21;
const MAX_BYTES: u64 = 1024 * 1024;
const MAX_PENDING_BYTES: u64 = 3 * MAX_BYTES;
const CAPTURE: &str = "http_connect_requests";

#[derive(Default)]
pub struct Options {
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub fail_on_new: bool,
    pub automatic: bool,
    pub ci: bool,
}

impl Options {
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
    #[serde(default, skip_serializing_if = "crate::attribution::Sources::is_empty")]
    attribution: crate::attribution::Sources,
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
}

impl Baseline {
    fn capture(backend: Backend, events: &[Destination]) -> Self {
        let mut counts = BTreeMap::<_, Endpoint>::new();
        for event in events {
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
                crate::attribution::record(&mut endpoint.attribution, source.clone());
            }
        }
        Self {
            schema_version: 1,
            coverage: CAPTURE.into(),
            backend,
            lockfile: None,
            destinations: counts.into_values().collect(),
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
            for endpoint in &diff.added {
                let unknown = crate::attribution::Attribution::unknown();
                let sources = endpoint
                    .attribution
                    .iter()
                    .chain(endpoint.attribution.is_empty().then_some(&unknown));
                for source in sources {
                    if let Some(evidence) = changes.label(source.package.as_ref(), summary) {
                        diff.lockfile_evidence.push(LockEvidence {
                            host: endpoint.host.clone(),
                            port: endpoint.port,
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
    port: u16,
    source: crate::attribution::Attribution,
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

    pub fn has_new(&self) -> bool {
        !self.added.is_empty()
    }

    fn changed(&self) -> bool {
        self.has_new() || !self.removed.is_empty() || !self.count_changes.is_empty()
    }

    pub fn display(&self, automatic: bool) {
        let message = match self.status {
            "new_destinations_only" => {
                "New destinations before command failure / コマンド失敗までに観測した新規宛先"
            }
            "created" => "Baseline saved / 基準を保存しました",
            "skipped" => "Comparison skipped / 比較を見送りました",
            _ if !self.changed() => "No destination changes / 宛先の変化なし",
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
            let unknown = crate::attribution::Attribution::unknown();
            for source in e.attribution.iter().chain(
                (e.attribution.is_empty()
                    && self
                        .lockfile_evidence
                        .iter()
                        .any(|x| x.host == e.host && x.port == e.port))
                .then_some(&unknown),
            ) {
                let suffix = self
                    .lockfile_evidence
                    .iter()
                    .find(|x| x.host == e.host && x.port == e.port && x.source == *source)
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
        for e in &self.removed {
            eprintln!("  - {}:{} ({})", e.host, e.port, e.attempts);
        }
        for e in &self.count_changes {
            eprintln!("  ~ {}:{} ({} -> {})", e.host, e.port, e.before, e.after);
        }
        let next = if self.has_new() && !automatic {
            "veil-tell --help (review the new destinations before updating the baseline) / 新規宛先を調査してから基準を更新してください"
        } else if automatic && self.changed() {
            "review, then veil-tell accept / 調査後、承認するなら veil-tell accept"
        } else if self.status == "skipped" {
            "fix the run and repeat the command / 実行を直して同じコマンドを再実行"
        } else {
            "veil-tell --help"
        };
        eprintln!("Next / 次: {next}");
    }
}

fn read<T: DeserializeOwned>(path: &Path, limit: u64) -> Result<T> {
    let mut bytes = Vec::new();
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(error(
            "use a regular file for the baseline or pending review",
        ));
    }
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(error(
            "baseline or pending review exceeds its size limit; use a smaller capture",
        ));
    }
    serde_json::from_slice(&bytes).map_err(|e| {
        error(format!(
            "invalid JSON in {}: {e}; recreate the file from a successful capture",
            path.display()
        ))
    })
}

fn baseline(path: &Path) -> Result<Baseline> {
    let value: Baseline = read(path, MAX_BYTES)?;
    value.validate()?;
    Ok(value)
}

fn optional_baseline(path: &Path) -> Result<Option<Baseline>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(_) => baseline(path).map(Some),
    }
}

fn write_json(file: &mut File, value: &impl Serialize, limit: u64) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > limit {
        return Err(error(
            "baseline or pending review exceeds its size limit; use a smaller capture",
        ));
    }
    file.write_all(&bytes)?;
    Ok(())
}

fn replace(path: &Path, value: &impl Serialize, limit: u64) -> Result<()> {
    let mut temp = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
    write_json(temp.as_file_mut(), value, limit)?;
    temp.as_file().sync_all()?;
    temp.persist(path)?;
    Ok(())
}

fn command_key(command: &[OsString]) -> String {
    let mut digest = Sha256::new();
    for arg in command {
        let bytes = arg.as_bytes();
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    format!("{:x}", digest.finalize())
}

fn baseline_path(state: &Path, key: &str) -> PathBuf {
    state.join(format!("baseline-{key}.json"))
}

fn lock(state: &Path) -> Result<File> {
    fs::create_dir_all(state)?;
    if fs::symlink_metadata(state)?.file_type().is_symlink() {
        return Err(error(
            ".veil-tell must be a real directory; move its files into a directory in this workspace",
        ));
    }
    let directory = File::open(state)?;
    // The directory stays open for the duration of each state transaction.
    if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(directory)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    key: String,
    before: Baseline,
    after: Baseline,
}

pub struct Session {
    before: Option<Baseline>,
    output: Option<OutputFile>,
    automatic: Option<(PathBuf, String)>,
    lock_root: PathBuf,
    ecosystem: Option<crate::lockfile::Ecosystem>,
    ci: bool,
    initial_lock: Option<crate::lockfile::Summary>,
}

impl Session {
    pub fn prepare(options: &Options, cwd: &Path, command: &[OsString]) -> Result<Self> {
        let state = cwd.join(".veil-tell");
        let key = command_key(command);
        let default = baseline_path(&state, &key);
        let mut before = if let Some(input) = &options.input {
            Some(baseline(input).map_err(|e| error(format!(
                "cannot read baseline {}: {e}; check the path or create a new baseline with --baseline-out / 基準ファイルのパスを確認してください",
                input.display()
            )))?)
        } else if options.ci || options.automatic {
            if fs::symlink_metadata(&state).is_ok_and(|m| m.file_type().is_symlink()) {
                return Err(error(
                    ".veil-tell must be a real directory; move its files into this workspace",
                ));
            }
            optional_baseline(&default)?
        } else {
            None
        };
        if options.ci && before.is_none() {
            return Err(error(
                "CI baseline is missing / CI の基準がありません。Run the same command locally with veil-tell and commit its baseline, or pass --baseline FILE",
            ));
        }
        use crate::lockfile::{Ecosystem, Summary};
        let executable = command
            .first()
            .and_then(|arg| Path::new(arg).file_name())
            .and_then(|s| s.to_str());
        let ecosystem = match executable {
            Some("cargo") => Some(Ecosystem::Cargo),
            Some("npm") => Some(Ecosystem::Npm),
            _ if cwd.join("package-lock.json").exists() => Some(Ecosystem::Npm),
            _ if cwd.join("Cargo.lock").exists() => Some(Ecosystem::Cargo),
            _ => None,
        };
        let initial_lock = ecosystem.and_then(|kind| Summary::read(cwd, kind));
        if options.ci
            && let Some(root) = std::env::var_os("VEIL_TELL_PR_BASE_LOCK_DIR")
            && let Some(before) = &mut before
        {
            before.lockfile = ecosystem.and_then(|kind| Summary::read(Path::new(&root), kind));
        }
        let output = options
            .output
            .as_deref()
            .map(|path| OutputFile::prepare(path, "baseline output"))
            .transpose()?;
        Ok(Self {
            before,
            output,
            lock_root: cwd.into(),
            ecosystem,
            ci: options.ci,
            initial_lock,
            automatic: options.automatic.then_some((state, key)),
        })
    }

    pub fn ci_endpoints(&self) -> Result<std::collections::BTreeSet<String>> {
        Ok(self
            .before
            .as_ref()
            .ok_or_else(|| error("CI baseline is missing"))?
            .destinations
            .iter()
            .map(|e| e.host.clone())
            .collect())
    }

    pub fn output(&self) -> Option<&Path> {
        self.output.as_ref().map(OutputFile::path)
    }

    pub fn finish(self, backend: Backend, events: &[Destination]) -> Result<Comparison> {
        let mut current = Baseline::capture(backend, events);
        current.lockfile = if self.ci || self.before.is_some() || self.initial_lock.is_some() {
            self.initial_lock
        } else {
            self.ecosystem
                .and_then(|kind| crate::lockfile::Summary::read(&self.lock_root, kind))
        };
        if serde_json::to_vec_pretty(&current)?.len() as u64 >= MAX_BYTES {
            current.lockfile = None;
        }
        if let Some(output) = self.output {
            output.save(|file| write_json(file, &current, MAX_BYTES))?;
            return Ok(Comparison::new("created"));
        }
        if let Some((state, key)) = self.automatic {
            let _lock = lock(&state)?;
            let path = baseline_path(&state, &key);
            let before = optional_baseline(&path)?;
            if before != self.before {
                return Err(error(
                    "baseline changed during execution; repeat the command against the current baseline",
                ));
            }
            if let Some(before) = before {
                let diff = before.compare(&current);
                if diff.changed() {
                    replace(
                        &state.join("pending.json"),
                        &Pending {
                            key,
                            before,
                            after: current,
                        },
                        MAX_PENDING_BYTES,
                    )?;
                } else {
                    let pending = state.join("pending.json");
                    match read::<Pending>(&pending, MAX_PENDING_BYTES) {
                        Ok(value) if value.key == key => fs::remove_file(pending)?,
                        _ => {}
                    }
                }
                return Ok(diff);
            }
            OutputFile::prepare(&path, "baseline")?
                .save(|file| write_json(file, &current, MAX_BYTES))?;
            eprintln!("veil-tell: {}", path.display());
            return Ok(Comparison::new("created"));
        }
        Ok(self
            .before
            .expect("comparison has a baseline or output")
            .compare(&current))
    }
}

pub fn accept(cwd: &Path) -> Result<u8> {
    let state = cwd.join(".veil-tell");
    if !state.is_dir() {
        return Err(error(
            "no pending baseline / 承認待ちの差分がありません。Run the command with veil-tell first",
        ));
    }
    let _lock = lock(&state)?;
    let path = state.join("pending.json");
    let pending: Pending = read(&path, MAX_PENDING_BYTES).map_err(|e| {
        error(format!(
            "cannot read pending review: {e}; run the command again / コマンドを再実行してください"
        ))
    })?;
    if pending.key.len() != 64 || !pending.key.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(error("invalid pending command key; run the command again"));
    }
    pending.before.validate()?;
    pending.after.validate()?;
    let destination = baseline_path(&state, &pending.key);
    if baseline(&destination)? != pending.before {
        return Err(error(
            "baseline changed since the pending review; run the command again before accepting",
        ));
    }
    replace(&destination, &pending.after, MAX_BYTES)?;
    fs::remove_file(path)?;
    eprintln!(
        "veil-tell: Baseline updated / 基準を更新しました: {}",
        destination.display()
    );
    eprintln!("Next / 次: git diff -- .veil-tell");
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(host: &str, attempts: u64) -> Destination {
        Destination {
            host: host.into(),
            port: 443,
            decision: "allow",
            reason: "observe",
            result: "completed",
            connected_ip: None,
            attempts,
            sent_bytes: 0,
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
        assert!(!before.compare(&before).changed());
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
    fn argument_boundaries_are_part_of_the_command_key() {
        assert_ne!(
            command_key(&["ab".into(), "c".into()]),
            command_key(&["a".into(), "bc".into()])
        );
    }
}
