use crate::cli::Backend;
use crate::report::{Attempted, Destination, OutputFile};
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
                crate::attribution::record(
                    &mut endpoint.attribution,
                    if source.manager.is_some() {
                        crate::attribution::Attribution::unknown()
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
                let unknown = crate::attribution::Attribution::unknown();
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
        source: &crate::attribution::Attribution,
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
            let unknown = crate::attribution::Attribution::unknown();
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
    if crate::manager::NAMES.contains(&key) {
        state.join(format!("{key}.json"))
    } else {
        state.join(format!("baseline-{key}.json"))
    }
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
        let manager =
            crate::manager::executable(command).filter(|name| crate::manager::NAMES.contains(name));
        let mut key = if options.ci {
            manager
        } else {
            crate::manager::install_key(command)
        }
        .map(str::to_owned)
        .unwrap_or_else(|| command_key(command));
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
            let current = optional_baseline(&default)?;
            if current.is_none() && crate::manager::NAMES.contains(&key.as_str()) {
                let exact_key = command_key(command);
                let exact = baseline_path(&state, &exact_key);
                if exact.is_file() && options.ci {
                    key = exact_key;
                    Some(baseline(&exact)?)
                } else if exact.is_file() {
                    let _guard = lock(&state)?;
                    if optional_baseline(&default)?.is_none() {
                        let legacy = baseline(&exact)?;
                        OutputFile::prepare(&default, "baseline")?
                            .save(|file| write_json(file, &legacy, MAX_BYTES))?;
                        eprintln!(
                            "veil-tell: Migrated baseline / 基準を移行しました: {}",
                            default.display()
                        );
                    }
                    optional_baseline(&default)?
                } else {
                    if options.ci {
                        eprintln!(
                            "veil-tell: if you have a legacy baseline, review it and run veil-tell migrate-baseline {key} .veil-tell/baseline-<hash>.json"
                        );
                    }
                    None
                }
            } else {
                current
            }
        } else {
            None
        };
        if options.ci && before.is_none() {
            return Err(error(
                "CI baseline is missing / CI の基準がありません。Run the same command locally with veil-tell and commit its baseline, or pass --baseline FILE",
            ));
        }
        use crate::lockfile::{Ecosystem, Summary};
        let executable = crate::manager::executable(command);
        let ecosystem = match executable {
            Some("cargo") => Some(Ecosystem::Cargo),
            Some("npm") => Some(Ecosystem::Npm),
            Some("pnpm") => Some(Ecosystem::Pnpm),
            Some("yarn") => Some(Ecosystem::Yarn),
            Some("bun") => Some(Ecosystem::Bun),
            _ if cwd.join("pnpm-lock.yaml").exists() => Some(Ecosystem::Pnpm),
            _ if cwd.join("yarn.lock").exists() => Some(Ecosystem::Yarn),
            _ if cwd.join("bun.lock").exists() => Some(Ecosystem::Bun),
            _ if cwd.join("package-lock.json").exists() => Some(Ecosystem::Npm),
            _ if cwd.join("Cargo.lock").exists() => Some(Ecosystem::Cargo),
            _ => None,
        };
        let ecosystem = ecosystem.filter(|_| !options.no_attribute);
        let initial_lock = ecosystem.and_then(|kind| Summary::read(cwd, kind));
        if options.ci
            && options.input.is_some()
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
            automatic: options.writes_pending().then_some((state, key)),
        })
    }

    pub fn volume_limits(&self, backend: Backend) -> BTreeMap<String, crate::volume::Sample> {
        self.before
            .as_ref()
            .filter(|before| before.backend == backend)
            .map(|before| {
                before
                    .volume
                    .iter()
                    .map(|(host, sample)| (host.clone(), sample.limits()))
                    .collect()
            })
            .unwrap_or_default()
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

    pub fn has_new_attempt(&self, attempted: &[Attempted]) -> bool {
        self.before.as_ref().is_some_and(|before| {
            attempted.iter().any(|entry| {
                before
                    .attempted
                    .binary_search_by(|old| old.host.cmp(&entry.host))
                    .is_err()
            })
        })
    }

    pub fn output(&self) -> Option<&Path> {
        self.output.as_ref().map(OutputFile::path)
    }

    pub fn finish(
        self,
        backend: Backend,
        events: &[Destination],
        attempted: &[Attempted],
    ) -> Result<Comparison> {
        let mut current = Baseline::capture(backend, events);
        current.attempted = attempted.to_vec();
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
                if diff.has_new() {
                    let samples = std::mem::take(&mut current.volume);
                    current.destinations.extend(diff.removed.iter().cloned());
                    current.volume = before.volume.clone();
                    for entry in &diff.added {
                        if let Some(sample) = samples.get(&entry.host) {
                            current.volume.insert(entry.host.clone(), sample.clone());
                        }
                    }
                    let attempts: BTreeMap<_, _> = before
                        .attempted
                        .iter()
                        .chain(&current.attempted)
                        .map(|e| (e.host.clone(), e.clone()))
                        .collect();
                    current.attempted = attempts.into_values().collect();
                    current
                        .destinations
                        .sort_by(|a, b| (&a.host, a.port).cmp(&(&b.host, b.port)));
                    current.validate()?;
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

pub fn clean(cwd: &Path, apply: bool) -> Result<u8> {
    let state = cwd.join(".veil-tell");
    if !state.exists() {
        eprintln!("veil-tell: No legacy baselines / 旧形式の基準はありません");
        return Ok(0);
    }
    let _guard = lock(&state)?;
    let mut candidates = Vec::new();
    for entry in fs::read_dir(&state)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(hash) = name
            .to_str()
            .and_then(|s| s.strip_prefix("baseline-"))
            .and_then(|s| s.strip_suffix(".json"))
        else {
            continue;
        };
        if hash.len() == 64
            && hash.bytes().all(|b| b.is_ascii_hexdigit())
            && entry.file_type()?.is_file()
            && baseline(&entry.path()).is_ok()
        {
            candidates.push(entry.path());
        }
    }
    candidates.sort_unstable();
    if candidates.is_empty() {
        eprintln!("veil-tell: No legacy baselines / 旧形式の基準はありません");
        return Ok(0);
    }
    for path in candidates {
        if apply {
            fs::remove_file(&path)?;
            println!("Removed / 削除: {}", path.display());
        } else {
            println!("Candidate / 削除候補: {}", path.display());
        }
    }
    if !apply {
        eprintln!(
            "Next / 次: review the list, then run veil-tell clean --apply / 確認して削除するなら veil-tell clean --apply"
        );
    }
    Ok(0)
}

pub fn migrate(cwd: &Path, manager: &str, file: &Path) -> Result<u8> {
    if !crate::manager::NAMES.contains(&manager) {
        return Err(error(
            "choose npm, pnpm, yarn, bun or cargo for baseline migration",
        ));
    }
    let old = baseline(file)?;
    let state = cwd.join(".veil-tell");
    let _guard = lock(&state)?;
    let path = baseline_path(&state, manager);
    OutputFile::prepare(&path, "baseline")?.save(|file| write_json(file, &old, MAX_BYTES))?;
    eprintln!(
        "veil-tell: Migrated baseline / 基準を移行しました: {}",
        path.display()
    );
    eprintln!("Next / 次: git add .veil-tell/{manager}.json");
    Ok(0)
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
    if !crate::manager::NAMES.contains(&pending.key.as_str())
        && (pending.key.len() != 64 || !pending.key.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(error("invalid pending command key; run the command again"));
    }
    pending.before.validate()?;
    pending.after.validate()?;
    if !pending.before.compare(&pending.after).has_new() {
        return Err(error(
            "this pending review has no new destinations; run the command again to clear it",
        ));
    }
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
    fn argument_boundaries_are_part_of_the_command_key() {
        assert_ne!(
            command_key(&["ab".into(), "c".into()]),
            command_key(&["a".into(), "bc".into()])
        );
    }
}
