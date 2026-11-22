//! Baseline persistence, session comparison lifecycle, and review workflow (`clean`, `migrate`, `accept`).

use super::{
    Baseline, Comparison, MAX_BYTES, MAX_PENDING_BYTES, Options,
};
use crate::domain::attribution_model::Backend;
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

pub(super) fn read<T: DeserializeOwned>(path: &Path, limit: u64) -> Result<T> {
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

pub(super) fn baseline(path: &Path) -> Result<Baseline> {
    let value: Baseline = read(path, MAX_BYTES)?;
    value.validate()?;
    Ok(value)
}

pub(super) fn optional_baseline(path: &Path) -> Result<Option<Baseline>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(_) => baseline(path).map(Some),
    }
}

pub(super) fn write_json(file: &mut File, value: &impl Serialize, limit: u64) -> Result<()> {
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

pub(super) fn replace(path: &Path, value: &impl Serialize, limit: u64) -> Result<()> {
    let mut temp = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
    write_json(temp.as_file_mut(), value, limit)?;
    temp.as_file().sync_all()?;
    temp.persist(path)?;
    Ok(())
}

pub(super) fn command_key(command: &[OsString]) -> String {
    let mut digest = Sha256::new();
    for arg in command {
        let bytes = arg.as_bytes();
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    format!("{:x}", digest.finalize())
}

pub(super) fn baseline_path(state: &Path, key: &str) -> PathBuf {
    if crate::manager::NAMES.contains(&key) {
        state.join(format!("{key}.json"))
    } else {
        state.join(format!("baseline-{key}.json"))
    }
}

pub(super) fn lock(state: &Path) -> Result<File> {
    fs::create_dir_all(state)?;
    if fs::symlink_metadata(state)?.file_type().is_symlink() {
        return Err(error(
            ".veil-tell must be a real directory; move its files into a directory in this workspace",
        ));
    }
    let directory = File::open(state)?;
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
