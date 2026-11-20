use crate::{
    Execution, FixtureResolver, Result, RunSignals,
    cli::{Backend, Mode, Options},
    error, isolation,
    policy::{Policy, normalize_host},
    report::{OutputFile, Report},
    run_command,
};
use serde::Serialize;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

struct Config {
    source: PathBuf,
    policy: PathBuf,
    host: String,
    report: PathBuf,
    timeout: Duration,
    command: Vec<OsString>,
}

impl Config {
    fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Self> {
        let (mut source, mut policy, mut host, mut report, mut timeout) =
            (None, None, None, None, None);
        loop {
            let flag = args
                .next()
                .ok_or_else(|| error("specify a command after --"))?;
            if flag == "--" {
                break;
            }
            let slot = match flag.to_str() {
                Some("--source") => &mut source,
                Some("--policy") => &mut policy,
                Some("--without") => &mut host,
                Some("--report") => &mut report,
                Some("--timeout-seconds") => &mut timeout,
                _ => {
                    return Err(error(format!(
                        "unexpected verify option: {}",
                        flag.to_string_lossy()
                    )));
                }
            };
            if slot.is_some() {
                return Err(error(format!(
                    "repeated verify option: {}",
                    flag.to_string_lossy()
                )));
            }
            *slot =
                Some(args.next().ok_or_else(|| {
                    error(format!("missing value for {}", flag.to_string_lossy()))
                })?);
        }
        let host = host
            .as_deref()
            .and_then(|value| value.to_str())
            .and_then(|value| value.strip_suffix(":443"))
            .and_then(normalize_host)
            .ok_or_else(|| error("verify requires --without HOST:443"))?;
        let seconds = match timeout {
            Some(value) => value
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
                .filter(|&n| n > 0)
                .ok_or_else(|| error("--timeout-seconds requires a positive integer"))?,
            None => 300,
        };
        let command: Vec<_> = args.collect();
        if command.is_empty() {
            return Err(error("specify a command after --"));
        }
        Ok(Self {
            source: source
                .map(PathBuf::from)
                .ok_or_else(|| error("verify requires --source"))?,
            policy: policy
                .map(PathBuf::from)
                .ok_or_else(|| error("verify requires --policy"))?,
            host,
            report: report
                .map(PathBuf::from)
                .ok_or_else(|| error("verify requires --report"))?,
            timeout: Duration::from_secs(seconds.into()),
            command,
        })
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Verdict {
    Passes,
    Fails,
    Inconclusive,
}

#[derive(Default, Serialize)]
struct Trials {
    allowed: Option<Trial>,
    denied: Option<Trial>,
    restored: Option<Trial>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Trial {
    Run(Box<Report>),
    SetupError { error: String },
}

impl Trial {
    fn completed(&self, host: &str, allowed: bool) -> std::result::Result<u8, (&'static str, u8)> {
        let Self::Run(report) = self else {
            return Err(("setup_failed", 2));
        };
        let status = &report.run_status;
        match status.reason {
            "interrupted" => return Err(("interrupted", status.exit_code)),
            "timed_out" => return Err(("timed_out", 2)),
            "completed" | "child_failed" => {}
            _ => return Err((status.reason, 2)),
        }
        if report.isolation != "applied" {
            return Err(("isolation_unconfirmed", 2));
        }
        let child = report
            .child_status
            .as_ref()
            .ok_or(("child_status_missing", 2))?;
        if child.signal.is_some() {
            return Err(("child_signalled", 2));
        }
        // The Linux wrapper uses 125 for setup/relay failures and 128 + signal
        // for a signalled child. These can also be ordinary child exit codes.
        if cfg!(target_os = "linux")
            && child
                .exit_code
                .is_some_and(|code| code == 125 || code >= 128)
        {
            return Err(("child_exit_ambiguous", 2));
        }
        if report.destinations.iter().any(|event| {
            event.host != host
                && (matches!(
                    event.reason,
                    "unknown_destination" | "non_public_destination"
                ) || event.decision == "allow" && event.connected_ip.is_none())
        }) {
            return Err(("other_destination_unavailable", 2));
        }
        if !report.destinations.iter().any(|event| {
            event.host == host
                && if allowed {
                    event.reason == "allow_rule" && event.received_bytes > 0
                } else {
                    event.reason == "explicit_deny" && event.result == "blocked"
                }
        }) {
            return Err((
                if allowed {
                    "allowed_connection_not_observed"
                } else {
                    "denial_not_observed"
                },
                2,
            ));
        }
        Ok(status.exit_code)
    }
}

#[derive(Serialize)]
struct Comparison<'a> {
    schema_version: u8,
    timeout_seconds: u64,
    destination: Destination<'a>,
    verdict: Verdict,
    reason: &'static str,
    exit_code: u8,
    phase: &'static str,
    trials: Trials,
}

#[derive(Serialize)]
struct Destination<'a> {
    host: &'a str,
    port: u16,
}

pub async fn run(
    mut args: impl Iterator<Item = OsString>,
    fixture: Option<FixtureResolver>,
) -> Result<u8> {
    let first = args.next();
    if first.as_ref().is_some_and(|arg| isolation::is_help(arg)) {
        println!("{}", crate::cli::USAGE);
        return Ok(0);
    }
    let config = Config::parse(first.into_iter().chain(args))?;
    let source = config.source.canonicalize()?;
    if !source.is_dir() {
        return Err(error("--source must be a directory"));
    }
    let output = OutputFile::prepare(&config.report, "verify report")?;
    let policy_path = config.policy.canonicalize()?;
    if policy_path.starts_with(&source) || output.path().starts_with(&source) {
        return Err(error(
            "verify requires the policy and report outside --source",
        ));
    }
    let allowed = Policy::read(&policy_path)?;
    let denied = allowed.denying(&config.host)?;
    let mut signals = RunSignals::new()?;
    let temp_parent = std::env::temp_dir().canonicalize()?;
    if temp_parent.starts_with(&source) {
        return Err(error(
            "--source must not contain the system temporary directory",
        ));
    }
    if temp_parent.starts_with(output.path().parent().unwrap()) {
        return Err(error(
            "verify requires a report directory separate from the temporary trial directory",
        ));
    }
    let snapshot = tempfile::tempdir_in(&temp_parent)?;
    copy_tree(&source, &source, snapshot.path())?;
    let mut trials = Trials::default();
    let mut runner = Runner {
        config: &config,
        fixture,
        snapshot: snapshot.path(),
        temp_parent: &temp_parent,
        output: output.path(),
        protected_dirs: [&source, snapshot.path(), &policy_path],
        signals: &mut signals,
    };
    let (verdict, reason, exit_code, phase) =
        match runner.compare(allowed, denied, &mut trials).await {
            Ok(Verdict::Passes) => (
                Verdict::Passes,
                "passed_with_destination_blocked",
                0,
                "denied",
            ),
            Ok(Verdict::Fails) => (
                Verdict::Fails,
                "failed_with_destination_blocked",
                1,
                "restored",
            ),
            Ok(Verdict::Inconclusive) => unreachable!(),
            Err((phase, reason, code)) => (Verdict::Inconclusive, reason, code, phase),
        };
    let comparison = Comparison {
        schema_version: 1,
        timeout_seconds: config.timeout.as_secs(),
        destination: Destination {
            host: &config.host,
            port: 443,
        },
        verdict,
        reason,
        exit_code,
        phase,
        trials,
    };
    output.save(|file| {
        serde_json::to_writer_pretty(&mut *file, &comparison)?;
        use std::io::Write;
        file.write_all(b"\n")?;
        Ok(())
    })?;
    let label = match verdict {
        Verdict::Passes => "閉じても通る (passes)",
        Verdict::Fails => "閉じると失敗 (fails)",
        Verdict::Inconclusive => "判定不能 (inconclusive)",
    };
    println!("{}:443 {label} [{phase}: {reason}]", config.host);
    Ok(exit_code)
}

struct Runner<'a> {
    config: &'a Config,
    fixture: Option<FixtureResolver>,
    snapshot: &'a Path,
    temp_parent: &'a Path,
    output: &'a Path,
    protected_dirs: [&'a Path; 3],
    signals: &'a mut RunSignals,
}

impl Runner<'_> {
    async fn trial(&mut self, phase: &str, policy: Policy) -> Trial {
        eprintln!("veil-tell verify: {phase}");
        match self.run_trial(policy).await {
            Ok(report) => Trial::Run(Box::new(report)),
            Err(error) => {
                eprintln!("veil-tell verify: {error}");
                Trial::SetupError {
                    error: error.to_string(),
                }
            }
        }
    }

    async fn run_trial(&mut self, policy: Policy) -> Result<Report> {
        let project = tempfile::tempdir_in(self.temp_parent)?;
        copy_tree(self.snapshot, self.snapshot, project.path())?;
        check_snapshot_links(project.path(), project.path())?;
        let options = Options {
            mode: Mode::Restrict,
            backend: Backend::Isolated,
            policy: None,
            report: None,
            emit_policy: None,
            fail_on_unknown: false,
            command: self.config.command.clone(),
            comparison: Default::default(),
            attribute_npm: false,
            no_attribute: true,
            json: false,
            log: false,
            shorthand: false,
            shim: false,
            save_baseline: false,
        };
        let execution = Execution {
            cwd: project.path(),
            stdin: None,
            timeout: Some(self.config.timeout),
            protected_outputs: &[self.output],
            protected_dirs: &self.protected_dirs,
        };
        run_command(
            &options,
            self.fixture,
            policy,
            self.signals,
            execution,
            None,
        )
        .await
    }

    async fn compare(
        &mut self,
        allowed: Policy,
        denied: Policy,
        trials: &mut Trials,
    ) -> std::result::Result<Verdict, (&'static str, &'static str, u8)> {
        let baseline = self
            .record("allowed", allowed.clone(), true, &mut trials.allowed)
            .await?;
        if baseline != 0 {
            return Err(("allowed", "baseline_failed", 2));
        }
        let blocked = self
            .record("denied", denied, false, &mut trials.denied)
            .await?;
        if blocked == 0 {
            return Ok(Verdict::Passes);
        }
        let restored = self
            .record("restored", allowed, true, &mut trials.restored)
            .await?;
        if restored != 0 {
            return Err(("restored", "restored_failed", 2));
        }
        Ok(Verdict::Fails)
    }

    async fn record(
        &mut self,
        phase: &'static str,
        policy: Policy,
        is_allowed: bool,
        slot: &mut Option<Trial>,
    ) -> std::result::Result<u8, (&'static str, &'static str, u8)> {
        let trial = self.trial(phase, policy).await;
        let result = trial.completed(&self.config.host, is_allowed);
        *slot = Some(trial);
        result.map_err(|(reason, code)| (phase, reason, code))
    }
}

fn check_snapshot_links(root: &Path, directory: &Path) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            check_snapshot_links(root, &entry.path())?;
        } else if kind.is_symlink() && !entry.path().canonicalize()?.starts_with(root) {
            return Err(error(format!(
                "symlink escapes snapshot: {}",
                entry.path().display()
            )));
        }
    }
    Ok(())
}

fn copy_tree(root: &Path, from: &Path, to: &Path) -> Result<()> {
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let source = entry.path();
        let target = to.join(entry.file_name());
        let kind = entry.file_type()?;
        if kind.is_dir() {
            fs::create_dir(&target)?;
            copy_tree(root, &source, &target)?;
        } else if kind.is_file() {
            fs::copy(&source, &target)?;
            let mode = fs::metadata(&target)?.permissions().mode() & 0o777;
            fs::set_permissions(&target, fs::Permissions::from_mode(mode))?;
        } else if kind.is_symlink() {
            let link = fs::read_link(&source)?;
            if !relative_within(root, from, &link) || !source.canonicalize()?.starts_with(root) {
                return Err(error(format!(
                    "symlink escapes snapshot: {}",
                    source.display()
                )));
            }
            symlink(link, &target)?;
        } else {
            return Err(error(format!(
                "unsupported snapshot entry: {}",
                source.display()
            )));
        }
    }
    Ok(())
}

// An absolute link or a relative path that walks outside the root can point
// somewhere else after relocation, even if it resolves inside the seed today.
fn relative_within(root: &Path, directory: &Path, link: &Path) -> bool {
    let mut depth = directory.strip_prefix(root).unwrap().components().count();
    for part in link.components() {
        match part {
            Component::Normal(_) => depth += 1,
            Component::ParentDir if depth > 0 => depth -= 1,
            Component::CurDir => {}
            _ => return false,
        }
    }
    true
}
