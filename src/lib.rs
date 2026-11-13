mod attribution;
mod baseline;
mod cargo_attribution;
mod cli;
mod isolation;
mod lockfile;
mod policy;
mod proxy;
mod report;
mod verify;

use base64::Engine;
use cli::{Backend, Mode, Options};
use report::{Coverage, OutputFile, Report, RunStatus};
use std::ffi::OsString;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::oneshot;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const SETUP_FAILURE: u8 = 125;
const UNKNOWN_DESTINATION: u8 = 20;

// The release binary always passes None. A separate local fixture executable can
// connect an approved synthetic host to a controlled receiver without changing
// the release binary's DNS or address rules.
#[doc(hidden)]
pub type FixtureResolver = fn(&str) -> Option<SocketAddr>;

fn error(message: impl Into<String>) -> Box<dyn std::error::Error + Send + Sync> {
    io::Error::other(message.into()).into()
}

fn credential() -> Result<String> {
    let mut random = [0; 24];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random))
}

async fn run(mut options: Options, fixture: Option<FixtureResolver>) -> Result<u8> {
    let cwd = std::env::current_dir()?.canonicalize()?;
    options.comparison.no_attribute = options.no_attribute;
    let state = cwd.join(".veil-tell");
    if options.comparison.automatic {
        if !state.exists() {
            std::fs::create_dir_all(&state)?;
        }
        if !state.is_dir() || state.is_symlink() {
            return Err(error("use a real .veil-tell directory inside this project"));
        }
        match isolation::probe(&cwd).await {
            Ok(()) => options.backend = Backend::Isolated,
            Err(reason) => {
                let setup = if cfg!(target_os = "linux") {
                    "sudo apt-get install bubblewrap (Ubuntu; requires unprivileged namespaces)"
                } else {
                    "test -x /usr/bin/sandbox-exec"
                };
                eprintln!(
                    "veil-tell: isolation unavailable ({reason}); observing via proxy. Direct connections are not visible / 直接通信は見えていません。隔離を使うには: {setup}"
                );
            }
        }
    }
    let policy = options
        .policy
        .as_deref()
        .map(policy::Policy::read)
        .transpose()?
        .unwrap_or_default();
    let mut signals = RunSignals::new()?;
    let execution = Execution {
        cwd: &cwd,
        timeout: None,
        protected_outputs: &[],
        protected_dirs: if options.comparison.automatic {
            &[state.as_path()]
        } else {
            &[]
        },
    };
    let report = run_command(options, fixture, policy, &mut signals, execution).await?;
    Ok(report.run_status.exit_code)
}

struct RunSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

impl RunSignals {
    fn new() -> Result<Self> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }

    async fn interrupted(&mut self) -> u8 {
        tokio::select! {
            _ = self.interrupt.recv() => 130,
            _ = self.terminate.recv() => 143,
        }
    }
}

struct Execution<'a> {
    cwd: &'a Path,
    timeout: Option<Duration>,
    protected_outputs: &'a [&'a Path],
    protected_dirs: &'a [&'a Path],
}

async fn run_command(
    options: Options,
    fixture: Option<FixtureResolver>,
    policy: policy::Policy,
    signals: &mut RunSignals,
    execution: Execution<'_>,
) -> Result<Report> {
    let Execution {
        cwd,
        timeout,
        protected_outputs,
        protected_dirs,
    } = execution;
    let report = options
        .report
        .as_deref()
        .map(|path| OutputFile::prepare(path, "report"))
        .transpose()?;
    let policy_output = options
        .emit_policy
        .as_deref()
        .map(|path| OutputFile::prepare(path, "policy output"))
        .transpose()?;
    if let (Some(report), Some(policy_output)) = (&report, &policy_output)
        && report.path() == policy_output.path()
    {
        return Err(error("--report and --emit-policy require different paths"));
    }
    let comparison = options
        .comparison
        .requested()
        .then(|| baseline::Session::prepare(&options.comparison, cwd, &options.command))
        .transpose()?;
    let mut outputs: Vec<_> = report
        .iter()
        .chain(&policy_output)
        .map(OutputFile::path)
        .chain(comparison.as_ref().and_then(baseline::Session::output))
        .chain(protected_outputs.iter().copied())
        .collect();
    let count = outputs.len();
    outputs.sort_unstable();
    outputs.dedup();
    if count != outputs.len() {
        return Err(error(
            "choose distinct paths for the report and generated files",
        ));
    }
    if options.backend == Backend::Isolated {
        isolation::check_isolated_paths(cwd, options.policy.as_deref(), &outputs)?;
    }
    let secret = credential()?;
    let executable = Path::new(&options.command[0]).file_name();
    let wants_npm = !options.no_attribute
        && (options.attribute_npm || executable.is_some_and(|name| name == "npm"));
    let custom_shell = wants_npm && attribution::custom_npm_shell(cwd, &options.command);
    if custom_shell {
        eprintln!(
            "veil-tell: using the configured npm script-shell; npm attribution is off / npm の既存シェル設定を使用するため帰属を無効化しました"
        );
    }
    let attribute_npm = wants_npm && !custom_shell;
    let attribute_cargo = !options.no_attribute
        && executable.is_some_and(|name| name == "cargo")
        && std::env::var_os("RUSTC_WRAPPER").is_none();
    let proxy = Arc::new(proxy::Proxy {
        mode: options.mode,
        policy,
        ci_hosts: if options.comparison.ci {
            Some(
                comparison
                    .as_ref()
                    .ok_or_else(|| error("CI baseline is missing"))?
                    .ci_endpoints()?,
            )
        } else {
            None
        },
        auth: format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("veil:{secret}"))
        ),
        attribute_npm: attribute_npm || attribute_cargo,
        compare_unauthenticated: options.comparison.ci,
        records: report::Records::default(),
        incomplete: AtomicBool::new(false),
        interfaces: proxy::host_interfaces()?,
        fixture,
    });
    let isolation::Launch {
        listener,
        mut command,
        temporary: _temporary,
        npm_wrapper: _npm_wrapper,
    } = isolation::prepare(
        options.backend,
        &options.command,
        cwd,
        &outputs,
        protected_dirs,
        &secret,
        (attribute_npm, attribute_cargo),
    )
    .await?;
    let (stop, stopped) = oneshot::channel();
    let mut proxy_task = tokio::spawn(proxy::serve(listener, Arc::clone(&proxy), stopped));
    if options.mode == Mode::Observe && options.backend == Backend::Proxy {
        eprintln!(
            "veil-tell: observing HTTP CONNECT requests from clients that use the local proxy. Direct connection attempts are outside the capture scope."
        );
    }
    let mut child = command.spawn()?;
    let pid = child.id();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let mut stdout_task =
        tokio::spawn(async move { tokio::io::copy(&mut stdout, &mut tokio::io::stdout()).await });
    let mut stderr_task =
        tokio::spawn(async move { tokio::io::copy(&mut stderr, &mut tokio::io::stderr()).await });
    let mut infrastructure_failure = None;
    let mut proxy_ended = false;
    let status = tokio::select! {
        biased;
        _ = &mut proxy_task => {
            proxy_ended = true;
            infrastructure_failure = Some((SETUP_FAILURE, "proxy_stopped"));
            None
        }
        code = signals.interrupted() => {
            infrastructure_failure = Some((code, "interrupted"));
            None
        }
        _ = async {
            match timeout {
                Some(duration) => tokio::time::sleep(duration).await,
                None => std::future::pending().await,
            }
        } => {
            infrastructure_failure = Some((124, "timed_out"));
            None
        }
        status = child.wait() => Some(status?),
    };
    isolation::terminate_group(pid);
    let status = match status {
        Some(status) => Some(status),
        None => child.wait().await.ok(),
    };
    let _ = stop.send(());
    if !proxy_ended && !matches!(proxy_task.await, Ok(Ok(()))) {
        infrastructure_failure = Some((SETUP_FAILURE, "proxy_stopped"));
    }
    for task in [&mut stdout_task, &mut stderr_task] {
        if tokio::time::timeout(Duration::from_secs(1), &mut *task)
            .await
            .is_err()
        {
            task.abort();
        }
    }
    let destinations = proxy.records.snapshot();
    let unknown = destinations
        .iter()
        .any(|destination| destination.reason == "unknown_destination");
    let (mut exit_code, mut reason) = if let Some(failure) = infrastructure_failure {
        failure
    } else if proxy.incomplete.load(Ordering::Relaxed) {
        (SETUP_FAILURE, "incomplete_capture")
    } else if options.fail_on_unknown && unknown {
        (UNKNOWN_DESTINATION, "unknown_destination")
    } else {
        let code = status.map(isolation::shell_exit).unwrap_or(SETUP_FAILURE);
        (
            code,
            if code == 0 {
                "completed"
            } else {
                "child_failed"
            },
        )
    };
    if let Some(file) = policy_output
        && exit_code == 0
        && let Err(error) = file.save(|output| {
            use std::io::Write;
            output.write_all(policy::draft(&destinations)?.as_bytes())?;
            Ok(())
        })
    {
        eprintln!("veil-tell: could not write policy draft: {error}");
        (exit_code, reason) = (SETUP_FAILURE, "policy_output_failed");
    }
    for destination in &destinations {
        eprintln!(
            "veil-tell: {}:{} {} {} ×{}",
            destination.host,
            destination.port,
            destination.decision,
            destination.reason,
            destination.attempts
        );
    }
    let connect_requests: u64 = destinations
        .iter()
        .map(|destination| destination.attempts)
        .sum();
    let isolation = match options.backend {
        Backend::Proxy => "not_requested",
        Backend::Isolated
            if status.is_some_and(|status| status.success()) || !destinations.is_empty() =>
        {
            "applied"
        }
        Backend::Isolated => "unconfirmed",
    };
    let comparison = if let Some(session) = comparison {
        let ci_denial = options.comparison.ci
            && reason == "child_failed"
            && status.is_some_and(|status| status.code().is_some())
            && destinations
                .iter()
                .any(|event| event.reason == "new_destination");
        let mut diff = if exit_code == 0 || ci_denial {
            match session.finish(options.backend, &destinations) {
                Ok(diff) => diff,
                Err(error) => {
                    eprintln!("veil-tell: {error}");
                    (exit_code, reason) = (SETUP_FAILURE, "baseline_failed");
                    baseline::Comparison::skipped()
                }
            }
        } else {
            baseline::Comparison::skipped()
        };
        if ci_denial {
            diff.retain_additions();
        }
        if diff.has_new() && (options.comparison.fail_on_new || options.comparison.ci) {
            (exit_code, reason) = (baseline::NEW_DESTINATION, "new_destination");
        }
        Some(Box::new(diff))
    } else {
        None
    };
    eprintln!(
        "veil-tell: {reason} (exit {exit_code}). Recorded HTTP CONNECT requests: {connect_requests}. Direct connection attempts are outside the capture scope."
    );
    let result = Report {
        schema_version: 1,
        backend: options.backend,
        mode: options.mode,
        isolation,
        coverage: Coverage {
            proxy: "http_connect_requests",
            direct_attempt_destinations: "not_observed",
            proxy_capture: if reason == "proxy_stopped" {
                "until_proxy_stopped"
            } else if reason == "incomplete_capture" {
                "incomplete"
            } else if timeout.is_some() && matches!(reason, "timed_out" | "interrupted") {
                "until_interrupted"
            } else {
                "while_running"
            },
        },
        child_status: status.map(Into::into),
        run_status: RunStatus { exit_code, reason },
        destinations,
        comparison,
    };
    if let Some(file) = report {
        file.save_report(&result)?;
    }
    if let Some(diff) = &result.comparison {
        if diff.created() && attribute_cargo {
            for destination in &result.destinations {
                for source in &destination.attribution {
                    if let Some(pkg) = &source.package {
                        eprintln!(
                            "  {}:{} ← {}@{} {} ({}) [inferred / 推定]",
                            destination.host,
                            destination.port,
                            pkg.name,
                            pkg.version,
                            pkg.script,
                            pkg.path
                        );
                    }
                }
            }
        }
        diff.display(options.comparison.automatic);
    }
    Ok(result)
}

async fn dispatch(args: Vec<OsString>, fixture: Option<FixtureResolver>) -> Result<u8> {
    #[cfg(target_os = "linux")]
    if args
        .first()
        .is_some_and(|arg| arg == "__veil_tell_linux_relay")
    {
        let secret = args
            .get(1)
            .and_then(|arg| arg.to_str())
            .filter(|_| args.len() >= 3)
            .ok_or_else(|| error("invalid internal relay invocation"))?;
        return isolation::linux::inside(secret, &args[2..]).await;
    }
    if args.as_slice() == ["--version"] {
        println!("veil-tell {}", env!("CARGO_PKG_VERSION"));
        return Ok(0);
    }
    if args.first().is_some_and(|arg| isolation::is_help(arg))
        || (args.len() == 2
            && matches!(
                args[0].to_str(),
                Some("observe" | "restrict" | "ci" | "accept")
            )
            && isolation::is_help(&args[1]))
    {
        println!("{}", cli::USAGE);
        return Ok(0);
    }
    if args.first().is_some_and(|arg| arg == "verify") {
        return verify::run(args.into_iter().skip(1), fixture).await;
    }
    if args.first().is_some_and(|arg| arg == "migrate-baseline") {
        if let [_, manager, file] = args.as_slice() {
            return baseline::migrate(
                &std::env::current_dir()?,
                manager.to_str().unwrap_or(""),
                Path::new(file),
            );
        }
        return Err(error("usage: veil-tell migrate-baseline npm|cargo FILE"));
    }
    if args.first().is_some_and(|arg| arg == "accept") {
        if args.len() != 1 {
            return Err(error(
                "accept takes no arguments; run veil-tell accept in the project directory",
            ));
        }
        return baseline::accept(&std::env::current_dir()?.canonicalize()?);
    }
    run(Options::parse(args)?, fixture).await
}

pub fn entry(fixture: Option<FixtureResolver>) -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = (|| {
        if args
            .first()
            .is_some_and(|arg| arg == attribution::WRAPPER_MODE)
        {
            isolation::mark_inherited_fds()?;
            return attribution::run_shell(&args[1..]);
        }
        if args
            .first()
            .is_some_and(|arg| arg == cargo_attribution::RUSTC_MODE)
        {
            return cargo_attribution::rustc(&args[1..]);
        }
        if args
            .first()
            .is_some_and(|arg| arg == cargo_attribution::BUILD_MODE)
        {
            return cargo_attribution::run_build(&args[1..]);
        }
        isolation::mark_inherited_fds()?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let result = runtime.block_on(dispatch(args, fixture));
        runtime.shutdown_timeout(Duration::from_millis(250));
        result
    })();
    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("veil-tell: {error}");
            eprintln!("Next / 次: veil-tell --help");
            ExitCode::from(SETUP_FAILURE)
        }
    }
}
