mod cli;
mod isolation;
mod policy;
mod proxy;
mod report;

use base64::Engine;
use cli::{Backend, Mode, Options};
use report::{Coverage, OutputFile, Report, RunStatus};
use std::ffi::OsString;
use std::io::{self, Read};
use std::net::SocketAddr;
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

async fn run(options: Options, fixture: Option<FixtureResolver>) -> Result<u8> {
    let cwd = std::env::current_dir()?.canonicalize()?;
    let policy = options
        .policy
        .as_deref()
        .map(policy::Policy::read)
        .transpose()?
        .unwrap_or_default();
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
    let outputs: Vec<_> = report
        .iter()
        .chain(&policy_output)
        .map(OutputFile::path)
        .collect();
    if options.backend == Backend::Isolated {
        isolation::check_isolated_paths(&cwd, options.policy.as_deref(), &outputs)?;
    }
    let secret = credential()?;
    let proxy = Arc::new(proxy::Proxy {
        mode: options.mode,
        policy,
        auth: format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("veil:{secret}"))
        ),
        records: report::Records::default(),
        incomplete: AtomicBool::new(false),
        interfaces: proxy::host_interfaces()?,
        fixture,
    });
    let isolation::Launch {
        listener,
        mut command,
        temporary: _temporary,
    } = isolation::prepare(options.backend, &options.command, &cwd, &outputs, &secret).await?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
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
        _ = interrupt.recv() => {
            infrastructure_failure = Some((130, "interrupted"));
            None
        }
        _ = terminate.recv() => {
            infrastructure_failure = Some((143, "interrupted"));
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
    eprintln!(
        "veil-tell: {reason} (exit {exit_code}). Recorded HTTP CONNECT requests: {connect_requests}. Direct connection attempts are outside the capture scope."
    );
    let isolation = match options.backend {
        Backend::Proxy => "not_requested",
        Backend::Isolated
            if status.is_some_and(|status| status.success()) || !destinations.is_empty() =>
        {
            "applied"
        }
        Backend::Isolated => "unconfirmed",
    };
    if let Some(file) = report {
        file.save_report(&Report {
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
                } else {
                    "while_running"
                },
            },
            child_status: status.map(Into::into),
            run_status: RunStatus { exit_code, reason },
            destinations,
        })?;
    }
    Ok(exit_code)
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
    if args.first().is_some_and(|arg| isolation::is_help(arg)) {
        println!("{}", cli::USAGE);
        return Ok(0);
    }
    run(Options::parse(args)?, fixture).await
}

pub fn entry(fixture: Option<FixtureResolver>) -> ExitCode {
    let args = std::env::args_os().skip(1).collect();
    let result = (|| {
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
            ExitCode::from(SETUP_FAILURE)
        }
    }
}
