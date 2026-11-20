use crate::{
    Backend, Coverage, FixtureResolver, Mode, Report, Result, RunSignals, RunStatus, SETUP_FAILURE,
    credential, error, isolation, proxy, session, upstream::Upstream,
};
use base64::Engine;
use std::{
    ffi::OsString,
    path::Path,
    sync::{Arc, atomic::Ordering},
};
use tokio::{net::TcpListener, process::Command, sync::oneshot};

const LOCAL_PROXY: &str = "VEIL_TELL_AGENT_LOCAL_PROXY";
const UPSTREAM: &str = "VEIL_TELL_AGENT_UPSTREAM";

fn https_proxy() -> Option<OsString> {
    std::env::var_os("HTTPS_PROXY").or_else(|| std::env::var_os("https_proxy"))
}

// A shim starts its own collector and applies its ordinary install policy. Chain
// that collector to the original upstream so its traffic is counted only once.
pub(super) fn restore_upstream(command: &mut std::process::Command) {
    if let Some(local) = std::env::var_os(LOCAL_PROXY)
        && https_proxy().as_ref() == Some(&local)
    {
        for key in ["HTTPS_PROXY", "https_proxy"] {
            if let Some(original) = std::env::var_os(UPSTREAM) {
                command.env(key, original);
            } else {
                command.env_remove(key);
            }
        }
    }
    command.env_remove(UPSTREAM).env_remove(LOCAL_PROXY);
}

pub(super) async fn run(args: &[OsString], fixture: Option<FixtureResolver>) -> Result<u8> {
    let [separator, program, rest @ ..] = args else {
        return Err(error("usage: veil-tell agent -- COMMAND [ARG...]"));
    };
    if separator != "--" || program.is_empty() {
        return Err(error("usage: veil-tell agent -- COMMAND [ARG...]"));
    }
    let cwd = std::env::current_dir()?;
    let result = observe(program, rest, fixture).await;
    // Free-form arguments can contain prompts, credentials or tool payloads.
    let name = Path::new(program).file_name().unwrap_or(program).to_owned();
    if let Err(e) = session::append(&cwd, &[name], result.as_ref().ok(), true) {
        eprintln!("veil-tell: session log: {e}");
    }
    Ok(result?.run_status.exit_code)
}

async fn observe(
    program: &OsString,
    args: &[OsString],
    fixture: Option<FixtureResolver>,
) -> Result<Report> {
    let shims = session::install_shims()?;
    let path = std::env::var_os("PATH").unwrap_or_default();
    let path = std::env::join_paths(
        std::iter::once(shims.clone()).chain(std::env::split_paths(&path).filter(|p| p != &shims)),
    )?;
    let original = https_proxy()
        .or_else(|| std::env::var_os("ALL_PROXY"))
        .or_else(|| std::env::var_os("all_proxy"))
        .filter(|s| !s.is_empty());
    let upstream = match &original {
        Some(url) => Some(
            Upstream::from_url(
                url.to_str()
                    .ok_or_else(|| error("invalid upstream proxy URL"))?,
            )?
            .ok_or_else(|| error("agent observation supports an http:// CONNECT upstream proxy"))?,
        ),
        None => None,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let secret = credential()?;
    let url = format!("http://veil:{secret}@{}", listener.local_addr()?);
    let proxy = Arc::new(proxy::Proxy {
        mode: Mode::Observe,
        shared_read_idle: Some(std::time::Duration::from_secs(300)),
        policy: Default::default(),
        ci_hosts: None,
        auth: format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("veil:{secret}"))
        ),
        attribute_npm: false,
        compare_unauthenticated: false,
        records: Default::default(),
        budgets: Default::default(),
        dns_attempts: None,
        incomplete: Default::default(),
        allow_fake_ip: std::env::var_os("VEIL_TELL_ALLOW_FAKE_IP").is_some_and(|s| s == "1"),
        upstream,
        interfaces: proxy::host_interfaces()?,
        fixture,
    });
    let mut command = Command::new(program);
    command
        .args(args)
        .env("PATH", path)
        .env("HTTPS_PROXY", &url)
        .env("https_proxy", &url)
        .env(LOCAL_PROXY, &url)
        .env_remove(UPSTREAM)
        .env("NODE_USE_ENV_PROXY", "1")
        .kill_on_drop(true);
    if let Some(original) = original {
        command.env(UPSTREAM, original);
    }
    // Inherit all three terminal descriptors and the foreground process group.
    // TUIs manage terminal modes themselves and receive normal terminal signals.
    let mut signals = RunSignals::new()?;
    let mut child = command.spawn()?;
    let (stop, stopped) = oneshot::channel();
    let mut server = tokio::spawn(proxy::serve(
        proxy::Listener::Tcp(listener),
        Arc::clone(&proxy),
        stopped,
    ));
    let (status, proxy_ok) = loop {
        tokio::select! {
            result = child.wait() => {
                let _ = stop.send(());
                break (result?, matches!(server.await, Ok(Ok(()))));
            }
            _ = &mut server => {
                child.start_kill()?;
                break (child.wait().await?, false);
            }
            signal = signals.interrupted() => {
                let signal = i32::from(signal) - 128;
                // The terminal delivers Ctrl-C to every foreground group member.
                // A second SIGINT could turn a cancelled prompt into an agent exit.
                let terminal_interrupt = signal == libc::SIGINT
                    && unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) == libc::getpgrp() };
                if !terminal_interrupt && let Some(pid) = child.id() {
                    unsafe { libc::kill(pid as i32, signal) };
                }
            }
        }
    };
    let code = isolation::shell_exit(status);
    let (exit_code, reason) = if !proxy_ok {
        (SETUP_FAILURE, "proxy_stopped")
    } else if proxy.incomplete.load(Ordering::Relaxed) {
        (SETUP_FAILURE, "incomplete_capture")
    } else if status.success() {
        (0, "completed")
    } else {
        (code, "child_failed")
    };
    Ok(Report {
        schema_version: 1,
        backend: Backend::Proxy,
        mode: Mode::Observe,
        isolation: "not_requested",
        coverage: Coverage {
            proxy: "http_connect_requests",
            direct_attempt_destinations: "not_observed",
            dns_attempts: "not_observed",
            proxy_capture: match reason {
                "proxy_stopped" => "until_proxy_stopped",
                "incomplete_capture" => "incomplete",
                _ => "while_running",
            },
        },
        child_status: Some(status.into()),
        run_status: RunStatus { exit_code, reason },
        destinations: proxy.records.snapshot(),
        direct_attempts: None,
        volume_anomalies: Vec::new(),
        attempted: None,
        comparison: None,
    })
}
