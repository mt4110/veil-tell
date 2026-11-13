use crate::{Result, cli::Backend, error, proxy::Listener};
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::Path;
use std::process::Stdio;
use tokio::net::TcpListener;
use tokio::process::Command;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
pub mod linux;

pub struct Launch {
    pub listener: Listener,
    pub command: Command,
    // Retain the private home or Unix socket directory until the session ends.
    pub temporary: Option<tempfile::TempDir>,
}

pub async fn prepare(
    backend: Backend,
    command: &[OsString],
    cwd: &Path,
    #[cfg_attr(not(target_os = "macos"), allow(unused_variables))] outputs: &[&Path],
    #[cfg_attr(not(target_os = "macos"), allow(unused_variables))] protected_dirs: &[&Path],
    secret: &str,
) -> Result<Launch> {
    #[cfg(target_os = "linux")]
    if backend == Backend::Isolated {
        return linux::prepare(command, cwd, secret).await;
    }

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let (mut launch, temporary) = if backend == Backend::Isolated {
        #[cfg(target_os = "macos")]
        {
            let home = tempfile::tempdir()?;
            // Named Mach and XPC services can perform network I/O outside the sandbox.
            let mut profile = format!(
                "(version 1)\n(allow default)\n(deny network*)\n\
                 (deny mach-lookup mach-register)\n\
                 (allow network-outbound (remote tcp4 \"localhost:{port}\"))\n"
            );
            for directory in outputs
                .iter()
                .filter_map(|output| output.parent())
                .chain(protected_dirs.iter().copied())
            {
                let path = directory
                    .to_str()
                    .ok_or_else(|| error("output directory must be UTF-8"))?;
                profile.push_str(&format!(
                    "(deny file-write* (subpath {}))\n",
                    serde_json::to_string(path)?
                ));
            }
            let mut launch = Command::new("/usr/bin/sandbox-exec");
            launch.args(["-p", &profile]).args(command);
            restricted_env(&mut launch, home.path());
            (launch, Some(home))
        }
        #[cfg(not(target_os = "macos"))]
        return Err(error("the isolated backend is unavailable on this OS"));
    } else {
        let mut launch = Command::new(&command[0]);
        launch.args(&command[1..]);
        (launch, None)
    };
    launch.current_dir(cwd);
    set_proxy(&mut launch, port, secret);
    supervise_stdio(&mut launch);
    Ok(Launch {
        listener: Listener::Tcp(listener),
        command: launch,
        temporary,
    })
}

pub fn restricted_env(command: &mut Command, home: &Path) {
    command.env_clear().env("HOME", home);
    for (key, value) in std::env::vars_os() {
        if matches!(key.to_str(), Some("PATH" | "LANG" | "TERM"))
            || key.to_str().is_some_and(|key| key.starts_with("LC_"))
        {
            command.env(key, value);
        }
    }
    if std::env::var_os("PATH").is_none() {
        command.env("PATH", "/usr/local/bin:/usr/bin:/bin");
    }
}

pub fn set_proxy(command: &mut Command, port: u16, secret: &str) {
    let url = format!("http://veil:{secret}@127.0.0.1:{port}");
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "npm_config_proxy",
        "npm_config_https_proxy",
        "NPM_CONFIG_PROXY",
        "NPM_CONFIG_HTTPS_PROXY",
    ] {
        command.env(key, &url);
    }
    for key in [
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
        "npm_config_noproxy",
        "NPM_CONFIG_NOPROXY",
    ] {
        command.env_remove(key);
    }
    command.env("npm_config_noproxy", "");
}

pub fn supervise_stdio(command: &mut Command) {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
}

pub fn mark_inherited_fds() -> Result<()> {
    // Run before creating threads. The standard library and Tokio open new FDs with CLOEXEC.
    let fds = std::fs::read_dir("/dev/fd")?.collect::<io::Result<Vec<_>>>()?;
    for fd in fds {
        if let Some(fd) = fd
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<libc::c_int>().ok())
            && fd > 2
        {
            // The directory descriptor itself may already be closed.
            if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EBADF) {
                    return Err(error.into());
                }
            }
        }
    }
    Ok(())
}

pub fn check_isolated_paths(cwd: &Path, policy: Option<&Path>, outputs: &[&Path]) -> Result<()> {
    if let Some(policy) = policy
        && policy.canonicalize()?.starts_with(cwd)
    {
        return Err(error(
            "the policy is inside the isolated working directory; move it to a sibling directory, for example ../state/policy.toml",
        ));
    }
    if outputs
        .iter()
        .any(|output| output.starts_with(cwd) || cwd.starts_with(output.parent().unwrap()))
    {
        return Err(error(
            "isolated output directory cannot be the working directory, its descendant, or its ancestor; create a sibling directory, for example mkdir -p ../state, then use ../state/report.json / 出力先には作業ディレクトリとその親・配下を指定できません。兄弟ディレクトリの ../state/report.json を使ってください",
        ));
    }
    Ok(())
}

pub fn shell_exit(status: std::process::ExitStatus) -> u8 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .map(|code| code as u8)
        .unwrap_or_else(|| 128_u8.saturating_add(status.signal().unwrap_or(1) as u8))
}

pub fn terminate_group(pid: Option<u32>) {
    if let Some(pid) = pid.and_then(|pid| i32::try_from(pid).ok()) {
        // Each supervised command starts its own process group.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
}

pub fn is_help(arg: &OsStr) -> bool {
    arg == "--help" || arg == "-h"
}
