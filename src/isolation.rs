use crate::{Result, cli::Backend, error, proxy::Listener};
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Component, Path, PathBuf};
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
    pub npm_wrapper: Option<tempfile::TempDir>,
}

#[derive(Default)]
pub struct LaunchConfig<'a> {
    pub npm: bool,
    pub cargo: bool,
    pub node_manager: Option<&'a str>,
    pub node_attribution: bool,
    pub project_home: Option<&'a Path>,
    pub pnpm_runtime: Option<&'a crate::pnpm::Runtime>,
}

pub async fn prepare(
    backend: Backend,
    command: &[OsString],
    cwd: &Path,
    #[cfg_attr(not(target_os = "macos"), allow(unused_variables))] outputs: &[&Path],
    protected_dirs: &[&Path],
    secret: &str,
    config: LaunchConfig<'_>,
) -> Result<Launch> {
    let LaunchConfig {
        npm: attribute_npm,
        cargo: attribute_cargo,
        node_manager,
        node_attribution,
        ..
    } = config;
    #[cfg(target_os = "linux")]
    if backend == Backend::Isolated {
        return linux::prepare(command, cwd, secret, protected_dirs, config).await;
    }

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let wrapper = (attribute_npm
        || attribute_cargo
        || node_manager.is_some()
        || backend == Backend::Isolated)
        .then(tempfile::tempdir)
        .transpose()?;
    let shell = wrapper
        .as_ref()
        .filter(|_| attribute_npm)
        .map(|dir| dir.path().join("npm-shell"));
    if let Some(path) = &shell {
        crate::attribution::create_shell(path, &std::env::current_exe()?)?;
    }
    let rustc = wrapper
        .as_ref()
        .filter(|_| attribute_cargo)
        .map(|dir| dir.path().join("rustc-wrapper"));
    if let Some(path) = &rustc {
        crate::attribution::create_wrapper(
            path,
            &std::env::current_exe()?,
            crate::cargo_attribution::RUSTC_MODE,
        )?;
    }
    let node_hook = wrapper
        .as_ref()
        .filter(|_| node_attribution || backend == Backend::Isolated)
        .map(|dir| dir.path().join("node-dns.cjs"));
    if let Some(hook) = &node_hook {
        std::fs::write(hook, NODE_DNS_HOOK)?;
    }
    let (mut launch, temporary) = if backend == Backend::Isolated {
        #[cfg(target_os = "macos")]
        {
            let home = config
                .project_home
                .is_none()
                .then(tempfile::tempdir)
                .transpose()?;
            let home_path = config
                .project_home
                .or_else(|| home.as_ref().map(|dir| dir.path()))
                .unwrap();
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
                .chain(wrapper.as_ref().map(|dir| dir.path()))
                .chain(
                    config
                        .pnpm_runtime
                        .and_then(|runtime| runtime.corepack_cache.as_deref()),
                )
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
            restricted_env(&mut launch, home_path);
            if let Some(runtime) = config.pnpm_runtime.filter(|runtime| runtime.corepack) {
                crate::pnpm::configure_corepack(&mut launch, runtime.corepack_cache.as_deref());
            }
            (launch, home)
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
    if let Some(hook) = &node_hook {
        configure_node_dns(
            &mut launch,
            hook,
            port,
            secret,
            backend == Backend::Isolated,
        )?;
    }
    if let Some(manager) = node_manager {
        configure_manager(&mut launch, cwd, manager, port, secret, node_attribution);
    }
    if let Some(shell) = &shell {
        crate::attribution::configure(&mut launch, shell, cwd);
    }
    if let Some(rustc) = &rustc {
        crate::cargo_attribution::configure(&mut launch, rustc, cwd);
    }
    supervise_stdio(&mut launch);
    Ok(Launch {
        listener: Listener::Tcp(listener),
        command: launch,
        temporary,
        npm_wrapper: wrapper,
    })
}

pub async fn probe(cwd: &Path) -> Result<()> {
    let mut launch = prepare(
        Backend::Isolated,
        &["/usr/bin/true".into()],
        cwd,
        &[],
        &[],
        &crate::credential()?,
        LaunchConfig::default(),
    )
    .await?;
    let output =
        tokio::time::timeout(std::time::Duration::from_secs(5), launch.command.output()).await??;
    if output.status.success() {
        return Ok(());
    }
    let reason = String::from_utf8_lossy(&output.stderr);
    Err(error(
        reason
            .lines()
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("sandbox probe failed"),
    ))
}

pub fn project_home(cwd: &Path, protected: &[&Path]) -> Result<Option<PathBuf>> {
    let Some(relative) = std::env::var_os("VEIL_TELL_PROJECT_HOME") else {
        return Ok(None);
    };
    let invalid = || {
        error(
            "VEIL_TELL_PROJECT_HOME must name a real relative directory inside the workspace, for example .veil-home",
        )
    };
    let mut path = cwd.to_path_buf();
    for part in Path::new(&relative).components() {
        match part {
            Component::CurDir => {}
            Component::Normal(name) if name != ".git" && name != ".veil-tell" => path.push(name),
            _ => return Err(invalid()),
        }
    }
    if path == cwd
        || protected
            .iter()
            .any(|dir| path.starts_with(dir) || dir.starts_with(&path))
    {
        return Err(invalid());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    let mut directory = cwd.to_path_buf();
    for part in path.strip_prefix(cwd)?.components() {
        directory.push(part);
        match builder.create(&directory) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(err.into()),
        }
        if !directory.symlink_metadata()?.is_dir() {
            return Err(invalid());
        }
    }
    Ok(Some(path))
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

pub const NODE_DNS_HOOK: &str = include_str!("node_dns.cjs");

pub fn configure_node_dns(
    command: &mut Command,
    hook: &Path,
    port: u16,
    secret: &str,
    dns: bool,
) -> Result<()> {
    let hook = hook
        .to_str()
        .ok_or_else(|| error("the DNS hook path must be UTF-8"))?;
    let mut node_options = if dns {
        OsString::new()
    } else {
        std::env::var_os("NODE_OPTIONS").unwrap_or_default()
    };
    node_options.push(format!(" --require {}", serde_json::to_string(hook)?));
    command.env("NODE_OPTIONS", node_options);
    if dns {
        command.env(
            "VEIL_TELL_DNS_RELAY",
            format!("http://veil:{secret}@127.0.0.1:{port}"),
        );
    } else {
        command.env_remove("VEIL_TELL_DNS_RELAY");
    }
    Ok(())
}

pub fn configure_manager(
    command: &mut Command,
    cwd: &Path,
    manager: &str,
    port: u16,
    secret: &str,
    attribute: bool,
) {
    if attribute {
        command
            .env("VEIL_TELL_NODE_ROOT", cwd)
            .env("VEIL_TELL_NODE_MANAGER", manager);
    } else {
        command
            .env_remove("VEIL_TELL_NODE_ROOT")
            .env_remove("VEIL_TELL_NODE_MANAGER");
    }
    if manager == "pnpm" {
        command.env("npm_config_update_notifier", "false");
    }
    if manager == "yarn" {
        let proxy = format!("http://veil:{secret}@127.0.0.1:{port}");
        command
            .env("YARN_HTTP_PROXY", &proxy)
            .env("YARN_HTTPS_PROXY", proxy);
    }
}

pub const PROXY_VARS: [&str; 8] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "npm_config_proxy",
    "npm_config_https_proxy",
    "NPM_CONFIG_PROXY",
    "NPM_CONFIG_HTTPS_PROXY",
];

pub fn set_proxy(command: &mut Command, port: u16, secret: &str) {
    let url = format!("http://veil:{secret}@127.0.0.1:{port}");
    for key in PROXY_VARS {
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
