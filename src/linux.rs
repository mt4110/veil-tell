use super::{
    Launch, LaunchConfig, NODE_DNS_HOOK, restricted_env, set_proxy, shell_exit, supervise_stdio,
};
use crate::{Result, error, proxy::Listener};
use std::ffi::OsString;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::process::Command;
use tokio::task::JoinSet;
use tokio::time::timeout;

#[path = "linux_notify.rs"]
mod notify;
const CAPTURE_SOCKET: &str = "/veil-tell-capture.sock";
const RELAY_SOCKET: &str = "/veil-tell-proxy.sock";
const DNS_HOOK: &str = "/veil-tell-node-dns.cjs";
const RELAY_PROGRAM: &str = "/veil-tell-relay";
const SYSTEM_DIRS: &[&str] = &["/usr", "/bin", "/lib", "/lib64", "/nix/store"];
const COREPACK_CACHE: &str = "/veil-tell-corepack";

fn runtime_visible(path: &Path, cwd: &Path) -> bool {
    path.starts_with(cwd) || SYSTEM_DIRS.iter().any(|dir| path.starts_with(dir))
}

fn expose_tool(launch: &mut Command, cwd: &Path, entry: &Path, target: &Path) {
    if !runtime_visible(target, cwd) {
        launch.arg("--ro-bind").arg(target).arg(target);
    }
    if entry != target && !runtime_visible(entry, cwd) {
        launch.arg("--symlink").arg(target).arg(entry);
    }
}

pub async fn prepare(
    command: &[OsString],
    cwd: &Path,
    secret: &str,
    protected_dirs: &[&Path],
    config: LaunchConfig<'_>,
) -> Result<Launch> {
    let bwrap = std::env::var_os("VEIL_TELL_BWRAP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/bin/bwrap"));
    if !bwrap.is_absolute() || std::fs::metadata(&bwrap)?.permissions().mode() & 0o6000 != 0 {
        return Err(error("use an absolute, non-setuid bubblewrap path"));
    }
    let reserved = [
        "/", "/tmp", "/home", "/usr", "/bin", "/lib", "/lib64", "/etc", "/proc", "/dev", "/sys",
        "/nix",
    ];
    let home = std::env::var_os("HOME").and_then(|path| PathBuf::from(path).canonicalize().ok());
    if reserved.iter().any(|path| cwd == Path::new(path))
        || reserved[3..].iter().any(|path| cwd.starts_with(path))
        || home.as_ref().is_some_and(|home| home.starts_with(cwd))
    {
        return Err(error(
            "choose a project working directory outside system and home roots",
        ));
    }
    let temporary = tempfile::Builder::new()
        .prefix("veil-tell-")
        .tempdir_in("/tmp")?;
    let child_home = temporary.path().join("home");
    std::fs::create_dir(&child_home)?;
    let socket = temporary.path().join("proxy.sock");
    let listener = UnixListener::bind(&socket)?;
    let capture_path = temporary.path().join("capture.sock");
    let capture = std::os::unix::net::UnixDatagram::bind(&capture_path)?;
    capture.set_nonblocking(true)?;
    let mut launch = Command::new(bwrap);
    launch.env_clear().args([
        "--unshare-user",
        "--disable-userns",
        "--unshare-net",
        "--unshare-pid",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/tmp/veil-tell-home",
    ]);
    launch
        .arg("--bind")
        .arg(&child_home)
        .arg("/tmp/veil-tell-home");
    if let Some(cache) = config.cache
        && let Some(manager) = crate::manager::executable(command)
    {
        launch
            .arg("--bind")
            .arg(cache)
            .arg("/veil-tell-cache")
            .args(["--setenv", "VEIL_TELL_CACHE_MANAGER", manager]);
    }
    for &dir in SYSTEM_DIRS {
        if Path::new(dir).is_dir() {
            launch.args(["--ro-bind", dir, dir]);
        }
    }
    for file in ["/etc/ssl/certs", "/etc/pki", "/etc/ld.so.cache"] {
        if Path::new(file).exists() {
            launch.args(["--ro-bind", file, file]);
        }
    }
    // Keep the helper environment independent of the caller's loader configuration.
    launch
        .args(["--setenv", "PATH"])
        .arg(std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into()));
    for (key, value) in std::env::vars_os() {
        if matches!(key.to_str(), Some("LANG" | "TERM"))
            || key.to_str().is_some_and(|key| key.starts_with("LC_"))
        {
            launch.arg("--setenv").arg(key).arg(value);
        }
    }
    if config.npm {
        let wrapper = temporary.path().join("npm-shell");
        crate::attribution::create_shell(&wrapper, Path::new(RELAY_PROGRAM))?;
        launch
            .arg("--ro-bind")
            .arg(wrapper)
            .arg(crate::attribution::LINUX_SHELL);
        launch.args(["--setenv", "VEIL_TELL_RELAY_NPM", "1"]);
    }
    if config.cargo {
        let wrapper = temporary.path().join("rustc-wrapper");
        crate::attribution::create_wrapper(
            &wrapper,
            Path::new(RELAY_PROGRAM),
            crate::cargo_attribution::RUSTC_MODE,
        )?;
        launch
            .arg("--ro-bind")
            .arg(wrapper)
            .arg(crate::cargo_attribution::LINUX_WRAPPER);
        launch.args(["--setenv", "VEIL_TELL_RELAY_CARGO", "1"]);
    }
    if let Some(manager) = config.node_manager {
        launch.args(["--setenv", "VEIL_TELL_NODE_MANAGER", manager]);
        if config.node_attribution {
            launch.args(["--setenv", "VEIL_TELL_NODE_ATTRIBUTION", "1"]);
        }
    }
    let hook = temporary.path().join("node-dns.cjs");
    std::fs::write(&hook, NODE_DNS_HOOK)?;
    launch.arg("--ro-bind").arg(hook).arg(DNS_HOOK);
    launch.arg("--bind").arg(cwd).arg(cwd);
    for path in protected_dirs
        .iter()
        .filter(|path| path.is_dir() && path.starts_with(cwd))
    {
        launch.arg("--ro-bind").arg(path).arg(path);
    }
    if let Some(home) = config.project_home {
        launch.args(["--setenv", "VEIL_TELL_RELAY_HOME"]).arg(home);
    }
    if let Some(runtime) = config.pnpm_runtime {
        expose_tool(&mut launch, cwd, &runtime.path_entry, &runtime.program);
        for path in runtime.support_files() {
            if !runtime_visible(&path, cwd) {
                launch.arg("--ro-bind").arg(&path).arg(&path);
            }
        }
        if let Some((entry, node)) = &runtime.node {
            expose_tool(&mut launch, cwd, entry, node);
        }
        if runtime.corepack {
            launch.args(["--setenv", "VEIL_TELL_RELAY_COREPACK", "1"]);
        }
        if let Some(cache) = &runtime.corepack_cache {
            launch
                .arg("--ro-bind")
                .arg(cache.join("v1/pnpm"))
                .arg(format!("{COREPACK_CACHE}/v1/pnpm"));
            let known_good = cache.join("lastKnownGood.json");
            if known_good.symlink_metadata().is_ok_and(|m| m.is_file()) {
                launch
                    .arg("--ro-bind")
                    .arg(known_good)
                    .arg(format!("{COREPACK_CACHE}/lastKnownGood.json"));
            }
            launch.args(["--setenv", "VEIL_TELL_RELAY_COREPACK_CACHE", COREPACK_CACHE]);
        }
    }
    launch
        .arg("--ro-bind")
        .arg(capture_path)
        .arg(CAPTURE_SOCKET)
        .arg("--ro-bind")
        .arg(socket)
        .arg(RELAY_SOCKET)
        .arg("--ro-bind")
        .arg(std::env::current_exe()?)
        .arg(RELAY_PROGRAM)
        .arg("--chdir")
        .arg(cwd)
        .args(["--", RELAY_PROGRAM, "__veil_tell_linux_relay", secret])
        .args(command);
    supervise_stdio(&mut launch);
    Ok(Launch {
        listener: Listener::Unix(listener),
        command: launch,
        temporary: Some(temporary),
        capture: Some(capture),
        npm_wrapper: None,
    })
}

pub async fn inside(secret: &str, args: &[OsString]) -> Result<u8> {
    // A same-UID target must not be able to read or write the relay via /proc.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let ready = timeout(Duration::from_secs(3), UnixStream::connect(RELAY_SOCKET)).await??;
    drop(ready);
    let mut command = Command::new(&args[0]);
    command.args(&args[1..]).kill_on_drop(true);
    let home = std::env::var_os("VEIL_TELL_RELAY_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| "/tmp/veil-tell-home".into());
    restricted_env(&mut command, &home);
    if std::env::var_os("VEIL_TELL_RELAY_COREPACK").is_some() {
        let cache = std::env::var_os("VEIL_TELL_RELAY_COREPACK_CACHE");
        crate::pnpm::configure_corepack(&mut command, cache.as_deref().map(Path::new));
    }
    let port = listener.local_addr()?.port();
    if let Ok(manager) = std::env::var("VEIL_TELL_CACHE_MANAGER") {
        crate::manager_files::configure(&mut command, &manager, Path::new("/veil-tell-cache"));
    }
    set_proxy(&mut command, port, secret);
    super::configure_node_dns(&mut command, Path::new(DNS_HOOK), port, secret, true)?;
    if let Ok(manager) = std::env::var("VEIL_TELL_NODE_MANAGER") {
        super::configure_manager(
            &mut command,
            &std::env::current_dir()?,
            &manager,
            port,
            secret,
            std::env::var_os("VEIL_TELL_NODE_ATTRIBUTION").is_some(),
        );
    }
    if std::env::var_os("VEIL_TELL_RELAY_NPM").is_some() {
        crate::attribution::configure(
            &mut command,
            Path::new(crate::attribution::LINUX_SHELL),
            &std::env::current_dir()?,
        );
    }
    if std::env::var_os("VEIL_TELL_RELAY_CARGO").is_some() {
        crate::cargo_attribution::configure(
            &mut command,
            Path::new(crate::cargo_attribution::LINUX_WRAPPER),
            &std::env::current_dir()?,
        );
    }
    let filter = filter();
    // Only async-signal-safe kernel calls are made between fork and exec.
    unsafe {
        command.pre_exec(move || apply_filter(&filter));
    }
    let feedback = std::os::unix::net::UnixDatagram::unbound()?;
    feedback.connect(CAPTURE_SOCKET)?;
    let (mut child, capture) = notify::spawn(command)?;
    let mut tunnels = JoinSet::new();
    let result = loop {
        tokio::select! {
            status = child.wait() => break status.map(shell_exit),
            finished = tunnels.join_next(), if !tunnels.is_empty() => {
                if !matches!(finished, Some(Ok(true))) {
                    break Err(io::Error::other("lost the host proxy"));
                }
            }
            stream = listener.accept() => {
                let (mut stream, _) = stream?;
                if tunnels.len() >= 128 {
                    break Err(io::Error::other("relay reached its connection limit"));
                }
                tunnels.spawn(async move {
                    if let Ok(Ok(mut upstream)) = timeout(Duration::from_secs(3), UnixStream::connect(RELAY_SOCKET)).await {
                        let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                        true
                    } else {
                        false
                    }
                });
            }
        }
    };
    drop(listener);
    let drained = timeout(Duration::from_millis(150), async {
        while let Some(finished) = tunnels.join_next().await {
            if !matches!(finished, Ok(true)) {
                return Err(error("lost the host proxy"));
            }
        }
        Ok(())
    })
    .await;
    tunnels.shutdown().await;
    if let Ok(result) = drained {
        result?;
    }
    if let Some(snapshot) = capture.and_then(|capture| capture.snapshot()) {
        let bytes = serde_json::to_vec(&snapshot)?;
        feedback.send(&bytes)?;
    }
    Ok(result?)
}

fn instruction(code: u32, yes: u8, no: u8, value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt: yes,
        jf: no,
        k: value,
    }
}

fn filter() -> Vec<libc::sock_filter> {
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc00000b7;
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000003e;
    const LOAD: u32 = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
    const EQUAL: u32 = libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K;
    const AT_LEAST: u32 = libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K;
    const RETURN: u32 = libc::BPF_RET | libc::BPF_K;
    const DENIED: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    // seccomp_data: syscall at 0, audit architecture at 4, arguments at 16.
    let mut code = vec![
        instruction(LOAD, 0, 0, 4),
        instruction(EQUAL, 1, 0, ARCH),
        instruction(RETURN, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
        instruction(LOAD, 0, 0, 0),
        instruction(AT_LEAST, 0, 1, 0x40000000),
        instruction(RETURN, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
    ];
    for syscall in [
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_ptrace,
        libc::SYS_pidfd_getfd,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_setns,
        libc::SYS_unshare,
    ] {
        code.push(instruction(EQUAL, 0, 1, syscall as u32));
        code.push(instruction(RETURN, 0, 0, DENIED));
    }
    code.extend([
        instruction(EQUAL, 0, 4, libc::SYS_socketpair as u32),
        instruction(LOAD, 0, 0, 16),
        instruction(EQUAL, 0, 1, libc::AF_UNIX as u32),
        instruction(RETURN, 0, 0, libc::SECCOMP_RET_ALLOW),
        instruction(RETURN, 0, 0, DENIED),
    ]);
    code.extend([
        instruction(EQUAL, 0, 4, libc::SYS_socket as u32),
        instruction(LOAD, 0, 0, 16),
        instruction(EQUAL, 2, 0, libc::AF_INET as u32),
        instruction(EQUAL, 1, 0, libc::AF_INET6 as u32),
        instruction(RETURN, 0, 0, DENIED),
        instruction(RETURN, 0, 0, libc::SECCOMP_RET_ALLOW),
    ]);
    code
}

fn apply_filter(code: &[libc::sock_filter]) -> io::Result<()> {
    let program = libc::sock_fprog {
        len: code.len() as u16,
        filter: code.as_ptr().cast_mut(),
    };
    // The kernel copies the filter while the program and backing slice remain live.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
