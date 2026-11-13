use crate::attribution::{self, Package};
use crate::{Result, error};
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::os::unix::{fs::PermissionsExt, process::CommandExt};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const RUSTC_MODE: &str = "__veil_tell_rustc";
pub const BUILD_MODE: &str = "__veil_tell_build_script";
#[cfg(target_os = "linux")]
pub const LINUX_WRAPPER: &str = "/veil-tell-rustc";

pub fn configure(command: &mut tokio::process::Command, wrapper: &Path, cwd: &Path) {
    command
        .env("RUSTC_WRAPPER", wrapper)
        .env("VEIL_TELL_CARGO_ROOT", cwd);
}

pub fn rustc(args: &[OsString]) -> Result<u8> {
    let (compiler, flags) = args
        .split_first()
        .ok_or_else(|| error("missing rustc executable"))?;
    let mut cmd = Command::new(compiler);
    cmd.args(flags);
    let output = build_output(flags);
    if output.is_none() {
        return Err(cmd.exec().into());
    }
    let status = cmd.status()?;
    if status.success()
        && let Some(output) = output
        && fs::symlink_metadata(&output).is_ok_and(|m| m.is_file())
        && let Err(err) = wrap(&output)
    {
        eprintln!("veil-tell: Cargo build-script attribution unavailable: {err}");
    }
    Ok(crate::isolation::shell_exit(status))
}

fn build_output(flags: &[OsString]) -> Option<PathBuf> {
    let value = |flag: &str| {
        flags.iter().enumerate().find_map(|(i, arg)| {
            let arg = arg.to_str()?;
            if arg == flag {
                flags.get(i + 1)?.to_str()
            } else {
                arg.strip_prefix(flag)?.strip_prefix('=')
            }
        })
    };
    if value("--crate-name")? != "build_script_build"
        || value("--crate-type")? != "bin"
        || !value("--emit")?.split(',').any(|e| e == "link")
    {
        return None;
    }
    let suffix = flags
        .windows(2)
        .filter(|pair| pair[0] == "-C")
        .filter_map(|pair| pair[1].to_str()?.strip_prefix("extra-filename="))
        .next()
        .unwrap_or("");
    if !suffix
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return None;
    }
    Some(PathBuf::from(value("--out-dir")?).join(format!("build_script_build{suffix}")))
}

fn wrap(output: &Path) -> Result<()> {
    let output = output.canonicalize()?;
    let parent = output
        .parent()
        .ok_or_else(|| error("missing Cargo output directory"))?;
    // A unique sidecar keeps already-running build scripts valid during recompilation.
    let sidecar = tempfile::Builder::new()
        .prefix("veil-build-")
        .tempfile_in(parent)?;
    fs::copy(&output, sidecar.path())?;
    let binary = attribution::shell_quote(&std::env::current_exe()?)?;
    let script = attribution::shell_quote(sidecar.path())?;
    let mut launcher = tempfile::NamedTempFile::new_in(parent)?;
    writeln!(
        launcher,
        "#!/bin/sh\nif [ -n \"${{VEIL_TELL_CARGO_ROOT:-}}\" ] && [ -x {binary} ]; then\n  exec {binary} {BUILD_MODE} {script} \"$@\"\nfi\nexec {script} \"$@\""
    )?;
    launcher
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o755))?;
    // Retain the sidecar with Cargo's other artifacts. cargo clean removes it.
    let _ = sidecar.keep()?;
    launcher.persist(&output)?;
    Ok(())
}

pub fn run_build(args: &[OsString]) -> Result<u8> {
    let (program, args) = args
        .split_first()
        .ok_or_else(|| error("missing build script executable"))?;
    let mut command = Command::new(program);
    command.args(args);
    attribution::annotate(&mut command, identify());
    Err(command.exec().into())
}

fn identify() -> Option<Package> {
    let root = PathBuf::from(std::env::var_os("VEIL_TELL_CARGO_ROOT")?)
        .canonicalize()
        .ok()?;
    let cwd = std::env::current_dir().ok()?.canonicalize().ok()?;
    let claimed = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR")?)
        .canonicalize()
        .ok()?;
    if claimed != cwd {
        return None;
    }
    let name = std::env::var("CARGO_PKG_NAME").ok()?;
    let version = std::env::var("CARGO_PKG_VERSION").ok()?;
    let manifest = attribution::read_manifest(&cwd.join("Cargo.toml"))?;
    let manifest: toml::Value = toml::from_str(std::str::from_utf8(&manifest).ok()?).ok()?;
    let package = manifest.get("package")?;
    if package.get("name")?.as_str()? != name || package.get("version")?.as_str()? != version {
        return None;
    }
    let relative = cwd.strip_prefix(&root).ok().and_then(Path::to_str);
    let path = match relative {
        Some("") => ".".into(),
        Some(path) => path.into(),
        None => format!("external/{name}-{version}"),
    };
    let package = Package {
        name,
        version,
        script: "build.rs".into(),
        path,
    };
    package.valid().then_some(package)
}
