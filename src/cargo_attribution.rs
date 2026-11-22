use crate::attribution::{self, Package};
use crate::{Result, error};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write;
use std::os::unix::{
    fs::{MetadataExt, PermissionsExt},
    process::CommandExt,
};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const RUSTC_MODE: &str = "__veil_tell_rustc";
pub const BUILD_MODE: &str = "__veil_tell_build_script";
#[cfg(target_os = "linux")]
pub const LINUX_WRAPPER: &str = "/veil-tell-rustc";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Toolchain {
    pub cargo: PathBuf,
    pub bin_dir: PathBuf,
    pub bind_root: PathBuf,
}

impl Toolchain {
    pub fn resolve(command: &[OsString], cwd: &Path) -> Option<Self> {
        let path_env =
            std::env::var_os("PATH").unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into());
        Self::resolve_with_path(command, cwd, &path_env)
    }

    fn resolve_with_path(command: &[OsString], cwd: &Path, path_env: &OsStr) -> Option<Self> {
        let program = command.first()?;
        let (entry, resolved) = find_executable(program, cwd, path_env)?;
        let rustup = rustup_binary(&entry, &resolved, cwd, path_env)?;
        let output = Command::new(rustup)
            .arg0("rustup")
            .args(["which", "cargo"])
            .current_dir(cwd)
            .env("PATH", path_env)
            // Block any implicit toolchain download while querying the active toolchain path.
            .env("HTTP_PROXY", "http://127.0.0.1:9")
            .env("HTTPS_PROXY", "http://127.0.0.1:9")
            .env("ALL_PROXY", "http://127.0.0.1:9")
            .env("RUSTUP_AUTO_INSTALL", "0")
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let raw_path = std::str::from_utf8(&output.stdout).ok()?.trim();
        if raw_path.is_empty() {
            return None;
        }
        let cargo = PathBuf::from(raw_path).canonicalize().ok()?;
        if cargo == resolved {
            return None;
        }
        let bin_dir = cargo.parent()?.to_path_buf();
        let bind_root = bin_dir.parent()?.to_path_buf();
        let cargo_meta = cargo.metadata().ok()?;
        let rustc_meta = bin_dir.join("rustc").metadata().ok()?;
        (cargo_meta.is_file()
            && cargo_meta.mode() & 0o111 != 0
            && rustc_meta.is_file()
            && rustc_meta.mode() & 0o111 != 0)
            .then_some(Self {
                cargo,
                bin_dir,
                bind_root,
            })
    }

    pub fn command(&self, command: &[OsString]) -> Vec<OsString> {
        std::iter::once(self.cargo.clone().into_os_string())
            .chain(command[1..].iter().cloned())
            .collect()
    }
}

fn find_executable(program: &OsStr, cwd: &Path, path_env: &OsStr) -> Option<(PathBuf, PathBuf)> {
    let resolve = |candidate: PathBuf| {
        let entry = cwd.join(candidate);
        let resolved = entry.canonicalize().ok()?;
        let metadata = resolved.metadata().ok()?;
        (metadata.is_file() && metadata.mode() & 0o111 != 0).then_some((entry, resolved))
    };
    let path = Path::new(program);
    if path.as_os_str().as_encoded_bytes().contains(&b'/') {
        return resolve(path.to_path_buf());
    }
    std::env::split_paths(path_env).find_map(|dir| resolve(dir.join(program)))
}

fn rustup_binary(entry: &Path, resolved: &Path, _cwd: &Path, _path_env: &OsStr) -> Option<PathBuf> {
    if matches!(
        resolved.file_name().and_then(OsStr::to_str),
        Some("rustup" | "rustup-init")
    ) {
        return Some(resolved.to_path_buf());
    }
    let entry_dir = entry.parent()?;
    let resolved_dir = resolved.parent()?;
    for dir in [entry_dir, resolved_dir] {
        let sibling = dir.join("rustup");
        if let Ok(meta) = sibling.metadata()
            && meta.is_file()
            && meta.mode() & 0o111 != 0
        {
            return Some(sibling);
        }
    }
    None
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_rustup_shim_without_touching_plain_cargo() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();

        // 1. Plain cargo alongside rustc (no rustup shim) -> returns None
        let plain_bin = root.join("plain-bin");
        fs::create_dir(&plain_bin).unwrap();
        for name in ["cargo", "rustc"] {
            let p = plain_bin.join(name);
            fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert_eq!(
            Toolchain::resolve_with_path(&[OsString::from("cargo")], &root, plain_bin.as_os_str()),
            None
        );

        // 2. Rustup shim directory with hardlinked/symlinked cargo -> resolves toolchain
        let toolchain = root.join("rustup/toolchains/stable");
        let tc_bin = toolchain.join("bin");
        fs::create_dir_all(&tc_bin).unwrap();
        for name in ["cargo", "rustc"] {
            let p = tc_bin.join(name);
            fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let shim_bin = root.join("cargo-home/bin");
        fs::create_dir_all(&shim_bin).unwrap();
        let rustup = shim_bin.join("rustup");
        let tc_cargo = tc_bin.join("cargo");
        fs::write(
            &rustup,
            format!("#!/bin/sh\nif [ \"$1\" = which ] && [ \"$2\" = cargo ]; then echo \"{}\"; exit 0; fi\nexit 1\n", tc_cargo.display()),
        )
        .unwrap();
        fs::set_permissions(&rustup, fs::Permissions::from_mode(0o755)).unwrap();
        let shim_cargo = shim_bin.join("cargo");
        let shim_rustc = shim_bin.join("rustc");
        fs::hard_link(&rustup, &shim_cargo).unwrap();
        fs::hard_link(&rustup, &shim_rustc).unwrap();

        let resolved = Toolchain::resolve_with_path(
            &[OsString::from("cargo")],
            &root,
            shim_bin.as_os_str(),
        )
        .unwrap();
        assert_eq!(resolved.cargo, tc_cargo);
        assert_eq!(resolved.bin_dir, tc_bin);
        assert_eq!(resolved.bind_root, toolchain);

        // 3. Symlink to rustup-init in another directory (Homebrew rustup style) -> resolves toolchain
        let brew_opt = root.join("brew/opt/rustup/bin");
        let brew_bin = root.join("brew/bin");
        fs::create_dir_all(&brew_opt).unwrap();
        fs::create_dir_all(&brew_bin).unwrap();
        let rustup_init = brew_opt.join("rustup-init");
        fs::copy(&rustup, &rustup_init).unwrap();
        fs::set_permissions(&rustup_init, fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(&rustup_init, brew_bin.join("cargo")).unwrap();
        let resolved_brew =
            Toolchain::resolve_with_path(&[OsString::from("cargo")], &root, brew_bin.as_os_str())
                .unwrap();
        assert_eq!(resolved_brew.cargo, tc_cargo);
    }
}
