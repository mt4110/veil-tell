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
    pub has_toolchain_selector: bool,
}

enum RustupInstallation {
    SharedBinary(PathBuf),
    HomebrewBin(PathBuf),
}

impl Toolchain {
    pub fn resolve(command: &[OsString], cwd: &Path) -> Option<Self> {
        let path_env =
            std::env::var_os("PATH").unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into());
        let cargo_home = std::env::var_os("CARGO_HOME").map(PathBuf::from);
        let default_home = std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo"));
        let mut installations: Vec<RustupInstallation> = [cargo_home, default_home]
            .into_iter()
            .flatten()
            .filter(|home| home.is_absolute())
            .map(|home| RustupInstallation::SharedBinary(home.join("bin/rustup")))
            .collect();
        installations.extend(
            ["/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"]
                .into_iter()
                .flat_map(|dir| ["rustup", "rustup-init"].map(|name| Path::new(dir).join(name)))
                .map(RustupInstallation::SharedBinary),
        );
        if cfg!(target_os = "macos") {
            installations.extend(
                ["/opt/homebrew/opt/rustup/bin", "/usr/local/opt/rustup/bin"]
                    .into_iter()
                    .map(|dir| RustupInstallation::HomebrewBin(PathBuf::from(dir))),
            );
        }
        Self::resolve_with_path(command, cwd, &path_env, &installations)
    }

    fn resolve_with_path(
        command: &[OsString],
        cwd: &Path,
        path_env: &OsStr,
        installations: &[RustupInstallation],
    ) -> Option<Self> {
        let program = command.first()?;
        let resolved = find_executable(program, cwd, path_env)?;
        let rustup = rustup_binary(&resolved, cwd, installations)?;
        let selector = command
            .get(1)
            .and_then(|arg| arg.to_str())
            .and_then(|s| s.strip_prefix('+'))
            .filter(|s| !s.is_empty());
        let mut cmd = Command::new(rustup);
        cmd.arg0("rustup").arg("which");
        if let Some(toolchain) = selector {
            cmd.args(["--toolchain", toolchain]);
        }
        let output = cmd
            .arg("cargo")
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
                has_toolchain_selector: selector.is_some(),
            })
    }

    pub fn command(&self, command: &[OsString]) -> Vec<OsString> {
        let skip = if self.has_toolchain_selector && command.len() >= 2 {
            2
        } else {
            1
        };
        std::iter::once(self.cargo.clone().into_os_string())
            .chain(command[skip..].iter().cloned())
            .collect()
    }
}

fn find_executable(program: &OsStr, cwd: &Path, path_env: &OsStr) -> Option<PathBuf> {
    let resolve = |candidate: PathBuf| {
        let resolved = cwd.join(candidate).canonicalize().ok()?;
        let metadata = resolved.metadata().ok()?;
        (metadata.is_file() && metadata.mode() & 0o111 != 0).then_some(resolved)
    };
    let path = Path::new(program);
    if path.as_os_str().as_encoded_bytes().contains(&b'/') {
        return resolve(path.to_path_buf());
    }
    std::env::split_paths(path_env).find_map(|dir| resolve(dir.join(program)))
}

fn rustup_binary(
    cargo: &Path,
    cwd: &Path,
    installations: &[RustupInstallation],
) -> Option<PathBuf> {
    if cargo.starts_with(cwd) {
        return None;
    }
    let cargo_meta = cargo.metadata().ok()?;
    installations.iter().find_map(|installation| {
        let candidate = match installation {
            RustupInstallation::SharedBinary(path) => path.clone(),
            // Homebrew installs separate environment wrappers for cargo and rustup.
            RustupInstallation::HomebrewBin(bin) => bin.join("rustup"),
        };
        let rustup = candidate.canonicalize().ok()?;
        let meta = rustup.metadata().ok()?;
        if candidate.starts_with(cwd)
            || rustup.starts_with(cwd)
            || !meta.is_file()
            || meta.mode() & 0o111 == 0
        {
            return None;
        }
        let known_shim = match installation {
            RustupInstallation::SharedBinary(_) => {
                (meta.dev(), meta.ino()) == (cargo_meta.dev(), cargo_meta.ino())
            }
            RustupInstallation::HomebrewBin(bin) => {
                let bin = bin.canonicalize().ok()?;
                cargo.parent() == Some(bin.as_path())
                    && rustup.parent() == Some(bin.as_path())
                    && cargo.file_name() == Some(OsStr::new("cargo"))
            }
        };
        known_shim.then_some(rustup)
    })
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
    fn probe_requires_a_matching_host_installation() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().canonicalize().unwrap();
        let cargo = project.join("cargo");
        let rustup = project.join("rustup");
        fs::write(&rustup, "").unwrap();
        fs::set_permissions(&rustup, fs::Permissions::from_mode(0o755)).unwrap();
        fs::hard_link(&rustup, &cargo).unwrap();

        assert_eq!(
            rustup_binary(
                &cargo,
                &project,
                &[RustupInstallation::SharedBinary(rustup.clone())]
            ),
            None
        );

        let host = tempfile::tempdir().unwrap();
        let host_rustup = host.path().join("rustup");
        fs::copy(&rustup, &host_rustup).unwrap();
        assert_eq!(
            rustup_binary(
                &cargo,
                &project,
                &[RustupInstallation::SharedBinary(host_rustup)]
            ),
            None
        );
    }

    #[test]
    fn resolves_rustup_shim_without_touching_plain_cargo() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let project = root.join("project");
        fs::create_dir(&project).unwrap();

        // 1. Plain cargo alongside rustc (no rustup shim) -> returns None
        let plain_bin = root.join("plain-bin");
        fs::create_dir(&plain_bin).unwrap();
        for name in ["cargo", "rustc"] {
            let p = plain_bin.join(name);
            fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert_eq!(
            Toolchain::resolve_with_path(
                &[OsString::from("cargo")],
                &project,
                plain_bin.as_os_str(),
                &[]
            ),
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
        let pinned_toolchain = root.join("rustup/toolchains/1.94.0");
        let pinned_bin = pinned_toolchain.join("bin");
        fs::create_dir_all(&pinned_bin).unwrap();
        for name in ["cargo", "rustc"] {
            let p = pinned_bin.join(name);
            fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let pinned_cargo = pinned_bin.join("cargo");
        fs::write(
            &rustup,
            format!(
                "#!/bin/sh\nif [ \"$1\" = which ] && [ \"$2\" = cargo ]; then echo \"{}\"; exit 0; fi\n\
                 if [ \"$1\" = which ] && [ \"$2\" = --toolchain ] && [ \"$3\" = 1.94.0 ] && [ \"$4\" = cargo ]; then echo \"{}\"; exit 0; fi\n\
                 exit 1\n",
                tc_cargo.display(),
                pinned_cargo.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&rustup, fs::Permissions::from_mode(0o755)).unwrap();
        let shim_cargo = shim_bin.join("cargo");
        let shim_rustc = shim_bin.join("rustc");
        fs::hard_link(&rustup, &shim_cargo).unwrap();
        fs::hard_link(&rustup, &shim_rustc).unwrap();

        let resolved = Toolchain::resolve_with_path(
            &[OsString::from("cargo"), OsString::from("build")],
            &project,
            shim_bin.as_os_str(),
            &[RustupInstallation::SharedBinary(rustup.clone())],
        )
        .unwrap();
        assert_eq!(resolved.cargo, tc_cargo);
        assert_eq!(resolved.bin_dir, tc_bin);
        assert_eq!(resolved.bind_root, toolchain);
        assert!(!resolved.has_toolchain_selector);
        assert_eq!(
            resolved.command(&[OsString::from("cargo"), OsString::from("build")]),
            vec![tc_cargo.clone().into_os_string(), OsString::from("build")]
        );

        let pinned_args = [
            OsString::from("cargo"),
            OsString::from("+1.94.0"),
            OsString::from("build"),
            OsString::from("--locked"),
        ];
        let resolved_pinned = Toolchain::resolve_with_path(
            &pinned_args,
            &project,
            shim_bin.as_os_str(),
            &[RustupInstallation::SharedBinary(rustup.clone())],
        )
        .unwrap();
        assert_eq!(resolved_pinned.cargo, pinned_cargo);
        assert_eq!(resolved_pinned.bin_dir, pinned_bin);
        assert_eq!(resolved_pinned.bind_root, pinned_toolchain);
        assert!(resolved_pinned.has_toolchain_selector);
        assert_eq!(
            resolved_pinned.command(&pinned_args),
            vec![
                pinned_cargo.into_os_string(),
                OsString::from("build"),
                OsString::from("--locked"),
            ]
        );

        // 3. Symlink to rustup-init in another directory (Homebrew rustup style) -> resolves toolchain
        let brew_opt = root.join("brew/opt/rustup/bin");
        let brew_bin = root.join("brew/bin");
        fs::create_dir_all(&brew_opt).unwrap();
        fs::create_dir_all(&brew_bin).unwrap();
        let rustup_init = brew_opt.join("rustup-init");
        fs::copy(&rustup, &rustup_init).unwrap();
        fs::set_permissions(&rustup_init, fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(&rustup_init, brew_bin.join("cargo")).unwrap();
        let resolved_brew = Toolchain::resolve_with_path(
            &[OsString::from("cargo")],
            &project,
            brew_bin.as_os_str(),
            &[RustupInstallation::SharedBinary(rustup_init)],
        )
        .unwrap();
        assert_eq!(resolved_brew.cargo, tc_cargo);

        // Homebrew also ships paired wrappers with distinct file identities.
        let brew_wrappers = root.join("brew/opt/rustup/wrappers");
        fs::create_dir(&brew_wrappers).unwrap();
        fs::copy(&rustup, brew_wrappers.join("rustup")).unwrap();
        fs::copy(&plain_bin.join("cargo"), brew_wrappers.join("cargo")).unwrap();
        let installations = [RustupInstallation::HomebrewBin(brew_wrappers.clone())];
        assert_eq!(
            Toolchain::resolve_with_path(
                &[OsString::from("cargo")],
                &project,
                brew_wrappers.as_os_str(),
                &installations,
            )
            .unwrap()
            .cargo,
            tc_cargo
        );
        assert_eq!(
            Toolchain::resolve_with_path(
                &[OsString::from("cargo")],
                &project,
                plain_bin.as_os_str(),
                &installations,
            ),
            None
        );
    }
}
