use crate::{Result, error};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::{
    fs::{OpenOptionsExt, PermissionsExt},
    process::CommandExt,
};
use std::path::{Path, PathBuf};
use tokio::process::Command;

const CODEC: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
const MAX_MANIFEST: u64 = 1024 * 1024;
#[cfg(target_os = "linux")]
pub const LINUX_SHELL: &str = "/veil-tell-npm-shell";
pub const WRAPPER_MODE: &str = "__veil_tell_npm_shell";

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Attribution {
    pub confidence: Confidence,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub package: Option<Package>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Inferred,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub script: String,
    pub path: String,
}

pub type Sources = BTreeSet<Attribution>;

pub fn record(sources: &mut Sources, source: Attribution) {
    // Keep the smallest four distinct inferred labels, plus any unknown label.
    sources.insert(source);
    if sources.iter().filter(|a| a.package.is_some()).count() > 4
        && let Some(last) = sources.iter().rev().find(|a| a.package.is_some()).cloned()
    {
        sources.remove(&last);
        sources.insert(Attribution::unknown());
    }
}

impl Attribution {
    pub fn unknown() -> Self {
        Self {
            confidence: Confidence::Unknown,
            package: None,
        }
    }

    pub fn decode(payload: Option<&str>) -> Self {
        payload
            .filter(|s| s.len() <= 2048)
            .and_then(|s| CODEC.decode(s).ok())
            .and_then(|bytes| serde_json::from_slice::<Package>(&bytes).ok())
            .filter(Package::valid)
            .map_or_else(Self::unknown, |package| Self {
                confidence: Confidence::Inferred,
                package: Some(package),
            })
    }

    pub fn valid(&self) -> bool {
        match (&self.confidence, &self.package) {
            (Confidence::Unknown, None) => true,
            (Confidence::Inferred, Some(package)) => package.valid(),
            _ => false,
        }
    }
}

fn identifier(s: &str, max: usize, punctuation: &[u8]) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || punctuation.contains(&b))
}

impl Package {
    pub fn valid(&self) -> bool {
        identifier(&self.name, 214, b"@/_.-")
            && identifier(&self.version, 80, b".-+")
            && identifier(&self.script, 64, b"_.:-")
            && self.path.len() <= 500
            && (self.path == "."
                || self
                    .path
                    .split('/')
                    .all(|s| s != "." && s != ".." && identifier(s, 255, b" @_.-+")))
    }
}

pub fn create_shell(path: &Path, binary: &Path) -> Result<()> {
    create_wrapper(path, binary, WRAPPER_MODE)
}

pub fn shell_quote(path: &Path) -> Result<String> {
    let path = path
        .to_str()
        .ok_or_else(|| error("attribution requires a UTF-8 executable path"))?;
    Ok(format!("'{}'", path.replace('\'', "'\"'\"'")))
}

pub fn create_wrapper(path: &Path, binary: &Path, mode: &str) -> Result<()> {
    let binary = shell_quote(binary)?;
    fs::write(path, format!("#!/bin/sh\nexec {binary} {mode} \"$@\"\n"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

pub fn configure(command: &mut Command, shell: &Path, cwd: &Path) {
    command
        .env("npm_config_script_shell", shell)
        .env("VEIL_TELL_NPM_ROOT", cwd);
}

fn identify(args: &[OsString]) -> Option<Package> {
    if args.len() != 2 || args[0] != "-c" {
        return None;
    }
    let cwd = std::env::current_dir().ok()?.canonicalize().ok()?;
    let root = PathBuf::from(std::env::var_os("VEIL_TELL_NPM_ROOT")?)
        .canonicalize()
        .ok()?;
    let relative = cwd.strip_prefix(root).ok()?;
    let manifest = cwd.join("package.json");
    let claimed = PathBuf::from(std::env::var_os("npm_package_json")?)
        .canonicalize()
        .ok()?;
    if claimed != manifest {
        return None;
    }
    let bytes = read_manifest(&manifest)?;
    let manifest: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let name = manifest["name"].as_str()?;
    let version = manifest["version"].as_str()?;
    let script = std::env::var("npm_lifecycle_event").ok()?;
    let body = manifest["scripts"].get(&script)?.as_str()?;
    if std::env::var("npm_package_name").ok().as_deref() != Some(name)
        || std::env::var("npm_package_version").ok().as_deref() != Some(version)
        || std::env::var("npm_lifecycle_script").ok().as_deref() != Some(body)
        || args[1].to_str()? != body
    {
        return None;
    }
    let package = Package {
        name: name.into(),
        version: version.into(),
        script,
        path: if relative.as_os_str().is_empty() {
            "."
        } else {
            relative.to_str()?
        }
        .into(),
    };
    package.valid().then_some(package)
}

pub fn read_manifest(path: &Path) -> Option<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_MANIFEST {
        return None;
    }
    Some(bytes)
}

pub fn run_shell(args: &[OsString]) -> Result<u8> {
    let mut shell = std::process::Command::new("/bin/sh");
    shell.args(args);
    annotate(&mut shell, identify(args));
    Err(shell.exec().into())
}

pub fn annotate(shell: &mut std::process::Command, package: Option<Package>) {
    let payload = package.and_then(|package| serde_json::to_vec(&package).ok());
    for key in crate::isolation::PROXY_VARS {
        if let Ok(value) = std::env::var(key)
            && let Some((login, address)) = value.split_once('@')
            && let Some((prefix, password)) = login.split_once("://veil:")
            && prefix == "http"
        {
            let secret = password.split('~').next().unwrap_or(password);
            let suffix = payload
                .as_ref()
                .map(|bytes| format!("~{}", CODEC.encode(bytes)))
                .unwrap_or_default();
            shell.env(key, format!("http://veil:{secret}{suffix}@{address}"));
        }
    }
}
