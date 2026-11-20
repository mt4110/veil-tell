use crate::{Result, error};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub fn cache(manager: Option<&str>) -> Result<Option<PathBuf>> {
    if std::env::var_os("VEIL_TELL_CACHE").is_none_or(|v| v != "persistent") {
        return Ok(None);
    }
    let Some(manager) = manager.filter(|m| matches!(*m, "npm" | "pnpm" | "yarn" | "bun")) else {
        return Ok(None);
    };
    let root = PathBuf::from(std::env::var_os("HOME").ok_or_else(|| error("missing HOME"))?)
        .join(".cache");
    if !root.is_absolute() {
        return Err(error("HOME must be absolute"));
    }
    let base = root.join("veil-tell");
    let path = base.join(manager);
    for dir in [&base, &path] {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let m = dir.symlink_metadata()?;
        if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
            return Err(error("use private veil-tell cache directories"));
        }
    }
    Ok(Some(path.canonicalize()?))
}

pub fn configure(command: &mut tokio::process::Command, manager: &str, path: &Path) {
    let key = match manager {
        "npm" => "npm_config_cache",
        "pnpm" => "XDG_CACHE_HOME",
        "yarn" => "YARN_CACHE_FOLDER",
        "bun" => "BUN_INSTALL_CACHE_DIR",
        _ => return,
    };
    command.env(key, path);
}

// Manager logs contain arbitrary script output and arguments. Preserve only
// recognized diagnostic codes, never credentials, headers or free-form text.
pub fn diagnostics(home: &Path, cwd: &Path) -> Result<Option<PathBuf>> {
    let home = home.canonicalize()?;
    let mut sources = Vec::new();
    for relative in [".npm/_logs", ".pnpm/_logs", ".yarn/_logs"] {
        let path = home.join(relative);
        if path.canonicalize().ok().as_ref() != Some(&path) {
            continue;
        }
        for entry in fs::read_dir(path)?.take(64) {
            let entry = entry?;
            if entry.file_type()?.is_file() && entry.path().extension().is_some_and(|s| s == "log")
            {
                sources.push(entry.path());
            }
        }
    }
    for name in ["yarn-error.log", "pnpm-debug.log"] {
        let path = home.join(name);
        if path.symlink_metadata().is_ok_and(|m| m.is_file()) {
            sources.push(path)
        }
    }
    if sources.is_empty() {
        return Ok(None);
    }
    let mut dir = cwd.to_path_buf();
    for name in [".veil-tell", "logs"] {
        dir.push(name);
        match fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e.into()),
        }
        if !dir.symlink_metadata()?.is_dir() {
            return Err(error("unsafe diagnostics directory"));
        }
    }
    let prefix = format!(
        "{}-",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
    );
    let run = tempfile::Builder::new().prefix(&prefix).tempdir_in(dir)?;
    let out = run.path().join("manager.log");
    let mut dest = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&out)?;
    writeln!(dest, "Manager diagnostics (recognized codes only)")?;
    let mut remaining = 1024 * 1024;
    let mut output_left = 1024 * 1024 - dest.metadata()?.len();
    'sources: for path in sources {
        if remaining == 0 {
            break;
        }
        let src = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let m = src.metadata()?;
        if !m.is_file() || m.nlink() != 1 {
            continue;
        }
        let limit = remaining.min(m.len());
        remaining -= limit;
        for line in BufReader::new(src.take(limit)).split(b'\n') {
            for token in line?.split(|b| !b.is_ascii_alphanumeric()) {
                if matches!(
                    token,
                    b"ENOENT"
                        | b"EACCES"
                        | b"ENOTFOUND"
                        | b"ECONNRESET"
                        | b"EAI"
                        | b"ETIMEDOUT"
                        | b"EINTEGRITY"
                        | b"ERESOLVE"
                        | b"ELIFECYCLE"
                        | b"ECONNREFUSED"
                ) {
                    let bytes = token.len() as u64 + 1;
                    if bytes > output_left {
                        break 'sources;
                    }
                    output_left -= bytes;
                    dest.write_all(token)?;
                    dest.write_all(b"\n")?;
                }
            }
        }
    }
    let _ = run.keep();
    Ok(Some(out))
}
