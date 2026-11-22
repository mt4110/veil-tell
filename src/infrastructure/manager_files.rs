use crate::{Result, error};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
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

const DIAGNOSTIC_LIMIT: u64 = 1024 * 1024;

// These labels are the only log-derived vocabulary that can reach the report.
fn code_description(code: &[u8]) -> Option<&'static str> {
    Some(match code {
        b"ENOENT" => "ENOENT - file or directory missing",
        b"EACCES" => "EACCES - permission denied",
        b"EPERM" => "EPERM - operation not permitted",
        b"ENOTFOUND" => "ENOTFOUND - name resolution failed",
        b"EAI_AGAIN" => "EAI_AGAIN - temporary name resolution failure",
        b"ETIMEDOUT" => "ETIMEDOUT - operation timed out",
        b"ECONNRESET" => "ECONNRESET - connection reset",
        b"ECONNREFUSED" => "ECONNREFUSED - connection refused",
        b"EINTEGRITY" => "EINTEGRITY - integrity check failed",
        b"ERESOLVE" => "ERESOLVE - dependency resolution failed",
        b"ELIFECYCLE" => "ELIFECYCLE - lifecycle script failed",
        b"EUSAGE" => "EUSAGE - command usage error",
        b"ERR_PNPM_OUTDATED_LOCKFILE" => "ERR_PNPM_OUTDATED_LOCKFILE - lockfile needs updating",
        b"ERR_PNPM_TARBALL_INTEGRITY" => {
            "ERR_PNPM_TARBALL_INTEGRITY - archive integrity check failed"
        }
        b"ERR_PNPM_UNEXPECTED_STORE" => {
            "ERR_PNPM_UNEXPECTED_STORE - dependency store location differs"
        }
        b"YN0009" => "YN0009 - package build failed",
        b"YN0018" => "YN0018 - cache checksum mismatch",
        b"YN0028" => "YN0028 - installation would change the lockfile",
        _ => return None,
    })
}

fn npm_label(line: &[u8]) -> Option<&'static str> {
    let mut words = line
        .split(|b| b.is_ascii_whitespace())
        .filter(|w| !w.is_empty());
    let number = words.next()?;
    if !number.iter().all(u8::is_ascii_digit) || words.next()? != b"error" {
        return None;
    }
    let field = words.next()?;
    let value = words.next()?;
    if words.next().is_some() {
        return None;
    }
    match (field, value) {
        (b"code", code) => code_description(code),
        (b"syscall", b"open") => Some("syscall: open"),
        (b"syscall", b"stat") => Some("syscall: stat"),
        (b"syscall", b"mkdir") => Some("syscall: mkdir"),
        (b"syscall", b"rename") => Some("syscall: rename"),
        (b"syscall", b"connect") => Some("syscall: connect"),
        (b"syscall", b"getaddrinfo") => Some("syscall: getaddrinfo"),
        _ => None,
    }
}

pub fn diagnostics(home: &Path, cwd: &Path) -> Result<Option<PathBuf>> {
    if !home.symlink_metadata()?.is_dir() {
        return Ok(None);
    }
    let home = home.canonicalize()?;
    let mut sources = Vec::new();
    let mut entry_limit = false;
    for (manager, relative) in [
        ("npm", ".npm/_logs"),
        ("pnpm", ".pnpm/_logs"),
        ("yarn", ".yarn/_logs"),
    ] {
        let path = home.join(relative);
        if path.canonicalize().ok().as_ref() != Some(&path) {
            continue;
        }
        let mut entries = fs::read_dir(path)?;
        for entry in entries.by_ref().take(64) {
            let entry = entry?;
            if entry.file_type()?.is_file() && entry.path().extension().is_some_and(|s| s == "log")
            {
                sources.push((manager, entry.path()));
            }
        }
        entry_limit |= entries.next().is_some();
    }
    for (manager, name) in [
        ("yarn", "yarn-error.log"),
        ("pnpm", "pnpm-debug.log"),
        ("pnpm", ".pnpm-debug.log"),
    ] {
        let path = home.join(name);
        if path.symlink_metadata().is_ok_and(|m| m.is_file()) {
            sources.push((manager, path));
        }
    }
    // npm names its logs by timestamp. Prefer the newest names and the final
    // lines, where npm writes the error code and failing syscall.
    sources.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    let mut remaining = DIAGNOSTIC_LIMIT;
    let mut byte_limit = false;
    let mut reports = BTreeMap::new();
    for (manager, path) in sources {
        let mut src = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let m = src.metadata()?;
        if !m.is_file() || m.nlink() != 1 {
            continue;
        }
        let labels = reports.entry(manager).or_insert_with(BTreeSet::new);
        let limit = remaining.min(m.len());
        let start = m.len() - limit;
        byte_limit |= start > 0;
        if limit == 0 {
            continue;
        }
        src.seek(SeekFrom::Start(start))?;
        let mut bytes = Vec::new();
        src.take(limit).read_to_end(&mut bytes)?;
        remaining -= bytes.len() as u64;
        let mut lines = bytes.split(|b| *b == b'\n');
        if start != 0 {
            // The first fragment can start in the middle of a longer token.
            lines.next();
        }
        for line in lines {
            if manager == "npm" {
                labels.extend(npm_label(line));
                continue;
            }
            for word in line.split(|b| !(b.is_ascii_alphanumeric() || *b == b'_')) {
                labels.extend(code_description(word));
            }
        }
    }
    if reports.is_empty() {
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
        let meta = dir.symlink_metadata()?;
        if !meta.is_dir()
            || (name == "logs"
                && (meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0))
        {
            return Err(error("unsafe diagnostics directory"));
        }
    }
    let prefix = format!(
        "{}-",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
    );
    let run = tempfile::Builder::new()
        .prefix(&prefix)
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(dir)?;
    let out = run.path().join("manager.log");
    let mut dest = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&out)?;
    writeln!(
        dest,
        "Manager diagnostics (recognized entries from temporary logs)"
    )?;
    for (manager, labels) in reports {
        writeln!(dest, "[{manager}]")?;
        if labels.is_empty() {
            writeln!(dest, "No recognized diagnostic entry in the scanned data.")?;
        }
        for label in labels {
            writeln!(dest, "{label}")?;
        }
    }
    if byte_limit {
        writeln!(dest, "Scan limited to 1 MiB across logs.")?;
    }
    if entry_limit {
        writeln!(dest, "Scan limited to 64 directory entries per manager.")?;
    }
    let _ = run.keep();
    Ok(Some(out))
}

#[cfg(test)]
mod tests;
