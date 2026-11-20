use crate::{
    Result, error,
    report::{Report, aggregate},
};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, symlink},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    time::SystemTime,
};

const SHIMS: &[&str] = &[
    "npm", "npx", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "cargo", "curl", "wget", "git",
];
const LINE: usize = 65536;
const DAY: u64 = 10 * 1024 * 1024;

pub(super) fn state() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| error("missing HOME"))?;
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| {
            PathBuf::from(home).join(if cfg!(target_os = "macos") {
                "Library/Application Support"
            } else {
                ".local/state"
            })
        });
    if !base.is_absolute() {
        return Err(error("state directory must be absolute"));
    }
    Ok(base.join("veil-tell"))
}

fn owned_dir(path: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    let meta = path.symlink_metadata()?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err(error("veil-tell state directories must be private (0700)"));
    }
    Ok(())
}

fn directory(name: &str) -> Result<PathBuf> {
    let base = state()?;
    owned_dir(&base)?;
    let path = base.join(name);
    owned_dir(&path)?;
    Ok(path)
}

pub fn agent_env(args: &[OsString]) -> Result<u8> {
    let shell = match args {
        [] => "bash",
        [flag, shell] if flag == "--shell" => shell.to_str().unwrap_or(""),
        _ => "",
    };
    if !matches!(shell, "bash" | "zsh" | "fish") {
        return Err(error("usage: veil-tell agent-env [--shell bash|zsh|fish]"));
    }
    let shims = install_shims()?;
    let dir = crate::attribution::shell_quote(&shims)?;
    if shell == "fish" {
        let raw = shims
            .to_str()
            .ok_or_else(|| error("non-UTF8 shim path"))?
            .replace('\\', "\\\\")
            .replace('\'', "\\'");
        println!("set -gx PATH '{raw}' $PATH");
    } else {
        println!("export PATH={dir}:\"$PATH\"")
    }
    Ok(0)
}

pub(super) fn install_shims() -> Result<PathBuf> {
    let shims = directory("shims")?;
    let exe = std::env::current_exe()?.canonicalize()?;
    let staging = tempfile::tempdir_in(&shims)?;
    for name in SHIMS {
        let link = shims.join(name);
        if fs::read_link(&link).ok().as_ref() == Some(&exe) {
            continue;
        }
        let new = staging.path().join(name);
        symlink(&exe, &new)?;
        fs::rename(new, link)?;
    }
    Ok(shims)
}

pub fn shim_name(program: &std::ffi::OsStr) -> Option<&str> {
    Path::new(program)
        .file_name()?
        .to_str()
        .filter(|s| SHIMS.contains(s))
}

pub fn shim(name: &str, args: &[OsString]) -> Result<u8> {
    let executable = std::env::current_exe()?.canonicalize()?;
    if executable.file_name().is_some_and(|s| s == name) {
        return Err(error(
            "install the executable as veil-tell before enabling shims",
        ));
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    // Remove every instance, including aliases of the same shim directory.
    let filtered = std::env::join_paths(
        std::env::split_paths(&path)
            .filter(|dir| dir.join(name).canonicalize().ok().as_ref() != Some(&executable)),
    )?;
    let mut launch = std::process::Command::new(executable);
    launch
        .args(["--log", "--", name])
        .args(args)
        .env("PATH", filtered);
    crate::agent::restore_upstream(&mut launch);
    Err(launch.exec().into())
}

fn scrub(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    if lower.contains("authorization")
        || lower.contains("password")
        || lower.contains("token")
        || s.chars().any(char::is_control)
    {
        return "***".into();
    }
    if let Some((scheme, tail)) = s.split_once("://") {
        if matches!(scheme, "http" | "https") {
            let authority = tail
                .split(['/', '?', '#'])
                .next()
                .unwrap_or("")
                .rsplit('@')
                .next()
                .unwrap_or("");
            return format!("{scheme}://{}", scrub(authority));
        }
        return "***".into();
    }
    if s.len() > 512
        || s.split(|c: char| !c.is_ascii_alphanumeric())
            .any(|p| p.len() >= 40)
    {
        return "***".into();
    }
    s.to_owned()
}

fn argv(args: &[OsString]) -> Vec<String> {
    // curl accepts both --header=value and short forms such as -fsSHvalue.
    // Once an option takes a value, the rest of that argument is data.
    let curl = args
        .first()
        .and_then(|a| Path::new(a).file_name())
        .is_some_and(|n| n == "curl");
    let mut mask = 0;
    args.iter()
        .map(|arg| {
            let s = arg.to_string_lossy();
            if mask > 0 {
                mask -= 1;
                if s.eq_ignore_ascii_case("bearer")
                    || s.eq_ignore_ascii_case("authorization:")
                    || s.to_ascii_lowercase().ends_with(": bearer")
                {
                    mask = 1
                }
                return "***".into();
            }
            if curl {
                let (option, value) = s.split_once('=').map_or((&*s, None), |(k, v)| (k, Some(v)));
                let sensitive = matches!(
                    option,
                    "--header"
                        | "--proxy-header"
                        | "--cookie"
                        | "--user"
                        | "--proxy-user"
                        | "--oauth2-bearer"
                        | "--data"
                        | "--data-ascii"
                        | "--data-binary"
                        | "--data-raw"
                        | "--data-urlencode"
                        | "--json"
                        | "--form"
                        | "--form-string"
                        | "--url-query"
                        | "--variable"
                );
                if sensitive {
                    if value.is_some() {
                        return "***".into();
                    }
                    mask = 1;
                    return option.to_owned();
                }
                if let Some(flags) = s.strip_prefix('-').filter(|f| !f.starts_with('-')) {
                    for (i, flag) in flags.char_indices() {
                        if "HbuUdeF".contains(flag) {
                            if i + 1 < flags.len() {
                                return "***".into();
                            }
                            mask = 1;
                            break;
                        }
                    }
                }
            }
            let lower = s.to_ascii_lowercase();
            if (lower.contains("authorization")
                || lower.contains("password")
                || lower.contains("token"))
                && !s.contains('=')
                && !s.contains("://")
            {
                mask = usize::from(!s.contains(' ') || lower.ends_with("bearer"));
            } else if matches!(
                &*s,
                "-H" | "--header" | "-u" | "--user" | "-d" | "--data" | "--data-raw" | "-c" | "-e"
            ) {
                mask = 1;
            }
            let cleaned = scrub(&s);
            if s.starts_with("-H") && s.len() > 2 {
                "***".into()
            } else {
                cleaned
            }
        })
        .collect()
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
fn calendar(t: i64) -> (String, String) {
    let mut tm = unsafe { std::mem::zeroed::<libc::tm>() };
    unsafe { libc::localtime_r(&t, &mut tm) };
    (
        format!(
            "{:04}-{:02}-{:02}",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday
        ),
        format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec),
    )
}

fn dates(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(stem) = name.to_str().and_then(|s| s.strip_suffix(".jsonl")) else {
            continue;
        };
        if stem.len() == 10
            && stem.bytes().enumerate().all(|(i, b)| {
                if i == 4 || i == 7 {
                    b == b'-'
                } else {
                    b.is_ascii_digit()
                }
            })
            && entry.file_type()?.is_file()
        {
            files.push(entry.path())
        }
    }
    files.sort();
    Ok(files)
}
fn private_file(path: &Path, append: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .append(append)
        .create(append)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
    {
        return Err(error("unsafe session file"));
    }
    Ok(file)
}

pub fn append(
    cwd: &Path,
    args: &[OsString],
    report: Option<&Report>,
    agent_session: bool,
) -> Result<()> {
    if std::env::var_os("VEIL_TELL_LOG").is_some_and(|s| s == "off") {
        return Ok(());
    }
    let dir = directory("log")?;
    let lock = private_file(&dir.join(".lock"), true)?;
    lock.lock()?;
    let time = now();
    let (date, clock) = calendar(time);
    let oldest = calendar(time - 29 * 86400).0;
    for file in dates(&dir)? {
        if file
            .file_stem()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s < oldest.as_str())
        {
            fs::remove_file(file)?;
        }
    }
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let cwd = home
        .and_then(|p| cwd.strip_prefix(p).ok().map(|s| Path::new("~").join(s)))
        .unwrap_or_else(|| cwd.into());
    let setup = crate::report::RunStatus {
        exit_code: crate::SETUP_FAILURE,
        reason: "setup_failed",
    };
    let status = report.map_or(&setup, |r| &r.run_status);
    let mut record = json!({"time":time,"clock":clock,"cwd":scrub(&cwd.to_string_lossy()),"argv":argv(args),"exit_code":status.exit_code,"run_status":status,"coverage":report.map(|r|&r.coverage),"destinations":[],"attempted":[],"direct_attempts":[]});
    if agent_session {
        record["scope"] = "agent_session".into();
    } else if let Some(name) = agent_name() {
        record["agent"] = json!({"name":name,"confidence":"inferred"});
    }
    let mut length = serde_json::to_vec(&record)?.len();
    if length > LINE / 2 {
        record["argv"] = json!([scrub(&args[0].to_string_lossy()), "***"]);
        record["truncated"] = true.into();
        length = serde_json::to_vec(&record)?.len();
    }
    let mut add = |key: &str, item: Value| -> Result<()> {
        let extra = serde_json::to_vec(&item)?.len() + 1;
        if length + extra + 32 >= LINE {
            record["truncated"] = true.into();
        } else {
            record[key].as_array_mut().unwrap().push(item);
            length += extra;
        }
        Ok(())
    };
    if let Some(report) = report {
        let diff = report.comparison.as_deref();
        for d in aggregate(&report.destinations) {
            let mut attribution = Vec::new();
            for source in &d.attribution {
                let mut item = serde_json::to_value(source)?;
                if let Some(label) = diff.and_then(|c| c.lock_evidence(&d.host, d.port, source)) {
                    item["lockfile_evidence"] = label.into();
                }
                attribution.push(item);
            }
            add(
                "destinations",
                json!({"host":d.host,"port":d.port,"decision":d.decision,"reason":d.reason,"result":d.result,"attempts":d.attempts,"sent_bytes":d.sent_bytes,"attribution":attribution,"new":d.reason=="new_destination"||diff.is_some_and(|c|c.added_host(&d.host,false)), "blocked":d.decision=="deny"||report.volume_anomalies.iter().any(|a|a.host==d.host&&a.blocked)}),
            )?;
        }
        for d in report.attempted.iter().flatten() {
            add(
                "attempted",
                json!({"host":d.host,"attempts":d.attempts,"attribution":d.attribution,"new":diff.is_some_and(|c|c.added_host(&d.host,true))}),
            )?;
        }
        for d in report.direct_attempts.iter().flatten() {
            add("direct_attempts", serde_json::to_value(d)?)?;
        }
    }
    let mut bytes = serde_json::to_vec(&record)?;
    bytes.push(b'\n');
    let path = dir.join(format!("{date}.jsonl"));
    let mut file = private_file(&path, true)?;
    if file.metadata()?.len() + bytes.len() as u64 > DAY {
        use std::io::{Read, Seek, SeekFrom};
        let keep = DAY - bytes.len() as u64;
        file.seek(SeekFrom::End(-(keep as i64)))?;
        let mut tail = Vec::new();
        file.take(keep).read_to_end(&mut tail)?;
        let mut replacement = tempfile::NamedTempFile::new_in(&dir)?;
        if let Some(index) = tail.iter().position(|b| *b == b'\n') {
            replacement.write_all(&tail[index + 1..])?;
        }
        replacement.write_all(&bytes)?;
        replacement.persist(path)?;
        return Ok(());
    }
    file.write_all(&bytes)?;
    Ok(())
}

pub fn show(args: &[OsString]) -> Result<u8> {
    let mut args = args.iter();
    let mut filter = "";
    let mut json = false;
    let mut since = None;
    let t = now();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--today") if since.is_none() => since = Some(0),
            Some("--since") if since.is_none() => {
                let value = args
                    .next()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| error("expected duration, e.g. 2h"))?;
                let factor = match value.as_bytes().last() {
                    Some(b's') => 1,
                    Some(b'm') => 60,
                    Some(b'h') => 3600,
                    Some(b'd') => 86400,
                    _ => return Err(error("invalid duration")),
                };
                let secs = value[..value.len() - 1].parse::<u32>()? as i64 * factor;
                since = Some(t.saturating_sub(secs).max(1));
            }
            Some("--json") => json = true,
            Some(f @ ("--only-new" | "--only-blocked")) if filter.is_empty() => filter = f,
            _ => return Err(error("invalid log option")),
        }
    }
    let dir = state()?.join("log");
    if !dir.exists() {
        return Ok(0);
    }
    let dir = directory("log")?;
    let lock = private_file(&dir.join(".lock"), true)?;
    lock.lock_shared()?;
    let start = since.unwrap_or(0);
    let earliest = calendar(if start == 0 { t } else { start }).0;
    for path in dates(&dir)? {
        if path.file_stem().unwrap().to_string_lossy().as_ref() < earliest.as_str() {
            continue;
        }
        let mut input = BufReader::new(private_file(&path, false)?);
        let mut line = Vec::new();
        loop {
            use std::io::Read;
            line.clear();
            if (&mut input)
                .take(LINE as u64 + 1)
                .read_until(b'\n', &mut line)?
                == 0
            {
                break;
            }
            if line.len() > LINE {
                return Err(error("oversized session record"));
            }
            let mut r: Value = serde_json::from_slice(&line)?;
            if r["time"].as_i64().unwrap_or(0) < start {
                continue;
            }
            for key in ["destinations", "attempted", "direct_attempts"] {
                if let Some(rows) = r[key].as_array_mut() {
                    rows.retain(|d| match filter {
                        "--only-new" => d["new"] == true,
                        "--only-blocked" => key != "destinations" || d["blocked"] == true,
                        _ => true,
                    });
                }
            }
            if !filter.is_empty()
                && ["destinations", "attempted", "direct_attempts"]
                    .iter()
                    .all(|k| r[k].as_array().is_none_or(Vec::is_empty))
            {
                continue;
            }
            if json {
                println!("{}", serde_json::to_string(&r)?);
                continue;
            }
            let command = r["argv"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ");
            let prefix = if r["scope"] == "agent_session" {
                "agent -- "
            } else {
                ""
            };
            println!(
                "{}  {prefix}{}  exit {}",
                r["clock"].as_str().unwrap_or(""),
                command,
                r["exit_code"]
            );
            for key in ["destinations", "attempted", "direct_attempts"] {
                for d in r[key].as_array().into_iter().flatten() {
                    let host = d["host"].as_str().unwrap_or("");
                    let new = if d["new"] == true { " [new]" } else { "" };
                    if key == "direct_attempts" {
                        println!(
                            "          ✗ {}:{}  direct ×{}",
                            d["ip"].as_str().unwrap_or(""),
                            d["port"],
                            d["attempts"]
                        );
                    } else if key == "attempted" {
                        println!("          ✗ {host}  DNS ×{}{new}", d["attempts"]);
                    } else {
                        let result = d["result"].as_str();
                        let symbol = if d["blocked"] == true {
                            "✗"
                        } else if result.is_some_and(|r| r != "completed") {
                            "!"
                        } else {
                            "✓"
                        };
                        print!(
                            "          {symbol} {host}:{}  ×{}  {} B  {}{new}",
                            d["port"],
                            d["attempts"],
                            d["sent_bytes"],
                            d["reason"].as_str().unwrap_or("")
                        );
                        if symbol == "!"
                            && let Some(result) = result
                        {
                            print!(" [{result}]");
                        }
                        for a in d["attribution"].as_array().into_iter().flatten() {
                            if let Some(m) = a["manager"].as_str() {
                                print!(" ← {m} (registry fetch) [inferred]");
                            }
                            if let Some(p) = a["package"].as_object() {
                                print!(
                                    " ← {}@{} {} [inferred{}]",
                                    p["name"].as_str().unwrap_or(""),
                                    p["version"].as_str().unwrap_or(""),
                                    p["script"].as_str().unwrap_or(""),
                                    a["lockfile_evidence"]
                                        .as_str()
                                        .map(|s| format!(", {s}"))
                                        .unwrap_or_default()
                                );
                            }
                        }
                        println!();
                    }
                }
            }
        }
    }
    Ok(0)
}

fn agent_name() -> Option<String> {
    let mut pid = unsafe { libc::getppid() };
    for _ in 0..8 {
        if pid <= 1 {
            break;
        }
        let (parent, name) = process_name(pid)?;
        let s = name.to_ascii_lowercase();
        if let Some(known) = ["codex", "claude", "cursor"].into_iter().find(|n| s == *n) {
            return Some(known.to_owned());
        }
        pid = parent;
    }
    None
}
#[cfg(target_os = "linux")]
fn process_name(pid: i32) -> Option<(i32, String)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (head, tail) = stat.rsplit_once(") ")?;
    Some((
        tail.split_whitespace().nth(1)?.parse().ok()?,
        head.split_once('(')?.1.to_owned(),
    ))
}
#[cfg(target_os = "macos")]
fn process_name(pid: i32) -> Option<(i32, String)> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of_val(&info) as i32;
    if unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    } != size
    {
        return None;
    }
    let bytes = info
        .pbi_comm
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    Some((info.pbi_ppid as i32, String::from_utf8(bytes).ok()?))
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    #[test]
    fn curl_argument_forms_do_not_persist_headers_credentials_or_bodies() {
        let args = [
            "/usr/bin/curl",
            "-fsSL",
            "--header=X-Key: abc",
            "-fsSHX-Key: abc",
            "-su",
            "user:abc",
            "--proxy-header",
            "Cookie: abc",
            "--cookie=abc",
            "--data-urlencode",
            "key=abc",
            "--json={payload}",
            "https://example.org/path?q=abc",
        ]
        .map(OsString::from);
        let logged = argv(&args);
        assert_eq!(logged[1], "-fsSL");
        assert_eq!(logged.last().unwrap(), "https://example.org");
        let rendered = logged.join(" ");
        for value in ["abc", "X-Key", "payload", "/path"] {
            assert!(!rendered.contains(value));
        }
    }
}
