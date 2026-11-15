use crate::{Result, cli::Backend, isolation, manager};
use std::ffi::OsString;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

#[derive(Debug)]
pub struct StoreError {
    reason: String,
    pub next: &'static str,
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for StoreError {}

fn setup_error(reason: impl Into<String>, next: &'static str) -> StoreError {
    StoreError {
        reason: reason.into(),
        next,
    }
}

const CONFIGURE: &str = "set `storeDir: .pnpm-store` in pnpm-workspace.yaml / pnpm-workspace.yaml に `storeDir: .pnpm-store` を設定";

fn changes_modules(command: &[OsString]) -> bool {
    manager::executable(command) == Some("pnpm")
        && matches!(
            manager::verb(command),
            Some(
                "install"
                    | "i"
                    | "ci"
                    | "add"
                    | "update"
                    | "up"
                    | "upgrade"
                    | "remove"
                    | "rm"
                    | "uninstall"
                    | "unlink"
                    | "link"
                    | "dedupe"
                    | "import"
                    | "install-test"
                    | "it"
                    | "fetch"
                    | "prune"
                    | "rebuild"
            )
        )
}

fn workspace_settings(cwd: &Path) -> Option<serde_yaml_ng::Value> {
    const LIMIT: u64 = 1024 * 1024;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(cwd.join("pnpm-workspace.yaml"))
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > LIMIT {
        return None;
    }
    serde_yaml_ng::from_slice(&bytes).ok()
}

fn store_for(cwd: &Path) -> Result<PathBuf> {
    let config = workspace_settings(cwd);
    let relative = config
        .as_ref()
        .and_then(|config| config.get("storeDir"))
        .and_then(serde_yaml_ng::Value::as_str)
        .map(Path::new)
        .filter(|path| {
            let mut has_child = false;
            for component in path.components() {
                match component {
                    Component::CurDir => {}
                    Component::Normal(name) => {
                        if name.to_str().is_none_or(|name| {
                            name.contains(['$', '~', '\\']) || matches!(name, ".git" | ".veil-tell")
                        }) {
                            return false;
                        }
                        has_child = true;
                    }
                    _ => return false,
                }
            }
            has_child
        })
        .ok_or_else(|| {
            setup_error(
                "isolated pnpm needs a persistent relative store in this workspace; a temporary store can break subsequent pnpm commands / 隔離内外で共有する作業ディレクトリ内の pnpm ストアが必要です",
                CONFIGURE,
            )
        })?;
    let mut store = cwd.to_path_buf();
    for component in relative.components() {
        if let Component::Normal(part) = component {
            store.push(part);
            match store.symlink_metadata() {
                Ok(metadata) if metadata.is_dir() => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                _ => {
                    return Err(setup_error(
                        "the pnpm store must use real directories inside the workspace / pnpm ストアのパスには作業ディレクトリ内の実ディレクトリを指定してください",
                        CONFIGURE,
                    )
                    .into());
                }
            }
        }
    }
    Ok(store)
}

fn changes_store_or_root(arg: &str) -> bool {
    let flag = arg.split_once('=').map_or(arg, |(flag, _)| flag);
    matches!(
        flag,
        "-g" | "-C"
            | "--global"
            | "--dir"
            | "--cwd"
            | "--prefix"
            | "--workspace-dir"
            | "--store-dir"
            | "--config"
            | "--config-dir"
            | "--userconfig"
            | "--globalconfig"
    ) || flag.starts_with("--config.")
        || flag.starts_with("-C")
}

pub async fn validate_store(
    command: &[OsString],
    cwd: &Path,
    outputs: &[&Path],
    protected_dirs: &[&Path],
    secret: &str,
) -> Result<()> {
    if !changes_modules(command) {
        return Ok(());
    }
    if command
        .iter()
        .skip(1)
        .any(|arg| arg.to_str().is_some_and(changes_store_or_root))
    {
        return Err(setup_error(
            "isolated pnpm needs to use the store and workspace configured in the current directory / 隔離 pnpm ではストア・作業ディレクトリを引数で変更できません",
            "cd to the workspace root, then run veil-tell pnpm install / ワークスペース直下で veil-tell pnpm install",
        ).into());
    }
    if std::env::vars_os().any(|(key, _)| {
        key.to_str().is_some_and(|key| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "pnpm_config_store_dir"
                    | "pnpm_config_store-dir"
                    | "npm_config_store_dir"
                    | "npm_config_store-dir"
            )
        })
    }) {
        return Err(setup_error(
            "a store environment override may give plain pnpm a different store / ストア用環境変数が隔離内外で異なる設定になる可能性があります",
            "unset the store environment override and use pnpm-workspace.yaml / ストア用環境変数を解除して pnpm-workspace.yaml を使用",
        ).into());
    }

    let store = store_for(cwd)?;
    // A store path alone can match by accident on Linux: the workspace
    // is a mount point and pnpm 9 may default to its .pnpm-store directory
    // while ignoring storeDir in YAML. Require an effective explicit setting.
    let probe = [
        "/bin/sh".into(),
        "-c".into(),
        r#""$1" config get store-dir && exec "$1" store path"#.into(),
        "veil-tell-pnpm-store".into(),
        command[0].clone(),
    ];
    let mut launch = isolation::prepare(
        Backend::Isolated,
        &probe,
        cwd,
        outputs,
        protected_dirs,
        secret,
        isolation::AttributionConfig::default(),
    )
    .await?;
    let resolved = tokio::time::timeout(Duration::from_secs(5), launch.command.output())
        .await
        .ok()
        .and_then(std::result::Result::ok)
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok());
    let matches = resolved.as_deref().is_some_and(|output| {
        let mut lines = output.lines();
        let (Some(setting), Some(path), None) = (lines.next(), lines.next(), lines.next()) else {
            return false;
        };
        let path = Path::new(path.trim());
        cwd.join(setting.trim()) == store
            && path.parent() == Some(store.as_path())
            && path.file_name().is_some()
            && match path.symlink_metadata() {
                Ok(metadata) => metadata.is_dir(),
                Err(err) => err.kind() == std::io::ErrorKind::NotFound,
            }
    });
    if !matches {
        return Err(setup_error(
            "pnpm did not resolve the configured persistent store inside isolation; check that pnpm is available inside isolation and is reading the project settings / 隔離内で pnpm が設定したストアを使えません",
            "run pnpm store path; for pnpm 9 also set `store-dir=.pnpm-store` in .npmrc to match the YAML / pnpm store path で確認。pnpm 9 は .npmrc にも同じパスを設定",
        ).into());
    }
    Ok(())
}
