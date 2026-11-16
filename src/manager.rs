use std::ffi::OsString;
use std::path::Path;

pub const NAMES: &[&str] = &["npm", "pnpm", "yarn", "bun", "cargo"];

pub fn executable(command: &[OsString]) -> Option<&str> {
    let program = Path::new(command.first()?).file_name()?.to_str()?;
    Some(if corepack_pnpm(command) {
        "pnpm"
    } else {
        program
    })
}

pub fn corepack_pnpm(command: &[OsString]) -> bool {
    command
        .first()
        .and_then(|program| Path::new(program).file_name())
        .is_some_and(|program| program == "corepack")
        && command
            .get(1)
            .and_then(|value| value.to_str())
            .is_some_and(|value| value == "pnpm" || value.starts_with("pnpm@"))
}

pub fn args(command: &[OsString]) -> &[OsString] {
    &command[if corepack_pnpm(command) { 2 } else { 1 }..]
}

pub fn verb(command: &[OsString]) -> Option<&str> {
    let pnpm = executable(command) == Some("pnpm");
    let mut args = args(command).iter();
    loop {
        let Some(value) = args.next() else {
            return Some("");
        };
        let value = value.to_str()?;
        if !value.starts_with('-') {
            return Some(value);
        }
        match value {
            "--cwd" | "--dir" | "--prefix" | "--config" | "--filter" | "-C" | "-F" => {
                args.next()?;
            }
            "--workspace-dir" | "--store-dir" | "--config-dir" | "--userconfig"
            | "--globalconfig"
                if pnpm =>
            {
                args.next()?;
            }
            flag if pnpm && flag.starts_with("--config.") && !flag.contains('=') => {
                args.next()?;
            }
            "--version" | "--help" | "-v" | "-h" | "--" => return None,
            _ => {}
        }
    }
}

pub fn install_key(command: &[OsString]) -> Option<&str> {
    let manager = executable(command)?;
    let verb = verb(command)?;
    if manager == "yarn" && verb.is_empty() {
        return Some(manager);
    }
    let eligible = match manager {
        "npm" => matches!(verb, "install" | "i" | "ci" | "add" | "update" | "up"),
        "pnpm" | "yarn" | "bun" => matches!(
            verb,
            "install" | "i" | "ci" | "add" | "update" | "up" | "upgrade"
        ),
        "cargo" => matches!(
            verb,
            "build" | "b" | "test" | "t" | "check" | "c" | "fetch" | "update"
        ),
        _ => false,
    };
    eligible.then_some(manager)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_dependency_commands_get_an_automatic_key() {
        for (args, key) in [
            (&["npm", "i"][..], Some("npm")),
            (&["npm", "ci"][..], Some("npm")),
            (&["pnpm", "--filter", "app", "install"][..], Some("pnpm")),
            (&["yarn"][..], Some("yarn")),
            (&["yarn", "--version"][..], None),
            (&["bun", "install"][..], Some("bun")),
            (&["cargo", "build"][..], Some("cargo")),
            (&["npm", "publish"][..], None),
            (&["cargo", "publish"][..], None),
            (&["node", "install"][..], None),
        ] {
            assert_eq!(
                install_key(&args.iter().map(OsString::from).collect::<Vec<_>>()),
                key
            );
        }
    }
}
