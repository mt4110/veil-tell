use std::ffi::OsString;
use std::path::Path;

pub const NAMES: &[&str] = &["npm", "pnpm", "yarn", "bun", "cargo"];

pub fn executable(command: &[OsString]) -> Option<&str> {
    Path::new(command.first()?).file_name()?.to_str()
}

pub fn install_key(command: &[OsString]) -> Option<&str> {
    let manager = executable(command)?;
    let mut args = command.iter().skip(1);
    let verb = loop {
        let Some(value) = args.next() else {
            return (manager == "yarn").then_some(manager);
        };
        let value = value.to_str()?;
        if !value.starts_with('-') {
            break value;
        }
        match value {
            "--cwd" | "--dir" | "--prefix" | "--config" | "--filter" | "-C" | "-F" => {
                args.next()?;
            }
            "--version" | "--help" | "-v" | "-h" | "--" => return None,
            _ => {}
        }
    };
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
