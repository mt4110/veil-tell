use crate::{Result, cli::Mode, error, report::Destination};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::net::IpAddr;
use std::path::Path;

const MAX_POLICY_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    Allow,
    Deny,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    action: Action,
    host: String,
    port: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u32,
    profile: String,
    #[serde(default)]
    rule: Vec<Rule>,
}

#[derive(Default)]
pub struct Policy(BTreeMap<String, Action>);

impl Policy {
    pub fn read(path: &Path) -> Result<Self> {
        use std::io::Read;
        let mut content = String::new();
        std::fs::File::open(path)?
            .take(MAX_POLICY_BYTES as u64 + 1)
            .read_to_string(&mut content)?;
        if content.len() > MAX_POLICY_BYTES {
            return Err(error("policy exceeds 1 MiB"));
        }
        let file: PolicyFile = toml::from_str(&content)?;
        if file.version != 1 || file.profile.trim().is_empty() {
            return Err(error("expected policy version 1 and a nonempty profile"));
        }
        let mut policy = BTreeMap::new();
        for rule in file.rule {
            let host =
                normalize_host(&rule.host).ok_or_else(|| error("invalid policy hostname"))?;
            if rule.port != 443 {
                return Err(error("only policy port 443 is supported"));
            }
            if policy.insert(host.clone(), rule.action).is_some() {
                return Err(error(format!("duplicate policy destination: {host}:443")));
            }
        }
        Ok(Self(policy))
    }

    pub fn decision(&self, mode: Mode, host: &str) -> (bool, &'static str) {
        if mode == Mode::Observe {
            return (true, "observe");
        }
        match self.0.get(host) {
            Some(Action::Allow) => (true, "allow_rule"),
            Some(Action::Deny) => (false, "explicit_deny"),
            None => (false, "unknown_destination"),
        }
    }
}

pub fn draft(destinations: &[Destination]) -> Result<String> {
    // The proxy records canonical DNS hostnames from accepted CONNECT requests.
    let candidates: BTreeSet<_> = destinations
        .iter()
        .map(|destination| (&destination.host, destination.port))
        .collect();
    let mut content = String::from(
        "# Pending review. Uncomment a candidate only after reviewing it.\n\
         # Uncommenting an entire block allows that exact host and port.\n\
         version = 1\nprofile = \"observed\"\n",
    );
    for (host, port) in candidates {
        write!(
            content,
            "\n# [[rule]]\n# action = \"allow\"\n# host = \"{host}\"\n# port = {port}\n"
        )?;
    }
    if content.len() > MAX_POLICY_BYTES {
        return Err(error("policy draft exceeds 1 MiB"));
    }
    Ok(content)
}

pub fn normalize_host(input: &str) -> Option<String> {
    let name = input
        .strip_suffix('.')
        .unwrap_or(input)
        .to_ascii_lowercase();
    if name.len() > 253 || !name.contains('.') || name.parse::<IpAddr>().is_ok() {
        return None;
    }
    let mut labels = name.split('.');
    if !labels.clone().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) || !labels
        .next_back()?
        .bytes()
        .any(|byte| byte.is_ascii_alphabetic())
    {
        return None;
    }
    Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_matches_normalized_exact_names_and_distinguishes_denials() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            r#"
version = 1
profile = "test"
[[rule]]
action = "deny"
host = "EXAMPLE.test."
port = 443
"#,
        )
        .unwrap();
        let policy = Policy::read(file.path()).unwrap();
        let host = normalize_host("Example.test.").unwrap();
        assert_eq!(
            policy.decision(Mode::Restrict, &host),
            (false, "explicit_deny")
        );
        assert_eq!(
            policy.decision(Mode::Restrict, "sub.example.test"),
            (false, "unknown_destination")
        );
        assert_eq!(policy.decision(Mode::Observe, &host), (true, "observe"));
        for host in [
            "127.0.0.1",
            "127.1",
            "[::1]",
            "*.example.test",
            "evil.test/anything",
            "host",
        ] {
            assert!(normalize_host(host).is_none(), "{host}");
        }
    }
}
