use crate::{Result, error};
use std::ffi::OsString;
use std::path::PathBuf;

pub const USAGE: &str = "\
Usage:
  veil-tell observe [--backend proxy|isolated] [--report FILE] [--emit-policy FILE] -- COMMAND [ARG...]
  veil-tell restrict --backend proxy|isolated --policy FILE [--fail-on-unknown] [--report FILE] -- COMMAND [ARG...]
  veil-tell verify --source DIR --policy FILE --without HOST:443 --report FILE [--timeout-seconds N] -- COMMAND [ARG...]\n\
  veil-tell COMMAND [ARG...]";

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Observe,
    Restrict,
}

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Proxy,
    Isolated,
}

pub struct Options {
    pub mode: Mode,
    pub backend: Backend,
    pub policy: Option<PathBuf>,
    pub report: Option<PathBuf>,
    pub emit_policy: Option<PathBuf>,
    pub fail_on_unknown: bool,
    pub command: Vec<OsString>,
}

impl Options {
    pub fn parse(args: Vec<OsString>) -> Result<Self> {
        let mut options = Self {
            mode: Mode::Observe,
            backend: Backend::Proxy,
            policy: None,
            report: None,
            emit_policy: None,
            fail_on_unknown: false,
            command: Vec::new(),
        };
        match args.first().and_then(|arg| arg.to_str()) {
            Some("observe") => {}
            Some("restrict") => options.mode = Mode::Restrict,
            _ if !args.is_empty() && !args[0].to_string_lossy().starts_with('-') => {
                options.command = args;
                return Ok(options);
            }
            _ => return Err(error(USAGE)),
        }
        let mut backend_selected = false;
        let mut args = args.into_iter().skip(1);
        while let Some(flag) = args.next() {
            match flag.to_str() {
                Some("--") => {
                    options.command = args.collect();
                    break;
                }
                Some("--backend") if !backend_selected => {
                    options.backend = match args.next().as_deref().and_then(|arg| arg.to_str()) {
                        Some("proxy") => Backend::Proxy,
                        Some("isolated") => Backend::Isolated,
                        _ => return Err(error("--backend requires proxy or isolated")),
                    };
                    backend_selected = true;
                }
                Some("--policy") if options.policy.is_none() => {
                    options.policy = Some(
                        args.next()
                            .ok_or_else(|| error("missing policy path"))?
                            .into(),
                    );
                }
                Some("--report") if options.report.is_none() => {
                    options.report = Some(
                        args.next()
                            .ok_or_else(|| error("missing report path"))?
                            .into(),
                    );
                }
                Some("--emit-policy") if options.emit_policy.is_none() => {
                    options.emit_policy = Some(
                        args.next()
                            .ok_or_else(|| error("missing --emit-policy path"))?
                            .into(),
                    );
                }
                Some("--fail-on-unknown") if !options.fail_on_unknown => {
                    options.fail_on_unknown = true
                }
                _ => {
                    return Err(error(format!(
                        "unexpected or repeated option: {}",
                        flag.to_string_lossy()
                    )));
                }
            }
        }
        if options.command.is_empty() {
            return Err(error("specify a command after --"));
        }
        match options.mode {
            Mode::Restrict if options.emit_policy.is_some() => {
                return Err(error("--emit-policy requires observe"));
            }
            Mode::Restrict if !backend_selected || options.policy.is_none() => {
                return Err(error("restrict requires --backend and --policy"));
            }
            Mode::Observe if options.policy.is_some() || options.fail_on_unknown => {
                return Err(error("--policy and --fail-on-unknown require restrict"));
            }
            _ => {}
        }
        Ok(options)
    }
}
