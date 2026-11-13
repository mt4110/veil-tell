use crate::{Result, error};
use std::ffi::OsString;
use std::path::PathBuf;

pub const USAGE: &str = "\
Usage:
  veil-tell observe [--backend proxy|isolated] [--report FILE] [--emit-policy FILE] [--baseline FILE | --baseline-out FILE] [--fail-on-new] -- COMMAND [ARG...]
  veil-tell restrict --backend proxy|isolated --policy FILE [--fail-on-unknown] [--report FILE] -- COMMAND [ARG...]
  veil-tell verify --source DIR --policy FILE --without HOST:443 --report FILE [--timeout-seconds N] -- COMMAND [ARG...]\n\
  veil-tell ci [--baseline FILE] [--report FILE] -- COMMAND [ARG...]\n\
  veil-tell accept\n\
  veil-tell COMMAND [ARG...]";

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Observe,
    Restrict,
}

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Debug)]
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
    pub comparison: crate::baseline::Options,
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
            comparison: Default::default(),
        };
        match args.first().and_then(|arg| arg.to_str()) {
            Some("observe") => {}
            Some("ci") => {
                options.backend = Backend::Isolated;
                options.comparison.ci = true;
            }
            Some("restrict") => options.mode = Mode::Restrict,
            _ if !args.is_empty() && !args[0].to_string_lossy().starts_with('-') => {
                options.comparison.automatic = true;
                options.command = args;
                return Ok(options);
            }
            _ => return Err(error(USAGE)),
        }
        let mut backend_selected = options.comparison.ci;
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
                Some("--baseline") if options.comparison.input.is_none() => {
                    options.comparison.input = Some(
                        args.next()
                            .ok_or_else(|| error("--baseline requires a file path"))?
                            .into(),
                    );
                }
                Some("--baseline-out")
                    if options.comparison.output.is_none() && !options.comparison.ci =>
                {
                    options.comparison.output = Some(
                        args.next()
                            .ok_or_else(|| error("--baseline-out requires a file path"))?
                            .into(),
                    );
                }
                Some("--fail-on-new")
                    if !options.comparison.fail_on_new && !options.comparison.ci =>
                {
                    options.comparison.fail_on_new = true;
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
        let comparison = &options.comparison;
        if options.mode == Mode::Restrict && comparison.requested() {
            return Err(error(
                "baseline options require observe or ci; run veil-tell observe --help for usage",
            ));
        }
        if comparison.input.is_some() && comparison.output.is_some() {
            return Err(error(
                "choose either --baseline to compare or --baseline-out to create a new file",
            ));
        }
        if comparison.fail_on_new && comparison.input.is_none() {
            return Err(error(
                "--fail-on-new requires --baseline FILE; create one with --baseline-out FILE first",
            ));
        }
        if comparison.ci && options.emit_policy.is_some() {
            return Err(error(
                "ci reads a baseline; use observe --emit-policy to create a policy draft",
            ));
        }
        Ok(options)
    }
}
