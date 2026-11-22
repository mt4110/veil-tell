use crate::{Result, error};
use std::ffi::OsString;

pub const USAGE: &str = "\
Usage:
  veil-tell observe [--backend proxy|isolated] [--report FILE] [--emit-policy FILE] [--baseline FILE | --baseline-out FILE] [--fail-on-new] [--attribute-npm | --no-attribute] -- COMMAND [ARG...]
  veil-tell restrict --backend proxy|isolated --policy FILE [--fail-on-unknown] [--report FILE] [--attribute-npm | --no-attribute] -- COMMAND [ARG...]
  veil-tell verify --source DIR --policy FILE --without HOST:443 --report FILE [--timeout-seconds N] -- COMMAND [ARG...]\n\
  veil-tell ci [--baseline FILE] [--report FILE] [--attribute-npm | --no-attribute] -- COMMAND [ARG...]\n\
  veil-tell migrate-baseline npm|pnpm|yarn|bun|cargo FILE\n\
  veil-tell clean [--apply]\n\
  veil-tell accept\n\
  veil-tell version | --version (run an executable named version with veil-tell -- version)
  veil-tell agent -- COMMAND [ARG...]
  veil-tell agent-env [--shell bash|zsh|fish]
  veil-tell log [--today | --since DURATION] [--only-new | --only-blocked] [--json]
  veil-tell summary REPORT.JSON [--github-output FILE] [--missing-reason TEXT]
  veil-tell rollup LEDGER.JSON [--format markdown|json|both] [--out-json FILE] [--out-md FILE]
  veil-tell [--log] [--json] [--save-baseline] [--no-attribute] COMMAND [ARG...]";

pub use crate::domain::attribution_model::{Backend, Mode, Options};

impl Options {
    pub fn parse(mut args: Vec<OsString>) -> Result<Self> {
        let mut no_attribute = false;
        let mut save_baseline = false;
        let mut log = false;
        let mut json = false;
        while let Some(flag) = args.first().and_then(|arg| arg.to_str()) {
            match flag {
                "--no-attribute" if !no_attribute => no_attribute = true,
                "--save-baseline" if !save_baseline => save_baseline = true,
                "--log" if !log => log = true,
                "--json" if !json => json = true,
                _ => break,
            }
            args.remove(0);
        }
        let mut options = Self {
            mode: Mode::Observe,
            backend: Backend::Proxy,
            policy: None,
            report: None,
            emit_policy: None,
            fail_on_unknown: false,
            command: Vec::new(),
            attribute_npm: false,
            no_attribute,
            json,
            log,
            shorthand: false,
            shim: false,
            save_baseline,
            comparison: Default::default(),
        };
        match args.first().and_then(|arg| arg.to_str()) {
            Some("--" | crate::session::SHIM_MODE) if args.len() >= 2 => {
                options.shim = args[0] == crate::session::SHIM_MODE;
                options.log |= options.shim;
                options.shorthand = true;
                options.command = args.split_off(1);
                return Ok(options);
            }
            Some("observe") => {}
            Some("ci") => {
                options.backend = Backend::Isolated;
                options.comparison.ci = true;
            }
            Some("restrict") => options.mode = Mode::Restrict,
            _ if !args.is_empty() && !args[0].to_string_lossy().starts_with('-') => {
                options.shorthand = true;
                options.command = args;
                return Ok(options);
            }
            _ => return Err(error(USAGE)),
        }
        if save_baseline {
            return Err(error(
                "--save-baseline requires the short form: veil-tell --save-baseline COMMAND",
            ));
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
                Some("--json") if !options.json => options.json = true,
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
                Some("--no-attribute") if !options.no_attribute => options.no_attribute = true,
                Some("--attribute-npm") if !options.attribute_npm => options.attribute_npm = true,
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
        if options.attribute_npm && options.no_attribute {
            return Err(error("choose either --attribute-npm or --no-attribute"));
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
