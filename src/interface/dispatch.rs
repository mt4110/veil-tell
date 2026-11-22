//! Top-level CLI subcommand router and process entrypoint.

use crate::cli::Options;
use crate::{
    FixtureResolver, Result, SETUP_FAILURE, agent, attribution, baseline, cargo_attribution, cli,
    error, isolation, pnpm, rollup, run, session, summary, verify,
};
use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

async fn dispatch(args: Vec<OsString>, fixture: Option<FixtureResolver>) -> Result<u8> {
    #[cfg(target_os = "linux")]
    if args
        .first()
        .is_some_and(|arg| arg == "__veil_tell_linux_relay")
    {
        let secret = args
            .get(1)
            .and_then(|arg| arg.to_str())
            .filter(|_| args.len() >= 3)
            .ok_or_else(|| error("invalid internal relay invocation"))?;
        return isolation::linux::inside(secret, &args[2..]).await;
    }
    match args.first().and_then(|arg| arg.to_str()) {
        Some("agent") if args.len() == 2 && isolation::is_help(&args[1]) => {
            println!("{}", cli::USAGE);
            return Ok(0);
        }
        Some("agent") => return agent::run(&args[1..], fixture).await,
        Some("agent-env") => return session::agent_env(&args[1..]),
        Some("log") => return session::show(&args[1..]),
        Some("summary") => return summary::run(&args[1..]),
        Some("rollup") => return rollup::run(&args[1..]),
        _ => {}
    }
    if args.as_slice() == ["--version"] || args.as_slice() == ["version"] {
        println!("veil-tell {}", env!("CARGO_PKG_VERSION"));
        return Ok(0);
    }
    if args.first().is_some_and(|arg| isolation::is_help(arg))
        || (args.len() == 2
            && matches!(
                args[0].to_str(),
                Some("observe" | "restrict" | "ci" | "accept" | "clean")
            )
            && isolation::is_help(&args[1]))
    {
        println!("{}", cli::USAGE);
        return Ok(0);
    }
    if args.first().is_some_and(|arg| arg == "verify") {
        if args.get(1).is_some_and(|arg| isolation::is_help(arg)) {
            println!("{}", cli::USAGE);
            return Ok(0);
        }
        return verify::run(args.into_iter().skip(1), fixture).await;
    }
    if args.first().is_some_and(|arg| arg == "clean") {
        return match args.get(1..) {
            Some([]) => baseline::clean(&std::env::current_dir()?.canonicalize()?, false),
            Some([flag]) if flag == "--apply" => {
                baseline::clean(&std::env::current_dir()?.canonicalize()?, true)
            }
            _ => Err(error("usage: veil-tell clean [--apply]")),
        };
    }
    if args.first().is_some_and(|arg| arg == "migrate-baseline") {
        if let [_, manager, file] = args.as_slice() {
            return baseline::migrate(
                &std::env::current_dir()?,
                manager.to_str().unwrap_or(""),
                Path::new(file),
            );
        }
        return Err(error(
            "usage: veil-tell migrate-baseline npm|pnpm|yarn|bun|cargo FILE",
        ));
    }
    if args.first().is_some_and(|arg| arg == "accept") {
        if args.len() != 1 {
            return Err(error(
                "accept takes no arguments; run veil-tell accept in the project directory",
            ));
        }
        return baseline::accept(&std::env::current_dir()?.canonicalize()?);
    }
    let options = Options::parse(args)?;
    let json = options.json;
    let log_args = options.log.then(|| options.command.clone());
    let result = run(options, fixture).await;
    if let Some(args) = log_args
        && let Err(e) = session::append(
            &std::env::current_dir()?,
            &args,
            result.as_ref().ok(),
            false,
        )
    {
        eprintln!("veil-tell: session log: {e}");
    }
    let report = result?;
    if json {
        println!("{}", serde_json::to_string(&report)?);
    }
    Ok(report.run_status.exit_code)
}

pub fn entry(fixture: Option<FixtureResolver>) -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let internal_relay = args.first().is_some_and(|s| s == "__veil_tell_linux_relay");
    let result = (|| {
        if let Some(program) = std::env::args_os().next()
            && let Some(name) = session::shim_name(&program)
        {
            return session::shim(name, &args);
        }
        if args
            .first()
            .is_some_and(|arg| arg == attribution::WRAPPER_MODE)
        {
            isolation::mark_inherited_fds()?;
            return attribution::run_shell(&args[1..]);
        }
        if args
            .first()
            .is_some_and(|arg| arg == cargo_attribution::RUSTC_MODE)
        {
            return cargo_attribution::rustc(&args[1..]);
        }
        if args
            .first()
            .is_some_and(|arg| arg == cargo_attribution::BUILD_MODE)
        {
            return cargo_attribution::run_build(&args[1..]);
        }
        isolation::mark_inherited_fds()?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let result = runtime.block_on(dispatch(args, fixture));
        runtime.shutdown_timeout(Duration::from_millis(250));
        result
    })();
    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("veil-tell: {error}");
            if internal_relay {
                return ExitCode::from(SETUP_FAILURE);
            }
            let next = error
                .downcast_ref::<pnpm::StoreError>()
                .map_or("veil-tell --help", |error| error.next);
            eprintln!("Next / 次: {next}");
            ExitCode::from(SETUP_FAILURE)
        }
    }
}
