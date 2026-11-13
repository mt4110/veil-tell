use super::{client_command, received, receiver_pair, require, run_trials};
use std::env;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::process::Command;

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

pub(super) fn run() -> io::Result<()> {
    let executable = env::current_exe()?;
    let (allowed, blocked) = receiver_pair(Ipv4Addr::LOCALHOST)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let proxy = listener.local_addr()?;
    let profile = format!(
        "(version 1)\n(allow default)\n(deny network*)\n\
         (allow network-outbound (remote tcp4 \"localhost:{}\"))",
        proxy.port()
    );
    println!("seatbelt tool={SANDBOX_EXEC} proxy={proxy} receivers=loopback-only");
    println!("profile:\n{profile}");

    run_trials(&allowed, &blocked, |trial, allowed, blocked| {
        let destination = if trial.route == "direct" {
            blocked
        } else {
            proxy
        };
        let mut command = if trial.isolated {
            let mut command = Command::new(SANDBOX_EXEC);
            command.args(["-p", &profile]).arg(&executable).args([
                "macos-child",
                trial.route,
                &destination.to_string(),
                trial.name,
            ]);
            command
        } else {
            client_command(&executable, trial.route, destination, trial.name)
        };
        if trial.route != "direct" {
            return trial.run_tcp_proxy(&listener, command, allowed, blocked);
        }
        let output = command.output()?;
        if trial.isolated {
            let stderr = String::from_utf8_lossy(&output.stderr);
            require(
                stderr.contains("connect-failed token=isolated-direct errno=Some(1)"),
                format!("expected EPERM from Seatbelt, got: {stderr}"),
            )?;
        }
        Ok(output)
    })?;

    let failure = Command::new(SANDBOX_EXEC)
        .args(["-p", "(version 1)(invalid-fixture-rule)"])
        .arg(&executable)
        .args([
            "macos-child",
            "direct",
            &blocked.local_addr()?.to_string(),
            "setup-failure",
        ])
        .output()?;
    let stderr = String::from_utf8_lossy(&failure.stderr);
    print!("{stderr}");
    require(
        !failure.status.success()
            && stderr.contains("invalid-fixture-rule")
            && !stderr.contains("client-start ")
            && received(&allowed)?.is_empty()
            && received(&blocked)?.is_empty(),
        "invalid profile did not fail before starting the client",
    )?;
    println!(
        "setup-failure exit={:?} client_started=false",
        failure.status.code()
    );
    println!("PASS: 7 macOS receiver trials and 1 setup failure");
    Ok(())
}

pub(super) fn child(route: &str, address: SocketAddr, token: &str) -> io::Result<i32> {
    let output = client_command(&env::current_exe()?, route, address, token).output()?;
    io::stderr().write_all(&output.stderr)?;
    output
        .status
        .code()
        .ok_or_else(|| io::Error::other("client was killed"))
}
