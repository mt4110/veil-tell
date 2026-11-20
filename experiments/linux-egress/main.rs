use std::env;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{self, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
#[path = "../macos-egress/seatbelt.rs"]
mod seatbelt;

const ALLOWED: &str = "allowed.test:443";
const BLOCKED: &str = "blocked.test:443";
const OK: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const DENIED: &[u8] = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
const DEADLINE: Duration = Duration::from_secs(3);
const PROXY_DENIED: i32 = 20;
const DIRECT_FAILED: i32 = 21;

fn require(condition: bool, reason: impl Into<String>) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(reason.into()))
    }
}

fn read_head(mut stream: impl Read) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    while head.len() < 1024 {
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
    }
    Err(io::Error::other("oversized HTTP header"))
}

fn tcp_deadlines(stream: &TcpStream) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(DEADLINE))?;
    stream.set_write_timeout(Some(DEADLINE))
}

fn dial(address: SocketAddr) -> io::Result<TcpStream> {
    let stream = TcpStream::connect_timeout(&address, DEADLINE)?;
    tcp_deadlines(&stream)?;
    Ok(stream)
}

fn accept(listener: &TcpListener) -> io::Result<TcpStream> {
    let end = Instant::now() + DEADLINE;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                tcp_deadlines(&stream)?;
                return Ok(stream);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < end => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

fn proxy(
    mut transport: impl Read + Write,
    allowed: SocketAddr,
    blocked: SocketAddr,
    restrict: bool,
    trial: &str,
) -> io::Result<()> {
    let request = read_head(&mut transport)?;
    let line = request.split(|byte| *byte == b'\r').next();
    let authority = match line {
        Some(b"CONNECT allowed.test:443 HTTP/1.1") => ALLOWED,
        Some(b"CONNECT blocked.test:443 HTTP/1.1") => BLOCKED,
        _ => return Err(io::Error::other("unexpected fixture CONNECT request")),
    };
    if restrict && authority != ALLOWED {
        println!(
            "proxy trial={trial} authority={authority} decision=deny resolve=false dial=false"
        );
        return transport.write_all(DENIED);
    }

    // Fixed test-only resolver. No system name lookup.
    let address = if authority == ALLOWED {
        allowed
    } else {
        blocked
    };
    println!("proxy trial={trial} authority={authority} decision=allow resolve=true dial=true");
    let mut upstream = dial(address)?;
    println!("proxy trial={trial} connected={address}");
    transport.write_all(OK)?;
    // The fixture only uploads a token. Bound the amount relayed per trial.
    io::copy(&mut transport.take(128), &mut upstream)?;
    upstream.shutdown(Shutdown::Write)
}

fn client(route: &str, address: SocketAddr, token: &str) -> io::Result<i32> {
    eprintln!("client-start token={token} route={route}");
    let mut stream = if route == "direct" {
        eprintln!("connect-attempt token={token} address={address}");
        match TcpStream::connect_timeout(&address, DEADLINE) {
            Ok(stream) => {
                tcp_deadlines(&stream)?;
                stream
            }
            Err(error) => {
                eprintln!(
                    "connect-failed token={token} errno={:?} error={error}",
                    error.raw_os_error()
                );
                return Ok(DIRECT_FAILED);
            }
        }
    } else {
        let mut stream = dial(address)?;
        write!(stream, "CONNECT {route} HTTP/1.1\r\nHost: {route}\r\n\r\n")?;
        let response = read_head(&mut stream)?;
        if response == DENIED {
            eprintln!("connect-denied token={token} status=403");
            return Ok(PROXY_DENIED);
        }
        require(response == OK, "unexpected CONNECT response")?;
        stream
    };
    stream.write_all(token.as_bytes())?;
    stream.shutdown(Shutdown::Write)?;
    Ok(0)
}

fn client_command(executable: &Path, route: &str, address: SocketAddr, token: &str) -> Command {
    let mut command = Command::new(executable);
    command.args(["client", route, &address.to_string(), token]);
    command
}

fn inside(route: &str, destination: SocketAddr, token: &str) -> io::Result<i32> {
    let relay = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    relay.set_nonblocking(true)?;
    let executable = Path::new("/lab");
    if route == "direct" {
        let child = client_command(executable, route, destination, token).output()?;
        io::stderr().write_all(&child.stderr)?;
        return child
            .status
            .code()
            .ok_or_else(|| io::Error::other("client was killed"));
    }

    // Only this relay has the socketpair on stdin/stdout. The client gets fresh pipes.
    let child = client_command(executable, route, relay.local_addr()?, token)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stream = accept(&relay)?;
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    output.write_all(&read_head(&mut stream)?)?;
    output.flush()?;
    let response = read_head(&mut input)?;
    stream.write_all(&response)?;
    if response == OK {
        io::copy(&mut stream.take(128), &mut output)?;
        output.flush()?;
    }
    let child = child.wait_with_output()?;
    io::stderr().write_all(&child.stderr)?;
    child
        .status
        .code()
        .ok_or_else(|| io::Error::other("client was killed"))
}

fn sandbox(bwrap: &Path, executable: &Path) -> Command {
    let mut command = Command::new(bwrap);
    command.args([
        "--unshare-user",
        "--unshare-net",
        "--unshare-pid",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--ro-bind",
    ]);
    command
        .arg(executable)
        .args(["/lab", "--dev", "/dev", "--chdir", "/"]);
    command
}

fn received(listener: &TcpListener) -> io::Result<Vec<Vec<u8>>> {
    let mut connections = Vec::new();
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                tcp_deadlines(&stream)?;
                let mut data = Vec::new();
                stream.take(128).read_to_end(&mut data)?;
                connections.push(data);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(connections),
            Err(error) => return Err(error),
        }
    }
}

struct Trial {
    name: &'static str,
    route: &'static str,
    restrict: bool,
    isolated: bool,
    exit: i32,
}

impl Trial {
    fn run_client(
        &self,
        bwrap: &Path,
        executable: &Path,
        allowed: SocketAddr,
        blocked: SocketAddr,
    ) -> io::Result<Output> {
        if self.isolated {
            let mut command = sandbox(bwrap, executable);
            command.args([
                "--",
                "/lab",
                "inside",
                self.route,
                &blocked.to_string(),
                self.name,
            ]);
            if self.route == "direct" {
                return command.output();
            }
            let (outside, bridge) = UnixStream::pair()?;
            outside.set_read_timeout(Some(DEADLINE))?;
            outside.set_write_timeout(Some(DEADLINE))?;
            command.stdin(Stdio::from(OwnedFd::from(bridge.try_clone()?)));
            command.stdout(Stdio::from(OwnedFd::from(bridge)));
            command.stderr(Stdio::piped());
            let child = command.spawn()?;
            drop(command);
            let result = proxy(outside, allowed, blocked, self.restrict, self.name);
            let child = child.wait_with_output()?;
            if let Err(error) = result {
                return Err(io::Error::other(format!(
                    "isolated proxy exchange failed: {error}; sandbox exit {}; stderr: {}",
                    child.status,
                    String::from_utf8_lossy(&child.stderr)
                )));
            }
            return Ok(child);
        }
        if self.route == "direct" {
            return client_command(executable, self.route, blocked, self.name).output();
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let command = client_command(executable, self.route, listener.local_addr()?, self.name);
        self.run_tcp_proxy(&listener, command, allowed, blocked)
    }

    fn run_tcp_proxy(
        &self,
        listener: &TcpListener,
        mut command: Command,
        allowed: SocketAddr,
        blocked: SocketAddr,
    ) -> io::Result<Output> {
        let child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let result = accept(listener)
            .and_then(|stream| proxy(stream, allowed, blocked, self.restrict, self.name));
        let child = child.wait_with_output()?;
        if let Err(error) = result {
            return Err(io::Error::other(format!(
                "proxy exchange failed: {error}; child exit {}; stderr: {}",
                child.status,
                String::from_utf8_lossy(&child.stderr)
            )));
        }
        Ok(child)
    }
}

fn receiver_pair(ip: Ipv4Addr) -> io::Result<(TcpListener, TcpListener)> {
    let allowed = TcpListener::bind((ip, 0))?;
    let blocked = TcpListener::bind((ip, 0))?;
    allowed.set_nonblocking(true)?;
    blocked.set_nonblocking(true)?;
    Ok((allowed, blocked))
}

fn run_trials(
    allowed: &TcpListener,
    blocked: &TcpListener,
    launch: impl Fn(&Trial, SocketAddr, SocketAddr) -> io::Result<Output>,
) -> io::Result<()> {
    let allowed_address = allowed.local_addr()?;
    let blocked_address = blocked.local_addr()?;
    println!("receivers allowed={allowed_address} unregistered={blocked_address}");

    let trials = [
        Trial {
            name: "open-connect",
            route: BLOCKED,
            restrict: false,
            isolated: false,
            exit: 0,
        },
        Trial {
            name: "open-direct",
            route: "direct",
            restrict: false,
            isolated: false,
            exit: 0,
        },
        Trial {
            name: "rules-connect",
            route: BLOCKED,
            restrict: true,
            isolated: false,
            exit: PROXY_DENIED,
        },
        Trial {
            name: "rules-direct",
            route: "direct",
            restrict: true,
            isolated: false,
            exit: 0,
        },
        Trial {
            name: "isolated-allowed",
            route: ALLOWED,
            restrict: true,
            isolated: true,
            exit: 0,
        },
        Trial {
            name: "isolated-connect",
            route: BLOCKED,
            restrict: true,
            isolated: true,
            exit: PROXY_DENIED,
        },
        Trial {
            name: "isolated-direct",
            route: "direct",
            restrict: true,
            isolated: true,
            exit: DIRECT_FAILED,
        },
    ];
    for trial in trials {
        let output = launch(&trial, allowed_address, blocked_address)?;
        let diagnostics = String::from_utf8_lossy(&output.stderr);
        print!("{diagnostics}");
        let at_allowed = received(allowed)?;
        let at_blocked = received(blocked)?;
        println!(
            "receiver trial={} allowed={:?} unregistered={:?} client_exit={:?}",
            trial.name,
            at_allowed
                .iter()
                .map(|bytes| String::from_utf8_lossy(bytes))
                .collect::<Vec<_>>(),
            at_blocked
                .iter()
                .map(|bytes| String::from_utf8_lossy(bytes))
                .collect::<Vec<_>>(),
            output.status.code(),
        );
        let expected = vec![trial.name.as_bytes().to_vec()];
        let matches = if trial.exit != 0 {
            at_allowed.is_empty() && at_blocked.is_empty()
        } else if trial.route == ALLOWED {
            at_allowed == expected && at_blocked.is_empty()
        } else {
            at_allowed.is_empty() && at_blocked == expected
        };
        require(
            matches
                && output.status.code() == Some(trial.exit)
                && diagnostics.contains("client-start "),
            format!("trial failed or was inconclusive: {}", trial.name),
        )?;
    }
    Ok(())
}

fn run(bwrap: &Path, ip: Ipv4Addr) -> io::Result<()> {
    require(bwrap.is_absolute(), "supply an absolute bubblewrap path")?;
    require(
        ip.is_private() && !ip.is_loopback(),
        "supply the lab's private IPv4 address",
    )?;
    let executable = env::current_exe()?;
    let (allowed, blocked) = receiver_pair(ip)?;
    run_trials(&allowed, &blocked, |trial, allowed, blocked| {
        trial.run_client(bwrap, &executable, allowed, blocked)
    })?;
    let failed = sandbox(bwrap, &executable)
        .args([
            "--ro-bind",
            "/dev/null/missing",
            "/forced-error",
            "--",
            "/lab",
            "inside",
            "direct",
        ])
        .arg(blocked.local_addr()?.to_string())
        .arg("setup-failure")
        .output()?;
    let diagnostics = String::from_utf8_lossy(&failed.stderr);
    print!("{diagnostics}");
    require(
        !failed.status.success()
            && diagnostics.contains("/dev/null/missing")
            && !diagnostics.contains("client-start ")
            && received(&allowed)?.is_empty()
            && received(&blocked)?.is_empty(),
        "forced setup failure did not fail before starting the client",
    )?;
    println!(
        "setup-failure exit={:?} client_started=false",
        failed.status.code()
    );
    println!("PASS: 7 receiver trials and 1 setup failure");
    Ok(())
}

fn parse_address(value: &str) -> io::Result<SocketAddr> {
    value.parse().map_err(io::Error::other)
}

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let result = match args.as_slice() {
        #[cfg(target_os = "linux")]
        [mode] if mode == "notify" => Command::new("python3").arg("-c")
            .arg(include_str!("notify_probe.py")).status().map(|s| s.code().unwrap_or(1)),

        #[cfg(target_os = "macos")]
        [mode] if mode == "macos" => seatbelt::run().map(|()| 0),
        #[cfg(target_os = "macos")]
        [mode, route, address, token] if mode == "macos-child" => {
            parse_address(address).and_then(|address| seatbelt::child(route, address, token))
        }
        [mode, bwrap, ip] if mode == "run" => ip
            .parse()
            .map_err(io::Error::other)
            .and_then(|ip| run(Path::new(bwrap), ip))
            .map(|()| 0),
        [mode, route, address, token] if mode == "client" => {
            parse_address(address).and_then(|address| client(route, address, token))
        }
        [mode, route, address, token] if mode == "inside" => {
            parse_address(address).and_then(|address| inside(route, address, token))
        }
        _ => Err(io::Error::other(
            "usage: lab run /absolute/path/to/bwrap LAB_IPV4",
        )),
    };
    match result {
        Ok(code) => process::exit(code),
        Err(error) => {
            eprintln!("experiment error: {error}");
            process::exit(1);
        }
    }
}
