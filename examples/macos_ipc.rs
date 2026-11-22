//! Check named Mach and XPC paths against local receivers with the ordinary CLI (macOS).

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

fn write_info_plist(contents: &Path, name: &str, executable: &str, service: bool) -> PathBuf {
    let macos_dir = contents.join("MacOS");
    fs::create_dir_all(&macos_dir).unwrap();
    let pkg_type = if service { "XPC!" } else { "APPL" };
    let xpc_block = if service {
        "  <key>XPCService</key>\n  <dict>\n    <key>ServiceType</key>\n    <string>Application</string>\n  </dict>\n"
    } else {
        ""
    };
    let plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
           <key>CFBundleIdentifier</key>\n\
           <string>{name}</string>\n\
           <key>CFBundleExecutable</key>\n\
           <string>{executable}</string>\n\
           <key>CFBundlePackageType</key>\n\
           <string>{pkg_type}</string>\n\
         {xpc_block}</dict>\n\
         </plist>\n"
    );
    fs::write(contents.join("Info.plist"), plist).unwrap();
    macos_dir.join(executable)
}

fn random_hex8() -> String {
    let mut bytes = [0u8; 8];
    fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut bytes)
        .unwrap();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    if !cfg!(target_os = "macos") {
        eprintln!("macos_ipc is only supported on macOS");
        std::process::exit(1);
    }
    let uid = unsafe { libc::getuid() };
    assert!(uid != 0, "run this example as an unprivileged user");

    let cli = PathBuf::from(env::args().nth(1).expect("pass veil-tell binary path"))
        .canonicalize()
        .unwrap();
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("macos-ipc.c")
        .canonicalize()
        .unwrap();
    let tmp = tempfile::Builder::new()
        .prefix("veil-tell-macos-ipc-")
        .tempdir_in("/tmp")
        .unwrap();
    let root = tmp.keep().canonicalize().unwrap();
    println!("evidence={}", root.display());

    let work = root.join("work");
    let reports = root.join("reports");
    fs::create_dir_all(&work).unwrap();
    fs::create_dir_all(&reports).unwrap();

    let policy = reports.join("empty.toml");
    fs::write(&policy, "version=1\nprofile=\"macos-ipc\"\n").unwrap();
    let mach_log = root.join("mach-receiver.log");
    let xpc_log = root.join("xpc-receiver.log");
    fs::write(&mach_log, "").unwrap();
    fs::write(&xpc_log, "").unwrap();

    let nonce = random_hex8();
    let mach_name = format!("local.veil.tell.mach.{nonce}");
    let xpc_name = format!("local.veil.tell.forward.{nonce}");
    let app = root.join("VeilForward.app").join("Contents");
    let sender = write_info_plist(&app, &format!("{xpc_name}.client"), "sender", false);
    let service = write_info_plist(
        &app.join("XPCServices/Receiver.xpc/Contents"),
        &xpc_name,
        "receiver",
        true,
    );

    let status = Command::new("/usr/bin/clang")
        .args(["-Wall", "-Wextra", "-Werror", "-fblocks"])
        .arg(&source)
        .args(["-framework", "CoreFoundation", "-o"])
        .arg(&sender)
        .status()
        .unwrap();
    assert!(status.success());

    let mut outcomes: BTreeMap<String, Value> = BTreeMap::new();
    let mut probe = |label: &str, args: Vec<PathBuf>, isolated: bool| {
        let mut cmd = if isolated {
            let mut c = Command::new(&cli);
            c.args(["restrict", "--backend", "isolated", "--policy"])
                .arg(&policy)
                .args(["--fail-on-unknown", "--report"])
                .arg(reports.join(format!("{label}.json")))
                .arg("--");
            for a in &args {
                c.arg(a);
            }
            c
        } else {
            let mut c = Command::new(&args[0]);
            for a in &args[1..] {
                c.arg(a);
            }
            c
        };
        cmd.current_dir(&work);
        let out = cmd.output().unwrap();
        let code = out.status.code().unwrap_or(125);
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        print!("{label} exit={code}\n{stdout}{stderr}");
        outcomes.insert(
            label.to_string(),
            json!({"exit_code": code, "stdout": stdout, "stderr": stderr}),
        );
    };

    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_port = tcp.local_addr().unwrap().port();
    let status = Command::new("/usr/bin/clang")
        .args(["-Wall", "-Wextra", "-Werror", "-fblocks"])
        .arg(&source)
        .arg("-DXPC_RECEIVER")
        .arg(format!("-DRECEIVER_LOG=\"{}\"", xpc_log.display()))
        .arg(format!("-DTCP_PORT={tcp_port}"))
        .arg("-o")
        .arg(&service)
        .status()
        .unwrap();
    assert!(status.success());

    let mut listener = Command::new(&sender)
        .arg("listen-mach")
        .arg(&mach_name)
        .arg(&mach_log)
        .current_dir(&work)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut reader = BufReader::new(listener.stdout.take().unwrap());
    let mut first_line = String::new();
    reader.read_line(&mut first_line).unwrap();
    assert_eq!(first_line.trim(), "mach_receiver=ready");

    for phase in ["control-before", "isolated", "control-after"] {
        for (path, name) in [("mach", &mach_name), ("xpc", &xpc_name)] {
            let label = format!("{path}-{phase}");
            probe(
                &label,
                vec![
                    sender.clone(),
                    PathBuf::from(format!("send-{path}")),
                    PathBuf::from(name),
                    PathBuf::from(&label),
                ],
                phase == "isolated",
            );
        }
    }
    probe(
        "mach-register-control",
        vec![
            sender.clone(),
            PathBuf::from("register-mach"),
            PathBuf::from(format!("{mach_name}.control")),
            mach_log.clone(),
        ],
        false,
    );
    probe(
        "mach-register-isolated",
        vec![
            sender.clone(),
            PathBuf::from("register-mach"),
            PathBuf::from(format!("{mach_name}.new")),
            mach_log.clone(),
        ],
        true,
    );

    let _ = listener.kill();
    let _ = listener.wait();
    let _ = Command::new(&sender)
        .args(["send-xpc", &xpc_name, "stop-fixture"])
        .current_dir(&work)
        .output();

    tcp.set_nonblocking(true).unwrap();
    let mut tcp_tokens = Vec::new();
    std::thread::sleep(Duration::from_millis(300));
    while let Ok((conn, _)) = tcp.accept() {
        conn.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut line = String::new();
        let mut br = BufReader::new(conn);
        let _ = br.read_line(&mut line);
        tcp_tokens.push(line.trim().to_string());
    }

    fs::write(
        root.join("tcp-receiver.json"),
        serde_json::to_string_pretty(&tcp_tokens).unwrap() + "\n",
    )
    .unwrap();
    fs::write(
        root.join("outcomes.json"),
        serde_json::to_string_pretty(&outcomes).unwrap() + "\n",
    )
    .unwrap();

    let mach_tokens: Vec<String> = fs::read_to_string(&mach_log)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    let xpc_tokens: Vec<String> = fs::read_to_string(&xpc_log)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(mach_tokens, vec!["mach-control-before", "mach-control-after"]);
    assert_eq!(xpc_tokens, vec!["xpc-control-before", "xpc-control-after"]);
    assert_eq!(tcp_tokens, xpc_tokens);

    let ctrl = &outcomes["mach-register-control"];
    assert_eq!(ctrl["exit_code"], 0);
    assert!(
        ctrl["stdout"]
            .as_str()
            .unwrap()
            .contains("mach_receiver=registered")
    );
    for path in ["mach", "xpc"] {
        for phase in ["control-before", "control-after"] {
            let c = &outcomes[&format!("{path}-{phase}")];
            assert_eq!(c["exit_code"], 0);
            assert!(
                c["stdout"]
                    .as_str()
                    .unwrap()
                    .contains(&format!("{path}_reply=ACK"))
            );
        }
    }
    for (label, code, expected_stdout) in [
        ("mach-isolated", 11, "mach_reply=unavailable"),
        ("xpc-isolated", 11, "xpc_reply=connection_invalid"),
        ("mach-register-isolated", 12, "mach_receiver=unavailable"),
    ] {
        let res = &outcomes[label];
        assert_eq!(res["exit_code"], code);
        assert!(res["stdout"].as_str().unwrap().contains(expected_stdout));
        let report: Value = serde_json::from_str(
            &fs::read_to_string(reports.join(format!("{label}.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(report["backend"], "isolated");
        assert_eq!(report["isolation"], "unconfirmed");
        assert_eq!(report["child_status"], json!({"exit_code": code, "signal": null}));
        assert_eq!(
            report["run_status"],
            json!({"exit_code": code, "reason": "child_failed"})
        );
        assert_eq!(report["coverage"]["proxy"], "http_connect_requests");
        assert_eq!(
            report["coverage"]["direct_attempt_destinations"],
            "not_observed"
        );
        assert_eq!(report["destinations"], json!([]));
    }
    println!("PASS: Mach and XPC receive logs, exit codes, and JSON");
}
