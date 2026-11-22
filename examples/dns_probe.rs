//! Compare local DNS recording and host egress with no public DNS traffic.

use std::env;
use std::net::UdpSocket;
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

fn query_bytes() -> Vec<u8> {
    let mut q = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    q.extend_from_slice(b"\x05probe\x04test\x00\x00\x01\x00\x01");
    q
}

fn receiver(ready: Arc<Barrier>) {
    let sock = UdpSocket::bind("127.0.0.1:15353").unwrap();
    ready.wait();
    let mut buf = [0u8; 512];
    let (n, peer) = sock.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], query_bytes().as_slice());
    println!("attempted=probe.test");
    let mut reply = Vec::with_capacity(n);
    reply.extend_from_slice(&buf[..2]);
    reply.extend_from_slice(b"\x81\x83");
    reply.extend_from_slice(&buf[4..n]);
    sock.send_to(&reply, peer).unwrap();
}

fn request(address: &str, port: u16) -> std::io::Result<Vec<u8>> {
    let sock = UdpSocket::bind("127.0.0.1:0")?;
    sock.set_read_timeout(Some(Duration::from_millis(400)))?;
    sock.connect((address, port))?;
    sock.send(&query_bytes())?;
    let mut buf = [0u8; 512];
    let n = sock.recv(&mut buf)?;
    Ok(buf[..n].to_vec())
}

fn child(address: &str, port: u16, local: bool) {
    let listener = if local {
        let ready = Arc::new(Barrier::new(2));
        let ready_clone = Arc::clone(&ready);
        let handle = thread::spawn(move || receiver(ready_clone));
        ready.wait();
        let response = request("127.0.0.1", 15353).unwrap();
        assert_eq!(response[3] & 15, 3);
        Some(handle)
    } else {
        None
    };

    if request(address, port).is_err() {
        println!("host DNS unavailable");
        if let Some(h) = listener {
            let _ = h.join();
        }
        return;
    }
    panic!("the isolated process received a host DNS response");
}

fn run() {
    let self_exe = env::current_exe().unwrap();
    let host = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = host.local_addr().unwrap().port();
    host.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();

    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done_clone = Arc::clone(&done);
    let received = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
    let received_clone = Arc::clone(&received);
    let host_clone = host.try_clone().unwrap();

    let worker = thread::spawn(move || {
        let mut buf = [0u8; 512];
        while !done_clone.load(std::sync::atomic::Ordering::Relaxed) {
            if let Ok((n, peer)) = host_clone.recv_from(&mut buf) {
                received_clone.lock().unwrap().push(buf[..n].to_vec());
                let _ = host_clone.send_to(&buf[..n], peer);
            }
        }
    });

    assert_eq!(request("127.0.0.1", port).unwrap(), query_bytes());
    assert_eq!(received.lock().unwrap().as_slice(), &[query_bytes()]);

    let mut cmd = if cfg!(target_os = "linux") {
        let mut c = Command::new("/usr/bin/bwrap");
        c.args([
            "--unshare-user",
            "--disable-userns",
            "--unshare-net",
            "--unshare-pid",
            "--cap-drop",
            "ALL",
            "--ro-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "--",
        ]);
        c.arg(&self_exe)
            .args(["child", "127.0.0.1", &port.to_string(), "local"]);
        c
    } else if cfg!(target_os = "macos") {
        let mut c = Command::new("/usr/bin/sandbox-exec");
        c.args([
            "-p",
            "(version 1)(allow default)(deny network*)(deny mach-lookup mach-register)",
        ]);
        c.arg(&self_exe)
            .args(["child", "127.0.0.1", &port.to_string()]);
        c
    } else {
        panic!("unsupported OS");
    };

    let output = cmd.output().unwrap();
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = worker.join();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    print!("{stdout}");
    assert!(output.status.success(), "{stderr}");
    assert_eq!(
        stdout.contains("attempted=probe.test"),
        cfg!(target_os = "linux")
    );
    assert!(stdout.contains("host DNS unavailable"));
    assert_eq!(received.lock().unwrap().as_slice(), &[query_bytes()]);
    let os_label = if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    };
    println!("{os_label}: host DNS control=1 isolated=0");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        run();
    } else {
        child(&args[2], args[3].parse().unwrap(), args.len() > 4);
    }
}
