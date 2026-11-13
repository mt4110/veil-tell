use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    let Ok(proxy) = std::env::var("HTTPS_PROXY") else { return };
    let (credential, address) = proxy.strip_prefix("http://").unwrap().split_once('@').unwrap();
    let mut stream = TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let host = "build-script.local:443";
    let mut encoder = std::process::Command::new("base64")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped()).spawn().unwrap();
    encoder.stdin.take().unwrap().write_all(credential.as_bytes()).unwrap();
    let encoded = encoder.wait_with_output().unwrap();
    let auth: String = String::from_utf8(encoded.stdout).unwrap().split_whitespace().collect();
    write!(stream, "CONNECT {host} HTTP/1.1\r\nHost: {host}\r\nProxy-Authorization: Basic {auth}\r\n\r\n").unwrap();
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 403 "), "{response}");
}
