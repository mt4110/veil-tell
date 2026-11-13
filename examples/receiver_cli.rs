use std::net::SocketAddr;

fn fixture(host: &str) -> Option<SocketAddr> {
    if !matches!(host, "allowed.test" | "new.test") {
        return None;
    }
    let address: SocketAddr = std::env::var("VEIL_TELL_FIXTURE_RECEIVER")
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        address.ip().is_loopback()
            || matches!(address.ip(), std::net::IpAddr::V4(ip) if ip.is_private())
    );
    Some(address)
}

fn main() -> std::process::ExitCode {
    veil_tell::entry(Some(fixture))
}
