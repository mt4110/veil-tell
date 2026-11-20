use crate::Result;
use crate::attribution::Attribution;
use crate::cli::Mode;
use crate::policy::{Policy, normalize_host};
use crate::report::{Attempted, Destination, Records};
use base64::Engine;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(target_os = "linux")]
use tokio::net::UnixListener;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::timeout;

const HEADER_LIMIT: usize = 16_384;
const CONNECT_LIMIT: Duration = Duration::from_secs(5);
const IDLE_LIMIT: Duration = Duration::from_secs(60);
const MAX_CONNECTIONS: usize = 64;
const MAX_DNS_NAMES: usize = 1024;
const MAX_DNS_ATTEMPTS: u64 = 16384;

#[derive(Default)]
pub struct DnsAttempts {
    pub names: std::collections::BTreeMap<String, Attempted>,
    total: u64,
}

impl DnsAttempts {
    fn record(&mut self, host: String, source: Option<Attribution>) -> bool {
        if self.total >= MAX_DNS_ATTEMPTS
            || (self.names.len() >= MAX_DNS_NAMES && !self.names.contains_key(&host))
        {
            return false;
        }
        self.total += 1;
        let attempt = self.names.entry(host.clone()).or_insert_with(|| Attempted {
            host,
            attempts: 0,
            attribution: Default::default(),
        });
        attempt.attempts += 1;
        crate::attribution::record(
            &mut attempt.attribution,
            source.unwrap_or_else(Attribution::unknown),
        );
        true
    }
}

pub struct Proxy {
    pub mode: Mode,
    pub policy: Policy,
    pub ci_hosts: Option<std::collections::BTreeSet<String>>,
    pub auth: String,
    pub attribute_npm: bool,
    pub compare_unauthenticated: bool,
    pub records: Records,
    pub budgets: std::collections::BTreeMap<String, crate::volume::Budget>,
    pub dns_attempts: Option<std::sync::Mutex<DnsAttempts>>,
    pub incomplete: AtomicBool,
    pub allow_fake_ip: bool,
    pub upstream: Option<crate::upstream::Upstream>,
    pub interfaces: Vec<IpAddr>,
    pub fixture: Option<crate::FixtureResolver>,
}

pub enum Listener {
    Tcp(TcpListener),
    #[cfg(target_os = "linux")]
    Unix(UnixListener),
}

enum Connection {
    Tcp(TcpStream),
    #[cfg(target_os = "linux")]
    Unix(tokio::net::UnixStream),
}

impl Listener {
    async fn accept(&self) -> io::Result<Connection> {
        match self {
            Self::Tcp(listener) => listener
                .accept()
                .await
                .map(|(stream, _)| Connection::Tcp(stream)),
            #[cfg(target_os = "linux")]
            Self::Unix(listener) => listener
                .accept()
                .await
                .map(|(stream, _)| Connection::Unix(stream)),
        }
    }
}

fn dispatch<S>(tasks: &mut JoinSet<()>, state: &Arc<Proxy>, stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if tasks.len() >= MAX_CONNECTIONS {
        state.incomplete.store(true, Ordering::Relaxed);
        return;
    }
    let state = Arc::clone(state);
    tasks.spawn(async move {
        let _ = request(stream, &state).await;
    });
}

pub async fn serve(
    listener: Listener,
    state: Arc<Proxy>,
    mut stop: oneshot::Receiver<()>,
) -> io::Result<()> {
    let mut tasks = JoinSet::new();
    let result = loop {
        tokio::select! {
            biased;
            _ = &mut stop => break Ok(()),
            finished = tasks.join_next(), if !tasks.is_empty() => {
                if finished.is_some_and(|result| result.is_err()) {
                    state.incomplete.store(true, Ordering::Relaxed);
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok(connection) => dispatch_connection(&mut tasks, &state, connection),
                    Err(error) => break Err(error),
                }
            }
        }
    };
    if result.is_ok() {
        // The child group and its relay have exited. Drain already queued connections
        // from the nonblocking socket without waiting for future clients.
        match listener {
            Listener::Tcp(server) => {
                let server = server.into_std()?;
                drain(&mut tasks, &state, || {
                    let (stream, _) = server.accept()?;
                    stream.set_nonblocking(true)?;
                    Ok(Connection::Tcp(TcpStream::from_std(stream)?))
                })?;
            }
            #[cfg(target_os = "linux")]
            Listener::Unix(server) => {
                let server = server.into_std()?;
                drain(&mut tasks, &state, || {
                    let (stream, _) = server.accept()?;
                    stream.set_nonblocking(true)?;
                    Ok(Connection::Unix(tokio::net::UnixStream::from_std(stream)?))
                })?;
            }
        }
    }
    if timeout(Duration::from_millis(300), async {
        while let Some(result) = tasks.join_next().await {
            if result.is_err() {
                state.incomplete.store(true, Ordering::Relaxed);
            }
        }
    })
    .await
    .is_err()
    {
        tasks.shutdown().await;
    }
    result
}

fn drain(
    tasks: &mut JoinSet<()>,
    state: &Arc<Proxy>,
    mut accept: impl FnMut() -> io::Result<Connection>,
) -> io::Result<()> {
    for _ in 0..MAX_CONNECTIONS {
        match accept() {
            Ok(connection) => dispatch_connection(tasks, state, connection),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) => return Err(e),
        }
    }
    // More pending connections than can be accounted for in the bounded drain.
    if accept().is_ok() {
        state.incomplete.store(true, Ordering::Relaxed);
    }
    Ok(())
}

fn dispatch_connection(tasks: &mut JoinSet<()>, state: &Arc<Proxy>, connection: Connection) {
    match connection {
        Connection::Tcp(stream) => dispatch(tasks, state, stream),
        #[cfg(target_os = "linux")]
        Connection::Unix(stream) => dispatch(tasks, state, stream),
    }
}

struct Exchange<'a> {
    state: &'a Proxy,
    event: Destination,
}

impl Drop for Exchange<'_> {
    fn drop(&mut self) {
        self.event.max_connection_bytes = self.event.sent_bytes;
        if !self.state.records.add(self.event.clone()) {
            self.state.incomplete.store(true, Ordering::Relaxed);
        }
    }
}

async fn head(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut block = [0; 2048];
    loop {
        let count = stream.read(&mut block).await?;
        if count == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        bytes.extend_from_slice(&block[..count]);
        if bytes.windows(4).any(|part| part == b"\r\n\r\n") {
            return Ok(bytes);
        }
        if bytes.len() >= HEADER_LIMIT {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
    }
}

enum Head {
    Accept {
        host: String,
        dns: bool,
        consumed: usize,
        authorized: bool,
        attribution: Option<Attribution>,
    },
    Reject(&'static str),
}

const AUTH_REQUIRED: &str =
    "407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"veil-tell\"";

fn parse(bytes: &[u8], auth: &str, attribute_npm: bool, compare_unauthenticated: bool) -> Head {
    let mut headers = [httparse::EMPTY_HEADER; 48];
    let mut request = httparse::Request::new(&mut headers);
    let bad = Head::Reject("400 Bad Request");
    let Ok(httparse::Status::Complete(consumed)) = request.parse(bytes) else {
        return bad;
    };
    if consumed > HEADER_LIMIT || request.version != Some(1) {
        return bad;
    }
    let dns = request.method == Some("VEIL-DNS");
    if !dns && request.method != Some("CONNECT") {
        return Head::Reject("405 Method Not Allowed");
    }
    if request.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("transfer-encoding")
            || (header.name.eq_ignore_ascii_case("content-length") && header.value != b"0")
    }) {
        return bad;
    }
    let mut credentials = request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("proxy-authorization"));
    let credential = credentials
        .next()
        .and_then(|h| std::str::from_utf8(h.value).ok());
    let single_credential = credentials.next().is_none() && credential.is_some();
    let mut authorized = single_credential && credential == Some(auth);
    let mut source = None;
    if attribute_npm
        && !authorized
        && single_credential
        && let Some(encoded) = credential.and_then(|h| h.strip_prefix("Basic "))
        && let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded)
        && let Some(index) = decoded.iter().position(|b| *b == b'~')
    {
        authorized = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(&decoded[..index])
        ) == auth;
        if authorized {
            source = std::str::from_utf8(&decoded[index + 1..])
                .ok()
                .map(str::to_owned);
        }
    }
    if !authorized && !attribute_npm && !compare_unauthenticated {
        return Head::Reject(AUTH_REQUIRED);
    }
    let Some(path) = request.path else { return bad };
    let name = if dns {
        path
    } else {
        match path.rsplit_once(':') {
            Some((name, "443")) => name,
            Some(_) => return Head::Reject("403 Forbidden"),
            None => return bad,
        }
    };
    let Some(host) = normalize_host(name) else {
        return bad;
    };
    let attribution = attribute_npm.then(|| {
        if !dns
            && authorized
            && host == "registry.npmjs.org"
            && source.as_deref() == Some("manager-npm")
        {
            Attribution {
                confidence: crate::attribution::Confidence::Inferred,
                package: None,
                manager: Some("npm".into()),
                phase: Some("fetch".into()),
            }
        } else {
            Attribution::decode(source.as_deref())
        }
    });
    Head::Accept {
        host,
        dns,
        consumed,
        authorized,
        attribution,
    }
}

async fn response(stream: &mut (impl AsyncWrite + Unpin), status: &str) -> io::Result<()> {
    let message = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    timeout(CONNECT_LIMIT, stream.write_all(message.as_bytes())).await?
}

async fn request<S>(mut stream: S, state: &Proxy) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let bytes = match timeout(CONNECT_LIMIT, head(&mut stream)).await? {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            return response(&mut stream, "400 Bad Request").await;
        }
        Err(error) => return Err(error),
    };
    let (host, dns, consumed, authorized, attribution) = match parse(
        &bytes,
        &state.auth,
        state.attribute_npm,
        state.compare_unauthenticated,
    ) {
        Head::Accept {
            host,
            dns,
            consumed,
            authorized,
            attribution,
        } => (host, dns, consumed, authorized, attribution),
        Head::Reject(status) => return response(&mut stream, status).await,
    };
    if dns {
        let Some(records) = &state.dns_attempts else {
            return response(&mut stream, "405 Method Not Allowed").await;
        };
        if !authorized {
            return response(&mut stream, AUTH_REQUIRED).await;
        }
        if !records.lock().unwrap().record(host, attribution) {
            state.incomplete.store(true, Ordering::Relaxed);
        }
        return response(&mut stream, "403 Forbidden").await;
    }
    let (allowed, reason) = if state
        .ci_hosts
        .as_ref()
        .is_some_and(|hosts| !hosts.contains(&host))
    {
        (false, "new_destination")
    } else if !authorized {
        (false, "proxy_authentication")
    } else if local_name(&host) {
        (false, "non_public_destination")
    } else {
        state.policy.decision(state.mode, &host)
    };
    let mut exchange = Exchange {
        state,
        event: Destination {
            host,
            port: 443,
            decision: if allowed { "allow" } else { "deny" },
            reason,
            result: if allowed { "interrupted" } else { "blocked" },
            resolver_hint: None,
            via_upstream_proxy: false,
            connected_ip: None,
            attempts: 1,
            sent_bytes: 0,
            max_connection_bytes: 0,
            received_bytes: 0,
            attribution: attribution.into_iter().collect(),
        },
    };
    if !authorized {
        return response(&mut stream, AUTH_REQUIRED).await;
    }
    if !allowed {
        return response(&mut stream, "403 Forbidden").await;
    }
    let budget = state
        .budgets
        .get(&exchange.event.host)
        .filter(|b| b.enforce);
    if let Some(budget) = budget
        && !budget.connect().await
    {
        exchange.event.result = "volume_blocked";
        return response(&mut stream, "403 Forbidden").await;
    }
    let route = state
        .upstream
        .as_ref()
        .filter(|u| u.applies(&exchange.event.host));
    let mut upstream = if let Some(route) = route {
        exchange.event.via_upstream_proxy = true;
        match timeout(CONNECT_LIMIT, route.tunnel(&exchange.event.host)).await {
            Ok(Ok(stream)) => stream,
            _ => {
                exchange.event.result = "connect_failed";
                return response(&mut stream, "502 Bad Gateway").await;
            }
        }
    } else {
        let addresses = match resolve(state, &exchange.event.host).await {
            Ok(addresses) => addresses,
            Err(kind @ ("non_public_destination" | "fake_ip")) => {
                exchange.event.resolver_hint = (kind == "fake_ip").then_some("fake_ip");
                exchange.event.decision = "deny";
                exchange.event.reason = "non_public_destination";
                exchange.event.result = "blocked";
                return response(&mut stream, "403 Forbidden").await;
            }
            Err(reason) => {
                exchange.event.result = reason;
                return response(&mut stream, "502 Bad Gateway").await;
            }
        };
        let Ok(Ok((upstream, address))) = timeout(CONNECT_LIMIT, connect(addresses)).await else {
            exchange.event.result = "connect_failed";
            return response(&mut stream, "502 Bad Gateway").await;
        };
        exchange.event.connected_ip = Some(address.ip());
        upstream
    };
    timeout(
        CONNECT_LIMIT,
        stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n"),
    )
    .await??;
    let (mut incoming, mut outgoing) = tokio::io::split(stream);
    let (mut from_upstream, mut to_upstream) = upstream.split();
    let event = &mut exchange.event;
    let result = tokio::try_join!(
        pump(
            &mut incoming,
            &mut to_upstream,
            &bytes[consumed..],
            &mut event.sent_bytes,
            budget,
        ),
        pump(
            &mut from_upstream,
            &mut outgoing,
            &[],
            &mut event.received_bytes,
            None,
        ),
    );
    event.result = if result.as_ref().err().is_some_and(|err| {
        err.get_ref()
            .is_some_and(|source| source.is::<crate::volume::Exceeded>())
    }) {
        "volume_blocked"
    } else if result.is_ok() {
        "completed"
    } else {
        "transfer_interrupted"
    };
    result.map(|_| ())
}

fn local_name(host: &str) -> bool {
    [".localhost", ".local", ".internal", ".home.arpa"]
        .iter()
        .any(|suffix| host.ends_with(suffix))
        || host == "home.arpa"
}

async fn resolve(state: &Proxy, host: &str) -> std::result::Result<Vec<SocketAddr>, &'static str> {
    if let Some(address) = state.fixture.and_then(|fixture| fixture(host)) {
        return Ok(vec![address]);
    }
    let addresses: Vec<_> = timeout(CONNECT_LIMIT, tokio::net::lookup_host((host, 443)))
        .await
        .map_err(|_| "dns_timeout")?
        .map_err(|_| "dns_failed")?
        .collect();
    classify(&addresses, &state.interfaces, state.allow_fake_ip)?;
    Ok(addresses)
}

fn classify(
    addresses: &[SocketAddr],
    interfaces: &[IpAddr],
    allow_fake: bool,
) -> std::result::Result<(), &'static str> {
    if addresses.is_empty() {
        return Err("dns_failed");
    }
    if addresses.iter().any(|a| interfaces.contains(&a.ip())) {
        return Err("non_public_destination");
    }
    if addresses
        .iter()
        .all(|a| matches!(a.ip(), IpAddr::V4(ip) if matches!(ip.octets(), [198, 18 | 19, ..])))
    {
        return if allow_fake { Ok(()) } else { Err("fake_ip") };
    }
    if addresses.iter().any(|address| !public(address.ip())) {
        return Err("non_public_destination");
    }
    Ok(())
}

fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => !matches!(
            ip.octets(),
            [0 | 10 | 127 | 224..=255, ..]
                | [100, 64..=127, ..]
                | [169, 254, ..]
                | [172, 16..=31, ..]
                | [192, 0, 0 | 2, _]
                | [192, 88, 99, _]
                | [192, 168, ..]
                | [198, 18 | 19, ..]
                | [198, 51, 100, _]
                | [203, 0, 113, _]
        ),
        IpAddr::V6(ip) => {
            let [a, b, ..] = ip.segments();
            a & 0xe000 == 0x2000
                && a != 0x2002
                && a != 0x3fff
                && !(a == 0x2001 && (b < 0x0200 || b == 0x0db8))
        }
    }
}

async fn connect(addresses: Vec<SocketAddr>) -> io::Result<(TcpStream, SocketAddr)> {
    let mut last_error = io::Error::from(io::ErrorKind::NotFound);
    for address in addresses {
        match timeout(Duration::from_secs(2), TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok((stream, address)),
            Ok(Err(error)) => last_error = error,
            Err(error) => last_error = error.into(),
        }
    }
    Err(last_error)
}

async fn pump(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    prefix: &[u8],
    count: &mut u64,
    budget: Option<&crate::volume::Budget>,
) -> io::Result<()> {
    transfer(writer, prefix, count, budget).await?;
    let mut buffer = [0; 8192];
    loop {
        let length = timeout(IDLE_LIMIT, reader.read(&mut buffer)).await??;
        if length == 0 {
            return writer.shutdown().await;
        }
        transfer(writer, &buffer[..length], count, budget).await?;
    }
}

async fn transfer(
    writer: &mut (impl AsyncWrite + Unpin),
    mut bytes: &[u8],
    count: &mut u64,
    budget: Option<&crate::volume::Budget>,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let written = match budget {
            Some(budget) => budget.write(writer, bytes, *count, IDLE_LIMIT).await?,
            None => timeout(IDLE_LIMIT, writer.write(bytes)).await??,
        };
        if written == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        *count += written as u64;
        bytes = &bytes[written..];
    }
    Ok(())
}

pub fn host_interfaces() -> Result<Vec<IpAddr>> {
    let mut list = std::ptr::null_mut();
    // getifaddrs supplies a linked list valid until freeifaddrs.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let mut result = Vec::new();
    let mut current = list;
    while !current.is_null() {
        unsafe {
            let entry = &*current;
            if !entry.ifa_addr.is_null() {
                match i32::from((*entry.ifa_addr).sa_family) {
                    libc::AF_INET => {
                        let address = &*entry.ifa_addr.cast::<libc::sockaddr_in>();
                        result.push(
                            std::net::Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()).into(),
                        );
                    }
                    libc::AF_INET6 => {
                        let address = &*entry.ifa_addr.cast::<libc::sockaddr_in6>();
                        result.push(std::net::Ipv6Addr::from(address.sin6_addr.s6_addr).into());
                    }
                    _ => {}
                }
            }
            current = entry.ifa_next;
        }
    }
    unsafe { libc::freeifaddrs(list) };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_records_are_bounded_by_distinct_names_and_total_attempts() {
        let mut records = DnsAttempts::default();
        for id in 0..MAX_DNS_NAMES {
            assert!(records.record(format!("fixture{id}.test"), None));
        }
        assert!(!records.record("overflow.test".into(), None));
        for _ in MAX_DNS_NAMES as u64..MAX_DNS_ATTEMPTS {
            assert!(records.record("fixture0.test".into(), None));
        }
        assert!(!records.record("fixture0.test".into(), None));
        assert_eq!(records.names.len(), MAX_DNS_NAMES);
        assert_eq!(
            records
                .names
                .values()
                .map(|attempt| attempt.attempts)
                .sum::<u64>(),
            MAX_DNS_ATTEMPTS
        );
    }

    #[test]
    fn tunnel_requires_session_auth_and_a_strict_authority() {
        let valid = b"CONNECT Allowed.test.:443 HTTP/1.1\r\nProxy-Authorization: Basic token\r\n\r\npayload";
        let Head::Accept { host, consumed, .. } = parse(valid, "Basic token", false, false) else {
            panic!("expected a valid CONNECT");
        };
        assert_eq!(host, "allowed.test");
        assert_eq!(&valid[consumed..], b"payload");
        assert!(
            matches!(parse(valid, "Basic different", false, false), Head::Reject(status) if status.starts_with("407"))
        );
        let bad = b"CONNECT allowed.test:443 HTTP/1.1\r\nProxy-Authorization: Basic token\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(matches!(
            parse(bad, "Basic token", false, false),
            Head::Reject("400 Bad Request")
        ));
    }

    #[test]
    fn public_address_filter_rejects_local_and_special_addresses() {
        for address in [
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.1",
            "100.64.0.1",
            "192.0.2.1",
            "::1",
            "::ffff:127.0.0.1",
            "64:ff9b::a00:1",
            "2001:db8::1",
            "fe80::1",
            "fd00::1",
        ] {
            assert!(!public(address.parse().unwrap()), "{address}");
        }
        for address in ["93.184.215.14", "2606:4700:4700::1111"] {
            assert!(public(address.parse().unwrap()), "{address}");
        }
    }
}

#[cfg(test)]
mod fake_ip_tests {
    use super::*;
    #[test]
    fn fake_ip_requires_a_homogeneous_non_local_answer() {
        let fake: SocketAddr = "198.19.255.255:443".parse().unwrap();
        let private: SocketAddr = "10.0.0.1:443".parse().unwrap();
        assert_eq!(classify(&[fake], &[], false), Err("fake_ip"));
        assert_eq!(classify(&[fake], &[], true), Ok(()));
        for opt in [false, true] {
            assert_eq!(
                classify(&[fake, private], &[], opt),
                Err("non_public_destination")
            );
            assert_eq!(
                classify(&[fake], &[fake.ip()], opt),
                Err("non_public_destination")
            );
        }
        assert!(local_name("service.localhost"));
        assert!(normalize_host("localhost").is_none());
    }
}
