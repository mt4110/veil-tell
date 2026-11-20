use crate::{Result, error};
use base64::Engine;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct Upstream {
    address: String,
    authorization: Option<String>,
    exclusions: Vec<String>,
}

impl Upstream {
    pub fn from_env() -> Result<Option<Self>> {
        let Ok(url) = std::env::var("HTTPS_PROXY").or_else(|_| std::env::var("https_proxy")) else {
            return Ok(None);
        };
        Self::from_url(&url)
    }

    pub fn from_url(url: &str) -> Result<Option<Self>> {
        let Some(authority) = url.strip_prefix("http://") else {
            return Ok(None);
        };
        let invalid = || error("invalid HTTP upstream proxy configuration");
        let authority = authority.strip_suffix('/').unwrap_or(authority);
        if authority.is_empty()
            || authority.contains(['/', '#', '?'])
            || authority.bytes().any(|b| b <= 32 || b == 127)
        {
            return Err(invalid());
        }
        let (address, authorization) = match authority.rsplit_once('@') {
            Some((userinfo, host)) => {
                let mut bytes = Vec::new();
                let mut chars = userinfo.bytes();
                while let Some(byte) = chars.next() {
                    bytes.push(if byte == b'%' {
                        let hi = chars
                            .next()
                            .and_then(|b| (b as char).to_digit(16))
                            .ok_or_else(invalid)?;
                        let lo = chars
                            .next()
                            .and_then(|b| (b as char).to_digit(16))
                            .ok_or_else(invalid)?;
                        (hi * 16 + lo) as u8
                    } else {
                        byte
                    });
                }
                (
                    host,
                    Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
                )
            }
            None => (authority, None),
        };
        let address = if address.ends_with(']') || !address.contains(':') {
            format!("{address}:80")
        } else {
            address.to_owned()
        };
        let (host, port) = address.rsplit_once(':').ok_or_else(invalid)?;
        if host.is_empty() || port.parse::<u16>().ok().filter(|p| *p != 0).is_none() {
            return Err(invalid());
        }
        let exclusions = std::env::var("NO_PROXY")
            .or_else(|_| std::env::var("no_proxy"))
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .collect();
        Ok(Some(Self {
            address,
            authorization,
            exclusions,
        }))
    }

    pub fn applies(&self, host: &str) -> bool {
        !self.exclusions.iter().any(|pat| {
            let suffix = pat
                .strip_suffix(":443")
                .unwrap_or(pat)
                .trim_start_matches("*.")
                .trim_start_matches('.');
            pat == "*"
                || (!suffix.is_empty()
                    && (suffix == host
                        || host.strip_suffix(suffix).is_some_and(|s| s.ends_with('.'))))
        })
    }

    pub async fn tunnel(&self, host: &str) -> io::Result<TcpStream> {
        let mut stream = TcpStream::connect(&self.address).await?;
        let mut request = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n");
        if let Some(auth) = &self.authorization {
            request.push_str(&format!("Proxy-Authorization: Basic {auth}\r\n"));
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await?;
        // Consume only the HTTP head. Any following byte belongs to the TLS tunnel.
        let mut bytes = Vec::new();
        while bytes.len() < 16384 {
            bytes.push(stream.read_u8().await?);
            if bytes.ends_with(b"\r\n\r\n") {
                let mut headers = [httparse::EMPTY_HEADER; 64];
                let mut head = httparse::Response::new(&mut headers);
                if head.parse(&bytes).is_ok_and(|s| s.is_complete()) && head.code == Some(200) {
                    return Ok(stream);
                }
                break;
            }
        }
        Err(io::Error::other("upstream CONNECT failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exclusions_match_host_boundaries_and_port() {
        let mut proxy = Upstream {
            address: "unused:80".into(),
            authorization: None,
            exclusions: vec![".example.org:443".into(), "test.org:9443".into()],
        };
        assert!(!proxy.applies("example.org"));
        assert!(!proxy.applies("registry.example.org"));
        assert!(proxy.applies("notexample.org"));
        assert!(proxy.applies("test.org"));
        proxy.exclusions.push("*".into());
        assert!(!proxy.applies("test.org"));
    }
}
