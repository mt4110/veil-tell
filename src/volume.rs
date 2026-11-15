use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::time::timeout;

// Comparing a completed observation against an explicit baseline is a change check.
pub const OBSERVED_ANOMALY: u8 = 21;
pub const LIMIT_EXCEEDED: u8 = 22;

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub sent_bytes: u64,
    pub connections: u64,
    pub max_connection_bytes: u64,
}

impl Sample {
    pub fn record(&mut self, event: &crate::report::Destination) {
        self.sent_bytes = self.sent_bytes.saturating_add(event.sent_bytes);
        self.connections = self.connections.saturating_add(event.attempts);
        self.max_connection_bytes = self.max_connection_bytes.max(event.max_connection_bytes);
    }

    pub fn limits(&self) -> Self {
        Self {
            sent_bytes: self.sent_bytes.saturating_mul(8).max(256 * 1024),
            connections: self.connections.saturating_mul(8).max(64),
            max_connection_bytes: self.max_connection_bytes.saturating_mul(8).max(128 * 1024),
        }
    }

    pub fn exceeds(&self, limit: &Self) -> bool {
        self.sent_bytes > limit.sent_bytes
            || self.connections > limit.connections
            || self.max_connection_bytes > limit.max_connection_bytes
    }
}

#[derive(Serialize)]
pub struct Anomaly {
    pub host: String,
    pub port: u16,
    pub observed: Sample,
    pub limits: Sample,
    pub blocked: bool,
    pub attribution: crate::attribution::Sources,
}

pub struct Budget {
    pub limit: Sample,
    pub enforce: bool,
    used: Mutex<Sample>,
}

impl Budget {
    pub fn new(limit: Sample, enforce: bool) -> Self {
        Self {
            limit,
            enforce,
            used: Mutex::default(),
        }
    }

    pub async fn connect(&self) -> bool {
        let mut used = self.used.lock().await;
        if used.connections >= self.limit.connections {
            return false;
        }
        used.connections += 1;
        true
    }

    pub async fn write(
        &self,
        writer: &mut (impl AsyncWrite + Unpin),
        bytes: &[u8],
        connection: u64,
        idle: std::time::Duration,
    ) -> io::Result<usize> {
        let mut used = self.used.lock().await;
        let remaining = self
            .limit
            .sent_bytes
            .saturating_sub(used.sent_bytes)
            .min(self.limit.max_connection_bytes.saturating_sub(connection));
        if remaining == 0 {
            return Err(io::Error::other(Exceeded));
        }
        let length = remaining.min(bytes.len() as u64) as usize;
        let written = timeout(idle, writer.write(&bytes[..length])).await??;
        used.sent_bytes += written as u64;
        Ok(written)
    }
}

#[derive(Debug)]
pub struct Exceeded;

impl std::fmt::Display for Exceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("outbound volume limit exceeded")
    }
}

impl std::error::Error for Exceeded {}

pub fn anomalies(
    events: &[crate::report::Destination],
    budgets: &BTreeMap<String, Budget>,
) -> Vec<Anomaly> {
    let mut found = BTreeMap::new();
    for event in events {
        if event.connected_ip.is_none() && event.result != "volume_blocked" {
            continue;
        }
        let Some(budget) = budgets.get(&event.host) else {
            continue;
        };
        let anomaly = found.entry(event.host.clone()).or_insert_with(|| Anomaly {
            host: event.host.clone(),
            port: event.port,
            observed: Sample::default(),
            limits: budget.limit.clone(),
            blocked: false,
            attribution: Default::default(),
        });
        anomaly.observed.record(event);
        anomaly.blocked |= event.result == "volume_blocked";
        for source in &event.attribution {
            crate::attribution::record(&mut anomaly.attribution, source.clone());
        }
    }
    found
        .into_values()
        .filter(|item| item.blocked || item.observed.exceeds(&item.limits))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floors_and_headroom() {
        let sample = Sample {
            sent_bytes: 65536,
            connections: 20,
            max_connection_bytes: 8192,
        };
        let limits = sample.limits();
        assert_eq!(limits.sent_bytes, 524288);
        assert_eq!(limits.connections, 160);
        assert_eq!(limits.max_connection_bytes, 131072);
        assert!(!limits.exceeds(&limits));
    }
}
