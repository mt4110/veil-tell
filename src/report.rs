use crate::Result;
use crate::cli::{Backend, Mode};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Write;
use std::net::IpAddr;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Mutex;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempted {
    pub host: String,
    pub attempts: u64,
    pub attribution: crate::attribution::Sources,
}

#[derive(Clone, Serialize)]
pub struct Destination {
    pub host: String,
    pub port: u16,
    pub decision: &'static str,
    pub reason: &'static str,
    pub result: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolver_hint: Option<&'static str>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub via_upstream_proxy: bool,
    pub connected_ip: Option<IpAddr>,
    pub attempts: u64,
    pub sent_bytes: u64,
    pub max_connection_bytes: u64,
    pub received_bytes: u64,
    #[serde(skip_serializing_if = "crate::attribution::Sources::is_empty")]
    pub attribution: crate::attribution::Sources,
}

type DestinationKey = (
    String,
    u16,
    &'static str,
    &'static str,
    &'static str,
    Option<IpAddr>,
    Option<&'static str>,
);

#[derive(Default)]
pub struct Records(Mutex<BTreeMap<DestinationKey, Destination>>);

impl Records {
    pub fn add(&self, event: Destination) -> bool {
        let key = (
            event.host.clone(),
            event.port,
            event.decision,
            event.reason,
            event.result,
            event.connected_ip,
            event.resolver_hint,
        );
        let mut records = self.0.lock().unwrap();
        if records.len() >= 4096 && !records.contains_key(&key) {
            return false;
        }
        records
            .entry(key)
            .and_modify(|total| {
                total.attempts += event.attempts;
                total.sent_bytes += event.sent_bytes;
                total.max_connection_bytes =
                    total.max_connection_bytes.max(event.max_connection_bytes);
                total.received_bytes += event.received_bytes;
                for source in &event.attribution {
                    crate::attribution::record(&mut total.attribution, source.clone());
                }
            })
            .or_insert(event);
        true
    }

    pub fn snapshot(&self) -> Vec<Destination> {
        self.0.lock().unwrap().values().cloned().collect()
    }
}

pub fn aggregate(events: &[Destination]) -> Vec<Destination> {
    let mut rows = BTreeMap::new();
    for e in events {
        let key = (&e.host, e.port, e.decision, e.reason);
        rows.entry(key)
            .and_modify(|row: &mut Destination| {
                row.attempts += e.attempts;
                row.sent_bytes += e.sent_bytes;
                for source in &e.attribution {
                    crate::attribution::record(&mut row.attribution, source.clone());
                }
            })
            .or_insert_with(|| e.clone());
    }
    rows.into_values().collect()
}
#[derive(Serialize, serde::Deserialize)]
pub struct DirectAttempt {
    pub ip: IpAddr,
    pub port: u16,
    pub attempts: u64,
}

#[derive(Serialize)]
pub struct Report {
    pub schema_version: u8,
    pub backend: Backend,
    pub mode: Mode,
    pub isolation: &'static str,
    pub coverage: Coverage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_attempts: Option<Vec<DirectAttempt>>,
    pub child_status: Option<ChildStatus>,
    pub run_status: RunStatus,
    pub destinations: Vec<Destination>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub volume_anomalies: Vec<crate::volume::Anomaly>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempted: Option<Vec<Attempted>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparison: Option<Box<crate::baseline::Comparison>>,
}

#[derive(Serialize)]
pub struct Coverage {
    pub proxy: &'static str,
    pub direct_attempt_destinations: &'static str,
    pub dns_attempts: &'static str,
    pub proxy_capture: &'static str,
}

#[derive(Serialize)]
pub struct ChildStatus {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
}

impl From<ExitStatus> for ChildStatus {
    fn from(status: ExitStatus) -> Self {
        Self {
            exit_code: status.code(),
            signal: status.signal(),
        }
    }
}

#[derive(Serialize)]
pub struct RunStatus {
    pub exit_code: u8,
    pub reason: &'static str,
}

pub struct OutputFile {
    path: PathBuf,
    staging: tempfile::NamedTempFile,
}

impl OutputFile {
    pub fn prepare(path: &Path, label: &str) -> Result<Self> {
        let name = path
            .file_name()
            .ok_or_else(|| crate::error(format!("invalid {label} path")))?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = parent.canonicalize()?;
        let path = parent.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => return Err(crate::error(format!("{label} already exists"))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(Self {
            path,
            staging: tempfile::NamedTempFile::new_in(parent)?,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn save(
        mut self,
        write_content: impl FnOnce(&mut std::fs::File) -> Result<()>,
    ) -> Result<()> {
        write_content(self.staging.as_file_mut())?;
        self.staging.as_file().sync_all()?;
        self.staging.persist_noclobber(&self.path)?;
        Ok(())
    }

    pub fn save_report(self, report: &Report) -> Result<()> {
        self.save(|file| {
            serde_json::to_writer_pretty(&mut *file, report)?;
            file.write_all(b"\n")?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn display_groups_multiple_public_ips_and_results() {
        let first = Destination {
            host: "registry.example".into(),
            port: 443,
            decision: "allow",
            reason: "observe",
            result: "completed",
            resolver_hint: None,
            via_upstream_proxy: false,
            connected_ip: Some("192.0.2.1".parse().unwrap()),
            attempts: 2,
            sent_bytes: 50,
            max_connection_bytes: 30,
            received_bytes: 0,
            attribution: Default::default(),
        };
        let second = Destination {
            connected_ip: Some("192.0.2.2".parse().unwrap()),
            result: "interrupted",
            attempts: 1,
            sent_bytes: 12,
            ..first.clone()
        };
        let rows = aggregate(&[first, second]);
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].attempts, rows[0].sent_bytes), (3, 62));
    }
}
