//! Durable, redacted request audit logging.
//!
//! The sink accepts only [`CallRecord`] values that have already crossed the
//! semantic host boundary. It never receives JavaScript source, console output,
//! response bodies, context handles, or credentials.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use thiserror::Error;

use crate::host::CallRecord;

/// Default maximum size of the active JSONL request log.
pub const DEFAULT_MAX_AUDIT_BYTES: u64 = 10 * 1024 * 1024;

/// Default number of rotated files retained beside the active log.
pub const DEFAULT_RETAINED_AUDIT_FILES: usize = 10;

const MIN_MAX_AUDIT_BYTES: u64 = 64 * 1024;
const MAX_RETAINED_AUDIT_FILES: usize = 100;
const MAX_AUDIT_RECORD_BYTES: usize = 64 * 1024;

/// A prepared destination for sanitized request records.
pub trait AuditSink: Send + Sync {
    /// Ensure the destination can be used before an Azure request is sent.
    fn prepare(&self) -> Result<(), AuditError>;

    /// Append one already-redacted record.
    fn append(&self, record: &CallRecord) -> Result<(), AuditError>;

    /// Append one content-free record for a managed local artifact write.
    fn append_artifact(&self, record: &ArtifactWriteAuditRecord) -> Result<(), AuditError>;
}

/// Redacted metadata for one authorized managed artifact write attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactWriteAuditRecord {
    pub correlation_id: String,
    pub operation: &'static str,
    pub decision: &'static str,
    pub bytes: usize,
    pub logical_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<&'static str>,
    pub media_type: &'static str,
    pub sensitivity: &'static str,
}

impl ArtifactWriteAuditRecord {
    pub fn authorized(
        correlation_id: impl Into<String>,
        operation: &'static str,
        bytes: usize,
        logical_bytes: usize,
        content_encoding: Option<&'static str>,
        media_type: &'static str,
    ) -> Self {
        Self {
            correlation_id: correlation_id.into(),
            operation,
            decision: "authorized",
            bytes,
            logical_bytes,
            content_encoding,
            media_type,
            sensitivity: "customerData",
        }
    }
}

/// Validated file rotation and retention settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileAuditConfig {
    path: PathBuf,
    max_bytes: u64,
    retained_files: usize,
}

impl FileAuditConfig {
    /// Construct a file sink configuration.
    pub fn new(
        path: impl Into<PathBuf>,
        max_bytes: u64,
        retained_files: usize,
    ) -> Result<Self, AuditError> {
        let path = path.into();
        if !path.is_absolute() || path.file_name().is_none() {
            return Err(AuditError::InvalidConfiguration);
        }
        if max_bytes < MIN_MAX_AUDIT_BYTES
            || retained_files == 0
            || retained_files > MAX_RETAINED_AUDIT_FILES
        {
            return Err(AuditError::InvalidConfiguration);
        }
        Ok(Self {
            path,
            max_bytes,
            retained_files,
        })
    }

    /// Construct the default bounded rotation settings for an absolute path.
    pub fn with_defaults(path: impl Into<PathBuf>) -> Result<Self, AuditError> {
        Self::new(path, DEFAULT_MAX_AUDIT_BYTES, DEFAULT_RETAINED_AUDIT_FILES)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    pub const fn retained_files(&self) -> usize {
        self.retained_files
    }
}

/// Append-only JSONL sink with bounded numeric rotations.
pub struct FileAuditLog {
    config: FileAuditConfig,
    state: Mutex<FileAuditState>,
}

#[derive(Default)]
struct FileAuditState {
    file: Option<File>,
    bytes: u64,
}

impl FileAuditLog {
    pub fn new(config: FileAuditConfig) -> Self {
        Self {
            config,
            state: Mutex::new(FileAuditState::default()),
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, FileAuditState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn ensure_open(&self, state: &mut FileAuditState) -> Result<(), AuditError> {
        if state.file.is_some() {
            return Ok(());
        }
        let parent = self
            .config
            .path
            .parent()
            .ok_or(AuditError::InvalidConfiguration)?;
        create_private_directory(parent)?;
        reject_non_regular_existing_path(&self.config.path)?;
        let file = open_private_append(&self.config.path)?;
        let metadata = file.metadata().map_err(map_io)?;
        if !metadata.is_file() {
            return Err(AuditError::UnsafeDestination);
        }
        state.bytes = metadata.len();
        state.file = Some(file);
        Ok(())
    }

    fn rotate(&self, state: &mut FileAuditState) -> Result<(), AuditError> {
        state.file.take();
        for index in (1..=self.config.retained_files).rev() {
            let source = if index == 1 {
                self.config.path.clone()
            } else {
                rotated_path(&self.config.path, index - 1)
            };
            let destination = rotated_path(&self.config.path, index);
            match fs::symlink_metadata(&source) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                    return Err(AuditError::UnsafeDestination);
                }
                Ok(_) => {
                    remove_rotation_destination(&destination)?;
                    fs::rename(&source, &destination).map_err(map_io)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(map_io(error)),
            }
        }
        state.bytes = 0;
        self.ensure_open(state)
    }
}

impl AuditSink for FileAuditLog {
    fn prepare(&self) -> Result<(), AuditError> {
        self.ensure_open(&mut self.lock_state())
    }

    fn append(&self, record: &CallRecord) -> Result<(), AuditError> {
        self.append_record(record)
    }

    fn append_artifact(&self, record: &ArtifactWriteAuditRecord) -> Result<(), AuditError> {
        self.append_record(record)
    }
}

impl FileAuditLog {
    fn append_record<T: Serialize>(&self, record: &T) -> Result<(), AuditError> {
        let envelope = AuditEnvelope {
            timestamp_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| AuditError::Clock)?
                .as_millis()
                .min(u128::from(u64::MAX)) as u64,
            record,
        };
        let mut bytes = serde_json::to_vec(&envelope).map_err(|_| AuditError::Serialization)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_AUDIT_RECORD_BYTES {
            return Err(AuditError::RecordTooLarge);
        }

        let mut state = self.lock_state();
        self.ensure_open(&mut state)?;
        if state.bytes > 0 && state.bytes.saturating_add(bytes.len() as u64) > self.config.max_bytes
        {
            self.rotate(&mut state)?;
        }
        let file = state.file.as_mut().ok_or(AuditError::Unavailable)?;
        file.write_all(&bytes).map_err(map_io)?;
        file.flush().map_err(map_io)?;
        file.sync_data().map_err(map_io)?;
        state.bytes = state.bytes.saturating_add(bytes.len() as u64);
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", bound(serialize = "T: Serialize"))]
struct AuditEnvelope<'a, T> {
    timestamp_unix_ms: u64,
    #[serde(flatten)]
    record: &'a T,
}

/// Sanitized failures from the durable logging boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AuditError {
    #[error("audit log configuration is invalid")]
    InvalidConfiguration,
    #[error("audit log destination is not a regular private file")]
    UnsafeDestination,
    #[error("audit log is unavailable")]
    Unavailable,
    #[error("audit log record could not be serialized")]
    Serialization,
    #[error("audit log record exceeds the bounded record size")]
    RecordTooLarge,
    #[error("system clock is unavailable for audit logging")]
    Clock,
}

fn map_io(_error: io::Error) -> AuditError {
    AuditError::Unavailable
}

fn reject_non_regular_existing_path(path: &Path) -> Result<(), AuditError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(AuditError::UnsafeDestination)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(map_io(error)),
    }
}

fn rotated_path(path: &Path, index: usize) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(format!(".{index}"));
    PathBuf::from(value)
}

fn remove_rotation_destination(path: &Path) -> Result<(), AuditError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => Err(AuditError::UnsafeDestination),
        Ok(_) => fs::remove_file(path).map_err(map_io),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(map_io(error)),
    }
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<(), AuditError> {
    fs::create_dir_all(path).map_err(map_io)?;
    let metadata = fs::symlink_metadata(path).map_err(map_io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AuditError::UnsafeDestination);
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> Result<(), AuditError> {
    fs::create_dir_all(path).map_err(map_io)
}

#[cfg(unix)]
fn open_private_append(path: &Path) -> Result<File, AuditError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(map_io)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(map_io)?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_private_append(path: &Path) -> Result<File, AuditError> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(map_io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{CallDecision, SubscriptionSource};
    use azmcp_core::cloud::AzureCloud;

    fn record(operation: &str) -> CallRecord {
        CallRecord {
            correlation_id: "corr-1".to_owned(),
            operation: operation.to_owned(),
            cloud: AzureCloud::AzureCloud,
            subscription: Some("11111111-1111-1111-1111-111111111111".to_owned()),
            subscription_source: Some(SubscriptionSource::Config),
            tenant: Some("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".to_owned()),
            identity: "user".to_owned(),
            arm_tier: "inspect".to_owned(),
            method: "GET".to_owned(),
            path_template: "/subscriptions/{subscription}".to_owned(),
            api_version: "2020-01-01".to_owned(),
            api_version_source: "reviewedRoute".to_owned(),
            policy_hash: "sha256:test".to_owned(),
            policy_version: "v0-test".to_owned(),
            rbac_action: Some("Microsoft.Resources/subscriptions/read".to_owned()),
            decision: CallDecision::Allowed,
            reason: None,
            status: Some(200),
            duration_ms: 1,
            retry_count: 0,
            remaining_subscription_reads: Some(99),
            graph_scope: None,
            data_plane: None,
            data_scope: None,
        }
    }

    #[test]
    fn appends_private_redacted_jsonl() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("audit/requests.jsonl");
        let sink = FileAuditLog::new(FileAuditConfig::with_defaults(&path).expect("config"));
        sink.prepare().expect("prepare");
        sink.append(&record("az.request")).expect("append");

        let line = fs::read_to_string(&path).expect("audit file");
        let value: serde_json::Value = serde_json::from_str(line.trim()).expect("json record");
        assert_eq!(value["pathTemplate"], "/subscriptions/{subscription}");
        assert!(value.get("contextId").is_none());
        assert!(value.get("body").is_none());
        assert!(value.get("query").is_none());
        assert!(value.get("token").is_none());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn appends_artifact_metadata_without_path_or_content() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("audit/requests.jsonl");
        let sink = FileAuditLog::new(FileAuditConfig::with_defaults(&path).expect("config"));
        sink.append_artifact(&ArtifactWriteAuditRecord::authorized(
            "corr-2",
            "az.artifacts.writeJson",
            123,
            123,
            None,
            "application/json",
        ))
        .expect("append artifact");

        let line = fs::read_to_string(&path).expect("audit file");
        let value: serde_json::Value = serde_json::from_str(line.trim()).expect("json record");
        assert_eq!(value["operation"], "az.artifacts.writeJson");
        assert_eq!(value["bytes"], 123);
        assert_eq!(value["logicalBytes"], 123);
        assert_eq!(value["mediaType"], "application/json");
        assert!(value.get("contentEncoding").is_none());
        assert_eq!(value["sensitivity"], "customerData");
        assert!(value.get("path").is_none());
        assert!(value.get("name").is_none());
        assert!(value.get("value").is_none());
    }

    #[test]
    fn rotates_before_exceeding_the_active_file_bound() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("audit/requests.jsonl");
        let sink =
            FileAuditLog::new(FileAuditConfig::new(&path, MIN_MAX_AUDIT_BYTES, 2).expect("config"));
        let large_operation = "x".repeat(32 * 1024);
        sink.append(&record(&large_operation)).expect("first");
        sink.append(&record(&large_operation)).expect("second");
        assert!(rotated_path(&path, 1).is_file());
        assert!(path.is_file());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_destinations() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("tempdir");
        let target = directory.path().join("target");
        fs::write(&target, "unchanged").expect("target");
        let path = directory.path().join("requests.jsonl");
        symlink(&target, &path).expect("symlink");
        let sink = FileAuditLog::new(FileAuditConfig::with_defaults(&path).expect("config"));
        assert_eq!(sink.prepare(), Err(AuditError::UnsafeDestination));
        assert_eq!(fs::read_to_string(target).expect("target"), "unchanged");
    }
}
