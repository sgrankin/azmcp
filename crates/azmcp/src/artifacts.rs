//! Bounded, private JSON artifacts for isolated execution contexts.
//!
//! Callers never choose a directory. The store allocates an opaque random
//! namespace for each context and accepts only conservative JSON basenames
//! beneath that namespace. Artifacts persist independently of context
//! lifetime so a caller can hand the returned path to a local visualization
//! process after closing the JavaScript worker.

use std::{
    collections::HashMap,
    fmt,
    fs::{self, File, OpenOptions},
    future::Future,
    io::{self, Read as _, Write as _},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
};

use lz4_flex::frame::{BlockMode, BlockSize, FrameEncoder, FrameInfo};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Maximum encoded bytes in one artifact, including its trailing newline.
pub const DEFAULT_MAX_ARTIFACT_BYTES: usize = 480 * 1024;
/// Maximum uncompressed bytes in one streamed artifact, including framing.
pub const DEFAULT_MAX_STREAM_LOGICAL_BYTES: usize = 64 * 1024 * 1024;
/// Maximum stored bytes in one streamed artifact, including compression framing.
pub const DEFAULT_MAX_STREAM_STORED_BYTES: usize = 65 * 1024 * 1024;
const _: () = assert!(DEFAULT_MAX_STREAM_STORED_BYTES > DEFAULT_MAX_STREAM_LOGICAL_BYTES);
/// Maximum encoded bytes accepted in one append operation.
pub const MAX_STREAM_APPEND_BYTES: usize = 400 * 1024;
/// Maximum artifacts retained in one context namespace.
pub const DEFAULT_MAX_CONTEXT_FILES: usize = 32;
/// Maximum aggregate bytes retained in one context namespace.
pub const DEFAULT_MAX_CONTEXT_BYTES: usize = 128 * 1024 * 1024;
/// Maximum artifacts retained beneath one store root.
pub const DEFAULT_MAX_ROOT_FILES: usize = 256;
/// Maximum aggregate artifact bytes retained beneath one store root.
pub const DEFAULT_MAX_ROOT_BYTES: usize = 512 * 1024 * 1024;

const NAMESPACE_RANDOM_BYTES: usize = 32;
const NAMESPACE_PREFIX: &str = "ctx_";
const MAX_FILE_NAME_BYTES: usize = 128;
const JSON_MEDIA_TYPE: &str = "application/json";
const JSON_LINES_MEDIA_TYPE: &str = "application/x-ndjson";
const CUSTOMER_DATA_SENSITIVITY: &str = "customerData";
const ROOT_LOCK_FILE: &str = ".azmcp.lock";
const ROOT_LOCK_CONTENT: &[u8] = b"azmcp-artifacts-v1\n";

/// A boxed asynchronous artifact operation.
pub type ArtifactFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ArtifactError>> + Send + 'a>>;

/// Encoding used for a streamed artifact's stored bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactCompression {
    Identity,
    Lz4Frame,
}

impl ArtifactCompression {
    fn content_encoding(self) -> Option<&'static str> {
        match self {
            Self::Identity => None,
            Self::Lz4Frame => Some("lz4"),
        }
    }
}

/// Logical record framing used by a streamed JSON artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactStreamFormat {
    JsonArray,
    JsonLines,
}

impl ArtifactStreamFormat {
    const fn media_type(self) -> &'static str {
        match self {
            Self::JsonArray => JSON_MEDIA_TYPE,
            Self::JsonLines => JSON_LINES_MEDIA_TYPE,
        }
    }
}

/// An opaque, context-bound handle for an incomplete streamed artifact.
///
/// The handle carries no filesystem path and is not serializable. The store
/// retains the open writer and exact inode identity until the stream is
/// finished or discarded.
#[derive(Clone, Eq, PartialEq)]
pub struct ArtifactStream {
    id: String,
    namespace: String,
    format: ArtifactStreamFormat,
    compression: ArtifactCompression,
}

impl ArtifactStream {
    pub fn format(&self) -> ArtifactStreamFormat {
        self.format
    }

    pub fn compression(&self) -> ArtifactCompression {
        self.compression
    }
}

impl fmt::Debug for ArtifactStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactStream")
            .field("id", &"<redacted>")
            .field("namespace", &"<redacted>")
            .field("format", &self.format)
            .field("compression", &self.compression)
            .finish()
    }
}

/// Managed artifact operations available to the application host boundary.
pub trait ArtifactStore: Send + Sync {
    /// Allocate an opaque namespace without touching the filesystem.
    fn allocate_namespace(&self) -> Result<ArtifactNamespace, ArtifactError>;

    /// Validate and encode one JSON artifact without touching the filesystem.
    fn prepare_json(
        &self,
        file_name: String,
        value: Value,
    ) -> Result<PreparedArtifact, ArtifactError>;

    /// Begin an incrementally written JSON stream.
    ///
    /// The concrete file format is selected by the filename extension:
    /// `.json` is an array, `.jsonl` is JSON Lines, with matching `.lz4`
    /// suffixes for compressed output.
    fn begin_json_array<'a>(
        &'a self,
        _namespace: ArtifactNamespace,
        _file_name: String,
        _compression: ArtifactCompression,
    ) -> ArtifactFuture<'a, ArtifactStream> {
        Box::pin(async { Err(ArtifactError::Unavailable) })
    }

    /// Begin a stream with an explicitly selected JSON format.
    fn begin_json_stream<'a>(
        &'a self,
        _namespace: ArtifactNamespace,
        _file_name: String,
        _compression: ArtifactCompression,
        _format: ArtifactStreamFormat,
    ) -> ArtifactFuture<'a, ArtifactStream> {
        Box::pin(async { Err(ArtifactError::Unavailable) })
    }

    /// Append compact JSON values to an owned stream handle.
    ///
    /// Success returns the handle so callers can continue using it after the
    /// asynchronous operation. On failure, the store owns and discards the
    /// incomplete stream.
    fn append_json_array<'a>(
        &'a self,
        _namespace: ArtifactNamespace,
        _stream: ArtifactStream,
        _values: Vec<Value>,
    ) -> ArtifactFuture<'a, ArtifactStream> {
        Box::pin(async { Err(ArtifactError::Unavailable) })
    }

    /// Finish a stream and return its unpublished artifact stage.
    fn finish_json_array<'a>(
        &'a self,
        _namespace: ArtifactNamespace,
        _stream: ArtifactStream,
    ) -> ArtifactFuture<'a, ArtifactStage> {
        Box::pin(async { Err(ArtifactError::Unavailable) })
    }

    /// Discard exactly one incomplete stream owned by this store.
    fn discard_stream<'a>(
        &'a self,
        _namespace: ArtifactNamespace,
        _stream: ArtifactStream,
    ) -> ArtifactFuture<'a, ()> {
        Box::pin(async { Err(ArtifactError::Unavailable) })
    }

    /// Discard every incomplete stream owned by one opaque context namespace.
    ///
    /// Implementations must attempt all matching streams and retain exact
    /// ownership state for any file whose cleanup fails so callers may retry.
    fn discard_streams<'a>(&'a self, _namespace: ArtifactNamespace) -> ArtifactFuture<'a, ()> {
        Box::pin(async { Err(ArtifactError::Unavailable) })
    }

    /// Stage one immutable JSON artifact without publishing its receipt path.
    fn stage_prepared<'a>(
        &'a self,
        namespace: ArtifactNamespace,
        prepared: PreparedArtifact,
    ) -> ArtifactFuture<'a, ArtifactStage>;

    /// Publish a run's complete set of staged artifacts.
    fn commit_staged<'a>(
        &'a self,
        namespace: ArtifactNamespace,
        stages: Vec<ArtifactStage>,
    ) -> ArtifactFuture<'a, ()>;

    /// Release ownership after publication at the application's synchronous
    /// commit point.
    fn finalize_staged(
        &self,
        namespace: &ArtifactNamespace,
        stages: &[ArtifactStage],
    ) -> Result<(), ArtifactError>;

    /// Discard only the exact files owned by the supplied opaque stages.
    fn discard_staged<'a>(
        &'a self,
        namespace: ArtifactNamespace,
        stages: Vec<ArtifactStage>,
    ) -> ArtifactFuture<'a, ()>;
}

/// Fixed storage bounds.
///
/// Custom values exist for deterministic tests and may only tighten the
/// production maxima.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactStoreLimits {
    pub max_artifact_bytes: usize,
    pub max_stream_logical_bytes: usize,
    pub max_stream_stored_bytes: usize,
    pub max_context_files: usize,
    pub max_context_bytes: usize,
    pub max_root_files: usize,
    pub max_root_bytes: usize,
}

impl ArtifactStoreLimits {
    pub const fn new(
        max_artifact_bytes: usize,
        max_context_files: usize,
        max_context_bytes: usize,
        max_root_files: usize,
        max_root_bytes: usize,
    ) -> Self {
        Self {
            max_artifact_bytes,
            max_stream_logical_bytes: DEFAULT_MAX_STREAM_LOGICAL_BYTES,
            max_stream_stored_bytes: DEFAULT_MAX_STREAM_STORED_BYTES,
            max_context_files,
            max_context_bytes,
            max_root_files,
            max_root_bytes,
        }
    }

    /// Tighten the per-stream logical and stored bounds for deterministic tests.
    pub const fn with_stream_limits(
        mut self,
        max_stream_logical_bytes: usize,
        max_stream_stored_bytes: usize,
    ) -> Self {
        self.max_stream_logical_bytes = max_stream_logical_bytes;
        self.max_stream_stored_bytes = max_stream_stored_bytes;
        self
    }

    fn validate(self) -> Result<Self, ArtifactError> {
        if self.max_artifact_bytes == 0
            || self.max_artifact_bytes > DEFAULT_MAX_ARTIFACT_BYTES
            || self.max_stream_logical_bytes == 0
            || self.max_stream_logical_bytes > DEFAULT_MAX_STREAM_LOGICAL_BYTES
            || self.max_stream_stored_bytes == 0
            || self.max_stream_stored_bytes > DEFAULT_MAX_STREAM_STORED_BYTES
            || self.max_context_files == 0
            || self.max_context_files > DEFAULT_MAX_CONTEXT_FILES
            || self.max_context_bytes == 0
            || self.max_context_bytes > DEFAULT_MAX_CONTEXT_BYTES
            || self.max_root_files == 0
            || self.max_root_files > DEFAULT_MAX_ROOT_FILES
            || self.max_root_bytes == 0
            || self.max_root_bytes > DEFAULT_MAX_ROOT_BYTES
            || self.max_artifact_bytes > self.max_context_bytes
            || self.max_artifact_bytes > self.max_root_bytes
            || self.max_context_files > self.max_root_files
            || self.max_context_bytes > self.max_root_bytes
        {
            return Err(ArtifactError::InvalidLimits);
        }
        Ok(self)
    }
}

impl Default for ArtifactStoreLimits {
    fn default() -> Self {
        Self::new(
            DEFAULT_MAX_ARTIFACT_BYTES,
            DEFAULT_MAX_CONTEXT_FILES,
            DEFAULT_MAX_CONTEXT_BYTES,
            DEFAULT_MAX_ROOT_FILES,
            DEFAULT_MAX_ROOT_BYTES,
        )
    }
}

/// An opaque, randomly allocated context namespace.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ArtifactNamespace(String);

impl ArtifactNamespace {
    fn generate() -> Result<Self, ArtifactError> {
        Ok(Self(random_name(NAMESPACE_PREFIX)?))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ArtifactNamespace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ArtifactNamespace(<redacted>)")
    }
}

/// A validated, compact JSON value owned by the artifact store boundary.
///
/// Encoding once keeps the audited byte count, quota decision, digest, and
/// eventual file contents consistent.
#[derive(Clone)]
pub struct PreparedArtifact {
    file_name: String,
    bytes: Arc<[u8]>,
    sha256: String,
}

impl PreparedArtifact {
    pub fn bytes(&self) -> usize {
        self.bytes.len()
    }
}

impl fmt::Debug for PreparedArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedArtifact")
            .field("file_name", &"<redacted>")
            .field("bytes", &self.bytes.len())
            .field("sha256", &"<redacted>")
            .finish()
    }
}

/// Metadata for one successfully published JSON artifact.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactReceipt {
    path: PathBuf,
    bytes: usize,
    sha256: String,
    logical_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_encoding: Option<&'static str>,
    media_type: &'static str,
    sensitivity: &'static str,
}

impl ArtifactReceipt {
    pub(crate) fn new(path: PathBuf, bytes: usize, sha256: String) -> Self {
        Self::new_with_metadata(path, bytes, sha256, bytes, None, JSON_MEDIA_TYPE)
    }

    fn new_with_metadata(
        path: PathBuf,
        bytes: usize,
        sha256: String,
        logical_bytes: usize,
        content_encoding: Option<&'static str>,
        media_type: &'static str,
    ) -> Self {
        Self {
            path,
            bytes,
            sha256,
            logical_bytes,
            content_encoding,
            media_type,
            sensitivity: CUSTOMER_DATA_SENSITIVITY,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub const fn logical_bytes(&self) -> usize {
        self.logical_bytes
    }

    pub const fn content_encoding(&self) -> Option<&'static str> {
        self.content_encoding
    }

    pub const fn media_type(&self) -> &'static str {
        self.media_type
    }

    pub const fn sensitivity(&self) -> &'static str {
        self.sensitivity
    }
}

/// Opaque ownership ticket for one unpublished artifact.
///
/// The ticket is deliberately not serializable. Only the store can interpret
/// its staging path, reservation identifier, and exact file identity.
#[derive(Clone, Eq, PartialEq)]
pub struct ArtifactStage {
    id: String,
    namespace: String,
    staging_path: PathBuf,
    receipt: ArtifactReceipt,
    identity: FileIdentity,
}

impl ArtifactStage {
    pub fn receipt(&self) -> &ArtifactReceipt {
        &self.receipt
    }
}

impl fmt::Debug for ArtifactStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactStage")
            .field("id", &"<redacted>")
            .field("namespace", &"<redacted>")
            .field("staging_path", &"<redacted>")
            .field("receipt", &self.receipt)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl fmt::Debug for ArtifactReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactReceipt")
            .field("path", &"<redacted>")
            .field("bytes", &self.bytes)
            .field("sha256", &"<redacted>")
            .field("logical_bytes", &self.logical_bytes)
            .field("content_encoding", &self.content_encoding)
            .field("media_type", &self.media_type)
            .field("sensitivity", &self.sensitivity)
            .finish()
    }
}

/// A filesystem-backed artifact store.
#[derive(Clone)]
pub struct FileArtifactStore {
    inner: Arc<FileArtifactStoreInner>,
}

struct FileArtifactStoreInner {
    root: PathBuf,
    limits: ArtifactStoreLimits,
    gate: Mutex<StoreState>,
}

#[derive(Default)]
struct StoreState {
    root_lock: Option<File>,
    root_identity: Option<FileIdentity>,
    reservations: HashMap<PathBuf, Reservation>,
    streams: HashMap<String, StreamState>,
}

#[derive(Clone)]
struct Reservation {
    stage_id: String,
    staging_path: PathBuf,
    identity: FileIdentity,
    cleanup_pending: bool,
}

struct StreamState {
    id: String,
    namespace: String,
    file_name: String,
    staging_path: PathBuf,
    identity: FileIdentity,
    format: ArtifactStreamFormat,
    compression: ArtifactCompression,
    logical_bytes: usize,
    has_values: bool,
    writer: Option<StreamWriter>,
    cleanup_pending: bool,
}

enum StreamWriter {
    Identity(File),
    Lz4Frame(FrameEncoder<File>),
}

impl StreamWriter {
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), ArtifactError> {
        match self {
            Self::Identity(file) => file
                .write_all(bytes)
                .map_err(|_| ArtifactError::Unavailable),
            Self::Lz4Frame(encoder) => encoder
                .write_all(bytes)
                .map_err(|_| ArtifactError::Unavailable),
        }
    }

    fn flush_and_sync(&mut self) -> Result<(), ArtifactError> {
        match self {
            Self::Identity(file) => file
                .flush()
                .and_then(|_| file.sync_all())
                .map_err(|_| ArtifactError::Unavailable),
            Self::Lz4Frame(encoder) => encoder
                .flush()
                .and_then(|_| encoder.get_ref().sync_all())
                .map_err(|_| ArtifactError::Unavailable),
        }
    }

    fn stored_len(&self) -> Result<usize, ArtifactError> {
        let length = match self {
            Self::Identity(file) => file
                .metadata()
                .map_err(|_| ArtifactError::Unavailable)?
                .len(),
            Self::Lz4Frame(encoder) => encoder
                .get_ref()
                .metadata()
                .map_err(|_| ArtifactError::Unavailable)?
                .len(),
        };
        usize::try_from(length).map_err(|_| ArtifactError::RootCapacity)
    }

    fn finish(self, suffix: &[u8]) -> Result<(File, usize), ArtifactError> {
        match self {
            Self::Identity(mut file) => {
                file.write_all(suffix)
                    .and_then(|_| file.flush())
                    .and_then(|_| file.sync_all())
                    .map_err(|_| ArtifactError::Unavailable)?;
                let length = usize::try_from(
                    file.metadata()
                        .map_err(|_| ArtifactError::Unavailable)?
                        .len(),
                )
                .map_err(|_| ArtifactError::RootCapacity)?;
                Ok((file, length))
            }
            Self::Lz4Frame(mut encoder) => {
                encoder
                    .write_all(suffix)
                    .and_then(|_| encoder.flush())
                    .map_err(|_| ArtifactError::Unavailable)?;
                let mut file = encoder.finish().map_err(|_| ArtifactError::Unavailable)?;
                file.flush()
                    .and_then(|_| file.sync_all())
                    .map_err(|_| ArtifactError::Unavailable)?;
                let length = usize::try_from(
                    file.metadata()
                        .map_err(|_| ArtifactError::Unavailable)?
                        .len(),
                )
                .map_err(|_| ArtifactError::RootCapacity)?;
                Ok((file, length))
            }
        }
    }
}

impl FileArtifactStore {
    /// Construct a store with the production limits.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, ArtifactError> {
        Self::with_limits(root, ArtifactStoreLimits::default())
    }

    /// Construct a store with limits that do not exceed production maxima.
    pub fn with_limits(
        root: impl Into<PathBuf>,
        limits: ArtifactStoreLimits,
    ) -> Result<Self, ArtifactError> {
        let root = root.into();
        if !root.is_absolute() {
            return Err(ArtifactError::InvalidRoot);
        }
        let limits = limits.validate()?;
        #[cfg(not(unix))]
        {
            let _ = (root, limits);
            Err(ArtifactError::UnsupportedPlatform)
        }
        #[cfg(unix)]
        {
            Ok(Self {
                inner: Arc::new(FileArtifactStoreInner {
                    root,
                    limits,
                    gate: Mutex::new(StoreState::default()),
                }),
            })
        }
    }

    pub fn root(&self) -> &Path {
        &self.inner.root
    }

    #[cfg(test)]
    async fn write_json(
        &self,
        namespace: ArtifactNamespace,
        file_name: String,
        value: Value,
    ) -> Result<ArtifactReceipt, ArtifactError> {
        let prepared = self.prepare_json(file_name, value)?;
        let stage = self.stage_prepared(namespace.clone(), prepared).await?;
        let receipt = stage.receipt().clone();
        if let Err(error) = self
            .commit_staged(namespace.clone(), vec![stage.clone()])
            .await
        {
            let _ = self.discard_staged(namespace, vec![stage]).await;
            return Err(error);
        }
        self.finalize_staged(&namespace, std::slice::from_ref(&stage))?;
        Ok(receipt)
    }

    fn prepare_json_value(
        &self,
        file_name: String,
        value: Value,
    ) -> Result<PreparedArtifact, ArtifactError> {
        validate_file_name(&file_name)?;
        let mut bytes = serde_json::to_vec(&value).map_err(|_| ArtifactError::Serialization)?;
        bytes.push(b'\n');
        if bytes.len() > self.inner.limits.max_artifact_bytes {
            return Err(ArtifactError::ValueTooLarge {
                bytes: bytes.len(),
                limit: self.inner.limits.max_artifact_bytes,
            });
        }
        let sha256 = sha256_hex(&bytes);
        Ok(PreparedArtifact {
            file_name,
            bytes: bytes.into(),
            sha256,
        })
    }

    fn begin_json_stream_blocking(
        &self,
        namespace: &ArtifactNamespace,
        file_name: String,
        compression: ArtifactCompression,
        format: ArtifactStreamFormat,
    ) -> Result<ArtifactStream, ArtifactError> {
        validate_stream_file_name(&file_name, compression, format)?;
        let mut state = self
            .inner
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = (|| {
            let minimum_logical_bytes = match format {
                ArtifactStreamFormat::JsonArray => 3,
                ArtifactStreamFormat::JsonLines => 0,
            };
            if minimum_logical_bytes > self.inner.limits.max_stream_logical_bytes {
                return Err(ArtifactError::ValueTooLarge {
                    bytes: minimum_logical_bytes,
                    limit: self.inner.limits.max_stream_logical_bytes,
                });
            }
            let minimum_stored_bytes = if matches!(compression, ArtifactCompression::Identity) {
                minimum_logical_bytes
            } else {
                1
            };
            if minimum_stored_bytes > self.inner.limits.max_stream_stored_bytes {
                return Err(ArtifactError::ValueTooLarge {
                    bytes: minimum_stored_bytes,
                    limit: self.inner.limits.max_stream_stored_bytes,
                });
            }
            ensure_store_ready(&self.inner.root, &mut state)?;
            let snapshot = scan_root(&self.inner.root, namespace)?;
            let initial_bytes = if matches!(compression, ArtifactCompression::Identity)
                && matches!(format, ArtifactStreamFormat::JsonArray)
            {
                1
            } else {
                0
            };
            ensure_capacity(
                snapshot.root,
                snapshot.context,
                initial_bytes,
                self.inner.limits,
            )?;
            let namespace_path = self.inner.root.join(namespace.as_str());
            if !snapshot.namespace_exists {
                create_private_directory(&namespace_path)
                    .map_err(|_| ArtifactError::Unavailable)?;
            }
            validate_namespace_path(&namespace_path)?;

            let destination = namespace_path.join(&file_name);
            if state.reservations.contains_key(&destination)
                || state.streams.values().any(|stream| {
                    stream.namespace == namespace.as_str()
                        && namespace_path.join(&stream.file_name) == destination
                })
            {
                return Err(ArtifactError::DestinationExists);
            }
            reject_existing_destination(&destination)?;
            let temporary_path = unique_temporary_path(&namespace_path)?;
            let file = open_private_new(&temporary_path)?;
            let mut writer = match compression {
                ArtifactCompression::Identity => StreamWriter::Identity(file),
                ArtifactCompression::Lz4Frame => {
                    StreamWriter::Lz4Frame(FrameEncoder::with_frame_info(stream_frame_info(), file))
                }
            };
            if matches!(format, ArtifactStreamFormat::JsonArray)
                && writer
                    .write_all(b"[")
                    .and_then(|_| writer.flush_and_sync())
                    .is_err()
            {
                drop(writer);
                let _ = fs::remove_file(&temporary_path);
                return Err(ArtifactError::Unavailable);
            }
            let identity = match stream_writer_identity(&writer) {
                Ok(identity) => identity,
                Err(error) => {
                    drop(writer);
                    let _ = fs::remove_file(&temporary_path);
                    return Err(error);
                }
            };
            let stream_id = match random_name("stream_") {
                Ok(stream_id) => stream_id,
                Err(error) => {
                    drop(writer);
                    let _ = fs::remove_file(&temporary_path);
                    return Err(error);
                }
            };
            state.streams.insert(
                stream_id.clone(),
                StreamState {
                    id: stream_id.clone(),
                    namespace: namespace.as_str().to_owned(),
                    file_name,
                    staging_path: temporary_path,
                    identity,
                    format,
                    compression,
                    logical_bytes: if matches!(format, ArtifactStreamFormat::JsonArray) {
                        1
                    } else {
                        0
                    },
                    has_values: false,
                    writer: Some(writer),
                    cleanup_pending: false,
                },
            );
            Ok(ArtifactStream {
                id: stream_id,
                namespace: namespace.as_str().to_owned(),
                format,
                compression,
            })
        })();
        if result.is_err() {
            release_root_if_idle(&mut state);
        }
        result
    }

    fn append_json_stream_blocking(
        &self,
        namespace: &ArtifactNamespace,
        stream: ArtifactStream,
        values: Vec<Value>,
    ) -> Result<ArtifactStream, ArtifactError> {
        let mut state = self
            .inner
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ensure_store_ready(&self.inner.root, &mut state)?;
        let Some(mut stream_state) = state.streams.remove(&stream.id) else {
            return Err(ArtifactError::ReceiptMismatch);
        };
        if !stream_handle_matches(namespace, &stream, &stream_state) {
            state.streams.insert(stream.id.clone(), stream_state);
            return Err(ArtifactError::ReceiptMismatch);
        }

        let chunk =
            match encode_stream_values(&values, stream_state.format, stream_state.has_values) {
                Ok(chunk) => chunk,
                Err(error) => {
                    return discard_removed_stream(&mut state, stream_state, error);
                }
            };
        if chunk.is_empty() {
            state.streams.insert(stream.id.clone(), stream_state);
            return Ok(stream);
        }
        let closing_bytes = stream_closing_bytes(stream_state.format);
        if stream_state
            .logical_bytes
            .saturating_add(chunk.len())
            .saturating_add(closing_bytes.len())
            > self.inner.limits.max_stream_logical_bytes
        {
            let bytes = stream_state
                .logical_bytes
                .saturating_add(chunk.len())
                .saturating_add(closing_bytes.len());
            return discard_removed_stream(
                &mut state,
                stream_state,
                ArtifactError::ValueTooLarge {
                    bytes,
                    limit: self.inner.limits.max_stream_logical_bytes,
                },
            );
        }
        let snapshot = match scan_root(&self.inner.root, namespace) {
            Ok(snapshot) => snapshot,
            Err(error) => return discard_removed_stream(&mut state, stream_state, error),
        };
        if matches!(stream_state.compression, ArtifactCompression::Identity)
            && let Err(error) = ensure_existing_capacity(
                snapshot.root,
                snapshot.context,
                chunk.len(),
                self.inner.limits,
            )
        {
            return discard_removed_stream(&mut state, stream_state, error);
        }
        let Some(writer) = stream_state.writer.as_mut() else {
            return discard_removed_stream(
                &mut state,
                stream_state,
                ArtifactError::ReceiptMismatch,
            );
        };
        if let Err(error) = writer
            .write_all(&chunk)
            .and_then(|_| writer.flush_and_sync())
        {
            return discard_removed_stream(&mut state, stream_state, error);
        }
        let stored_bytes = match writer.stored_len() {
            Ok(bytes) => bytes,
            Err(error) => return discard_removed_stream(&mut state, stream_state, error),
        };
        if stored_bytes > self.inner.limits.max_stream_stored_bytes {
            return discard_removed_stream::<ArtifactStream>(
                &mut state,
                stream_state,
                ArtifactError::ValueTooLarge {
                    bytes: stored_bytes,
                    limit: self.inner.limits.max_stream_stored_bytes,
                },
            );
        }
        let after = match scan_root(&self.inner.root, namespace) {
            Ok(snapshot) => snapshot,
            Err(error) => return discard_removed_stream(&mut state, stream_state, error),
        };
        if after.context.bytes > self.inner.limits.max_context_bytes {
            return discard_removed_stream::<ArtifactStream>(
                &mut state,
                stream_state,
                ArtifactError::ContextCapacity,
            );
        }
        if after.root.bytes > self.inner.limits.max_root_bytes {
            return discard_removed_stream::<ArtifactStream>(
                &mut state,
                stream_state,
                ArtifactError::RootCapacity,
            );
        }
        stream_state.logical_bytes = stream_state.logical_bytes.saturating_add(chunk.len());
        stream_state.has_values = true;
        state.streams.insert(stream.id.clone(), stream_state);
        Ok(stream)
    }

    fn finish_json_stream_blocking(
        &self,
        namespace: &ArtifactNamespace,
        stream: ArtifactStream,
    ) -> Result<ArtifactStage, ArtifactError> {
        let mut state = self
            .inner
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ensure_store_ready(&self.inner.root, &mut state)?;
        let Some(mut stream_state) = state.streams.remove(&stream.id) else {
            return Err(ArtifactError::ReceiptMismatch);
        };
        if !stream_handle_matches(namespace, &stream, &stream_state) {
            state.streams.insert(stream.id.clone(), stream_state);
            return Err(ArtifactError::ReceiptMismatch);
        }
        let suffix = stream_closing_bytes(stream_state.format);
        let logical_bytes = stream_state.logical_bytes.saturating_add(suffix.len());
        if logical_bytes > self.inner.limits.max_stream_logical_bytes {
            return discard_removed_stream::<ArtifactStage>(
                &mut state,
                stream_state,
                ArtifactError::ValueTooLarge {
                    bytes: logical_bytes,
                    limit: self.inner.limits.max_stream_logical_bytes,
                },
            )
            .map(|_| unreachable!("stream finish error cannot produce a stage"));
        }
        let destination = self
            .inner
            .root
            .join(namespace.as_str())
            .join(&stream_state.file_name);
        let Some(writer) = stream_state.writer.take() else {
            return discard_removed_stream(
                &mut state,
                stream_state,
                ArtifactError::ReceiptMismatch,
            );
        };
        let (file, stored_bytes) = match writer.finish(suffix) {
            Ok(result) => result,
            Err(error) => {
                return discard_removed_stream(&mut state, stream_state, error);
            }
        };
        drop(file);
        if stored_bytes > self.inner.limits.max_stream_stored_bytes {
            return discard_removed_stream(
                &mut state,
                stream_state,
                ArtifactError::ValueTooLarge {
                    bytes: stored_bytes,
                    limit: self.inner.limits.max_stream_stored_bytes,
                },
            );
        }
        if let Err(error) = reject_existing_destination(&destination) {
            return discard_removed_stream(&mut state, stream_state, error);
        }
        let snapshot = match scan_root(&self.inner.root, namespace) {
            Ok(snapshot) => snapshot,
            Err(error) => return discard_removed_stream(&mut state, stream_state, error),
        };
        if snapshot.context.bytes > self.inner.limits.max_context_bytes {
            return discard_removed_stream(
                &mut state,
                stream_state,
                ArtifactError::ContextCapacity,
            );
        }
        if snapshot.root.bytes > self.inner.limits.max_root_bytes {
            return discard_removed_stream(&mut state, stream_state, ArtifactError::RootCapacity);
        }
        let (hashed_bytes, sha256) =
            match hash_exact_file(&stream_state.staging_path, stream_state.identity) {
                Ok(result) => result,
                Err(error) => return discard_removed_stream(&mut state, stream_state, error),
            };
        if hashed_bytes != stored_bytes {
            return discard_removed_stream(
                &mut state,
                stream_state,
                ArtifactError::ReceiptMismatch,
            );
        }
        let stage_id = match random_name("stage_") {
            Ok(stage_id) => stage_id,
            Err(error) => return discard_removed_stream(&mut state, stream_state, error),
        };
        let receipt = ArtifactReceipt::new_with_metadata(
            destination.clone(),
            stored_bytes,
            sha256,
            logical_bytes,
            stream_state.compression.content_encoding(),
            stream_state.format.media_type(),
        );
        state.reservations.insert(
            destination,
            Reservation {
                stage_id: stage_id.clone(),
                staging_path: stream_state.staging_path.clone(),
                identity: stream_state.identity,
                cleanup_pending: false,
            },
        );
        Ok(ArtifactStage {
            id: stage_id,
            namespace: namespace.as_str().to_owned(),
            staging_path: stream_state.staging_path,
            receipt,
            identity: stream_state.identity,
        })
    }

    fn discard_stream_blocking(
        &self,
        namespace: &ArtifactNamespace,
        stream: ArtifactStream,
    ) -> Result<(), ArtifactError> {
        let mut state = self
            .inner
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ensure_store_ready(&self.inner.root, &mut state)?;
        let Some(stream_state) = state.streams.remove(&stream.id) else {
            return Ok(());
        };
        if !stream_handle_matches(namespace, &stream, &stream_state) {
            state.streams.insert(stream.id, stream_state);
            return Err(ArtifactError::ReceiptMismatch);
        }
        discard_stream_state(&mut state, stream_state)
    }

    fn discard_namespace_streams_blocking(
        &self,
        namespace: &ArtifactNamespace,
    ) -> Result<(), ArtifactError> {
        let mut state = self
            .inner
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ensure_store_root_ready(&self.inner.root, &mut state)?;
        let stream_ids = state
            .streams
            .iter()
            .filter(|(_, stream)| stream.namespace == namespace.as_str())
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        let mut first_error = None;
        for stream_id in stream_ids {
            let Some(stream) = state.streams.remove(&stream_id) else {
                continue;
            };
            if let Err(error) = discard_stream_state(&mut state, stream)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        release_root_if_idle(&mut state);
        first_error.map_or(Ok(()), Err)
    }

    fn stage_prepared_blocking(
        &self,
        namespace: &ArtifactNamespace,
        prepared: PreparedArtifact,
    ) -> Result<ArtifactStage, ArtifactError> {
        let mut state = self
            .inner
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = (|| {
            ensure_store_ready(&self.inner.root, &mut state)?;
            let snapshot = scan_root(&self.inner.root, namespace)?;
            ensure_capacity(
                snapshot.root,
                snapshot.context,
                prepared.bytes.len(),
                self.inner.limits,
            )?;
            let namespace_path = self.inner.root.join(namespace.as_str());
            if !snapshot.namespace_exists {
                create_private_directory(&namespace_path)
                    .map_err(|_| ArtifactError::Unavailable)?;
            }
            validate_namespace_path(&namespace_path)?;

            let destination = namespace_path.join(&prepared.file_name);
            if state.reservations.contains_key(&destination)
                || state.streams.values().any(|stream| {
                    stream.namespace == namespace.as_str()
                        && namespace_path.join(&stream.file_name) == destination
                })
            {
                return Err(ArtifactError::DestinationExists);
            }
            reject_existing_destination(&destination)?;
            let temporary_path = unique_temporary_path(&namespace_path)?;
            let mut temporary = TemporaryArtifact::create(temporary_path)?;
            temporary.write_all(&prepared.bytes)?;
            let stage_id = random_name("stage_")?;
            let (staging_path, identity) = temporary.retain()?;
            let receipt =
                ArtifactReceipt::new(destination.clone(), prepared.bytes.len(), prepared.sha256);
            state.reservations.insert(
                destination,
                Reservation {
                    stage_id: stage_id.clone(),
                    staging_path: staging_path.clone(),
                    identity,
                    cleanup_pending: false,
                },
            );
            Ok(ArtifactStage {
                id: stage_id,
                namespace: namespace.as_str().to_owned(),
                staging_path,
                receipt,
                identity,
            })
        })();
        if result.is_err() {
            release_root_if_idle(&mut state);
        }
        result
    }

    fn commit_staged_blocking(
        &self,
        namespace: &ArtifactNamespace,
        stages: &[ArtifactStage],
    ) -> Result<(), ArtifactError> {
        if stages.is_empty() {
            return Ok(());
        }
        let mut state = self
            .inner
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ensure_store_ready(&self.inner.root, &mut state)?;
        for stage in stages {
            self.validate_stage(namespace, &state, stage)?;
            require_exact_artifact(&stage.staging_path, stage)?;
            match file_identity_if_regular(stage.receipt.path())? {
                None => {}
                Some(identity) if identity == stage.identity => {}
                Some(_) => return Err(ArtifactError::DestinationExists),
            }
        }

        let publish = (|| {
            for stage in stages {
                if file_identity_if_regular(stage.receipt.path())?.is_none() {
                    fs::hard_link(&stage.staging_path, stage.receipt.path())
                        .map_err(|_| ArtifactError::Unavailable)?;
                }
                require_exact_artifact(stage.receipt.path(), stage)?;
            }
            for stage in stages {
                remove_exact_file(&stage.staging_path, stage.identity)?;
            }
            sync_directory(&self.inner.root.join(namespace.as_str()))?;
            Ok(())
        })();
        if let Err(error) = publish {
            discard_exact_files(stages)?;
            return Err(error);
        }
        Ok(())
    }

    fn finalize_staged_now(
        &self,
        namespace: &ArtifactNamespace,
        stages: &[ArtifactStage],
    ) -> Result<(), ArtifactError> {
        let mut state = self
            .inner
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ensure_store_ready(&self.inner.root, &mut state)?;
        for stage in stages {
            if stage.namespace != namespace.as_str() {
                return Err(ArtifactError::ReceiptMismatch);
            }
            let reservation = state
                .reservations
                .get(stage.receipt.path())
                .ok_or(ArtifactError::ReceiptMismatch)?;
            validate_reservation(reservation, stage)?;
            require_exact_artifact(stage.receipt.path(), stage)?;
        }
        for stage in stages {
            state.reservations.remove(stage.receipt.path());
        }
        release_root_if_idle(&mut state);
        Ok(())
    }

    fn discard_staged_blocking(
        &self,
        namespace: &ArtifactNamespace,
        stages: &[ArtifactStage],
    ) -> Result<(), ArtifactError> {
        let mut state = self
            .inner
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ensure_store_ready(&self.inner.root, &mut state)?;
        let mut first_error = None;
        for stage in stages {
            let owns_reservation = self.validate_stage_shape(namespace, stage).is_ok()
                && state
                    .reservations
                    .get(stage.receipt.path())
                    .is_some_and(|reservation| validate_reservation(reservation, stage).is_ok());
            let result = self
                .validate_stage_shape(namespace, stage)
                .and_then(|_| {
                    match state.reservations.get(stage.receipt.path()) {
                        Some(reservation) => validate_reservation(reservation, stage)?,
                        None if file_identity_if_regular(stage.receipt.path())?.is_none()
                            && file_identity_if_regular(&stage.staging_path)?.is_none() => {}
                        None => return Err(ArtifactError::ReceiptMismatch),
                    }
                    Ok(())
                })
                .and_then(|_| discard_exact_files(std::slice::from_ref(stage)));
            match result {
                Ok(()) => {
                    state.reservations.remove(stage.receipt.path());
                }
                Err(error) => {
                    if owns_reservation
                        && let Some(reservation) = state.reservations.get_mut(stage.receipt.path())
                    {
                        reservation.cleanup_pending = true;
                    }
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        let namespace_path = self.inner.root.join(namespace.as_str());
        remove_directory_if_empty(&namespace_path)?;
        release_root_if_idle(&mut state);
        first_error.map_or(Ok(()), Err)
    }

    fn validate_stage(
        &self,
        namespace: &ArtifactNamespace,
        state: &StoreState,
        stage: &ArtifactStage,
    ) -> Result<(), ArtifactError> {
        self.validate_stage_shape(namespace, stage)?;
        let reservation = state
            .reservations
            .get(stage.receipt.path())
            .ok_or(ArtifactError::ReceiptMismatch)?;
        validate_reservation(reservation, stage)
    }

    fn validate_stage_shape(
        &self,
        namespace: &ArtifactNamespace,
        stage: &ArtifactStage,
    ) -> Result<(), ArtifactError> {
        validate_namespace_name(namespace.as_str())?;
        let namespace_path = self.inner.root.join(namespace.as_str());
        validate_namespace_path(&namespace_path)?;
        if stage.namespace != namespace.as_str()
            || stage.receipt.path.parent() != Some(namespace_path.as_path())
            || stage.staging_path.parent() != Some(namespace_path.as_path())
        {
            return Err(ArtifactError::ReceiptMismatch);
        }
        let file_name = stage
            .receipt
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(ArtifactError::ReceiptMismatch)?;
        let (compression, _) =
            validate_stored_file_name(file_name).map_err(|_| ArtifactError::ReceiptMismatch)?;
        if stage.receipt.content_encoding != compression.content_encoding() {
            return Err(ArtifactError::ReceiptMismatch);
        }
        validate_temporary_name(
            stage
                .staging_path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(ArtifactError::ReceiptMismatch)?,
        )?;
        Ok(())
    }
}

fn validate_reservation(
    reservation: &Reservation,
    stage: &ArtifactStage,
) -> Result<(), ArtifactError> {
    if reservation.stage_id != stage.id
        || reservation.staging_path != stage.staging_path
        || reservation.identity != stage.identity
    {
        return Err(ArtifactError::ReceiptMismatch);
    }
    Ok(())
}

fn release_root_if_idle(state: &mut StoreState) {
    if state.reservations.is_empty() && state.streams.is_empty() {
        state.root_identity = None;
        state.root_lock = None;
    }
}

impl fmt::Debug for FileArtifactStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileArtifactStore")
            .field("root", &"<redacted>")
            .field("limits", &self.inner.limits)
            .finish()
    }
}

impl ArtifactStore for FileArtifactStore {
    fn allocate_namespace(&self) -> Result<ArtifactNamespace, ArtifactError> {
        ArtifactNamespace::generate()
    }

    fn prepare_json(
        &self,
        file_name: String,
        value: Value,
    ) -> Result<PreparedArtifact, ArtifactError> {
        self.prepare_json_value(file_name, value)
    }

    fn begin_json_array<'a>(
        &'a self,
        namespace: ArtifactNamespace,
        file_name: String,
        compression: ArtifactCompression,
    ) -> ArtifactFuture<'a, ArtifactStream> {
        let store = self.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let format = infer_stream_format(&file_name, compression)?;
                store.begin_json_stream_blocking(&namespace, file_name, compression, format)
            })
            .await
            .map_err(|_| ArtifactError::Unavailable)?
        })
    }

    fn begin_json_stream<'a>(
        &'a self,
        namespace: ArtifactNamespace,
        file_name: String,
        compression: ArtifactCompression,
        format: ArtifactStreamFormat,
    ) -> ArtifactFuture<'a, ArtifactStream> {
        let store = self.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                store.begin_json_stream_blocking(&namespace, file_name, compression, format)
            })
            .await
            .map_err(|_| ArtifactError::Unavailable)?
        })
    }

    fn append_json_array<'a>(
        &'a self,
        namespace: ArtifactNamespace,
        stream: ArtifactStream,
        values: Vec<Value>,
    ) -> ArtifactFuture<'a, ArtifactStream> {
        let store = self.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                store.append_json_stream_blocking(&namespace, stream, values)
            })
            .await
            .map_err(|_| ArtifactError::Unavailable)?
        })
    }

    fn finish_json_array<'a>(
        &'a self,
        namespace: ArtifactNamespace,
        stream: ArtifactStream,
    ) -> ArtifactFuture<'a, ArtifactStage> {
        let store = self.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                store.finish_json_stream_blocking(&namespace, stream)
            })
            .await
            .map_err(|_| ArtifactError::Unavailable)?
        })
    }

    fn discard_stream<'a>(
        &'a self,
        namespace: ArtifactNamespace,
        stream: ArtifactStream,
    ) -> ArtifactFuture<'a, ()> {
        let store = self.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || store.discard_stream_blocking(&namespace, stream))
                .await
                .map_err(|_| ArtifactError::Unavailable)?
        })
    }

    fn discard_streams<'a>(&'a self, namespace: ArtifactNamespace) -> ArtifactFuture<'a, ()> {
        let store = self.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                store.discard_namespace_streams_blocking(&namespace)
            })
            .await
            .map_err(|_| ArtifactError::Unavailable)?
        })
    }

    fn stage_prepared<'a>(
        &'a self,
        namespace: ArtifactNamespace,
        prepared: PreparedArtifact,
    ) -> ArtifactFuture<'a, ArtifactStage> {
        let store = self.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || store.stage_prepared_blocking(&namespace, prepared))
                .await
                .map_err(|_| ArtifactError::Unavailable)?
        })
    }

    fn commit_staged<'a>(
        &'a self,
        namespace: ArtifactNamespace,
        stages: Vec<ArtifactStage>,
    ) -> ArtifactFuture<'a, ()> {
        let store = self.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || store.commit_staged_blocking(&namespace, &stages))
                .await
                .map_err(|_| ArtifactError::Unavailable)?
        })
    }

    fn finalize_staged(
        &self,
        namespace: &ArtifactNamespace,
        stages: &[ArtifactStage],
    ) -> Result<(), ArtifactError> {
        self.finalize_staged_now(namespace, stages)
    }

    fn discard_staged<'a>(
        &'a self,
        namespace: ArtifactNamespace,
        stages: Vec<ArtifactStage>,
    ) -> ArtifactFuture<'a, ()> {
        let store = self.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || store.discard_staged_blocking(&namespace, &stages))
                .await
                .map_err(|_| ArtifactError::Unavailable)?
        })
    }
}

/// Closed, content-free failures from managed artifact storage.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ArtifactError {
    #[error("artifact root must be an absolute path")]
    InvalidRoot,
    #[error("artifact storage limits are invalid")]
    InvalidLimits,
    #[error("artifact storage is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("artifact file name is invalid")]
    InvalidFileName,
    #[error("artifact contains {bytes} bytes, exceeding the {limit}-byte limit")]
    ValueTooLarge { bytes: usize, limit: usize },
    #[error("artifact context capacity is exhausted")]
    ContextCapacity,
    #[error("artifact root capacity is exhausted")]
    RootCapacity,
    #[error("artifact destination already exists")]
    DestinationExists,
    #[error("artifact root is already in use")]
    RootInUse,
    #[error("artifact root is unsafe")]
    UnsafeRoot,
    #[error("artifact namespace is unsafe")]
    UnsafeNamespace,
    #[error("artifact destination is unsafe")]
    UnsafeDestination,
    #[error("artifact receipt does not identify the created file")]
    ReceiptMismatch,
    #[error("artifact identifier generation failed")]
    RandomId,
    #[error("artifact JSON serialization failed")]
    Serialization,
    #[error("artifact storage is unavailable")]
    Unavailable,
}

#[derive(Clone, Copy, Default)]
struct Usage {
    files: usize,
    bytes: usize,
}

struct RootSnapshot {
    root: Usage,
    context: Usage,
    namespace_exists: bool,
}

fn ensure_capacity(
    root: Usage,
    context: Usage,
    added_bytes: usize,
    limits: ArtifactStoreLimits,
) -> Result<(), ArtifactError> {
    if context.files >= limits.max_context_files
        || context.bytes.saturating_add(added_bytes) > limits.max_context_bytes
    {
        return Err(ArtifactError::ContextCapacity);
    }
    if root.files >= limits.max_root_files
        || root.bytes.saturating_add(added_bytes) > limits.max_root_bytes
    {
        return Err(ArtifactError::RootCapacity);
    }
    Ok(())
}

fn ensure_existing_capacity(
    root: Usage,
    context: Usage,
    added_bytes: usize,
    limits: ArtifactStoreLimits,
) -> Result<(), ArtifactError> {
    if context.bytes.saturating_add(added_bytes) > limits.max_context_bytes {
        return Err(ArtifactError::ContextCapacity);
    }
    if root.bytes.saturating_add(added_bytes) > limits.max_root_bytes {
        return Err(ArtifactError::RootCapacity);
    }
    Ok(())
}

fn stream_frame_info() -> FrameInfo {
    FrameInfo::new()
        .block_size(BlockSize::Max256KB)
        .block_mode(BlockMode::Independent)
        .block_checksums(false)
        .content_checksum(true)
}

fn stream_writer_identity(writer: &StreamWriter) -> Result<FileIdentity, ArtifactError> {
    let metadata = match writer {
        StreamWriter::Identity(file) => file.metadata(),
        StreamWriter::Lz4Frame(encoder) => encoder.get_ref().metadata(),
    }
    .map_err(|_| ArtifactError::Unavailable)?;
    file_identity(&metadata)
}

fn stream_handle_matches(
    namespace: &ArtifactNamespace,
    stream: &ArtifactStream,
    state: &StreamState,
) -> bool {
    stream.namespace == namespace.as_str()
        && state.namespace == namespace.as_str()
        && stream.format == state.format
        && stream.compression == state.compression
}

fn discard_stream_state(
    state: &mut StoreState,
    mut stream: StreamState,
) -> Result<(), ArtifactError> {
    let path = stream.staging_path.clone();
    let identity = stream.identity;
    match remove_exact_file(&path, identity) {
        Ok(()) => {
            drop(stream);
            release_root_if_idle(state);
            Ok(())
        }
        Err(error) => {
            stream.cleanup_pending = true;
            state.streams.insert(stream.id.clone(), stream);
            Err(error)
        }
    }
}

fn discard_removed_stream<T>(
    state: &mut StoreState,
    stream: StreamState,
    error: ArtifactError,
) -> Result<T, ArtifactError> {
    match discard_stream_state(state, stream) {
        Ok(()) => Err(error),
        Err(cleanup_error) => Err(cleanup_error),
    }
}

fn stream_closing_bytes(format: ArtifactStreamFormat) -> &'static [u8] {
    match format {
        ArtifactStreamFormat::JsonArray => b"]\n",
        ArtifactStreamFormat::JsonLines => b"",
    }
}

fn encode_stream_values(
    values: &[Value],
    format: ArtifactStreamFormat,
    has_values: bool,
) -> Result<Vec<u8>, ArtifactError> {
    let mut output = BoundedBuffer::new(MAX_STREAM_APPEND_BYTES);
    for (index, value) in values.iter().enumerate() {
        match format {
            ArtifactStreamFormat::JsonArray => {
                if has_values || index != 0 {
                    output.push_byte(b',')?;
                }
                serde_json::to_writer(&mut output, value).map_err(|_| {
                    ArtifactError::ValueTooLarge {
                        bytes: MAX_STREAM_APPEND_BYTES.saturating_add(1),
                        limit: MAX_STREAM_APPEND_BYTES,
                    }
                })?;
            }
            ArtifactStreamFormat::JsonLines => {
                serde_json::to_writer(&mut output, value).map_err(|_| {
                    ArtifactError::ValueTooLarge {
                        bytes: MAX_STREAM_APPEND_BYTES.saturating_add(1),
                        limit: MAX_STREAM_APPEND_BYTES,
                    }
                })?;
                output.push_byte(b'\n')?;
            }
        }
    }
    Ok(output.into_inner())
}

struct BoundedBuffer {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedBuffer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(16 * 1024)),
            limit,
        }
    }

    fn push_byte(&mut self, byte: u8) -> Result<(), ArtifactError> {
        if self.bytes.len() == self.limit {
            return Err(ArtifactError::ValueTooLarge {
                bytes: self.limit.saturating_add(1),
                limit: self.limit,
            });
        }
        self.bytes.push(byte);
        Ok(())
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl io::Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "stream append bound",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn ensure_store_ready(root: &Path, state: &mut StoreState) -> Result<(), ArtifactError> {
    ensure_store_root_ready(root, state)?;
    let mut first_error = retry_pending_stage_cleanup(state).err();
    if let Err(error) = retry_pending_stream_cleanup(state)
        && first_error.is_none()
    {
        first_error = Some(error);
    }
    first_error.map_or(Ok(()), Err)
}

fn ensure_store_root_ready(root: &Path, state: &mut StoreState) -> Result<(), ArtifactError> {
    if let Some(expected) = state.root_identity {
        let metadata = fs::symlink_metadata(root).map_err(|_| ArtifactError::Unavailable)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || file_identity(&metadata)? != expected
        {
            return Err(ArtifactError::UnsafeRoot);
        }
        validate_private_owned_directory(&metadata, ArtifactError::UnsafeRoot)?;
        let held_lock = state.root_lock.as_ref().ok_or(ArtifactError::UnsafeRoot)?;
        let held_identity = file_identity(
            &held_lock
                .metadata()
                .map_err(|_| ArtifactError::Unavailable)?,
        )?;
        let lock_path = root.join(ROOT_LOCK_FILE);
        let lock_metadata =
            fs::symlink_metadata(&lock_path).map_err(|_| ArtifactError::UnsafeRoot)?;
        validate_private_owned_file(&lock_metadata, ArtifactError::UnsafeRoot)?;
        if file_identity(&lock_metadata)? != held_identity
            || fs::read(lock_path).map_err(|_| ArtifactError::Unavailable)? != ROOT_LOCK_CONTENT
        {
            return Err(ArtifactError::UnsafeRoot);
        }
        return Ok(());
    }
    prepare_dedicated_root(root)?;
    validate_root_shape(root)?;
    let lock = open_root_lock(&root.join(ROOT_LOCK_FILE))?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => return Err(ArtifactError::RootInUse),
        Err(fs::TryLockError::Error(_)) => return Err(ArtifactError::Unavailable),
    }
    validate_root_shape(root)?;
    scavenge_staging_files(root)?;
    let metadata = fs::symlink_metadata(root).map_err(|_| ArtifactError::Unavailable)?;
    let identity = file_identity(&metadata)?;
    state.root_lock = Some(lock);
    state.root_identity = Some(identity);
    Ok(())
}

fn retry_pending_stream_cleanup(state: &mut StoreState) -> Result<(), ArtifactError> {
    let stream_ids = state
        .streams
        .iter()
        .filter(|(_, stream)| stream.cleanup_pending)
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    let mut first_error = None;
    for stream_id in stream_ids {
        let Some(stream) = state.streams.remove(&stream_id) else {
            continue;
        };
        let path = stream.staging_path.clone();
        let identity = stream.identity;
        match remove_exact_file(&path, identity) {
            Ok(()) => drop(stream),
            Err(error) => {
                state.streams.insert(stream_id, stream);
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn retry_pending_stage_cleanup(state: &mut StoreState) -> Result<(), ArtifactError> {
    let destinations = state
        .reservations
        .iter()
        .filter(|(_, reservation)| reservation.cleanup_pending)
        .map(|(destination, _)| destination.clone())
        .collect::<Vec<_>>();
    let mut first_error = None;
    for destination in destinations {
        let Some(reservation) = state.reservations.remove(&destination) else {
            continue;
        };
        let mut cleanup_error = None;
        for path in [destination.as_path(), reservation.staging_path.as_path()] {
            if let Err(error) = remove_exact_file(path, reservation.identity)
                && cleanup_error.is_none()
            {
                cleanup_error = Some(error);
            }
        }
        if cleanup_error.is_none()
            && let Some(namespace_path) = destination.parent()
            && let Err(error) = remove_directory_if_empty(namespace_path)
        {
            cleanup_error = Some(error);
        }
        if let Some(error) = cleanup_error {
            state.reservations.insert(destination, reservation);
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn prepare_dedicated_root(root: &Path) -> Result<(), ArtifactError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(ArtifactError::UnsafeRoot);
        }
        Ok(metadata) => validate_private_owned_directory(&metadata, ArtifactError::UnsafeRoot)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = root.parent().ok_or(ArtifactError::InvalidRoot)?;
            fs::create_dir_all(parent).map_err(|_| ArtifactError::Unavailable)?;
            match create_private_directory(root) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(ArtifactError::Unavailable),
            }
            let metadata = fs::symlink_metadata(root).map_err(|_| ArtifactError::Unavailable)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(ArtifactError::UnsafeRoot);
            }
            validate_private_owned_directory(&metadata, ArtifactError::UnsafeRoot)?;
        }
        Err(_) => return Err(ArtifactError::Unavailable),
    }
    Ok(())
}

fn validate_root_shape(root: &Path) -> Result<(), ArtifactError> {
    let mut saw_lock = false;
    let mut saw_namespace = false;
    for entry in fs::read_dir(root).map_err(|_| ArtifactError::Unavailable)? {
        let entry = entry.map_err(|_| ArtifactError::Unavailable)?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or(ArtifactError::UnsafeRoot)?
            .to_owned();
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|_| ArtifactError::Unavailable)?;
        if name == ROOT_LOCK_FILE {
            validate_private_owned_file(&metadata, ArtifactError::UnsafeRoot)?;
            if fs::read(entry.path()).map_err(|_| ArtifactError::Unavailable)? != ROOT_LOCK_CONTENT
            {
                return Err(ArtifactError::UnsafeRoot);
            }
            saw_lock = true;
            continue;
        }
        saw_namespace = true;
        validate_namespace_name(&name)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ArtifactError::UnsafeNamespace);
        }
        validate_private_owned_directory(&metadata, ArtifactError::UnsafeNamespace)?;
        let _ = scan_namespace(&entry.path())?;
    }
    if saw_namespace && !saw_lock {
        return Err(ArtifactError::UnsafeRoot);
    }
    Ok(())
}

fn scavenge_staging_files(root: &Path) -> Result<(), ArtifactError> {
    for entry in fs::read_dir(root).map_err(|_| ArtifactError::Unavailable)? {
        let entry = entry.map_err(|_| ArtifactError::Unavailable)?;
        if entry.file_name() == ROOT_LOCK_FILE {
            continue;
        }
        for artifact in fs::read_dir(entry.path()).map_err(|_| ArtifactError::Unavailable)? {
            let artifact = artifact.map_err(|_| ArtifactError::Unavailable)?;
            let name = artifact
                .file_name()
                .to_str()
                .ok_or(ArtifactError::UnsafeDestination)?
                .to_owned();
            if name.starts_with(".tmp_") {
                validate_temporary_name(&name)?;
                let metadata = fs::symlink_metadata(artifact.path())
                    .map_err(|_| ArtifactError::Unavailable)?;
                validate_private_owned_file(&metadata, ArtifactError::UnsafeDestination)?;
                fs::remove_file(artifact.path()).map_err(|_| ArtifactError::Unavailable)?;
            }
        }
        remove_directory_if_empty(&entry.path())?;
    }
    Ok(())
}

fn scan_root(root: &Path, namespace: &ArtifactNamespace) -> Result<RootSnapshot, ArtifactError> {
    validate_namespace_name(namespace.as_str())?;
    let mut root_usage = Usage::default();
    let mut context_usage = Usage::default();
    let mut namespace_exists = false;
    let entries = fs::read_dir(root).map_err(|_| ArtifactError::Unavailable)?;
    for entry in entries {
        let entry = entry.map_err(|_| ArtifactError::Unavailable)?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or(ArtifactError::UnsafeNamespace)?
            .to_owned();
        if name == ROOT_LOCK_FILE {
            continue;
        }
        validate_namespace_name(&name)?;
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|_| ArtifactError::Unavailable)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ArtifactError::UnsafeNamespace);
        }
        let usage = scan_namespace(&entry.path())?;
        root_usage.files = root_usage.files.saturating_add(usage.files);
        root_usage.bytes = root_usage.bytes.saturating_add(usage.bytes);
        if name == namespace.as_str() {
            namespace_exists = true;
            context_usage = usage;
        }
    }
    Ok(RootSnapshot {
        root: root_usage,
        context: context_usage,
        namespace_exists,
    })
}

fn scan_namespace(path: &Path) -> Result<Usage, ArtifactError> {
    validate_namespace_path(path)?;
    let mut usage = Usage::default();
    for entry in fs::read_dir(path).map_err(|_| ArtifactError::Unavailable)? {
        let entry = entry.map_err(|_| ArtifactError::Unavailable)?;
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|_| ArtifactError::Unavailable)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ArtifactError::UnsafeDestination);
        }
        validate_private_owned_file(&metadata, ArtifactError::UnsafeDestination)?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or(ArtifactError::UnsafeDestination)?
            .to_owned();
        if name.starts_with(".tmp_") {
            validate_temporary_name(&name)?;
        } else {
            validate_stored_file_name(&name).map_err(|_| ArtifactError::UnsafeDestination)?;
        }
        usage.files = usage.files.saturating_add(1);
        let bytes = usize::try_from(metadata.len()).map_err(|_| ArtifactError::RootCapacity)?;
        usage.bytes = usage.bytes.saturating_add(bytes);
    }
    Ok(usage)
}

fn validate_namespace_path(path: &Path) -> Result<(), ArtifactError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            ArtifactError::UnsafeNamespace
        } else {
            ArtifactError::Unavailable
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ArtifactError::UnsafeNamespace);
    }
    validate_private_owned_directory(&metadata, ArtifactError::UnsafeNamespace)
}

fn validate_namespace_name(name: &str) -> Result<(), ArtifactError> {
    let suffix = name
        .strip_prefix(NAMESPACE_PREFIX)
        .ok_or(ArtifactError::UnsafeNamespace)?;
    if suffix.len() != NAMESPACE_RANDOM_BYTES * 2
        || suffix
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ArtifactError::UnsafeNamespace);
    }
    Ok(())
}

fn validate_file_name(file_name: &str) -> Result<(), ArtifactError> {
    let (compression, format) = validate_stored_file_name(file_name)?;
    if compression != ArtifactCompression::Identity || format != ArtifactStreamFormat::JsonArray {
        return Err(ArtifactError::InvalidFileName);
    }
    Ok(())
}

fn validate_stream_file_name(
    file_name: &str,
    compression: ArtifactCompression,
    format: ArtifactStreamFormat,
) -> Result<(), ArtifactError> {
    let (actual_compression, actual_format) = validate_stored_file_name(file_name)?;
    if actual_compression != compression || actual_format != format {
        return Err(ArtifactError::InvalidFileName);
    }
    Ok(())
}

fn infer_stream_format(
    file_name: &str,
    compression: ArtifactCompression,
) -> Result<ArtifactStreamFormat, ArtifactError> {
    let (actual_compression, format) = validate_stored_file_name(file_name)?;
    if actual_compression != compression {
        return Err(ArtifactError::InvalidFileName);
    }
    Ok(format)
}

fn validate_stored_file_name(
    file_name: &str,
) -> Result<(ArtifactCompression, ArtifactStreamFormat), ArtifactError> {
    if file_name.is_empty() || file_name.len() > MAX_FILE_NAME_BYTES || !file_name.is_ascii() {
        return Err(ArtifactError::InvalidFileName);
    }
    let (compression, suffix) = if let Some(stem) = file_name.strip_suffix(".json.lz4") {
        (ArtifactCompression::Lz4Frame, (stem, ".json"))
    } else if let Some(stem) = file_name.strip_suffix(".jsonl.lz4") {
        (ArtifactCompression::Lz4Frame, (stem, ".jsonl"))
    } else if let Some(stem) = file_name.strip_suffix(".json") {
        (ArtifactCompression::Identity, (stem, ".json"))
    } else if let Some(stem) = file_name.strip_suffix(".jsonl") {
        (ArtifactCompression::Identity, (stem, ".jsonl"))
    } else {
        return Err(ArtifactError::InvalidFileName);
    };
    if suffix.0.is_empty()
        || suffix
            .0
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_'))
    {
        return Err(ArtifactError::InvalidFileName);
    }
    let format = if suffix.1 == ".json" {
        ArtifactStreamFormat::JsonArray
    } else {
        ArtifactStreamFormat::JsonLines
    };
    Ok((compression, format))
}

fn validate_temporary_name(file_name: &str) -> Result<(), ArtifactError> {
    let suffix = file_name
        .strip_prefix(".tmp_")
        .ok_or(ArtifactError::ReceiptMismatch)?;
    if suffix.len() != NAMESPACE_RANDOM_BYTES * 2
        || suffix
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ArtifactError::ReceiptMismatch);
    }
    Ok(())
}

fn file_identity_if_regular(path: &Path) -> Result<Option<FileIdentity>, ArtifactError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ArtifactError::Unavailable),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ArtifactError::UnsafeDestination);
    }
    Ok(Some(file_identity(&metadata)?))
}

fn require_exact_artifact(path: &Path, stage: &ArtifactStage) -> Result<(), ArtifactError> {
    let (bytes, sha256) = hash_exact_file(path, stage.identity)?;
    if bytes != stage.receipt.bytes || sha256 != stage.receipt.sha256 {
        return Err(ArtifactError::ReceiptMismatch);
    }
    Ok(())
}

fn hash_exact_file(path: &Path, identity: FileIdentity) -> Result<(usize, String), ArtifactError> {
    let mut file = open_private_read(path)?;
    let metadata = file.metadata().map_err(|_| ArtifactError::Unavailable)?;
    validate_private_owned_file(&metadata, ArtifactError::UnsafeDestination)?;
    if file_identity(&metadata)? != identity {
        return Err(ArtifactError::ReceiptMismatch);
    }

    let mut digest = Sha256::new();
    let mut bytes = 0_usize;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| ArtifactError::Unavailable)?;
        if read == 0 {
            break;
        }
        bytes = bytes.checked_add(read).ok_or(ArtifactError::RootCapacity)?;
        digest.update(&buffer[..read]);
    }
    if file_identity(&file.metadata().map_err(|_| ArtifactError::Unavailable)?)? != identity
        || file_identity_if_regular(path)? != Some(identity)
    {
        return Err(ArtifactError::ReceiptMismatch);
    }
    Ok((bytes, hex_digest(digest.finalize())))
}

fn remove_exact_file(path: &Path, identity: FileIdentity) -> Result<(), ArtifactError> {
    match file_identity_if_regular(path)? {
        Some(actual) if actual == identity => {
            fs::remove_file(path).map_err(|_| ArtifactError::Unavailable)?;
        }
        Some(_) => return Err(ArtifactError::ReceiptMismatch),
        None => {}
    }
    Ok(())
}

fn discard_exact_files(stages: &[ArtifactStage]) -> Result<(), ArtifactError> {
    let mut first_error = None;
    for stage in stages {
        for path in [stage.receipt.path(), stage.staging_path.as_path()] {
            if let Err(error) = remove_exact_file(path, stage.identity)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn remove_directory_if_empty(path: &Path) -> Result<(), ArtifactError> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::DirectoryNotEmpty => Ok(()),
        Err(_) => Err(ArtifactError::Unavailable),
    }
}

fn sync_directory(path: &Path) -> Result<(), ArtifactError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ArtifactError::Unavailable)
}

#[cfg(unix)]
fn file_identity(metadata: &fs::Metadata) -> Result<FileIdentity, ArtifactError> {
    use std::os::unix::fs::MetadataExt as _;

    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn file_identity(_metadata: &fs::Metadata) -> Result<FileIdentity, ArtifactError> {
    // Exact rollback ownership is part of the safety boundary. Add the
    // platform's stable volume/file identity before enabling artifacts there.
    Err(ArtifactError::UnsupportedPlatform)
}

#[cfg(unix)]
fn validate_private_owned_directory(
    metadata: &fs::Metadata,
    error: ArtifactError,
) -> Result<(), ArtifactError> {
    use std::os::unix::fs::PermissionsExt as _;

    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(error);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_owned_directory(
    metadata: &fs::Metadata,
    error: ArtifactError,
) -> Result<(), ArtifactError> {
    if !metadata.is_dir() {
        return Err(error);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_owned_file(
    metadata: &fs::Metadata,
    error: ArtifactError,
) -> Result<(), ArtifactError> {
    use std::os::unix::fs::PermissionsExt as _;

    if !metadata.is_file() || metadata.permissions().mode() & 0o177 != 0 {
        return Err(error);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_owned_file(
    metadata: &fs::Metadata,
    error: ArtifactError,
) -> Result<(), ArtifactError> {
    if !metadata.is_file() {
        return Err(error);
    }
    Ok(())
}

#[cfg(unix)]
fn open_root_lock(path: &Path) -> Result<File, ArtifactError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ArtifactError::Unavailable)?;
    validate_private_owned_file(
        &file.metadata().map_err(|_| ArtifactError::Unavailable)?,
        ArtifactError::UnsafeRoot,
    )?;
    initialize_or_validate_lock_file(&mut file)?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_root_lock(path: &Path) -> Result<File, ArtifactError> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .map_err(|_| ArtifactError::Unavailable)?;
    validate_private_owned_file(
        &file.metadata().map_err(|_| ArtifactError::Unavailable)?,
        ArtifactError::UnsafeRoot,
    )?;
    initialize_or_validate_lock_file(&mut file)?;
    Ok(file)
}

fn initialize_or_validate_lock_file(file: &mut File) -> Result<(), ArtifactError> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let mut contents = Vec::new();
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.read_to_end(&mut contents))
        .map_err(|_| ArtifactError::Unavailable)?;
    if contents.is_empty() {
        file.seek(SeekFrom::Start(0))
            .and_then(|_| file.write_all(ROOT_LOCK_CONTENT))
            .and_then(|_| file.sync_all())
            .map_err(|_| ArtifactError::Unavailable)?;
    } else if contents != ROOT_LOCK_CONTENT {
        return Err(ArtifactError::UnsafeRoot);
    }
    Ok(())
}

fn reject_existing_destination(path: &Path) -> Result<(), ArtifactError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(ArtifactError::UnsafeDestination)
        }
        Ok(_) => Err(ArtifactError::DestinationExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ArtifactError::Unavailable),
    }
}

fn unique_temporary_path(namespace: &Path) -> Result<PathBuf, ArtifactError> {
    for _ in 0..4 {
        let path = namespace.join(random_name(".tmp_")?);
        if !path.exists() {
            return Ok(path);
        }
    }
    Err(ArtifactError::RandomId)
}

fn random_name(prefix: &str) -> Result<String, ArtifactError> {
    let mut bytes = [0_u8; NAMESPACE_RANDOM_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| ArtifactError::RandomId)?;
    let mut name = String::with_capacity(prefix.len() + bytes.len() * 2);
    name.push_str(prefix);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(name, "{byte:02x}").expect("writing to a string cannot fail");
    }
    Ok(name)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_digest(Sha256::digest(bytes))
}

fn hex_digest(digest: impl AsRef<[u8]>) -> String {
    let digest = digest.as_ref();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    encoded
}

struct TemporaryArtifact {
    path: Option<PathBuf>,
    file: Option<File>,
}

impl TemporaryArtifact {
    fn create(path: PathBuf) -> Result<Self, ArtifactError> {
        let file = open_private_new(&path)?;
        Ok(Self {
            path: Some(path),
            file: Some(file),
        })
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), ArtifactError> {
        let file = self.file.as_mut().ok_or(ArtifactError::Unavailable)?;
        file.write_all(bytes)
            .map_err(|_| ArtifactError::Unavailable)?;
        file.sync_all().map_err(|_| ArtifactError::Unavailable)
    }

    fn retain(mut self) -> Result<(PathBuf, FileIdentity), ArtifactError> {
        let file = self.file.take().ok_or(ArtifactError::Unavailable)?;
        let identity = file_identity(&file.metadata().map_err(|_| ArtifactError::Unavailable)?)?;
        drop(file);
        Ok((
            self.path.take().expect("temporary artifact has a path"),
            identity,
        ))
    }
}

impl Drop for TemporaryArtifact {
    fn drop(&mut self) {
        self.file.take();
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir(path)
}

#[cfg(unix)]
fn open_private_new(path: &Path) -> Result<File, ArtifactError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ArtifactError::Unavailable)
}

#[cfg(unix)]
fn open_private_read(path: &Path) -> Result<File, ArtifactError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ArtifactError::Unavailable)
}

#[cfg(not(unix))]
fn open_private_read(_path: &Path) -> Result<File, ArtifactError> {
    Err(ArtifactError::UnsupportedPlatform)
}

#[cfg(not(unix))]
fn open_private_new(path: &Path) -> Result<File, ArtifactError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| ArtifactError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn limits(
        max_artifact_bytes: usize,
        max_context_files: usize,
        max_context_bytes: usize,
        max_root_files: usize,
        max_root_bytes: usize,
    ) -> ArtifactStoreLimits {
        ArtifactStoreLimits::new(
            max_artifact_bytes,
            max_context_files,
            max_context_bytes,
            max_root_files,
            max_root_bytes,
        )
    }

    #[test]
    fn roots_and_limits_are_closed_and_cannot_widen_production_bounds() {
        assert_eq!(
            FileArtifactStore::new("relative/artifacts").expect_err("relative root"),
            ArtifactError::InvalidRoot
        );
        for invalid in [
            limits(0, 1, 1, 1, 1),
            limits(DEFAULT_MAX_ARTIFACT_BYTES + 1, 1, 1, 1, 1),
            limits(8, 0, 8, 1, 8),
            limits(8, 2, 8, 1, 8),
            limits(8, 1, 7, 1, 8),
            limits(8, 1, 9, 1, 8),
        ] {
            assert_eq!(
                FileArtifactStore::with_limits(PathBuf::from("/tmp/artifacts"), invalid)
                    .expect_err("invalid limits"),
                ArtifactError::InvalidLimits
            );
        }
    }

    #[tokio::test]
    async fn writes_compact_private_create_only_json_and_rolls_back_exact_receipt() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().join("artifacts");
        let store = FileArtifactStore::new(&root).expect("artifact store");
        let namespace = store.allocate_namespace().expect("namespace");
        let value = json!({"z": [1, 2], "secret": "customer-data"});

        let receipt = store
            .write_json(
                namespace.clone(),
                "query-result.json".to_owned(),
                value.clone(),
            )
            .await
            .expect("write artifact");
        let mut expected = serde_json::to_vec(&value).expect("expected compact JSON");
        expected.push(b'\n');
        assert_eq!(fs::read(receipt.path()).expect("artifact bytes"), expected);
        assert_eq!(receipt.bytes(), expected.len());
        assert_eq!(receipt.sha256(), sha256_hex(&expected));
        assert_eq!(receipt.media_type(), JSON_MEDIA_TYPE);
        assert_eq!(receipt.sensitivity(), CUSTOMER_DATA_SENSITIVITY);
        assert_eq!(
            receipt.path().parent(),
            Some(root.join(namespace.as_str()).as_path())
        );
        assert_eq!(
            serde_json::to_value(&receipt).expect("receipt JSON"),
            json!({
                "path": receipt.path(),
                "bytes": expected.len(),
                "sha256": sha256_hex(&expected),
                "logicalBytes": expected.len(),
                "mediaType": "application/json",
                "sensitivity": "customerData",
            })
        );
        assert!(!format!("{receipt:?}").contains(receipt.path().to_string_lossy().as_ref()));
        assert!(!format!("{store:?}").contains(root.to_string_lossy().as_ref()));

        assert_eq!(
            store
                .write_json(
                    namespace.clone(),
                    "query-result.json".to_owned(),
                    json!({"replacement": true}),
                )
                .await
                .expect_err("create only"),
            ArtifactError::DestinationExists
        );
        assert_eq!(
            fs::read(receipt.path()).expect("original retained"),
            expected
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            assert_eq!(
                fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(root.join(namespace.as_str()))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(receipt.path()).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        drop(store.clone());
        assert!(
            receipt.path().is_file(),
            "context/store drops do not delete artifacts"
        );
        let stage = store
            .stage_prepared(
                namespace.clone(),
                store
                    .prepare_json("rollback.json".to_owned(), json!({"temporary": true}))
                    .unwrap(),
            )
            .await
            .expect("stage rollback candidate");
        assert!(!stage.receipt().path().exists());
        let other_namespace = store.allocate_namespace().expect("other namespace");
        let other_stage = stage.clone();
        store
            .discard_staged(namespace, vec![stage])
            .await
            .expect("exact rollback");
        assert_eq!(
            store
                .discard_staged(other_namespace, vec![other_stage])
                .await
                .expect_err("stage cannot become an arbitrary delete"),
            ArtifactError::UnsafeNamespace
        );
        assert!(receipt.path().exists());
    }

    #[tokio::test]
    async fn namespaces_are_random_and_isolate_caller_file_names() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = FileArtifactStore::new(directory.path().join("artifacts")).unwrap();
        let first = store.allocate_namespace().unwrap();
        let second = store.allocate_namespace().unwrap();
        assert_ne!(first, second);
        assert!(!format!("{first:?}").contains(first.as_str()));

        let first_receipt = store
            .write_json(first.clone(), "result.json".to_owned(), json!({"owner": 1}))
            .await
            .unwrap();
        let second_receipt = store
            .write_json(
                second.clone(),
                "result.json".to_owned(),
                json!({"owner": 2}),
            )
            .await
            .unwrap();
        assert_ne!(first_receipt.path(), second_receipt.path());
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(first_receipt.path()).unwrap()).unwrap(),
            json!({"owner": 1})
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(second_receipt.path()).unwrap()).unwrap(),
            json!({"owner": 2})
        );
    }

    #[tokio::test]
    async fn file_names_and_per_file_size_fail_before_filesystem_creation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().join("artifacts");
        let store = FileArtifactStore::with_limits(&root, limits(32, 2, 64, 4, 128)).unwrap();
        let namespace = store.allocate_namespace().unwrap();
        for invalid in [
            "",
            ".json",
            "result",
            "result.JSON",
            "../result.json",
            "nested/result.json",
            "a.b.json",
            "résultat.json",
        ] {
            assert_eq!(
                store
                    .write_json(namespace.clone(), invalid.to_owned(), json!(null))
                    .await
                    .expect_err("invalid filename"),
                ArtifactError::InvalidFileName,
                "{invalid}"
            );
        }
        assert_eq!(
            store
                .write_json(namespace, "large.json".to_owned(), json!("x".repeat(32)),)
                .await
                .expect_err("file bound"),
            ArtifactError::ValueTooLarge {
                bytes: 35,
                limit: 32,
            }
        );
        assert!(
            !root.exists(),
            "validation must precede filesystem mutation"
        );
    }

    #[tokio::test]
    async fn context_and_root_file_quotas_are_independent() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = FileArtifactStore::with_limits(
            directory.path().join("artifacts"),
            limits(32, 2, 64, 3, 128),
        )
        .unwrap();
        let first = store.allocate_namespace().unwrap();
        for name in ["one.json", "two.json"] {
            store
                .write_json(first.clone(), name.to_owned(), json!({"ok": true}))
                .await
                .unwrap();
        }
        assert_eq!(
            store
                .write_json(first, "three.json".to_owned(), json!(null))
                .await
                .expect_err("context file cap"),
            ArtifactError::ContextCapacity
        );

        let second = store.allocate_namespace().unwrap();
        store
            .write_json(second, "three.json".to_owned(), json!(null))
            .await
            .unwrap();
        let third = store.allocate_namespace().unwrap();
        assert_eq!(
            store
                .write_json(third, "four.json".to_owned(), json!(null))
                .await
                .expect_err("root file cap"),
            ArtifactError::RootCapacity
        );
    }

    #[tokio::test]
    async fn context_and_root_byte_quotas_are_independent() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let context_store = FileArtifactStore::with_limits(
            directory.path().join("context-artifacts"),
            limits(16, 4, 16, 8, 64),
        )
        .unwrap();
        let namespace = context_store.allocate_namespace().unwrap();
        context_store
            .write_json(namespace.clone(), "one.json".to_owned(), json!({"a": 1}))
            .await
            .unwrap();
        context_store
            .write_json(namespace.clone(), "two.json".to_owned(), json!({"a": 2}))
            .await
            .unwrap();
        assert_eq!(
            context_store
                .write_json(namespace, "three.json".to_owned(), json!(null))
                .await
                .expect_err("context byte cap"),
            ArtifactError::ContextCapacity
        );

        let root_store = FileArtifactStore::with_limits(
            directory.path().join("root-artifacts"),
            limits(16, 4, 16, 8, 20),
        )
        .unwrap();
        for index in 0..2 {
            root_store
                .write_json(
                    root_store.allocate_namespace().unwrap(),
                    format!("{index}.json"),
                    json!({"a": index}),
                )
                .await
                .unwrap();
        }
        assert_eq!(
            root_store
                .write_json(
                    root_store.allocate_namespace().unwrap(),
                    "last.json".to_owned(),
                    json!({"a": 3}),
                )
                .await
                .expect_err("root byte cap"),
            ArtifactError::RootCapacity
        );
    }

    #[tokio::test]
    async fn concurrent_writes_publish_only_complete_unique_files() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = FileArtifactStore::new(directory.path().join("artifacts")).unwrap();
        let namespace = store.allocate_namespace().unwrap();
        let writes = (0..8).map(|index| {
            let store = store.clone();
            let namespace = namespace.clone();
            tokio::spawn(async move {
                store
                    .write_json(
                        namespace,
                        format!("result_{index}.json"),
                        json!({"index": index, "padding": "x".repeat(100)}),
                    )
                    .await
            })
        });
        let mut paths = std::collections::HashSet::new();
        for write in writes {
            let receipt = write.await.unwrap().unwrap();
            assert!(paths.insert(receipt.path().to_owned()));
            let bytes = fs::read(receipt.path()).unwrap();
            assert_eq!(bytes.last(), Some(&b'\n'));
            serde_json::from_slice::<Value>(&bytes).expect("complete JSON");
        }
        let namespace_path = store.root().join(namespace.as_str());
        assert_eq!(fs::read_dir(namespace_path).unwrap().count(), 8);
    }

    #[tokio::test]
    async fn stages_reserve_final_names_and_publish_only_on_commit() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = FileArtifactStore::new(directory.path().join("artifacts")).unwrap();
        let namespace = store.allocate_namespace().unwrap();
        store
            .commit_staged(namespace.clone(), Vec::new())
            .await
            .unwrap();
        assert!(
            store
                .inner
                .gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .root_lock
                .is_none()
        );
        let prepared = store
            .prepare_json("result.json".to_owned(), json!({"answer": 42}))
            .unwrap();
        let stage = store
            .stage_prepared(namespace.clone(), prepared.clone())
            .await
            .unwrap();
        assert!(!stage.receipt().path().exists());
        assert_eq!(
            store
                .stage_prepared(namespace.clone(), prepared)
                .await
                .expect_err("reserved destination"),
            ArtifactError::DestinationExists
        );

        store
            .commit_staged(namespace.clone(), vec![stage.clone()])
            .await
            .unwrap();
        let second = FileArtifactStore::new(directory.path().join("artifacts")).unwrap();
        assert_eq!(
            second
                .write_json(
                    second.allocate_namespace().unwrap(),
                    "blocked.json".to_owned(),
                    json!(null),
                )
                .await
                .expect_err("published stage still owns rollback boundary"),
            ArtifactError::RootInUse
        );
        store
            .finalize_staged(&namespace, std::slice::from_ref(&stage))
            .unwrap();
        second
            .write_json(
                second.allocate_namespace().unwrap(),
                "accepted.json".to_owned(),
                json!(null),
            )
            .await
            .expect("finalized stage releases root");
        assert!(stage.receipt().path().is_file());
        assert!(!stage.staging_path.exists());
        assert_eq!(
            store
                .discard_staged(namespace, vec![stage.clone()])
                .await
                .expect_err("finalized ticket cannot delete a durable artifact"),
            ArtifactError::ReceiptMismatch
        );
        assert!(stage.receipt().path().is_file());
    }

    #[tokio::test]
    async fn finalize_rejects_a_replaced_published_file_and_retains_ownership() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().join("artifacts");
        let store = FileArtifactStore::new(&root).unwrap();
        let namespace = store.allocate_namespace().unwrap();
        let stage = store
            .stage_prepared(
                namespace.clone(),
                store
                    .prepare_json("result.json".to_owned(), json!({"answer": 42}))
                    .unwrap(),
            )
            .await
            .unwrap();
        store
            .commit_staged(namespace.clone(), vec![stage.clone()])
            .await
            .unwrap();

        let bytes = fs::read(stage.receipt().path()).unwrap();
        fs::remove_file(stage.receipt().path()).unwrap();
        let mut replacement = open_private_new(stage.receipt().path()).unwrap();
        replacement.write_all(&bytes).unwrap();
        replacement.sync_all().unwrap();
        drop(replacement);

        assert_eq!(
            store
                .finalize_staged(&namespace, std::slice::from_ref(&stage))
                .expect_err("replaced published file"),
            ArtifactError::ReceiptMismatch
        );
        let second = FileArtifactStore::new(&root).unwrap();
        assert_eq!(
            second
                .write_json(
                    second.allocate_namespace().unwrap(),
                    "blocked.json".to_owned(),
                    json!(null),
                )
                .await
                .expect_err("failed finalize retains the root lock"),
            ArtifactError::RootInUse
        );
        assert_eq!(fs::read(stage.receipt().path()).unwrap(), bytes);
    }

    #[tokio::test]
    async fn root_lock_serializes_store_processes_and_stale_stages_are_scavenged() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().join("artifacts");
        let first = FileArtifactStore::new(&root).unwrap();
        let first_namespace = first.allocate_namespace().unwrap();
        let abandoned = first
            .stage_prepared(
                first_namespace,
                first
                    .prepare_json("abandoned.json".to_owned(), json!(null))
                    .unwrap(),
            )
            .await
            .unwrap();
        let second = FileArtifactStore::new(&root).unwrap();
        assert_eq!(
            second
                .write_json(
                    second.allocate_namespace().unwrap(),
                    "blocked.json".to_owned(),
                    json!(null),
                )
                .await
                .expect_err("root lock"),
            ArtifactError::RootInUse
        );

        drop(first);
        let receipt = second
            .write_json(
                second.allocate_namespace().unwrap(),
                "accepted.json".to_owned(),
                json!(null),
            )
            .await
            .expect("lock released");
        assert!(receipt.path().is_file());
        assert!(!abandoned.staging_path.exists());
        assert!(!abandoned.receipt().path().exists());
    }

    #[tokio::test]
    async fn resolving_the_last_stage_releases_the_root_for_another_store() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().join("artifacts");
        let first = FileArtifactStore::new(&root).unwrap();
        let first_namespace = first.allocate_namespace().unwrap();
        let stage = first
            .stage_prepared(
                first_namespace.clone(),
                first
                    .prepare_json("temporary.json".to_owned(), json!(null))
                    .unwrap(),
            )
            .await
            .unwrap();
        let second = FileArtifactStore::new(&root).unwrap();
        assert_eq!(
            second
                .write_json(
                    second.allocate_namespace().unwrap(),
                    "blocked.json".to_owned(),
                    json!(null),
                )
                .await
                .expect_err("active transaction owns root"),
            ArtifactError::RootInUse
        );

        first
            .discard_staged(first_namespace, vec![stage])
            .await
            .unwrap();
        let receipt = second
            .write_json(
                second.allocate_namespace().unwrap(),
                "accepted.json".to_owned(),
                json!(null),
            )
            .await
            .expect("resolved transaction releases root");
        assert!(receipt.path().is_file());
        drop(first);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unsafe_existing_root_is_rejected_without_mutation() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().join("not-an-artifact-root");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let sentinel = root.join("sentinel.txt");
        fs::write(&sentinel, b"keep me").unwrap();
        let store = FileArtifactStore::new(&root).unwrap();

        assert_eq!(
            store
                .write_json(
                    store.allocate_namespace().unwrap(),
                    "result.json".to_owned(),
                    json!(null),
                )
                .await
                .expect_err("unsafe root"),
            ArtifactError::UnsafeRoot
        );
        assert_eq!(fs::read(&sentinel).unwrap(), b"keep me");
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert!(!root.join(ROOT_LOCK_FILE).exists());
    }

    #[tokio::test]
    async fn same_content_collision_is_not_owned_or_deleted() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = FileArtifactStore::new(directory.path().join("artifacts")).unwrap();
        let namespace = store.allocate_namespace().unwrap();
        let stage = store
            .stage_prepared(
                namespace.clone(),
                store
                    .prepare_json("result.json".to_owned(), json!({"same": true}))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = fs::read(&stage.staging_path).unwrap();
        let mut collision = open_private_new(stage.receipt().path()).unwrap();
        collision.write_all(&bytes).unwrap();
        collision.sync_all().unwrap();
        drop(collision);

        assert_eq!(
            store
                .commit_staged(namespace.clone(), vec![stage.clone()])
                .await
                .expect_err("different inode"),
            ArtifactError::DestinationExists
        );
        assert_eq!(
            store
                .discard_staged(namespace, vec![stage.clone()])
                .await
                .expect_err("collision is not owned"),
            ArtifactError::ReceiptMismatch
        );
        assert_eq!(fs::read(stage.receipt().path()).unwrap(), bytes);
        assert!(!stage.staging_path.exists());
    }

    #[tokio::test]
    async fn replacing_the_root_after_lock_is_fail_closed() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().join("artifacts");
        let moved = directory.path().join("moved-artifacts");
        let store = FileArtifactStore::new(&root).unwrap();
        let namespace = store.allocate_namespace().unwrap();
        let _pending = store
            .stage_prepared(
                namespace,
                store
                    .prepare_json("first.json".to_owned(), json!(null))
                    .unwrap(),
            )
            .await
            .unwrap();
        fs::rename(&root, &moved).unwrap();
        create_private_directory(&root).unwrap();

        assert_eq!(
            store
                .write_json(
                    store.allocate_namespace().unwrap(),
                    "second.json".to_owned(),
                    json!(null),
                )
                .await
                .expect_err("replaced root"),
            ArtifactError::UnsafeRoot
        );
        assert!(moved.join(ROOT_LOCK_FILE).is_file());
        assert!(fs::read_dir(&root).unwrap().next().is_none());
    }

    #[tokio::test]
    async fn replacing_the_lock_file_after_acquisition_is_fail_closed() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().join("artifacts");
        let store = FileArtifactStore::new(&root).unwrap();
        let namespace = store.allocate_namespace().unwrap();
        let _pending = store
            .stage_prepared(
                namespace,
                store
                    .prepare_json("first.json".to_owned(), json!(null))
                    .unwrap(),
            )
            .await
            .unwrap();
        let lock_path = root.join(ROOT_LOCK_FILE);
        fs::remove_file(&lock_path).unwrap();
        let mut replacement = open_private_new(&lock_path).unwrap();
        replacement.write_all(ROOT_LOCK_CONTENT).unwrap();
        replacement.sync_all().unwrap();
        drop(replacement);

        assert_eq!(
            store
                .write_json(
                    store.allocate_namespace().unwrap(),
                    "second.json".to_owned(),
                    json!(null),
                )
                .await
                .expect_err("replaced lock"),
            ArtifactError::UnsafeRoot
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symlink_and_nonregular_filesystem_shapes() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let real_root = directory.path().join("real-root");
        fs::create_dir(&real_root).unwrap();
        let linked_root = directory.path().join("linked-root");
        symlink(&real_root, &linked_root).unwrap();
        let linked_store = FileArtifactStore::new(&linked_root).unwrap();
        assert_eq!(
            linked_store
                .write_json(
                    linked_store.allocate_namespace().unwrap(),
                    "result.json".to_owned(),
                    json!(null),
                )
                .await
                .expect_err("symlink root"),
            ArtifactError::UnsafeRoot
        );

        let file_root = directory.path().join("file-root");
        fs::write(&file_root, b"not a directory").unwrap();
        let file_store = FileArtifactStore::new(&file_root).unwrap();
        assert_eq!(
            file_store
                .write_json(
                    file_store.allocate_namespace().unwrap(),
                    "result.json".to_owned(),
                    json!(null),
                )
                .await
                .expect_err("file root"),
            ArtifactError::UnsafeRoot
        );

        let namespace_root = directory.path().join("namespace-root");
        let namespace_store = FileArtifactStore::new(&namespace_root).unwrap();
        namespace_store
            .write_json(
                namespace_store.allocate_namespace().unwrap(),
                "seed.json".to_owned(),
                json!(null),
            )
            .await
            .unwrap();
        let namespace = namespace_store.allocate_namespace().unwrap();
        let target = directory.path().join("namespace-target");
        fs::create_dir(&target).unwrap();
        symlink(&target, namespace_root.join(namespace.as_str())).unwrap();
        assert_eq!(
            namespace_store
                .write_json(namespace, "result.json".to_owned(), json!(null),)
                .await
                .expect_err("symlink namespace"),
            ArtifactError::UnsafeNamespace
        );

        let destination_store = FileArtifactStore::new(directory.path().join("destination-root"))
            .expect("destination store");
        let namespace = destination_store.allocate_namespace().unwrap();
        let receipt = destination_store
            .write_json(namespace.clone(), "safe.json".to_owned(), json!(null))
            .await
            .unwrap();
        let external = directory.path().join("external.json");
        fs::write(&external, b"null\n").unwrap();
        symlink(
            &external,
            receipt.path().parent().unwrap().join("linked.json"),
        )
        .unwrap();
        assert_eq!(
            destination_store
                .write_json(namespace, "other.json".to_owned(), json!(null))
                .await
                .expect_err("symlink destination"),
            ArtifactError::UnsafeDestination
        );
        assert_eq!(fs::read(external).unwrap(), b"null\n");
    }

    #[tokio::test]
    async fn pending_stage_cleanup_recovers_without_ticket_and_rejects_other_namespaces() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = FileArtifactStore::new(directory.path().join("artifacts")).unwrap();
        let first = store.allocate_namespace().unwrap();
        let stage = store
            .stage_prepared(
                first.clone(),
                store
                    .prepare_json("result.json".to_owned(), json!({"a": 1}))
                    .unwrap(),
            )
            .await
            .unwrap();
        let original = fs::read(&stage.staging_path).unwrap();
        fs::remove_file(&stage.staging_path).unwrap();
        let mut replacement = open_private_new(&stage.staging_path).unwrap();
        replacement.write_all(&original).unwrap();
        replacement.sync_all().unwrap();
        drop(replacement);
        assert_eq!(
            store
                .discard_staged(first.clone(), vec![stage.clone()])
                .await
                .expect_err("changed inode"),
            ArtifactError::ReceiptMismatch
        );
        assert!(stage.staging_path.exists());
        let replaced_path = stage.staging_path.clone();
        drop(stage);

        let second = store.allocate_namespace().unwrap();
        assert_eq!(
            store
                .write_json(second.clone(), "blocked.json".to_owned(), json!(null))
                .await
                .expect_err("pending cleanup blocks later writes"),
            ArtifactError::ReceiptMismatch
        );
        assert!(replaced_path.exists());
        fs::remove_file(&replaced_path).unwrap();
        let second_receipt = store
            .write_json(second.clone(), "result.json".to_owned(), json!(null))
            .await
            .unwrap();

        let foreign_stage = store
            .stage_prepared(
                first.clone(),
                store
                    .prepare_json("foreign.json".to_owned(), json!(null))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .discard_staged(second, vec![foreign_stage.clone()])
                .await
                .expect_err("other namespace"),
            ArtifactError::ReceiptMismatch
        );
        assert!(second_receipt.path().exists());
        assert!(foreign_stage.staging_path.exists());
        store
            .discard_staged(first, vec![foreign_stage])
            .await
            .expect("wrong-namespace denial did not schedule cleanup");
    }

    #[tokio::test]
    async fn streams_write_compact_arrays_and_json_lines_with_trailing_newlines() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().join("artifacts");
        let store = FileArtifactStore::new(&root).expect("artifact store");

        let array_namespace = store.allocate_namespace().unwrap();
        let array_stream = store
            .begin_json_array(
                array_namespace.clone(),
                "array.json".to_owned(),
                ArtifactCompression::Identity,
            )
            .await
            .unwrap();
        assert_eq!(array_stream.format(), ArtifactStreamFormat::JsonArray);
        let array_stream = store
            .append_json_array(
                array_namespace.clone(),
                array_stream,
                vec![json!({"a": 1}), json!([2, 3])],
            )
            .await
            .unwrap();
        let array_stage = store
            .finish_json_array(array_namespace.clone(), array_stream)
            .await
            .unwrap();
        let array_receipt = array_stage.receipt().clone();
        store
            .commit_staged(array_namespace.clone(), vec![array_stage.clone()])
            .await
            .unwrap();
        store
            .finalize_staged(&array_namespace, std::slice::from_ref(&array_stage))
            .unwrap();
        assert_eq!(
            fs::read(array_receipt.path()).unwrap(),
            br#"[{"a":1},[2,3]]
"#
        );
        assert_eq!(array_receipt.logical_bytes(), array_receipt.bytes());
        assert_eq!(array_receipt.content_encoding(), None);
        assert_eq!(array_receipt.media_type(), JSON_MEDIA_TYPE);

        let lines_namespace = store.allocate_namespace().unwrap();
        let lines_stream = store
            .begin_json_array(
                lines_namespace.clone(),
                "rows.jsonl".to_owned(),
                ArtifactCompression::Identity,
            )
            .await
            .unwrap();
        assert_eq!(lines_stream.format(), ArtifactStreamFormat::JsonLines);
        let lines_stream = store
            .append_json_array(
                lines_namespace.clone(),
                lines_stream,
                vec![json!({"a": 1}), json!({"a": 2})],
            )
            .await
            .unwrap();
        let lines_stage = store
            .finish_json_array(lines_namespace.clone(), lines_stream)
            .await
            .unwrap();
        let lines_receipt = lines_stage.receipt().clone();
        store
            .commit_staged(lines_namespace.clone(), vec![lines_stage.clone()])
            .await
            .unwrap();
        store
            .finalize_staged(&lines_namespace, std::slice::from_ref(&lines_stage))
            .unwrap();
        assert_eq!(
            fs::read(lines_receipt.path()).unwrap(),
            br#"{"a":1}
{"a":2}
"#
        );
        assert_eq!(lines_receipt.logical_bytes(), lines_receipt.bytes());
        assert_eq!(lines_receipt.content_encoding(), None);
        assert_eq!(lines_receipt.media_type(), JSON_LINES_MEDIA_TYPE);

        let empty_namespace = store.allocate_namespace().unwrap();
        let empty_stream = store
            .begin_json_stream(
                empty_namespace.clone(),
                "empty.jsonl".to_owned(),
                ArtifactCompression::Identity,
                ArtifactStreamFormat::JsonLines,
            )
            .await
            .unwrap();
        let empty_stage = store
            .finish_json_array(empty_namespace.clone(), empty_stream)
            .await
            .unwrap();
        let empty_receipt = empty_stage.receipt().clone();
        store
            .commit_staged(empty_namespace.clone(), vec![empty_stage.clone()])
            .await
            .unwrap();
        store
            .finalize_staged(&empty_namespace, std::slice::from_ref(&empty_stage))
            .unwrap();
        assert_eq!(fs::read(empty_receipt.path()).unwrap(), b"");
        assert_eq!(empty_receipt.bytes(), 0);
        assert_eq!(empty_receipt.logical_bytes(), 0);
    }

    #[tokio::test]
    async fn lz4_streams_have_frame_output_and_stored_byte_receipts() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().join("artifacts");
        let store = FileArtifactStore::new(&root).expect("artifact store");
        let namespace = store.allocate_namespace().unwrap();
        let stream = store
            .begin_json_array(
                namespace.clone(),
                "result.json.lz4".to_owned(),
                ArtifactCompression::Lz4Frame,
            )
            .await
            .unwrap();
        assert_eq!(stream.compression(), ArtifactCompression::Lz4Frame);
        let stream = store
            .append_json_array(
                namespace.clone(),
                stream,
                vec![json!({"payload": "repeat-".repeat(10_000)})],
            )
            .await
            .unwrap();
        let stage = store
            .finish_json_array(namespace.clone(), stream)
            .await
            .unwrap();
        let receipt = stage.receipt().clone();
        assert_eq!(receipt.content_encoding(), Some("lz4"));
        assert!(receipt.logical_bytes() > receipt.bytes());
        store
            .commit_staged(namespace.clone(), vec![stage.clone()])
            .await
            .unwrap();
        store
            .finalize_staged(&namespace, std::slice::from_ref(&stage))
            .unwrap();
        let bytes = fs::read(receipt.path()).unwrap();
        assert_eq!(&bytes[..4], &[0x04, 0x22, 0x4d, 0x18]);
        assert_eq!(receipt.bytes(), bytes.len());
        assert_eq!(receipt.sha256(), sha256_hex(&bytes));
        assert_eq!(receipt.media_type(), JSON_MEDIA_TYPE);
        let mut decoded = Vec::new();
        lz4_flex::frame::FrameDecoder::new(bytes.as_slice())
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded.first(), Some(&b'['));
        assert_eq!(decoded.last(), Some(&b'\n'));
        assert_eq!(
            serde_json::to_value(&receipt).unwrap()["contentEncoding"],
            json!("lz4")
        );
    }

    #[tokio::test]
    async fn incomplete_streams_are_exactly_discarded_and_release_the_root() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().join("artifacts");
        let store = FileArtifactStore::new(&root).expect("artifact store");
        let namespace = store.allocate_namespace().unwrap();
        let stream = store
            .begin_json_array(
                namespace.clone(),
                "pending.json".to_owned(),
                ArtifactCompression::Identity,
            )
            .await
            .unwrap();
        let stream = store
            .append_json_array(namespace.clone(), stream, vec![json!({"ok": true})])
            .await
            .unwrap();
        let stream_copy = stream.clone();
        assert_eq!(
            store
                .discard_stream(store.allocate_namespace().unwrap(), stream_copy)
                .await
                .expect_err("wrong namespace"),
            ArtifactError::ReceiptMismatch
        );
        store.discard_stream(namespace, stream).await.unwrap();
        let second = FileArtifactStore::new(&root).expect("second store");
        let receipt = second
            .write_json(
                second.allocate_namespace().unwrap(),
                "accepted.json".to_owned(),
                json!(null),
            )
            .await
            .unwrap();
        assert!(receipt.path().exists());
        assert!(
            !root
                .read_dir()
                .unwrap()
                .flat_map(Result::ok)
                .flat_map(|entry| entry.path().read_dir().into_iter().flatten().flatten())
                .any(|entry| entry.file_name().to_string_lossy().starts_with(".tmp_"))
        );
    }

    #[tokio::test]
    async fn namespace_stream_cleanup_attempts_all_files_and_retains_failed_ownership() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().join("artifacts");
        let store = FileArtifactStore::new(&root).expect("artifact store");
        let namespace = store.allocate_namespace().unwrap();
        let first = store
            .begin_json_stream(
                namespace.clone(),
                "first.json".to_owned(),
                ArtifactCompression::Identity,
                ArtifactStreamFormat::JsonArray,
            )
            .await
            .unwrap();
        let second = store
            .begin_json_stream(
                namespace.clone(),
                "second.jsonl".to_owned(),
                ArtifactCompression::Identity,
                ArtifactStreamFormat::JsonLines,
            )
            .await
            .unwrap();
        let first_path = store
            .inner
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .streams[&first.id]
            .staging_path
            .clone();
        fs::remove_file(&first_path).unwrap();
        let mut replacement = open_private_new(&first_path).unwrap();
        replacement.write_all(b"not owned").unwrap();
        replacement.sync_all().unwrap();
        drop(replacement);

        assert_eq!(
            store
                .discard_stream(namespace.clone(), first.clone())
                .await
                .expect_err("the replaced stream must retain cleanup ownership"),
            ArtifactError::ReceiptMismatch
        );
        assert_eq!(
            store
                .discard_streams(namespace.clone())
                .await
                .expect_err("batch retry still reports the replaced stream"),
            ArtifactError::ReceiptMismatch
        );
        {
            let state = store
                .inner
                .gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(state.streams.contains_key(&first.id));
            assert!(!state.streams.contains_key(&second.id));
            assert!(state.root_lock.is_some());
        }
        assert_eq!(fs::read(&first_path).unwrap(), b"not owned");

        fs::remove_file(&first_path).unwrap();
        store
            .discard_streams(namespace)
            .await
            .expect("retry clears the now-unlinked owned stream");
        let state = store
            .inner
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(state.streams.is_empty());
        assert!(state.root_lock.is_none());
    }

    #[tokio::test]
    async fn stream_append_and_logical_bounds_fail_closed() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let limits = limits(32, 4, 256, 8, 512).with_stream_limits(32, 128);
        let store =
            FileArtifactStore::with_limits(directory.path().join("artifacts"), limits).unwrap();
        let namespace = store.allocate_namespace().unwrap();
        let stream = store
            .begin_json_array(
                namespace.clone(),
                "bounded.json".to_owned(),
                ArtifactCompression::Identity,
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .append_json_array(
                    namespace,
                    stream,
                    vec![json!("x".repeat(MAX_STREAM_APPEND_BYTES))],
                )
                .await
                .expect_err("append chunk bound"),
            ArtifactError::ValueTooLarge {
                bytes: MAX_STREAM_APPEND_BYTES + 1,
                limit: MAX_STREAM_APPEND_BYTES,
            }
        );
        let other = store.allocate_namespace().unwrap();
        let stage = store
            .begin_json_array(
                other.clone(),
                "small.json".to_owned(),
                ArtifactCompression::Identity,
            )
            .await
            .unwrap();
        let stage = store
            .append_json_array(other.clone(), stage, vec![json!({"a": 1})])
            .await
            .unwrap();
        assert!(matches!(
            store
                .append_json_array(other, stage, vec![json!({"long": "y".repeat(40)})])
                .await
                .expect_err("logical bound"),
            ArtifactError::ValueTooLarge { limit: 32, .. }
        ));
    }
}
