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
    io::{self, Write as _},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
};

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Maximum encoded bytes in one artifact, including its trailing newline.
pub const DEFAULT_MAX_ARTIFACT_BYTES: usize = 480 * 1024;
/// Maximum artifacts retained in one context namespace.
pub const DEFAULT_MAX_CONTEXT_FILES: usize = 32;
/// Maximum aggregate bytes retained in one context namespace.
pub const DEFAULT_MAX_CONTEXT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum artifacts retained beneath one store root.
pub const DEFAULT_MAX_ROOT_FILES: usize = 256;
/// Maximum aggregate artifact bytes retained beneath one store root.
pub const DEFAULT_MAX_ROOT_BYTES: usize = 16 * 1024 * 1024;

const NAMESPACE_RANDOM_BYTES: usize = 32;
const NAMESPACE_PREFIX: &str = "ctx_";
const MAX_FILE_NAME_BYTES: usize = 128;
const JSON_MEDIA_TYPE: &str = "application/json";
const CUSTOMER_DATA_SENSITIVITY: &str = "customerData";
const ROOT_LOCK_FILE: &str = ".azmcp.lock";
const ROOT_LOCK_CONTENT: &[u8] = b"azmcp-artifacts-v1\n";

/// A boxed asynchronous artifact operation.
pub type ArtifactFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ArtifactError>> + Send + 'a>>;

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

    /// Create one immutable JSON artifact.
    fn write_json<'a>(
        &'a self,
        namespace: ArtifactNamespace,
        file_name: String,
        value: Value,
    ) -> ArtifactFuture<'a, ArtifactReceipt> {
        Box::pin(async move {
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
            Ok(receipt)
        })
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
            max_context_files,
            max_context_bytes,
            max_root_files,
            max_root_bytes,
        }
    }

    fn validate(self) -> Result<Self, ArtifactError> {
        if self.max_artifact_bytes == 0
            || self.max_artifact_bytes > DEFAULT_MAX_ARTIFACT_BYTES
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
            .field("sha256", &self.sha256)
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
    media_type: &'static str,
    sensitivity: &'static str,
}

impl ArtifactReceipt {
    pub(crate) fn new(path: PathBuf, bytes: usize, sha256: String) -> Self {
        Self {
            path,
            bytes,
            sha256,
            media_type: JSON_MEDIA_TYPE,
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
            .field("sha256", &self.sha256)
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
}

#[derive(Clone)]
struct Reservation {
    stage_id: String,
    staging_path: PathBuf,
    identity: FileIdentity,
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
        Ok(Self {
            inner: Arc::new(FileArtifactStoreInner {
                root,
                limits: limits.validate()?,
                gate: Mutex::new(StoreState::default()),
            }),
        })
    }

    pub fn root(&self) -> &Path {
        &self.inner.root
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
            create_private_directory(&namespace_path).map_err(|_| ArtifactError::Unavailable)?;
        }
        validate_namespace_path(&namespace_path)?;

        let destination = namespace_path.join(&prepared.file_name);
        if state.reservations.contains_key(&destination) {
            return Err(ArtifactError::DestinationExists);
        }
        reject_existing_destination(&destination)?;
        let temporary_path = unique_temporary_path(&namespace_path)?;
        let mut temporary = TemporaryArtifact::create(temporary_path)?;
        temporary.write_all(&prepared.bytes)?;
        let (staging_path, identity) = temporary.retain()?;
        let stage_id = random_name("stage_")?;
        let receipt =
            ArtifactReceipt::new(destination.clone(), prepared.bytes.len(), prepared.sha256);
        state.reservations.insert(
            destination,
            Reservation {
                stage_id: stage_id.clone(),
                staging_path: staging_path.clone(),
                identity,
            },
        );
        Ok(ArtifactStage {
            id: stage_id,
            namespace: namespace.as_str().to_owned(),
            staging_path,
            receipt,
            identity,
        })
    }

    fn commit_staged_blocking(
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
            let _ = discard_exact_files(stages);
            return Err(error);
        }
        for stage in stages {
            state.reservations.remove(stage.receipt.path());
        }
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
            let result = self
                .validate_stage_shape(namespace, stage)
                .and_then(|_| {
                    if let Some(reservation) = state.reservations.get(stage.receipt.path()) {
                        validate_reservation(reservation, stage)?;
                    }
                    Ok(())
                })
                .and_then(|_| discard_exact_files(std::slice::from_ref(stage)));
            match result {
                Ok(()) => {
                    state.reservations.remove(stage.receipt.path());
                }
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        let namespace_path = self.inner.root.join(namespace.as_str());
        remove_directory_if_empty(&namespace_path)?;
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
        validate_file_name(file_name).map_err(|_| ArtifactError::ReceiptMismatch)?;
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

fn ensure_store_ready(root: &Path, state: &mut StoreState) -> Result<(), ArtifactError> {
    if let Some(expected) = state.root_identity {
        let metadata = fs::symlink_metadata(root).map_err(|_| ArtifactError::Unavailable)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || file_identity(&metadata)? != expected
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
            validate_file_name(&name).map_err(|_| ArtifactError::UnsafeDestination)?;
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
    if file_name.is_empty()
        || file_name.len() > MAX_FILE_NAME_BYTES
        || !file_name.is_ascii()
        || !file_name.ends_with(".json")
    {
        return Err(ArtifactError::InvalidFileName);
    }
    let stem = &file_name[..file_name.len() - ".json".len()];
    if stem.is_empty()
        || stem
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_'))
    {
        return Err(ArtifactError::InvalidFileName);
    }
    Ok(())
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

fn require_exact_file(path: &Path, identity: FileIdentity) -> Result<(), ArtifactError> {
    if file_identity_if_regular(path)? != Some(identity) {
        return Err(ArtifactError::ReceiptMismatch);
    }
    Ok(())
}

fn require_exact_artifact(path: &Path, stage: &ArtifactStage) -> Result<(), ArtifactError> {
    require_exact_file(path, stage.identity)?;
    let bytes = fs::read(path).map_err(|_| ArtifactError::Unavailable)?;
    if bytes.len() != stage.receipt.bytes || sha256_hex(&bytes) != stage.receipt.sha256 {
        return Err(ArtifactError::ReceiptMismatch);
    }
    Ok(())
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
fn file_identity(metadata: &fs::Metadata) -> Result<FileIdentity, ArtifactError> {
    let modified = metadata
        .modified()
        .map_err(|_| ArtifactError::Unavailable)?
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ArtifactError::Unavailable)?;
    Ok(FileIdentity {
        device: metadata.len(),
        inode: modified.as_nanos() as u64,
    })
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
    let digest = Sha256::digest(bytes);
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
            .commit_staged(namespace, vec![stage.clone()])
            .await
            .unwrap();
        assert!(stage.receipt().path().is_file());
        assert!(!stage.staging_path.exists());
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
        store
            .write_json(
                store.allocate_namespace().unwrap(),
                "first.json".to_owned(),
                json!(null),
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
    async fn rollback_rejects_replaced_inode_and_other_namespaces() {
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
                .discard_staged(first, vec![stage.clone()])
                .await
                .expect_err("changed inode"),
            ArtifactError::ReceiptMismatch
        );
        assert!(stage.staging_path.exists());

        let second = store.allocate_namespace().unwrap();
        let second_receipt = store
            .write_json(second.clone(), "result.json".to_owned(), json!(null))
            .await
            .unwrap();
        assert_eq!(
            store
                .discard_staged(second, vec![stage])
                .await
                .expect_err("other namespace"),
            ArtifactError::ReceiptMismatch
        );
        assert!(second_receipt.path().exists());
    }
}
