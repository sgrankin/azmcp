//! Azure CLI credential-broker boundary.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::time;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    cloud::AzureCloud,
    config::{SubscriptionId, TenantId},
};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const REFRESH_SKEW: Duration = Duration::from_secs(5 * 60);
const MAX_CLI_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_CACHE_ENTRIES: usize = 64;
const MIN_AZURE_CLI_VERSION: (u64, u64, u64) = (2, 89, 0);
const CLOUD_ENV: &str = "AZURE_CLOUD_NAME";
const CORRELATION_ENV: &str = "COPILOT_AGENT_SESSION_ID";

static CORRELATION_COUNTER: AtomicU64 = AtomicU64::new(1);
static IDENTITY_PIN_COUNTER: AtomicU64 = AtomicU64::new(1);
static BROKER_PROCESS_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

fn process_mutex() -> &'static Mutex<()> {
    BROKER_PROCESS_MUTEX.get_or_init(|| Mutex::new(()))
}

/// Inputs that are explicit on every Azure CLI token request.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TokenRequest {
    /// One of the closed, reviewed Azure clouds.
    pub cloud: AzureCloud,
    /// Tenant expected in the returned token response.
    pub tenant_id: TenantId,
    /// Subscription passed to Azure CLI and expected in the response.
    pub subscription_id: SubscriptionId,
    /// A reviewed audience family resolved from the selected cloud manifest.
    pub audience: TokenAudience,
    // Separates broker cache entries by explicit application-context
    // lifetime. It is never forwarded to Azure CLI or emitted on the wire.
    cache_scope: u64,
}

impl TokenRequest {
    /// Construct an explicit token request.
    pub fn new(
        cloud: AzureCloud,
        tenant_id: TenantId,
        subscription_id: SubscriptionId,
        audience: TokenAudience,
    ) -> Self {
        Self {
            cloud,
            tenant_id,
            subscription_id,
            audience,
            cache_scope: 0,
        }
    }

    pub(crate) fn with_identity_pin(mut self, pin: &CredentialIdentityPin) -> Self {
        self.cache_scope = pin.cache_scope;
        self
    }

    /// The exact reviewed token resource for this cloud/audience pair.
    pub fn resource(&self) -> &'static str {
        self.audience.resource(self.cloud)
    }
}

/// Closed token audiences implemented in v0.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TokenAudience {
    /// The selected cloud's Azure Resource Manager audience.
    Arm,
}

impl TokenAudience {
    pub const fn resource(self, cloud: AzureCloud) -> &'static str {
        match (self, cloud) {
            (Self::Arm, AzureCloud::AzureCloud) => crate::cloud::AZURE_CLOUD_ARM_AUDIENCE,
            (Self::Arm, AzureCloud::AzureUSGovernment) => {
                crate::cloud::AZURE_US_GOVERNMENT_ARM_AUDIENCE
            }
        }
    }
}

/// An access token retained in memory by the broker.
///
/// The bearer value is held in [`Zeroizing`], so it is overwritten when the
/// token is dropped. It is intentionally excluded from `Debug` and is not
/// serializable. The remaining fields are response provenance, expiry, and
/// validated token identity metadata.
#[derive(Clone)]
pub struct AccessToken {
    token: Zeroizing<String>,
    token_type: String,
    expires_on: String,
    tenant_id: String,
    subscription_id: String,
    identity: CredentialIdentity,
    expires_at: Option<SystemTime>,
}

impl AccessToken {
    fn new(
        token: Zeroizing<String>,
        token_type: String,
        expires_on: String,
        tenant_id: String,
        subscription_id: String,
        identity: CredentialIdentity,
    ) -> Self {
        let expires_at = parse_expiration(&expires_on);
        Self {
            token,
            token_type,
            expires_on,
            tenant_id,
            subscription_id,
            identity,
            expires_at,
        }
    }

    /// Borrow the bearer value for the short operation that signs a request.
    pub fn token(&self) -> &str {
        self.token.as_str()
    }

    /// Alias for [`AccessToken::token`] for callers that use secret terminology.
    pub fn secret(&self) -> &str {
        self.token()
    }

    /// The token type reported by Azure CLI, normally `Bearer`.
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    /// The raw `expiresOn` value reported by Azure CLI.
    pub fn expires_on(&self) -> &str {
        &self.expires_on
    }

    /// The tenant returned by Azure CLI after validation.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// The subscription returned by Azure CLI after validation.
    pub fn subscription_id(&self) -> &str {
        &self.subscription_id
    }

    /// The `oid` principal identifier validated from the JWT payload.
    pub fn principal_id(&self) -> &str {
        &self.identity.oid
    }

    /// The `appid` or `azp` client identifier validated from the JWT payload.
    pub fn client_id(&self) -> &str {
        &self.identity.client_id
    }

    pub(crate) fn identity(&self) -> &CredentialIdentity {
        &self.identity
    }

    fn is_fresh(&self, now: SystemTime) -> bool {
        self.expires_at
            .and_then(|expires_at| expires_at.duration_since(now).ok())
            .is_some_and(|remaining| remaining > REFRESH_SKEW)
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessToken")
            .field("token", &"<redacted>")
            .field("token_type", &self.token_type)
            .field("expires_on", &self.expires_on)
            .field("tenant_id", &self.tenant_id)
            .field("subscription_id", &self.subscription_id)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct CredentialIdentity {
    oid: String,
    client_id: String,
}

impl CredentialIdentity {
    pub(crate) fn from_parts(
        oid: impl Into<String>,
        client_id: impl Into<String>,
    ) -> Result<Self, CredentialError> {
        let oid = oid.into();
        let client_id = client_id.into();
        let oid = normalized_identity_claim(&oid).ok_or(CredentialError::InvalidResponse {
            field: "principalId",
        })?;
        let client_id = normalized_identity_claim(&client_id)
            .ok_or(CredentialError::InvalidResponse { field: "clientId" })?;
        Ok(Self { oid, client_id })
    }
}

impl fmt::Debug for CredentialIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialIdentity")
            .field("oid", &"<redacted>")
            .field("client_id", &"<redacted>")
            .finish()
    }
}

/// Semantic aliases for integrations that name the in-memory secret directly.
pub type InMemoryToken = AccessToken;
pub type BearerToken = AccessToken;

/// Stable, sanitized categories returned by [`CredentialError::code`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialErrorCode {
    InvalidRequest,
    SpawnFailed,
    OutputReadFailed,
    Timeout,
    AuthenticationRequired,
    SubscriptionRejected,
    CliRejected,
    InvalidJson,
    InvalidResponse,
    TenantMismatch,
    SubscriptionMismatch,
    PrincipalMismatch,
    EmptyToken,
    InvalidTokenType,
    ExpiredToken,
    UnsupportedCli,
}

impl CredentialErrorCode {
    /// Machine-readable snake-case representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::SpawnFailed => "spawn_failed",
            Self::OutputReadFailed => "output_read_failed",
            Self::Timeout => "timeout",
            Self::AuthenticationRequired => "authentication_required",
            Self::SubscriptionRejected => "subscription_rejected",
            Self::CliRejected => "cli_rejected",
            Self::InvalidJson => "invalid_json",
            Self::InvalidResponse => "invalid_response",
            Self::TenantMismatch => "tenant_mismatch",
            Self::SubscriptionMismatch => "subscription_mismatch",
            Self::PrincipalMismatch => "principal_mismatch",
            Self::EmptyToken => "empty_token",
            Self::InvalidTokenType => "invalid_token_type",
            Self::ExpiredToken => "expired_token",
            Self::UnsupportedCli => "unsupported_cli",
        }
    }
}

/// Sanitized errors from the broker boundary.
///
/// No variant stores CLI stdout/stderr, the access token, or a parser error
/// containing response text. Raw diagnostics can therefore not leak through a
/// structured error or its `Display`/`Debug` representations.
#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("credential request field {field} is empty or contains control characters")]
    InvalidRequest { field: &'static str },
    #[error("credential broker could not start")]
    SpawnFailed { kind: io::ErrorKind },
    #[error("credential broker output could not be read from {stream}")]
    OutputReadFailed { stream: &'static str },
    #[error("credential broker timed out after {timeout_ms} ms")]
    Timeout { timeout_ms: u64 },
    #[error(
        "Azure CLI authentication is required; run AZURE_CLOUD_NAME={cloud_name} az login --tenant {tenant_id}"
    )]
    AuthenticationRequired {
        cloud_name: String,
        tenant_id: String,
    },
    #[error("Azure CLI rejected the requested subscription")]
    SubscriptionRejected { exit_code: Option<i32> },
    #[error("Azure CLI rejected the credential request")]
    CliRejected { exit_code: Option<i32> },
    #[error("credential broker returned invalid JSON")]
    InvalidJson,
    #[error("credential broker returned an incomplete response ({field})")]
    InvalidResponse { field: &'static str },
    #[error("credential broker returned a token for a different tenant")]
    TenantMismatch,
    #[error("credential broker returned a token for a different subscription")]
    SubscriptionMismatch,
    #[error("credential broker returned a different token principal or client identity")]
    PrincipalMismatch,
    #[error("credential broker returned an empty access token")]
    EmptyToken,
    #[error("credential broker returned an unsupported token type")]
    InvalidTokenType,
    #[error("credential broker returned an expired or near-expiry token")]
    ExpiredToken,
    #[error("Azure CLI is missing or does not meet the supported version and command requirements")]
    UnsupportedCli,
}

impl CredentialError {
    /// Return the stable category without exposing subprocess diagnostics.
    pub const fn code(&self) -> CredentialErrorCode {
        match self {
            Self::InvalidRequest { .. } => CredentialErrorCode::InvalidRequest,
            Self::SpawnFailed { .. } => CredentialErrorCode::SpawnFailed,
            Self::OutputReadFailed { .. } => CredentialErrorCode::OutputReadFailed,
            Self::Timeout { .. } => CredentialErrorCode::Timeout,
            Self::AuthenticationRequired { .. } => CredentialErrorCode::AuthenticationRequired,
            Self::SubscriptionRejected { .. } => CredentialErrorCode::SubscriptionRejected,
            Self::CliRejected { .. } => CredentialErrorCode::CliRejected,
            Self::InvalidJson => CredentialErrorCode::InvalidJson,
            Self::InvalidResponse { .. } => CredentialErrorCode::InvalidResponse,
            Self::TenantMismatch => CredentialErrorCode::TenantMismatch,
            Self::SubscriptionMismatch => CredentialErrorCode::SubscriptionMismatch,
            Self::PrincipalMismatch => CredentialErrorCode::PrincipalMismatch,
            Self::EmptyToken => CredentialErrorCode::EmptyToken,
            Self::InvalidTokenType => CredentialErrorCode::InvalidTokenType,
            Self::ExpiredToken => CredentialErrorCode::ExpiredToken,
            Self::UnsupportedCli => CredentialErrorCode::UnsupportedCli,
        }
    }
}

/// The identity pinning scope deliberately excludes subscription ID. A broker
/// must not silently switch principals when it refreshes a token for another
/// subscription in the same cloud, tenant, and audience.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct PrincipalPinKey {
    cloud: AzureCloud,
    tenant_id: TenantId,
    audience: TokenAudience,
}

impl From<&TokenRequest> for PrincipalPinKey {
    fn from(request: &TokenRequest) -> Self {
        Self {
            cloud: request.cloud,
            tenant_id: request.tenant_id.clone(),
            audience: request.audience,
        }
    }
}

/// Context-owned token identity state.
///
/// The handle is cloneable so one context can share its pin across sequential
/// host calls while distinct contexts retain independent identity state. The
/// key deliberately excludes subscription ID: a context cannot silently switch
/// principals when it acquires a token for another subscription in the same
/// cloud, tenant, and audience.
#[derive(Clone)]
pub struct CredentialIdentityPin {
    identities: Arc<Mutex<BTreeMap<PrincipalPinKey, CredentialIdentity>>>,
    cache_scope: u64,
}

impl Default for CredentialIdentityPin {
    fn default() -> Self {
        Self {
            identities: Arc::new(Mutex::new(BTreeMap::new())),
            cache_scope: IDENTITY_PIN_COUNTER.fetch_add(1, Ordering::Relaxed),
        }
    }
}

impl CredentialIdentityPin {
    /// Construct an empty context identity pin.
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) async fn check(
        &self,
        request: &TokenRequest,
        identity: &CredentialIdentity,
    ) -> Result<(), CredentialError> {
        let key = PrincipalPinKey::from(request);
        let mut identities = self.identities.lock().await;
        if let Some(pinned) = identities.get(&key) {
            if pinned != identity {
                return Err(CredentialError::PrincipalMismatch);
            }
        } else {
            identities.insert(key, identity.clone());
        }
        Ok(())
    }
}

/// The validated Azure CLI capabilities required by the production broker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureCliProbe {
    version: String,
    agent_session_attribution_active: bool,
}

impl AzureCliProbe {
    /// The exact `azure-cli` version reported by the startup probe.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Whether this CLI supports the agent-session attribution environment
    /// value forwarded by the broker.
    pub const fn agent_session_attribution_active(&self) -> bool {
        self.agent_session_attribution_active
    }
}

/// Azure CLI token broker with an injectable executable path.
///
/// The broker never reads Azure CLI profile files and never mutates them. It
/// directly spawns the configured executable with an argv array, setting cloud
/// and agent-correlation values on the child only. Cache and single-flight
/// state are local to this broker instance; all actual CLI subprocesses also
/// pass through one process-wide mutex to avoid MSAL cache contention.
#[derive(Clone, Debug)]
pub struct AzureCliBroker {
    executable: PathBuf,
    timeout: Duration,
    correlation_id: String,
    cache: Arc<Mutex<BTreeMap<TokenRequest, AccessToken>>>,
}

impl AzureCliBroker {
    /// Construct a broker using the default short subprocess timeout.
    ///
    /// `executable` is required explicitly so tests can provide a temporary
    /// fake and production callers can choose a known, reviewed Azure CLI
    /// installation.
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        Self::with_timeout(executable, DEFAULT_TIMEOUT)
    }

    /// Construct a broker with a caller-selected timeout.
    pub fn with_timeout(executable: impl Into<PathBuf>, timeout: Duration) -> Self {
        let correlation_id = std::env::var(CORRELATION_ENV)
            .ok()
            .filter(|value| valid_correlation_id(value))
            .unwrap_or_else(generate_correlation_id);
        Self::with_parts(executable.into(), timeout, correlation_id)
    }

    /// Construct a broker with a deterministic correlation value, useful for
    /// a host that has already validated its own agent-session identifier.
    pub fn with_correlation_id(
        executable: impl Into<PathBuf>,
        timeout: Duration,
        correlation_id: impl Into<String>,
    ) -> Result<Self, CredentialError> {
        let correlation_id = correlation_id.into();
        if !valid_correlation_id(&correlation_id) {
            return Err(CredentialError::InvalidRequest {
                field: CORRELATION_ENV,
            });
        }
        Ok(Self::with_parts(executable.into(), timeout, correlation_id))
    }

    fn with_parts(executable: PathBuf, timeout: Duration, correlation_id: String) -> Self {
        Self {
            executable,
            timeout,
            correlation_id,
            cache: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// The exact executable path selected for this broker.
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// The child-only agent correlation value.
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    /// Probe the configured Azure CLI without reading account state or
    /// acquiring a token.
    ///
    /// The probe validates the exact command shape used by this broker and
    /// gates production startup on Azure CLI 2.89.0 or newer, which is the
    /// first reviewed release with agent-session attribution support.
    pub async fn probe(&self) -> Result<AzureCliProbe, CredentialError> {
        let mut command = self.base_command();
        command
            .args(["version", "--output", "json", "--only-show-errors"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let child = command
            .spawn()
            .map_err(|error| CredentialError::SpawnFailed { kind: error.kind() })?;
        let (status, mut stdout, mut stderr) = self.wait_for_child(child).await?;
        if !status.success() {
            stdout.0.zeroize();
            stderr.0.zeroize();
            return Err(CredentialError::UnsupportedCli);
        }

        let parsed = serde_json::from_slice::<CliVersionResponse>(&stdout.0);
        stdout.0.zeroize();
        stderr.0.zeroize();
        let response = parsed.map_err(|_| CredentialError::UnsupportedCli)?;
        let version = response
            .azure_cli
            .filter(|value| !value.trim().is_empty())
            .ok_or(CredentialError::UnsupportedCli)?;
        let parsed_version = parse_cli_version(&version).ok_or(CredentialError::UnsupportedCli)?;
        if parsed_version < MIN_AZURE_CLI_VERSION {
            return Err(CredentialError::UnsupportedCli);
        }

        Ok(AzureCliProbe {
            version,
            agent_session_attribution_active: true,
        })
    }

    /// Acquire a token for an explicit cloud, tenant, subscription, and
    /// audience.
    pub async fn acquire(&self, request: TokenRequest) -> Result<AccessToken, CredentialError> {
        validate_request(&request)?;

        if let Some(token) = self.cached_fresh(&request).await {
            return Ok(token);
        }

        // This is both the process-wide Azure CLI serialization boundary and a
        // second cache check, which turns concurrent requests for the same key
        // into one subprocess (single-flight).
        let _process_guard = process_mutex().lock().await;
        if let Some(token) = self.cached_fresh(&request).await {
            return Ok(token);
        }

        let token = self.spawn_and_parse(&request).await?;
        if token.is_fresh(SystemTime::now()) {
            let mut cache = self.cache.lock().await;
            let now = SystemTime::now();
            cache.retain(|_, cached| cached.is_fresh(now));
            if cache.len() < MAX_CACHE_ENTRIES {
                cache.insert(request, token.clone());
            }
        }
        Ok(token)
    }

    /// Convenience form for callers that do not need to construct a request
    /// record themselves.
    pub async fn get_access_token(
        &self,
        cloud: AzureCloud,
        tenant_id: TenantId,
        subscription_id: SubscriptionId,
        audience: TokenAudience,
    ) -> Result<AccessToken, CredentialError> {
        self.acquire(TokenRequest::new(
            cloud,
            tenant_id,
            subscription_id,
            audience,
        ))
        .await
    }

    async fn cached_fresh(&self, request: &TokenRequest) -> Option<AccessToken> {
        let mut cache = self.cache.lock().await;
        let is_fresh = cache
            .get(request)
            .is_some_and(|token| token.is_fresh(SystemTime::now()));
        if is_fresh {
            cache.get(request).cloned()
        } else {
            cache.remove(request);
            None
        }
    }

    async fn spawn_and_parse(
        &self,
        request: &TokenRequest,
    ) -> Result<AccessToken, CredentialError> {
        let mut command = self.base_command();
        command
            .args([
                "account",
                "get-access-token",
                "--subscription",
                request.subscription_id.as_str(),
                "--resource",
                request.resource(),
                "--output",
                "json",
                "--only-show-errors",
            ])
            .env(CLOUD_ENV, request.cloud.as_str());
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let child = command
            .spawn()
            .map_err(|error| CredentialError::SpawnFailed { kind: error.kind() })?;
        let (status, mut stdout, mut stderr) = self.wait_for_child(child).await?;

        if !status.success() {
            let error = classify_cli_failure(status, &stderr.0, request);
            stdout.0.zeroize();
            stderr.0.zeroize();
            return Err(error);
        }

        let parsed = serde_json::from_slice::<CliTokenResponse>(&stdout.0);
        stdout.0.zeroize();
        stderr.0.zeroize();
        let mut response = parsed.map_err(|_| CredentialError::InvalidJson)?;

        let token = Zeroizing::new(response.access_token.take().ok_or(
            CredentialError::InvalidResponse {
                field: "accessToken",
            },
        )?);
        if token.trim().is_empty()
            || token.as_str() != token.trim()
            || token.chars().any(char::is_control)
        {
            return Err(CredentialError::EmptyToken);
        }

        let identity = parse_token_identity(token.as_str(), request.tenant_id.as_str())?;

        let tenant_id = response
            .tenant
            .take()
            .ok_or(CredentialError::InvalidResponse { field: "tenant" })?;
        if !tenant_id.eq_ignore_ascii_case(request.tenant_id.as_str()) {
            return Err(CredentialError::TenantMismatch);
        }

        let subscription_id =
            response
                .subscription
                .take()
                .ok_or(CredentialError::InvalidResponse {
                    field: "subscription",
                })?;
        if !subscription_id.eq_ignore_ascii_case(request.subscription_id.as_str()) {
            return Err(CredentialError::SubscriptionMismatch);
        }

        let expires_on = response
            .expires_on_epoch
            .take()
            .or_else(|| response.expires_on.take())
            .ok_or(CredentialError::InvalidResponse { field: "expiresOn" })?;
        if expires_on.trim().is_empty() {
            return Err(CredentialError::InvalidResponse { field: "expiresOn" });
        }
        let expires_at = parse_expiration(&expires_on).ok_or(CredentialError::ExpiredToken)?;
        if expires_at
            .duration_since(SystemTime::now())
            .ok()
            .is_none_or(|remaining| remaining <= REFRESH_SKEW)
        {
            return Err(CredentialError::ExpiredToken);
        }

        let token_type = response
            .token_type
            .take()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "Bearer".to_owned());
        if !token_type.eq_ignore_ascii_case("Bearer") {
            return Err(CredentialError::InvalidTokenType);
        }

        Ok(AccessToken::new(
            token,
            token_type,
            expires_on,
            tenant_id,
            subscription_id,
            identity,
        ))
    }

    fn base_command(&self) -> Command {
        let mut command = Command::new(&self.executable);
        command.env_clear();
        for name in [
            "HOME",
            "PATH",
            "LANG",
            "LC_ALL",
            "TMPDIR",
            "USERPROFILE",
            "SystemRoot",
            "SSL_CERT_FILE",
            "AZURE_CONFIG_DIR",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command.env(CORRELATION_ENV, &self.correlation_id);
        command
    }

    async fn wait_for_child(
        &self,
        mut child: Child,
    ) -> Result<(ExitStatus, SensitiveBytes, SensitiveBytes), CredentialError> {
        let stdout = child
            .stdout
            .take()
            .ok_or(CredentialError::OutputReadFailed { stream: "stdout" })?;
        let stderr = child
            .stderr
            .take()
            .ok_or(CredentialError::OutputReadFailed { stream: "stderr" })?;

        let mut stdout_task = tokio::spawn(read_stream(stdout));
        let mut stderr_task = tokio::spawn(read_stream(stderr));
        let waited = time::timeout(self.timeout, child.wait()).await;
        let status = match waited {
            Ok(Ok(status)) => status,
            Ok(Err(_)) => {
                stdout_task.abort();
                stderr_task.abort();
                return Err(CredentialError::OutputReadFailed { stream: "process" });
            }
            Err(_) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                stdout_task.abort();
                stderr_task.abort();
                return Err(CredentialError::Timeout {
                    timeout_ms: self.timeout.as_millis().min(u128::from(u64::MAX)) as u64,
                });
            }
        };

        let output = time::timeout(self.timeout, async {
            let stdout = (&mut stdout_task).await;
            let stderr = (&mut stderr_task).await;
            (stdout, stderr)
        })
        .await;
        let (stdout, stderr) = match output {
            Ok(output) => output,
            Err(_) => {
                stdout_task.abort();
                stderr_task.abort();
                return Err(CredentialError::OutputReadFailed { stream: "process" });
            }
        };
        let stdout = match stdout {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(())) | Err(_) => {
                return Err(CredentialError::OutputReadFailed { stream: "stdout" });
            }
        };
        let stderr = match stderr {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(())) | Err(_) => {
                return Err(CredentialError::OutputReadFailed { stream: "stderr" });
            }
        };
        Ok((status, stdout, stderr))
    }
}

#[derive(Debug, Deserialize, Zeroize)]
#[zeroize(drop)]
struct CliTokenResponse {
    #[serde(rename = "accessToken", default)]
    access_token: Option<String>,
    #[serde(rename = "expiresOn", default)]
    expires_on: Option<String>,
    #[serde(
        rename = "expires_on",
        default,
        deserialize_with = "deserialize_optional_expiry"
    )]
    expires_on_epoch: Option<String>,
    #[serde(default)]
    subscription: Option<String>,
    #[serde(default)]
    tenant: Option<String>,
    #[serde(rename = "tokenType", default)]
    token_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CliVersionResponse {
    #[serde(rename = "azure-cli", default)]
    azure_cli: Option<String>,
}

#[derive(Debug)]
struct SensitiveBytes(Vec<u8>);

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

async fn read_stream<R>(mut stream: R) -> Result<SensitiveBytes, ()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut bytes = SensitiveBytes(Vec::new());
    let mut limited = (&mut stream).take((MAX_CLI_OUTPUT_BYTES + 1) as u64);
    if limited.read_to_end(&mut bytes.0).await.is_err() || bytes.0.len() > MAX_CLI_OUTPUT_BYTES {
        return Err(());
    }
    Ok(bytes)
}

fn deserialize_optional_expiry<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Expiry {
        String(String),
        Integer(u64),
    }

    Option::<Expiry>::deserialize(deserializer).map(|value| {
        value.map(|value| match value {
            Expiry::String(value) => value,
            Expiry::Integer(value) => value.to_string(),
        })
    })
}

fn parse_cli_version(value: &str) -> Option<(u64, u64, u64)> {
    let mut components = value.trim().split('.');
    let major = components.next()?.parse().ok()?;
    let minor = components.next()?.parse().ok()?;
    let patch = components.next()?.parse().ok()?;
    if components.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

#[derive(Deserialize)]
struct JwtClaims {
    #[serde(default)]
    tid: Option<String>,
    #[serde(default)]
    oid: Option<String>,
    #[serde(default)]
    appid: Option<String>,
    #[serde(default)]
    azp: Option<String>,
}

fn parse_token_identity(
    token: &str,
    requested_tenant: &str,
) -> Result<CredentialIdentity, CredentialError> {
    let mut segments = token.split('.');
    let (Some(header), Some(payload), Some(signature)) =
        (segments.next(), segments.next(), segments.next())
    else {
        return Err(invalid_token_claims());
    };
    if header.is_empty() || payload.is_empty() || signature.is_empty() || segments.next().is_some()
    {
        return Err(invalid_token_claims());
    }

    let mut decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| invalid_token_claims())?;
    let claims = serde_json::from_slice::<JwtClaims>(&decoded);
    decoded.zeroize();
    let claims = claims.map_err(|_| invalid_token_claims())?;

    let tenant_id = required_claim(claims.tid, "accessToken.tid")?;
    if !tenant_id.eq_ignore_ascii_case(requested_tenant) {
        return Err(CredentialError::TenantMismatch);
    }

    let oid = required_identity_claim(claims.oid, "accessToken.oid")?;
    let client_id = claims
        .appid
        .and_then(|value| normalized_identity_claim(&value))
        .or_else(|| {
            claims
                .azp
                .and_then(|value| normalized_identity_claim(&value))
        })
        .ok_or_else(|| invalid_token_claims_for("accessToken.appidOrAzp"))?;

    Ok(CredentialIdentity { oid, client_id })
}

fn required_identity_claim(
    value: Option<String>,
    field: &'static str,
) -> Result<String, CredentialError> {
    value
        .as_deref()
        .and_then(normalized_identity_claim)
        .ok_or_else(|| invalid_token_claims_for(field))
}

fn normalized_identity_claim(value: &str) -> Option<String> {
    TenantId::new(value.to_owned())
        .ok()
        .map(|value| value.as_str().to_owned())
}

fn required_claim(value: Option<String>, field: &'static str) -> Result<String, CredentialError> {
    let value = value.ok_or_else(|| invalid_token_claims_for(field))?;
    if !valid_claim(&value) {
        return Err(invalid_token_claims_for(field));
    }
    Ok(value)
}

fn valid_claim(value: &str) -> bool {
    !value.trim().is_empty() && value == value.trim() && !value.chars().any(char::is_control)
}

fn invalid_token_claims() -> CredentialError {
    invalid_token_claims_for("accessTokenClaims")
}

fn invalid_token_claims_for(field: &'static str) -> CredentialError {
    CredentialError::InvalidResponse { field }
}

fn validate_request(request: &TokenRequest) -> Result<(), CredentialError> {
    validate_field("tenant_id", request.tenant_id.as_str())?;
    validate_field("subscription_id", request.subscription_id.as_str())?;
    validate_field("resource", request.resource())
}

fn validate_field(field: &'static str, value: &str) -> Result<(), CredentialError> {
    if value.trim().is_empty() || value != value.trim() || value.chars().any(char::is_control) {
        return Err(CredentialError::InvalidRequest { field });
    }
    Ok(())
}

fn valid_correlation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn generate_correlation_id() -> String {
    let counter = CORRELATION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!("azmcp-{nanos:x}-{:x}-{counter:x}", std::process::id())
}

fn classify_cli_failure(
    status: ExitStatus,
    stderr: &[u8],
    request: &TokenRequest,
) -> CredentialError {
    let exit_code = status.code();
    if contains_ascii_case_insensitive(stderr, b"login")
        || contains_ascii_case_insensitive(stderr, b"aadsts")
        || contains_ascii_case_insensitive(stderr, b"authentication")
        || contains_ascii_case_insensitive(stderr, b"not logged in")
    {
        return CredentialError::AuthenticationRequired {
            cloud_name: request.cloud.as_str().to_owned(),
            tenant_id: request.tenant_id.as_str().to_owned(),
        };
    }

    if contains_ascii_case_insensitive(stderr, b"subscription")
        && (contains_ascii_case_insensitive(stderr, b"not found")
            || contains_ascii_case_insensitive(stderr, b"does not exist")
            || contains_ascii_case_insensitive(stderr, b"invalid"))
    {
        return CredentialError::SubscriptionRejected { exit_code };
    }

    CredentialError::CliRejected { exit_code }
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn parse_expiration(value: &str) -> Option<SystemTime> {
    let value = value.trim();
    if let Ok(mut seconds) = value.parse::<u64>() {
        // Some clients use milliseconds while Azure CLI's documented shape is
        // seconds. Accept both without allowing an overflow during conversion.
        if seconds > 100_000_000_000 {
            seconds /= 1_000;
        }
        return UNIX_EPOCH.checked_add(Duration::from_secs(seconds));
    }

    let (date, time_and_zone) = value.split_once(['T', ' '])?;
    let mut date_parts = date.split('-');
    let year = date_parts.next()?.parse::<i32>().ok()?;
    let month = date_parts.next()?.parse::<u32>().ok()?;
    let day = date_parts.next()?.parse::<u32>().ok()?;
    if date_parts.next().is_some() {
        return None;
    }

    let time_and_zone = time_and_zone.trim_end_matches('Z');
    let (time, offset_seconds) = if let Some(index) = time_and_zone.rfind(['+', '-']) {
        let (time, signed_offset) = time_and_zone.split_at(index);
        let sign = if signed_offset.starts_with('-') {
            -1
        } else {
            1
        };
        let mut offset_parts = signed_offset[1..].split(':');
        let hours = offset_parts.next()?.parse::<i64>().ok()?;
        let minutes = offset_parts.next()?.parse::<i64>().ok()?;
        if offset_parts.next().is_some() {
            return None;
        }
        if hours > 23 || minutes > 59 {
            return None;
        }
        let offset = hours
            .checked_mul(3_600)?
            .checked_add(minutes.checked_mul(60)?)?;
        (time, sign * offset)
    } else {
        (time_and_zone, 0)
    };

    let mut time_parts = time.split(':');
    let hour = time_parts.next()?.parse::<u64>().ok()?;
    let minute = time_parts.next()?.parse::<u64>().ok()?;
    let second_and_fraction = time_parts.next()?;
    if time_parts.next().is_some() {
        return None;
    }
    let second = second_and_fraction
        .split_once('.')
        .map_or(second_and_fraction, |(second, _)| second)
        .parse::<u64>()
        .ok()?;
    if month == 0
        || month > 12
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }

    let days = days_from_civil(year, month, day)?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(i64::try_from(hour * 3_600 + minute * 60 + second).ok()?)?
        .checked_sub(offset_seconds)?;
    if seconds < 0 {
        return None;
    }
    UNIX_EPOCH.checked_add(Duration::from_secs(u64::try_from(seconds).ok()?))
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 31,
    }
}

// Howard Hinnant's proleptic-Gregorian civil-date conversion, kept local to
// avoid adding a date dependency solely for Azure CLI's expiry string.
fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day = i64::from(day);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era.checked_mul(146_097)?
        .checked_add(day_of_era)
        .and_then(|days| days.checked_sub(719_468))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    const SUBSCRIPTION_A: &str = "11111111-1111-1111-1111-111111111111";
    const SUBSCRIPTION_B: &str = "22222222-2222-2222-2222-222222222222";
    const TENANT_A: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const TENANT_B: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    const OID_A: &str = "cccccccc-cccc-cccc-cccc-cccccccccccc";
    const OID_B: &str = "dddddddd-dddd-dddd-dddd-dddddddddddd";
    const CLIENT_A: &str = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee";
    const CLIENT_B: &str = "ffffffff-ffff-ffff-ffff-ffffffffffff";

    fn jwt_token(tenant: &str, oid: &str, client_id: &str) -> String {
        jwt_token_with_claims(serde_json::json!({
            "tid": tenant,
            "oid": oid,
            "appid": client_id,
        }))
    }

    fn jwt_token_with_claims(claims: serde_json::Value) -> String {
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
        format!("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.{payload}.synthetic-signature")
    }

    fn jwt_token_with_raw_payload(payload: &str) -> String {
        let payload = URL_SAFE_NO_PAD.encode(payload);
        format!("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.{payload}.synthetic-signature")
    }

    fn cli_body(token: &str, subscription: &str, tenant: &str, token_type: Option<&str>) -> String {
        let mut body = serde_json::json!({
            "accessToken": token,
            "expiresOn": "2099-01-01 00:00:00.000000",
            "subscription": subscription,
            "tenant": tenant,
        });
        if let Some(token_type) = token_type {
            body["tokenType"] = serde_json::json!(token_type);
        }
        body.to_string()
    }

    fn fake_az(
        directory: &TempDir,
        body: &str,
        stderr: &str,
        exit_code: i32,
        sleep_seconds: Option<u64>,
    ) -> PathBuf {
        let executable = directory.path().join("fake-az");
        let script = format!(
            "#!/bin/sh\n{}{}printf '%s' '{}'\nprintf '%s' '{}' >&2\nexit {}\n",
            sleep_seconds.map_or(String::new(), |seconds| format!("sleep {seconds}\n")),
            "printf '%s\\n' \"$AZURE_CLOUD_NAME|$COPILOT_AGENT_SESSION_ID|$HTTP_PROXY|$AZURE_CLIENT_SECRET|$*\" >> \"$(dirname \"$0\")/argv.log\"\n",
            body.replace('\'', "'\\''"),
            stderr.replace('\'', "'\\''"),
            exit_code
        );
        fs::write(&executable, script).expect("write fake executable");
        let mut permissions = fs::metadata(&executable)
            .expect("stat fake executable")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&executable, permissions).expect("chmod fake executable");
        executable
    }

    fn fake_az_by_subscription(
        directory: &TempDir,
        first_subscription: &str,
        first_body: &str,
        second_subscription: &str,
        second_body: &str,
    ) -> PathBuf {
        let executable = directory.path().join("fake-az-by-subscription");
        let script = format!(
            "#!/bin/sh\ncase \"$*\" in\n*{first_subscription}*) printf '%s' '{first_body}' ;;\n*{second_subscription}*) printf '%s' '{second_body}' ;;\n*) exit 1 ;;\nesac\n",
            first_body = first_body.replace('\'', "'\\''"),
            second_body = second_body.replace('\'', "'\\''"),
        );
        fs::write(&executable, script).expect("write fake executable");
        let mut permissions = fs::metadata(&executable)
            .expect("stat fake executable")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&executable, permissions).expect("chmod fake executable");
        executable
    }

    fn fake_az_version(directory: &TempDir, body: &str, exit_code: i32) -> PathBuf {
        let executable = directory.path().join("fake-az-version");
        let script = format!(
            "#!/bin/sh\nif [ \"$1\" = version ]; then printf '%s' '{body}'; else exit 99; fi\nexit {exit_code}\n",
            body = body.replace('\'', "'\\''"),
        );
        fs::write(&executable, script).expect("write fake version executable");
        let mut permissions = fs::metadata(&executable)
            .expect("stat fake version executable")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&executable, permissions).expect("chmod fake version executable");
        executable
    }

    fn request() -> TokenRequest {
        request_for_subscription(SUBSCRIPTION_A)
    }

    fn request_for_subscription(subscription_id: &str) -> TokenRequest {
        TokenRequest::new(
            AzureCloud::AzureCloud,
            TenantId::new(TENANT_A).expect("valid tenant"),
            SubscriptionId::new(subscription_id).expect("valid subscription"),
            TokenAudience::Arm,
        )
    }

    #[tokio::test]
    async fn uses_exact_argv_child_only_environment_and_validates_response() {
        let directory = tempfile::tempdir().expect("temporary fake directory");
        let log = directory.path().join("argv.log");
        let access_token = jwt_token(TENANT_A, OID_A, CLIENT_A);
        let executable = fake_az(
            &directory,
            &cli_body(&access_token, SUBSCRIPTION_A, TENANT_A, Some("Bearer")),
            "",
            0,
            None,
        );
        let broker =
            AzureCliBroker::with_correlation_id(&executable, DEFAULT_TIMEOUT, "test-correlation")
                .expect("valid correlation id");

        let token = broker
            .acquire(request())
            .await
            .expect("fake token succeeds");
        assert_eq!(token.token(), access_token);
        assert_eq!(token.tenant_id(), TENANT_A);
        assert_eq!(token.subscription_id(), SUBSCRIPTION_A);
        assert_eq!(token.principal_id(), OID_A);
        assert_eq!(token.client_id(), CLIENT_A);
        assert_eq!(token.token_type(), "Bearer");
        let debug = format!("{token:?}");
        assert!(!debug.contains(&access_token));
        assert!(!debug.contains(OID_A));
        assert!(!debug.contains(CLIENT_A));

        let invocation = fs::read_to_string(&log).expect("fake saw invocation");
        assert!(invocation.contains(
            "AzureCloud|test-correlation|||account get-access-token --subscription 11111111-1111-1111-1111-111111111111 --resource https://management.azure.com/ --output json --only-show-errors"
        ));
    }

    #[tokio::test]
    async fn token_cache_is_single_flight_for_one_request() {
        let directory = tempfile::tempdir().expect("temporary fake directory");
        let log = directory.path().join("argv.log");
        let access_token = jwt_token(TENANT_A, OID_A, CLIENT_A);
        let executable = fake_az(
            &directory,
            &cli_body(&access_token, SUBSCRIPTION_A, TENANT_A, None),
            "",
            0,
            None,
        );
        let broker =
            AzureCliBroker::with_correlation_id(&executable, DEFAULT_TIMEOUT, "cache-test")
                .expect("valid correlation id");

        let (first, second) = tokio::join!(broker.acquire(request()), broker.acquire(request()));
        assert_eq!(first.expect("first token").token(), access_token);
        assert_eq!(second.expect("second token").token(), access_token);
        assert_eq!(
            fs::read_to_string(&log).expect("fake log").lines().count(),
            1
        );
    }

    #[tokio::test]
    async fn token_cache_does_not_cross_context_identity_pins() {
        let directory = tempfile::tempdir().expect("temporary fake directory");
        let log = directory.path().join("argv.log");
        let access_token = jwt_token(TENANT_A, OID_A, CLIENT_A);
        let executable = fake_az(
            &directory,
            &cli_body(&access_token, SUBSCRIPTION_A, TENANT_A, None),
            "",
            0,
            None,
        );
        let broker =
            AzureCliBroker::with_correlation_id(&executable, DEFAULT_TIMEOUT, "scope-test")
                .expect("valid correlation id");
        let first_context = CredentialIdentityPin::new();
        let second_context = CredentialIdentityPin::new();

        broker
            .acquire(request().with_identity_pin(&first_context))
            .await
            .expect("first context token");
        broker
            .acquire(request().with_identity_pin(&second_context))
            .await
            .expect("second context obtains its own token");

        assert_eq!(
            fs::read_to_string(&log).expect("fake log").lines().count(),
            2
        );
    }

    #[tokio::test]
    async fn mismatch_and_cli_failures_are_sanitized() {
        let directory = tempfile::tempdir().expect("temporary fake directory");
        let access_token = jwt_token(TENANT_A, OID_A, CLIENT_A);
        let executable = fake_az(
            &directory,
            &cli_body(&access_token, SUBSCRIPTION_B, TENANT_A, None),
            "super-secret-diagnostic",
            1,
            None,
        );
        let broker =
            AzureCliBroker::with_correlation_id(&executable, DEFAULT_TIMEOUT, "sanitize-test")
                .expect("valid correlation id");
        let error = broker.acquire(request()).await.expect_err("fake failure");
        assert_eq!(error.code(), CredentialErrorCode::CliRejected);
        assert!(!error.to_string().contains("super-secret-diagnostic"));
        assert!(!format!("{error:?}").contains("super-secret-diagnostic"));

        let mismatch_executable = fake_az(
            &directory,
            &cli_body(&access_token, SUBSCRIPTION_B, TENANT_A, None),
            "",
            0,
            None,
        );
        let mismatch = AzureCliBroker::with_correlation_id(
            &mismatch_executable,
            DEFAULT_TIMEOUT,
            "mismatch-test",
        )
        .expect("valid correlation id")
        .acquire(request())
        .await
        .expect_err("mismatched subscription fails closed");
        assert_eq!(mismatch.code(), CredentialErrorCode::SubscriptionMismatch);
        assert!(!mismatch.to_string().contains(access_token.as_str()));
    }

    #[tokio::test]
    async fn timeout_kills_fake_child() {
        let directory = tempfile::tempdir().expect("temporary fake directory");
        let access_token = jwt_token(TENANT_A, OID_A, CLIENT_A);
        let executable = fake_az(
            &directory,
            &cli_body(&access_token, SUBSCRIPTION_A, TENANT_A, None),
            "",
            0,
            Some(30),
        );
        let broker = AzureCliBroker::with_correlation_id(
            &executable,
            Duration::from_millis(25),
            "timeout-test",
        )
        .expect("valid correlation id");
        let error = broker
            .acquire(request())
            .await
            .expect_err("fake exceeds timeout");
        assert_eq!(error.code(), CredentialErrorCode::Timeout);
    }

    #[tokio::test]
    async fn rejects_expired_tokens_and_non_bearer_types() {
        let directory = tempfile::tempdir().expect("temporary fake directory");
        let access_token = jwt_token(TENANT_A, OID_A, CLIENT_A);
        let expired = fake_az(
            &directory,
            &format!(
                r#"{{"accessToken":"{access_token}","expires_on":1,"subscription":"{SUBSCRIPTION_A}","tenant":"{TENANT_A}"}}"#
            ),
            "",
            0,
            None,
        );
        let error = AzureCliBroker::with_correlation_id(&expired, DEFAULT_TIMEOUT, "expired-test")
            .expect("valid correlation id")
            .acquire(request())
            .await
            .expect_err("expired token fails closed");
        assert_eq!(error.code(), CredentialErrorCode::ExpiredToken);
        assert!(!format!("{error:?}").contains(access_token.as_str()));

        let invalid_type_token = jwt_token(TENANT_A, OID_A, CLIENT_A);
        let invalid_type = fake_az(
            &directory,
            &cli_body(&invalid_type_token, SUBSCRIPTION_A, TENANT_A, Some("Basic")),
            "",
            0,
            None,
        );
        let error =
            AzureCliBroker::with_correlation_id(&invalid_type, DEFAULT_TIMEOUT, "type-test")
                .expect("valid correlation id")
                .acquire(request())
                .await
                .expect_err("non-bearer token fails closed");
        assert_eq!(error.code(), CredentialErrorCode::InvalidTokenType);
    }

    #[tokio::test]
    async fn rejects_malformed_or_incomplete_jwt_claims() {
        let malformed = [
            jwt_token_with_raw_payload("not-json"),
            jwt_token_with_raw_payload("[]"),
            jwt_token_with_claims(serde_json::json!({
                "oid": OID_A,
                "appid": CLIENT_A,
            })),
            jwt_token_with_claims(serde_json::json!({
                "tid": TENANT_A,
                "appid": CLIENT_A,
            })),
            jwt_token_with_claims(serde_json::json!({
                "tid": TENANT_A,
                "oid": OID_A,
            })),
        ];

        for access_token in malformed {
            let directory = tempfile::tempdir().expect("temporary fake directory");
            let executable = fake_az(
                &directory,
                &cli_body(&access_token, SUBSCRIPTION_A, TENANT_A, None),
                "",
                0,
                None,
            );
            let error =
                AzureCliBroker::with_correlation_id(&executable, DEFAULT_TIMEOUT, "claims-test")
                    .expect("valid correlation id")
                    .acquire(request())
                    .await
                    .expect_err("malformed or incomplete claims fail closed");
            assert_eq!(error.code(), CredentialErrorCode::InvalidResponse);
            assert!(!error.to_string().contains(access_token.as_str()));
        }

        let directory = tempfile::tempdir().expect("temporary fake directory");
        let access_token = jwt_token_with_claims(serde_json::json!({
            "tid": TENANT_A,
            "oid": OID_A,
            "azp": CLIENT_A,
        }));
        let executable = fake_az(
            &directory,
            &cli_body(&access_token, SUBSCRIPTION_A, TENANT_A, None),
            "",
            0,
            None,
        );
        let token = AzureCliBroker::with_correlation_id(&executable, DEFAULT_TIMEOUT, "azp-test")
            .expect("valid correlation id")
            .acquire(request())
            .await
            .expect("azp satisfies the client identity requirement");
        assert_eq!(token.client_id(), CLIENT_A);
    }

    #[tokio::test]
    async fn rejects_jwt_tenant_claim_mismatch() {
        let directory = tempfile::tempdir().expect("temporary fake directory");
        let access_token = jwt_token(TENANT_B, OID_A, CLIENT_A);
        let executable = fake_az(
            &directory,
            &cli_body(&access_token, SUBSCRIPTION_A, TENANT_A, None),
            "",
            0,
            None,
        );
        let error =
            AzureCliBroker::with_correlation_id(&executable, DEFAULT_TIMEOUT, "tenant-claim-test")
                .expect("valid correlation id")
                .acquire(request())
                .await
                .expect_err("JWT tenant mismatch fails closed");
        assert_eq!(error.code(), CredentialErrorCode::TenantMismatch);
        assert!(!error.to_string().contains(access_token.as_str()));
    }

    #[tokio::test]
    async fn pins_identity_across_subscriptions() {
        let directory = tempfile::tempdir().expect("temporary fake directory");
        let first_token = jwt_token(TENANT_A, OID_A, CLIENT_A);
        let second_token = jwt_token(TENANT_A, OID_B, CLIENT_B);
        let executable = fake_az_by_subscription(
            &directory,
            SUBSCRIPTION_A,
            &cli_body(&first_token, SUBSCRIPTION_A, TENANT_A, None),
            SUBSCRIPTION_B,
            &cli_body(&second_token, SUBSCRIPTION_B, TENANT_A, None),
        );
        let broker =
            AzureCliBroker::with_correlation_id(&executable, DEFAULT_TIMEOUT, "principal-pin-test")
                .expect("valid correlation id");

        let first = broker
            .acquire(request_for_subscription(SUBSCRIPTION_A))
            .await
            .expect("first subscription token succeeds");
        assert_eq!(first.principal_id(), OID_A);
        assert_eq!(first.client_id(), CLIENT_A);
        let pin = CredentialIdentityPin::new();
        pin.check(&request_for_subscription(SUBSCRIPTION_A), first.identity())
            .await
            .expect("first subscription identity pins");

        let second = broker
            .acquire(request_for_subscription(SUBSCRIPTION_B))
            .await
            .expect("second subscription token acquisition succeeds");
        let error = pin
            .check(&request_for_subscription(SUBSCRIPTION_B), second.identity())
            .await
            .expect_err("principal switch across subscriptions fails closed");
        assert_eq!(error.code(), CredentialErrorCode::PrincipalMismatch);
        assert!(!error.to_string().contains(first_token.as_str()));
        assert!(!error.to_string().contains(second_token.as_str()));
    }

    #[tokio::test]
    async fn identity_pins_are_independent_per_context() {
        let request = request();
        let first_identity = CredentialIdentity {
            oid: OID_A.to_owned(),
            client_id: CLIENT_A.to_owned(),
        };
        let second_identity = CredentialIdentity {
            oid: OID_B.to_owned(),
            client_id: CLIENT_B.to_owned(),
        };
        let first_context = CredentialIdentityPin::new();
        let second_context = CredentialIdentityPin::new();

        let (first_result, second_result) = tokio::join!(
            first_context.check(&request, &first_identity),
            second_context.check(&request, &second_identity),
        );
        first_result.expect("first context establishes its principal");
        second_result.expect("second context establishes its principal");

        let error = first_context
            .check(&request, &second_identity)
            .await
            .expect_err("one context rejects an identity change");
        assert_eq!(error.code(), CredentialErrorCode::PrincipalMismatch);
        second_context
            .check(&request, &second_identity)
            .await
            .expect("second context retains its independent principal");
    }

    #[tokio::test]
    async fn startup_probe_requires_supported_cli_and_never_requests_a_token() {
        let directory = tempfile::tempdir().expect("temporary fake directory");
        let executable = fake_az_version(
            &directory,
            r#"{"azure-cli":"2.89.0","azure-cli-core":"2.89.0"}"#,
            0,
        );
        let broker =
            AzureCliBroker::with_correlation_id(&executable, DEFAULT_TIMEOUT, "probe-test")
                .expect("valid correlation id");
        let probe = broker.probe().await.expect("supported CLI probe");
        assert_eq!(probe.version(), "2.89.0");
        assert!(probe.agent_session_attribution_active());

        let old = fake_az_version(&directory, r#"{"azure-cli":"2.88.0"}"#, 0);
        let error = AzureCliBroker::with_correlation_id(&old, DEFAULT_TIMEOUT, "old-test")
            .expect("valid correlation id")
            .probe()
            .await
            .expect_err("old CLI is rejected");
        assert_eq!(error.code(), CredentialErrorCode::UnsupportedCli);

        let malformed = fake_az_version(&directory, r#"{"azure-cli":"not-a-version"}"#, 0);
        let error = AzureCliBroker::with_correlation_id(
            &malformed,
            DEFAULT_TIMEOUT,
            "malformed-probe-test",
        )
        .expect("valid correlation id")
        .probe()
        .await
        .expect_err("malformed version is rejected");
        assert_eq!(error.code(), CredentialErrorCode::UnsupportedCli);
    }

    #[test]
    fn expiration_parser_handles_cli_and_epoch_shapes() {
        assert!(parse_expiration("2099-01-01 00:00:00.000000").is_some());
        assert!(parse_expiration("2099-01-01T00:00:00Z").is_some());
        assert!(parse_expiration("4102444800").is_some());
        assert!(parse_expiration("not-a-date").is_none());
        assert!(parse_expiration("2099-02-29 00:00:00").is_none());
        assert!(parse_expiration("2099-01-01T00:00:00-05:00").is_some());
        assert!(parse_expiration("2099-01-01T00:00:00+99:00").is_none());
    }
}
