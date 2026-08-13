//! Azure CLI credential-broker boundary.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
const CLOUD_ENV: &str = "AZURE_CLOUD_NAME";
const CORRELATION_ENV: &str = "COPILOT_AGENT_SESSION_ID";

static CORRELATION_COUNTER: AtomicU64 = AtomicU64::new(1);
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
        }
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
/// serializable. The remaining fields are response provenance and expiry
/// metadata, not secrets.
#[derive(Clone)]
pub struct AccessToken {
    token: Zeroizing<String>,
    token_type: String,
    expires_on: String,
    tenant_id: String,
    subscription_id: String,
    expires_at: Option<SystemTime>,
}

impl AccessToken {
    fn new(
        token: Zeroizing<String>,
        token_type: String,
        expires_on: String,
        tenant_id: String,
        subscription_id: String,
    ) -> Self {
        let expires_at = parse_expiration(&expires_on);
        Self {
            token,
            token_type,
            expires_on,
            tenant_id,
            subscription_id,
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
    EmptyToken,
    InvalidTokenType,
    ExpiredToken,
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
            Self::EmptyToken => "empty_token",
            Self::InvalidTokenType => "invalid_token_type",
            Self::ExpiredToken => "expired_token",
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
    #[error("credential broker returned an empty access token")]
    EmptyToken,
    #[error("credential broker returned an unsupported token type")]
    InvalidTokenType,
    #[error("credential broker returned an expired or near-expiry token")]
    ExpiredToken,
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
            Self::EmptyToken => CredentialErrorCode::EmptyToken,
            Self::InvalidTokenType => CredentialErrorCode::InvalidTokenType,
            Self::ExpiredToken => CredentialErrorCode::ExpiredToken,
        }
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
        let mut command = Command::new(&self.executable);
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
            .env_clear();
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
        command
            .env(CLOUD_ENV, request.cloud.as_str())
            .env(CORRELATION_ENV, &self.correlation_id)
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
        ))
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
    const TENANT_A: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

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

    fn request() -> TokenRequest {
        TokenRequest::new(
            AzureCloud::AzureCloud,
            TenantId::new(TENANT_A).expect("valid tenant"),
            SubscriptionId::new(SUBSCRIPTION_A).expect("valid subscription"),
            TokenAudience::Arm,
        )
    }

    #[tokio::test]
    async fn uses_exact_argv_child_only_environment_and_validates_response() {
        let directory = tempfile::tempdir().expect("temporary fake directory");
        let log = directory.path().join("argv.log");
        let executable = fake_az(
            &directory,
            r#"{"accessToken":"secret-token","expiresOn":"2099-01-01 00:00:00.000000","subscription":"11111111-1111-1111-1111-111111111111","tenant":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","tokenType":"Bearer"}"#,
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
        assert_eq!(token.token(), "secret-token");
        assert_eq!(token.tenant_id(), TENANT_A);
        assert_eq!(token.subscription_id(), SUBSCRIPTION_A);
        assert_eq!(token.token_type(), "Bearer");
        assert!(!format!("{token:?}").contains("secret-token"));

        let invocation = fs::read_to_string(&log).expect("fake saw invocation");
        assert!(invocation.contains(
            "AzureCloud|test-correlation|||account get-access-token --subscription 11111111-1111-1111-1111-111111111111 --resource https://management.azure.com/ --output json --only-show-errors"
        ));
    }

    #[tokio::test]
    async fn token_cache_is_single_flight_for_one_request() {
        let directory = tempfile::tempdir().expect("temporary fake directory");
        let log = directory.path().join("argv.log");
        let executable = fake_az(
            &directory,
            r#"{"accessToken":"cached-token","expiresOn":"2099-01-01 00:00:00.000000","subscription":"11111111-1111-1111-1111-111111111111","tenant":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}"#,
            "",
            0,
            None,
        );
        let broker =
            AzureCliBroker::with_correlation_id(&executable, DEFAULT_TIMEOUT, "cache-test")
                .expect("valid correlation id");

        let (first, second) = tokio::join!(broker.acquire(request()), broker.acquire(request()));
        assert_eq!(first.expect("first token").token(), "cached-token");
        assert_eq!(second.expect("second token").token(), "cached-token");
        assert_eq!(
            fs::read_to_string(&log).expect("fake log").lines().count(),
            1
        );
    }

    #[tokio::test]
    async fn mismatch_and_cli_failures_are_sanitized() {
        let directory = tempfile::tempdir().expect("temporary fake directory");
        let executable = fake_az(
            &directory,
            r#"{"accessToken":"must-not-leak","expiresOn":"2099-01-01 00:00:00.000000","subscription":"22222222-2222-2222-2222-222222222222","tenant":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}"#,
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
            r#"{"accessToken":"must-not-leak","expiresOn":"2099-01-01 00:00:00.000000","subscription":"22222222-2222-2222-2222-222222222222","tenant":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}"#,
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
        assert!(!mismatch.to_string().contains("must-not-leak"));
    }

    #[tokio::test]
    async fn timeout_kills_fake_child() {
        let directory = tempfile::tempdir().expect("temporary fake directory");
        let executable = fake_az(
            &directory,
            r#"{"accessToken":"too-late","expiresOn":"2099-01-01 00:00:00.000000","subscription":"11111111-1111-1111-1111-111111111111","tenant":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}"#,
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

    #[test]
    fn expiration_parser_handles_cli_and_epoch_shapes() {
        assert!(parse_expiration("2099-01-01 00:00:00.000000").is_some());
        assert!(parse_expiration("2099-01-01T00:00:00Z").is_some());
        assert!(parse_expiration("4102444800").is_some());
        assert!(parse_expiration("not-a-date").is_none());
        assert!(parse_expiration("2099-02-29 00:00:00").is_none());
        assert!(parse_expiration("2099-01-01T00:00:00-05:00").is_some());
    }
}
