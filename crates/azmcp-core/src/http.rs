//! The fail-closed ARM HTTP execution boundary.
//!
//! This module deliberately owns the last few decisions before a request can
//! leave the process.  A caller supplies a relative, canonical target and an
//! API version separately; this boundary checks the reviewed policy and
//! subscription scope before asking the credential broker for a token.  The
//! token is held only long enough to construct the request's Authorization
//! header and is never part of a public result or error.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use reqwest::header::{AUTHORIZATION, HeaderName, HeaderValue};
use reqwest::redirect::Policy as RedirectPolicy;
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::cloud::AzureCloud;
use crate::config::{ResolvedCloudBinding, SubscriptionId, TenantId};
use crate::credential::{
    AccessToken, AzureCliBroker, CredentialError, CredentialIdentity, CredentialIdentityPin,
    TokenAudience, TokenRequest,
};
use crate::policy::{HttpMethod, PolicyBundle, PolicyDenial, RoutePurpose};
use crate::routes::LOGS_QUERY_API_VERSION;
use crate::target::{InvalidRequestTarget, RelativeRequestTarget};

mod paging;

pub use paging::{
    MAX_PAGING_BYTES, MAX_PAGING_ELAPSED, MAX_PAGING_ITEMS, MAX_PAGING_PAGES, PagedHttpPage,
    PagedHttpResponse, PagingError, PagingLimits,
};

/// The default upper bound for a request body.
pub const DEFAULT_REQUEST_BODY_LIMIT: usize = 1024 * 1024;
/// The default upper bound for a response body.
pub const DEFAULT_RESPONSE_BODY_LIMIT: usize = 8 * 1024 * 1024;
/// Absolute upper bound accepted for one buffered HTTP response body.
pub const MAX_RESPONSE_BODY_LIMIT: usize = 64 * 1024 * 1024;
/// The default wall-clock timeout for one ARM HTTP exchange.
pub const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
/// The default total number of HTTP attempts, including the initial request.
pub const DEFAULT_RETRY_MAX_ATTEMPTS: u32 = 3;
/// The default wall-clock budget for one retrying HTTP operation.
pub const DEFAULT_RETRY_MAX_ELAPSED: Duration = Duration::from_secs(10);
/// The default delay before the first retry when `Retry-After` is absent.
pub const DEFAULT_RETRY_INITIAL_BACKOFF: Duration = Duration::from_millis(100);
/// The largest delay used for either exponential backoff or `Retry-After`.
pub const DEFAULT_RETRY_MAX_BACKOFF: Duration = Duration::from_secs(2);
/// Absolute upper bound accepted for configured retry attempts.
pub const MAX_RETRY_ATTEMPTS: u32 = 8;
/// Absolute upper bound accepted for one retrying operation's elapsed time.
pub const MAX_RETRY_ELAPSED: Duration = Duration::from_secs(60);
/// Absolute upper bound accepted for one retry delay.
pub const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(30);

const MAX_SAFE_HEADER_VALUE_BYTES: usize = 4096;
const MAX_SAFE_RETRY_AFTER_BYTES: usize = 128;

/// A boxed asynchronous credential acquisition operation.
pub type CredentialFuture<'a> =
    Pin<Box<dyn Future<Output = Result<BearerCredential, CredentialError>> + Send + 'a>>;

/// Credential acquisition is intentionally an injectable asynchronous trait.
///
/// The trait returns only a request-scoped bearer value.  It does not expose
/// an Azure CLI process, profile path, or ambient account selection to this
/// transport.  Implementations must return a sanitized [`CredentialError`]
/// and must not put secret material in that error.
pub trait CredentialProvider: Send + Sync {
    /// Acquire a credential for the exact cloud, tenant, subscription, and
    /// audience selected by the HTTP execution context.
    fn acquire<'a>(&'a self, request: TokenRequest) -> CredentialFuture<'a>;
}

/// A bearer credential retained only inside the signing boundary.
///
/// The value is zeroized on drop and is intentionally redacted from `Debug`.
/// It has no `Display` implementation, which makes accidental formatting less
/// likely at call sites.
#[derive(Clone)]
pub struct BearerCredential {
    token: Zeroizing<String>,
    identity: Option<CredentialIdentity>,
}

impl BearerCredential {
    /// Validate and retain a bearer value supplied by a credential provider.
    pub fn new(token: impl Into<String>) -> Result<Self, CredentialError> {
        let token = token.into();
        if token.trim().is_empty() || token != token.trim() || token.chars().any(char::is_control) {
            return Err(CredentialError::EmptyToken);
        }
        Ok(Self {
            token: Zeroizing::new(token),
            identity: None,
        })
    }

    /// Construct an injected bearer credential with already validated
    /// principal and client identifiers.
    pub fn with_identity(
        token: impl Into<String>,
        principal_id: impl Into<String>,
        client_id: impl Into<String>,
    ) -> Result<Self, CredentialError> {
        let mut credential = Self::new(token)?;
        credential.identity = Some(crate::credential::CredentialIdentity::from_parts(
            principal_id,
            client_id,
        )?);
        Ok(credential)
    }

    /// Borrow the value for the short signing operation.
    pub fn secret(&self) -> &str {
        self.token.as_str()
    }

    fn from_access_token(token: &AccessToken) -> Result<Self, CredentialError> {
        let mut credential = Self::new(token.token())?;
        credential.identity = Some(token.identity().clone());
        Ok(credential)
    }

    fn identity(&self) -> Option<&CredentialIdentity> {
        self.identity.as_ref()
    }
}

impl fmt::Debug for BearerCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BearerCredential")
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Adapt the repository's Azure CLI broker to the transport credential seam.
impl CredentialProvider for AzureCliBroker {
    fn acquire<'a>(&'a self, request: TokenRequest) -> CredentialFuture<'a> {
        Box::pin(async move {
            let token = AzureCliBroker::acquire(self, request).await?;
            BearerCredential::from_access_token(&token)
        })
    }
}

/// Request and response resource limits for one HTTP exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpLimits {
    request_body_bytes: usize,
    response_body_bytes: usize,
    timeout: Duration,
    retry_policy: RetryPolicy,
}

impl HttpLimits {
    /// Construct explicit limits.  Request, response, and timeout limits must
    /// be non-zero; retry backoffs may be zero for deterministic tests.
    pub const fn new(
        request_body_bytes: usize,
        response_body_bytes: usize,
        timeout: Duration,
    ) -> Self {
        Self {
            request_body_bytes,
            response_body_bytes,
            timeout,
            retry_policy: RetryPolicy::new(
                DEFAULT_RETRY_MAX_ATTEMPTS,
                DEFAULT_RETRY_MAX_ELAPSED,
                DEFAULT_RETRY_INITIAL_BACKOFF,
                DEFAULT_RETRY_MAX_BACKOFF,
            ),
        }
    }

    /// Maximum request body size in bytes.
    pub const fn request_body_bytes(self) -> usize {
        self.request_body_bytes
    }

    /// Maximum response body size in bytes.
    pub const fn response_body_bytes(self) -> usize {
        self.response_body_bytes
    }

    /// Wall-clock timeout for the HTTP exchange.
    pub const fn timeout(self) -> Duration {
        self.timeout
    }

    /// Retry policy for reviewed read operations.
    pub const fn retry_policy(self) -> RetryPolicy {
        self.retry_policy
    }

    /// Replace the bounded retry policy.
    pub const fn with_retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    /// Alias for [`HttpLimits::with_retry_policy`].
    pub const fn with_retry(self, retry_policy: RetryPolicy) -> Self {
        self.with_retry_policy(retry_policy)
    }

    fn validate(self) -> Result<Self, HttpError> {
        if self.request_body_bytes == 0 {
            return Err(HttpError::InvalidLimits {
                field: "request body limit",
            });
        }
        if self.response_body_bytes == 0 || self.response_body_bytes > MAX_RESPONSE_BODY_LIMIT {
            return Err(HttpError::InvalidLimits {
                field: "response body limit",
            });
        }
        if self.timeout.is_zero() {
            return Err(HttpError::InvalidLimits { field: "timeout" });
        }
        self.retry_policy.validate()?;
        Ok(self)
    }
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self::new(
            DEFAULT_REQUEST_BODY_LIMIT,
            DEFAULT_RESPONSE_BODY_LIMIT,
            DEFAULT_HTTP_TIMEOUT,
        )
    }
}

/// Bounded retry controls for one policy-approved read operation.
///
/// `max_attempts` includes the initial request.  The elapsed-time bound covers
/// request attempts and backoff sleeps together.  A zero backoff is accepted
/// for deterministic tests, but production defaults use exponential delays.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    max_attempts: u32,
    max_elapsed: Duration,
    initial_backoff: Duration,
    max_backoff: Duration,
}

impl RetryPolicy {
    /// Construct explicit retry controls.
    pub const fn new(
        max_attempts: u32,
        max_elapsed: Duration,
        initial_backoff: Duration,
        max_backoff: Duration,
    ) -> Self {
        Self {
            max_attempts,
            max_elapsed,
            initial_backoff,
            max_backoff,
        }
    }

    /// Maximum number of attempts, including the first request.
    pub const fn max_attempts(self) -> u32 {
        self.max_attempts
    }

    /// Maximum elapsed time for all attempts and backoff sleeps.
    pub const fn max_elapsed(self) -> Duration {
        self.max_elapsed
    }

    /// Initial exponential-backoff delay.
    pub const fn initial_backoff(self) -> Duration {
        self.initial_backoff
    }

    /// Maximum delay for exponential backoff and `Retry-After`.
    pub const fn max_backoff(self) -> Duration {
        self.max_backoff
    }

    fn validate(self) -> Result<(), HttpError> {
        if self.max_attempts == 0 {
            return Err(HttpError::InvalidLimits {
                field: "retry attempt limit",
            });
        }
        if self.max_attempts > MAX_RETRY_ATTEMPTS {
            return Err(HttpError::InvalidLimits {
                field: "retry attempt limit",
            });
        }
        if self.max_elapsed.is_zero() {
            return Err(HttpError::InvalidLimits {
                field: "retry elapsed-time limit",
            });
        }
        if self.max_elapsed > MAX_RETRY_ELAPSED {
            return Err(HttpError::InvalidLimits {
                field: "retry elapsed-time limit",
            });
        }
        if self.initial_backoff > self.max_backoff {
            return Err(HttpError::InvalidLimits {
                field: "retry backoff limit",
            });
        }
        if self.max_backoff > MAX_RETRY_BACKOFF {
            return Err(HttpError::InvalidLimits {
                field: "retry backoff limit",
            });
        }
        Ok(())
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::new(
            DEFAULT_RETRY_MAX_ATTEMPTS,
            DEFAULT_RETRY_MAX_ELAPSED,
            DEFAULT_RETRY_INITIAL_BACKOFF,
            DEFAULT_RETRY_MAX_BACKOFF,
        )
    }
}

/// Descriptive alias for callers configuring the HTTP boundary.
pub type HttpRetryPolicy = RetryPolicy;

/// An exact reviewed ARM origin.
///
/// Production origins can only be created from the built-in cloud manifest.
/// The loopback constructor is an explicit test seam and rejects every
/// non-loopback host, so it cannot become a general arbitrary-origin escape
/// hatch.
#[derive(Clone, Eq, PartialEq)]
pub struct ArmOrigin {
    cloud: AzureCloud,
    url: Url,
    loopback_override: bool,
}

impl ArmOrigin {
    /// Construct the exact resource-manager origin from a reviewed manifest.
    pub fn for_cloud(cloud: AzureCloud) -> Result<Self, HttpError> {
        let manifest = cloud.manifest();
        let url = Url::parse(manifest.resource_manager())
            .map_err(|_| HttpError::InvalidManifestOrigin)?;
        if url.as_str() != manifest.resource_manager()
            || url.scheme() != "https"
            || url.host_str().is_none()
            || url.path() != "/"
            || url.username() != ""
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.port().is_some()
        {
            return Err(HttpError::InvalidManifestOrigin);
        }
        Ok(Self {
            cloud,
            url,
            loopback_override: false,
        })
    }

    /// Construct a loopback-only origin for a synthetic HTTP simulator.
    ///
    /// This is intentionally explicit and accepts only `localhost`, IPv4
    /// loopback, or IPv6 loopback hosts.  Production callers should use
    /// [`ArmOrigin::for_cloud`].
    pub fn loopback(cloud: AzureCloud, url: Url) -> Result<Self, HttpError> {
        let host = url.host_str().unwrap_or_default();
        let is_loopback = host.eq_ignore_ascii_case("localhost")
            || host == "127.0.0.1"
            || host == "[::1]"
            || host == "::1";
        if !is_loopback
            || !matches!(url.scheme(), "http" | "https")
            || url.path() != "/"
            || url.username() != ""
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(HttpError::InvalidLoopbackOrigin);
        }
        Ok(Self {
            cloud,
            url,
            loopback_override: true,
        })
    }

    /// Parse and construct a loopback-only origin from a URL string.
    pub fn loopback_from_str(cloud: AzureCloud, value: &str) -> Result<Self, HttpError> {
        let url = Url::parse(value).map_err(|_| HttpError::InvalidLoopbackOrigin)?;
        Self::loopback(cloud, url)
    }

    /// The selected cloud.
    pub const fn cloud(&self) -> AzureCloud {
        self.cloud
    }

    /// The exact URL used as the request origin.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The origin string, including its required trailing slash.
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    fn is_loopback_override(&self) -> bool {
        self.loopback_override
    }
}

/// An exact reviewed Log Analytics Query API origin.
///
/// It is a separate type from [`ArmOrigin`] so an ARM route can never be
/// redirected to the Logs audience or accidentally receive ARM's
/// `api-version` query serialization.
#[derive(Clone, Eq, PartialEq)]
pub struct LogsOrigin {
    cloud: AzureCloud,
    url: Url,
    loopback_override: bool,
}

impl LogsOrigin {
    /// Construct the exact Logs Query origin from the reviewed cloud manifest.
    pub fn for_cloud(cloud: AzureCloud) -> Result<Self, HttpError> {
        let manifest = cloud.manifest();
        let url = Url::parse(manifest.data_plane().logs_query())
            .map_err(|_| HttpError::InvalidManifestOrigin)?;
        if url.as_str() != manifest.data_plane().logs_query()
            || url.scheme() != "https"
            || url.host_str().is_none()
            || url.path() != "/"
            || url.username() != ""
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.port().is_some()
        {
            return Err(HttpError::InvalidManifestOrigin);
        }
        Ok(Self {
            cloud,
            url,
            loopback_override: false,
        })
    }

    /// Construct a loopback-only origin for a synthetic Logs API simulator.
    pub fn loopback(cloud: AzureCloud, url: Url) -> Result<Self, HttpError> {
        let host = url.host_str().unwrap_or_default();
        let is_loopback = host.eq_ignore_ascii_case("localhost")
            || host == "127.0.0.1"
            || host == "[::1]"
            || host == "::1";
        if !is_loopback
            || !matches!(url.scheme(), "http" | "https")
            || url.path() != "/"
            || url.username() != ""
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(HttpError::InvalidLoopbackOrigin);
        }
        Ok(Self {
            cloud,
            url,
            loopback_override: true,
        })
    }

    /// Parse a loopback-only Logs origin from a URL string.
    pub fn loopback_from_str(cloud: AzureCloud, value: &str) -> Result<Self, HttpError> {
        let url = Url::parse(value).map_err(|_| HttpError::InvalidLoopbackOrigin)?;
        Self::loopback(cloud, url)
    }

    /// The selected cloud.
    pub const fn cloud(&self) -> AzureCloud {
        self.cloud
    }

    /// The exact URL used as the request origin.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The origin string, including its required trailing slash.
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    fn is_loopback_override(&self) -> bool {
        self.loopback_override
    }
}

impl fmt::Debug for LogsOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LogsOrigin")
            .field("cloud", &self.cloud)
            .field("url", &self.url.as_str())
            .field("loopback_override", &self.loopback_override)
            .finish()
    }
}

impl fmt::Debug for ArmOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArmOrigin")
            .field("cloud", &self.cloud)
            .field("url", &self.url.as_str())
            .field("loopback_override", &self.loopback_override)
            .finish()
    }
}

/// An exact regional Azure Monitor Metrics origin.
#[derive(Clone, Eq, PartialEq)]
pub struct MetricsOrigin {
    cloud: AzureCloud,
    region: String,
    url: Url,
    loopback_override: bool,
}

impl MetricsOrigin {
    /// Construct the exact regional data-plane origin from the reviewed cloud
    /// manifest.
    pub fn for_cloud(cloud: AzureCloud, region: &str) -> Result<Self, HttpError> {
        let region = normalize_metrics_region(region)?;
        let manifest = cloud.manifest();
        let suffix = manifest.data_plane().metrics();
        let url = Url::parse(&format!("https://{region}.{suffix}/"))
            .map_err(|_| HttpError::InvalidManifestOrigin)?;
        if url.scheme() != "https"
            || url.path() != "/"
            || url.username() != ""
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.port().is_some()
        {
            return Err(HttpError::InvalidManifestOrigin);
        }
        Ok(Self {
            cloud,
            region,
            url,
            loopback_override: false,
        })
    }

    /// Construct a loopback-only origin for a synthetic metrics server.
    pub fn loopback(cloud: AzureCloud, region: &str, url: Url) -> Result<Self, HttpError> {
        let region = normalize_metrics_region(region)?;
        let host = url.host_str().unwrap_or_default();
        let is_loopback = host.eq_ignore_ascii_case("localhost")
            || host == "127.0.0.1"
            || host == "[::1]"
            || host == "::1";
        if !is_loopback
            || !matches!(url.scheme(), "http" | "https")
            || url.path() != "/"
            || url.username() != ""
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(HttpError::InvalidLoopbackOrigin);
        }
        Ok(Self {
            cloud,
            region,
            url,
            loopback_override: true,
        })
    }

    /// Parse and construct a loopback-only metrics origin.
    pub fn loopback_from_str(
        cloud: AzureCloud,
        region: &str,
        value: &str,
    ) -> Result<Self, HttpError> {
        let url = Url::parse(value).map_err(|_| HttpError::InvalidLoopbackOrigin)?;
        Self::loopback(cloud, region, url)
    }

    /// The selected cloud.
    pub const fn cloud(&self) -> AzureCloud {
        self.cloud
    }

    /// The normalized region encoded in this origin.
    pub fn region(&self) -> &str {
        &self.region
    }

    /// The exact URL used as the request origin.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The origin string, including its required trailing slash.
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    fn is_loopback_override(&self) -> bool {
        self.loopback_override
    }
}

impl fmt::Debug for MetricsOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MetricsOrigin")
            .field("cloud", &self.cloud)
            .field("region", &self.region)
            .field("url", &self.url.as_str())
            .field("loopback_override", &self.loopback_override)
            .finish()
    }
}

/// A request origin selected from one of the reviewed Azure service families.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestOrigin {
    /// Azure Resource Manager.
    Arm(ArmOrigin),
    /// Azure Monitor Metrics data plane.
    Metrics(MetricsOrigin),
}

impl RequestOrigin {
    /// The selected cloud.
    pub const fn cloud(&self) -> AzureCloud {
        match self {
            Self::Arm(origin) => origin.cloud(),
            Self::Metrics(origin) => origin.cloud(),
        }
    }

    /// The exact URL used as the request origin.
    pub fn url(&self) -> &Url {
        match self {
            Self::Arm(origin) => origin.url(),
            Self::Metrics(origin) => origin.url(),
        }
    }

    /// The origin string, including its required trailing slash.
    pub fn as_str(&self) -> &str {
        self.url().as_str()
    }

    fn is_loopback_override(&self) -> bool {
        match self {
            Self::Arm(origin) => origin.is_loopback_override(),
            Self::Metrics(origin) => origin.is_loopback_override(),
        }
    }
}

fn normalize_metrics_region(value: &str) -> Result<String, HttpError> {
    if value.is_empty()
        || value.len() > 63
        || value != value.trim()
        || value.chars().any(char::is_control)
    {
        return Err(HttpError::InvalidMetricsRegion);
    }
    let value = value.to_ascii_lowercase();
    if value == "global"
        || (value.len() >= 2
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && value
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && value
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric))
    {
        Ok(value)
    } else {
        Err(HttpError::InvalidMetricsRegion)
    }
}

/// Return the exact reviewed ARM origin URL for a cloud without making a
/// network request.
pub fn manifest_origin(cloud: AzureCloud) -> Result<Url, HttpError> {
    Ok(ArmOrigin::for_cloud(cloud)?.url().clone())
}

/// A caller request crossing the ARM boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct HttpRequest {
    purpose: RoutePurpose,
    method: HttpMethod,
    target: RelativeRequestTarget,
    api_version: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpRequest {
    /// Construct a request from an already parsed, canonical target.
    pub fn new(
        method: HttpMethod,
        target: RelativeRequestTarget,
        api_version: impl Into<String>,
    ) -> Result<Self, HttpError> {
        Self::for_purpose(RoutePurpose::Request, method, target, api_version)
    }

    /// Construct a request for a trusted, purpose-specific host operation.
    pub fn for_purpose(
        purpose: RoutePurpose,
        method: HttpMethod,
        target: RelativeRequestTarget,
        api_version: impl Into<String>,
    ) -> Result<Self, HttpError> {
        let api_version = api_version.into();
        validate_api_version(&api_version)?;
        Ok(Self {
            purpose,
            method,
            target,
            api_version,
            headers: Vec::new(),
            body: Vec::new(),
        })
    }

    /// Construct a request directly from a caller-supplied relative path.
    pub fn from_path(
        method: HttpMethod,
        path: &str,
        api_version: impl Into<String>,
    ) -> Result<Self, HttpError> {
        let target = RelativeRequestTarget::parse(path).map_err(HttpError::InvalidTarget)?;
        Self::new(method, target, api_version)
    }

    /// Convenience constructor for a GET request.
    pub fn get(path: &str, api_version: impl Into<String>) -> Result<Self, HttpError> {
        Self::from_path(HttpMethod::Get, path, api_version)
    }

    /// Convenience constructor for a POST request.
    pub fn post(path: &str, api_version: impl Into<String>) -> Result<Self, HttpError> {
        Self::from_path(HttpMethod::Post, path, api_version)
    }

    /// Set the request body.  The execution boundary enforces its configured
    /// size cap before requesting credentials or sending bytes.
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Add a caller header.  Sensitive and hop-by-hop names are rejected when
    /// the request is executed, before credentials are acquired.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// The HTTP method selected by the caller.
    pub const fn method(&self) -> HttpMethod {
        self.method
    }

    /// The trusted route entry point selected by the host.
    pub const fn purpose(&self) -> RoutePurpose {
        self.purpose
    }

    /// The canonical relative target.
    pub fn target(&self) -> &RelativeRequestTarget {
        &self.target
    }

    /// The separately supplied API version.
    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    /// The request body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpRequest")
            .field("purpose", &self.purpose)
            .field("method", &self.method)
            .field("target", &self.target.to_string())
            .field("api_version", &self.api_version)
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>(),
            )
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// A bounded response with status, selected non-secret headers, and raw body.
///
/// The body is intentionally bytes rather than an eagerly decoded JSON value:
/// ARM endpoints also return plain text, binary payloads, and error formats.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct HttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    #[serde(skip)]
    retry_count: u32,
}

impl HttpResponse {
    /// Construct a response from bounded parts.
    ///
    /// Embedders can use this for deterministic protocol tests; network
    /// execution still creates responses only after the transport limits run.
    pub fn from_parts(status: u16, headers: BTreeMap<String, String>, body: Vec<u8>) -> Self {
        Self {
            status,
            headers,
            body,
            retry_count: 0,
        }
    }

    /// HTTP status code.
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Selected safe response headers, keyed by lowercase header name.
    pub fn headers(&self) -> &BTreeMap<String, String> {
        &self.headers
    }

    /// Raw response body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Copy the raw response body into an owned vector.
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// Number of retry attempts made before this response was returned.
    pub const fn retry_count(&self) -> u32 {
        self.retry_count
    }

    fn with_retry_count(mut self, retry_count: u32) -> Self {
        self.retry_count = retry_count;
        self
    }
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body_len", &self.body.len())
            .field("retry_count", &self.retry_count)
            .finish()
    }
}

/// Immutable client configuration for one selected cloud binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpClientConfig {
    cloud: AzureCloud,
    subscription: SubscriptionId,
    tenant: TenantId,
    audience: TokenAudience,
    origin: RequestOrigin,
    policy: PolicyBundle,
    limits: HttpLimits,
}

impl HttpClientConfig {
    /// Build a production configuration using the exact cloud manifest origin.
    pub fn new(
        cloud: AzureCloud,
        subscription: SubscriptionId,
        tenant: TenantId,
        audience: TokenAudience,
        policy: PolicyBundle,
    ) -> Result<Self, HttpError> {
        let origin = ArmOrigin::for_cloud(cloud)?;
        Self::with_origin(cloud, subscription, tenant, audience, origin, policy)
    }

    /// Build a configuration with an explicit origin.  The only non-manifest
    /// origins accepted are loopback origins created by [`ArmOrigin::loopback`].
    pub fn with_origin(
        cloud: AzureCloud,
        subscription: SubscriptionId,
        tenant: TenantId,
        audience: TokenAudience,
        origin: ArmOrigin,
        policy: PolicyBundle,
    ) -> Result<Self, HttpError> {
        if audience != TokenAudience::Arm {
            return Err(HttpError::InvalidAudience);
        }
        Self::with_request_origin(
            cloud,
            subscription,
            tenant,
            audience,
            RequestOrigin::Arm(origin),
            policy,
        )
    }

    /// Build a metrics configuration with an exact regional origin.
    pub fn with_metrics_origin(
        cloud: AzureCloud,
        subscription: SubscriptionId,
        tenant: TenantId,
        origin: MetricsOrigin,
        policy: PolicyBundle,
    ) -> Result<Self, HttpError> {
        Self::with_request_origin(
            cloud,
            subscription,
            tenant,
            TokenAudience::Metrics,
            RequestOrigin::Metrics(origin),
            policy,
        )
    }

    fn with_request_origin(
        cloud: AzureCloud,
        subscription: SubscriptionId,
        tenant: TenantId,
        audience: TokenAudience,
        origin: RequestOrigin,
        policy: PolicyBundle,
    ) -> Result<Self, HttpError> {
        if origin.cloud() != cloud {
            return Err(HttpError::OriginCloudMismatch);
        }
        if !origin.is_loopback_override() {
            let expected = match audience {
                TokenAudience::Arm => RequestOrigin::Arm(ArmOrigin::for_cloud(cloud)?),
                TokenAudience::Metrics => match &origin {
                    RequestOrigin::Metrics(metrics) => {
                        RequestOrigin::Metrics(MetricsOrigin::for_cloud(cloud, metrics.region())?)
                    }
                    RequestOrigin::Arm(_) => return Err(HttpError::InvalidAudience),
                },
                TokenAudience::LogAnalytics => return Err(HttpError::InvalidAudience),
            };
            if origin != expected {
                return Err(HttpError::InvalidManifestOrigin);
            }
        }
        let limits = HttpLimits::default();
        Ok(Self {
            cloud,
            subscription,
            tenant,
            audience,
            origin,
            policy,
            limits,
        })
    }

    /// Build a configuration from an already resolved binding.
    pub fn from_binding(
        binding: &ResolvedCloudBinding,
        audience: TokenAudience,
        policy: PolicyBundle,
    ) -> Result<Self, HttpError> {
        Self::new(
            binding.cloud(),
            binding.subscription().clone(),
            binding.tenant().clone(),
            audience,
            policy,
        )
    }

    /// Replace the request/response limits.
    pub fn with_limits(mut self, limits: HttpLimits) -> Result<Self, HttpError> {
        self.limits = limits.validate()?;
        Ok(self)
    }

    /// Selected cloud.
    pub const fn cloud(&self) -> AzureCloud {
        self.cloud
    }

    /// Selected canonical subscription.
    pub fn subscription(&self) -> &SubscriptionId {
        &self.subscription
    }

    /// Selected tenant.
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Selected token audience.
    pub const fn audience(&self) -> TokenAudience {
        self.audience
    }

    /// Exact token resource selected for the cloud/audience pair.
    pub fn audience_resource(&self) -> &'static str {
        self.audience.resource(self.cloud)
    }

    /// Selected exact origin.
    pub fn origin(&self) -> &RequestOrigin {
        &self.origin
    }

    /// Selected immutable route policy.
    pub fn policy(&self) -> &PolicyBundle {
        &self.policy
    }

    /// Selected limits.
    pub const fn limits(&self) -> HttpLimits {
        self.limits
    }
}

/// A host-owned Logs Query request. It has no caller header or API-version
/// fields: the route and JSON body are fixed by the semantic host operation.
#[derive(Clone, Eq, PartialEq)]
pub struct LogsHttpRequest {
    target: RelativeRequestTarget,
    body: Vec<u8>,
}

impl LogsHttpRequest {
    /// Construct a Logs Query request from a canonical route target and JSON.
    pub fn new(target: RelativeRequestTarget, body: impl Into<Vec<u8>>) -> Result<Self, HttpError> {
        if !target.query().is_empty() {
            return Err(HttpError::InvalidRequestUrl);
        }
        Ok(Self {
            target,
            body: body.into(),
        })
    }

    /// The canonical relative route target.
    pub fn target(&self) -> &RelativeRequestTarget {
        &self.target
    }

    /// The host-owned JSON body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for LogsHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LogsHttpRequest")
            .field("target", &self.target.to_string())
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// An ARM client that performs only policy-approved requests.
pub struct HttpClient {
    http: Client,
    credential_provider: Arc<dyn CredentialProvider>,
    config: HttpClientConfig,
}

impl HttpClient {
    /// Construct a client using the exact reviewed cloud-manifest origin.
    pub fn new(
        credential_provider: Arc<dyn CredentialProvider>,
        cloud: AzureCloud,
        subscription: SubscriptionId,
        tenant: TenantId,
        audience: TokenAudience,
        policy: PolicyBundle,
    ) -> Result<Self, HttpError> {
        let config = HttpClientConfig::new(cloud, subscription, tenant, audience, policy)?;
        Self::from_config(credential_provider, config)
    }

    /// Construct a client from a selected immutable configuration.
    pub fn from_config(
        credential_provider: Arc<dyn CredentialProvider>,
        config: HttpClientConfig,
    ) -> Result<Self, HttpError> {
        let http = Client::builder()
            // Be explicit even though the workspace's reqwest dependency has
            // no default proxy feature: this boundary must not inherit a
            // process-wide proxy configuration if features change later.
            .no_proxy()
            .redirect(RedirectPolicy::none())
            .timeout(config.limits.timeout())
            .build()
            .map_err(|_| HttpError::ClientBuild)?;
        Ok(Self {
            http,
            credential_provider,
            config,
        })
    }

    /// Construct a client with a loopback-only origin for a synthetic server.
    pub fn with_loopback_origin(
        credential_provider: Arc<dyn CredentialProvider>,
        cloud: AzureCloud,
        subscription: SubscriptionId,
        tenant: TenantId,
        audience: TokenAudience,
        origin: ArmOrigin,
        policy: PolicyBundle,
    ) -> Result<Self, HttpError> {
        let config =
            HttpClientConfig::with_origin(cloud, subscription, tenant, audience, origin, policy)?;
        Self::from_config(credential_provider, config)
    }

    /// Construct a metrics client for an explicit region while retaining the
    /// immutable subscription, tenant, policy, credential provider, and test
    /// origin selected for this client.
    pub fn metrics_for_region(&self, region: &str) -> Result<Self, HttpError> {
        let origin = match &self.config.origin {
            RequestOrigin::Arm(origin) if origin.is_loopback_override() => {
                MetricsOrigin::loopback_from_str(self.config.cloud, region, origin.as_str())?
            }
            RequestOrigin::Metrics(origin) if origin.is_loopback_override() => {
                MetricsOrigin::loopback_from_str(self.config.cloud, region, origin.as_str())?
            }
            RequestOrigin::Arm(_) | RequestOrigin::Metrics(_) => {
                MetricsOrigin::for_cloud(self.config.cloud, region)?
            }
        };
        let config = HttpClientConfig::with_metrics_origin(
            self.config.cloud,
            self.config.subscription.clone(),
            self.config.tenant.clone(),
            origin,
            self.config.policy.clone(),
        )?
        .with_limits(self.config.limits)?;
        Self::from_config(Arc::clone(&self.credential_provider), config)
    }

    /// The immutable execution configuration.
    pub fn config(&self) -> &HttpClientConfig {
        &self.config
    }

    /// Execute one request after target, header, body, route, and subscription
    /// checks.  Credential acquisition is deliberately after every denial
    /// which can be determined locally.
    pub async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        self.execute_with_identity_pin(request, None).await
    }

    /// Execute one request while pinning Azure CLI principal/client identity
    /// to the supplied context lifetime.
    pub async fn execute_with_identity_pin(
        &self,
        request: HttpRequest,
        identity_pin: Option<&CredentialIdentityPin>,
    ) -> Result<HttpResponse, HttpError> {
        self.execute_with_identity_pin_and_response_limit(
            request,
            identity_pin,
            self.config.limits.response_body_bytes(),
        )
        .await
    }

    /// Execute through the ordinary policy/signing boundary while narrowing
    /// the response-body cap for one internally owned operation.
    ///
    /// This is the paging seam: it can only lower the immutable configured
    /// limit and therefore cannot widen an ordinary caller's transport budget.
    async fn execute_with_identity_pin_and_response_limit(
        &self,
        request: HttpRequest,
        identity_pin: Option<&CredentialIdentityPin>,
        response_body_limit: usize,
    ) -> Result<HttpResponse, HttpError> {
        if response_body_limit == 0
            || response_body_limit > self.config.limits.response_body_bytes()
        {
            return Err(HttpError::InvalidLimits {
                field: "response body limit",
            });
        }
        validate_api_version(&request.api_version)?;
        if request.body.len() > self.config.limits.request_body_bytes() {
            return Err(HttpError::RequestBodyTooLarge {
                limit: self.config.limits.request_body_bytes(),
            });
        }
        validate_headers(&request.headers)?;

        // Route classification is a hard gate.  There is intentionally no
        // generic GET/POST fallback for paths absent from the reviewed bundle.
        let route = self
            .config
            .policy
            .classify(
                self.config.cloud,
                request.purpose,
                request.method,
                &request.target,
                &request.api_version,
            )
            .map_err(HttpError::PolicyDenied)?;
        let retryable_route = retryable_route(route);

        verify_subscription_scope(&request.target, self.config.subscription.as_str())?;

        let url = build_request_url(&self.config.origin, &request.target, &request.api_version)?;

        let mut token_request = TokenRequest::new(
            self.config.cloud,
            self.config.tenant.clone(),
            self.config.subscription.clone(),
            self.config.audience,
        );
        if let Some(identity_pin) = identity_pin {
            token_request = token_request.with_identity_pin(identity_pin);
        }
        let credential = self
            .credential_provider
            .acquire(token_request.clone())
            .await
            .map_err(HttpError::Credential)?;
        if let (Some(identity_pin), Some(identity)) = (identity_pin, credential.identity()) {
            identity_pin
                .check(&token_request, identity)
                .await
                .map_err(HttpError::Credential)?;
        }

        let mut auth_bytes = Vec::with_capacity(b"Bearer ".len() + credential.secret().len());
        auth_bytes.extend_from_slice(b"Bearer ");
        auth_bytes.extend_from_slice(credential.secret().as_bytes());
        let authorization = HeaderValue::from_bytes(&auth_bytes)
            .map_err(|_| HttpError::Credential(CredentialError::EmptyToken));
        auth_bytes.zeroize();
        let authorization = authorization?;

        let method = reqwest_method(request.method);
        let mut headers = Vec::with_capacity(request.headers.len());
        for (name, value) in request.headers {
            // Header validation has already run and this conversion cannot
            // contain the bearer value, which is held in a separate object.
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| HttpError::InvalidHeader { name })?;
            let value =
                HeaderValue::from_str(&value).map_err(|_| HttpError::InvalidHeaderValue {
                    name: name.to_string(),
                })?;
            headers.push((name, value));
        }
        execute_with_retries(
            &self.http,
            PreparedRequest {
                method,
                url,
                authorization,
                headers,
                body: request.body,
                retryable: retryable_route,
            },
            self.config.limits,
            response_body_limit,
        )
        .await
    }
}

/// Immutable client configuration for the direct Logs Query data plane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogsHttpClientConfig {
    cloud: AzureCloud,
    subscription: SubscriptionId,
    tenant: TenantId,
    audience: TokenAudience,
    origin: LogsOrigin,
    policy: PolicyBundle,
    limits: HttpLimits,
}

impl LogsHttpClientConfig {
    /// Build a production configuration using the exact Logs origin.
    pub fn new(
        cloud: AzureCloud,
        subscription: SubscriptionId,
        tenant: TenantId,
        audience: TokenAudience,
        policy: PolicyBundle,
    ) -> Result<Self, HttpError> {
        let origin = LogsOrigin::for_cloud(cloud)?;
        Self::with_origin(cloud, subscription, tenant, audience, origin, policy)
    }

    /// Build a configuration with a manifest origin or explicit loopback seam.
    pub fn with_origin(
        cloud: AzureCloud,
        subscription: SubscriptionId,
        tenant: TenantId,
        audience: TokenAudience,
        origin: LogsOrigin,
        policy: PolicyBundle,
    ) -> Result<Self, HttpError> {
        if audience != TokenAudience::LogAnalytics {
            return Err(HttpError::InvalidAudience);
        }
        if origin.cloud() != cloud {
            return Err(HttpError::OriginCloudMismatch);
        }
        if !origin.is_loopback_override() {
            let expected = LogsOrigin::for_cloud(cloud)?;
            if origin != expected {
                return Err(HttpError::InvalidManifestOrigin);
            }
        }
        let limits = HttpLimits::default();
        Ok(Self {
            cloud,
            subscription,
            tenant,
            audience,
            origin,
            policy,
            limits,
        })
    }

    /// Build a configuration from a resolved context binding.
    pub fn from_binding(
        binding: &ResolvedCloudBinding,
        policy: PolicyBundle,
    ) -> Result<Self, HttpError> {
        Self::new(
            binding.cloud(),
            binding.subscription().clone(),
            binding.tenant().clone(),
            TokenAudience::LogAnalytics,
            policy,
        )
    }

    /// Replace request/response limits.
    pub fn with_limits(mut self, limits: HttpLimits) -> Result<Self, HttpError> {
        self.limits = limits.validate()?;
        Ok(self)
    }

    /// Selected cloud.
    pub const fn cloud(&self) -> AzureCloud {
        self.cloud
    }

    /// Selected subscription.
    pub fn subscription(&self) -> &SubscriptionId {
        &self.subscription
    }

    /// Selected tenant.
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Selected token audience.
    pub const fn audience(&self) -> TokenAudience {
        self.audience
    }

    /// Exact token resource selected for the cloud.
    pub fn audience_resource(&self) -> &'static str {
        self.audience.resource(self.cloud)
    }

    /// Selected exact Logs origin.
    pub fn origin(&self) -> &LogsOrigin {
        &self.origin
    }

    /// Selected immutable route policy.
    pub fn policy(&self) -> &PolicyBundle {
        &self.policy
    }

    /// Selected limits.
    pub const fn limits(&self) -> HttpLimits {
        self.limits
    }
}

/// A dedicated direct Logs Query client. It never appends an ARM
/// `api-version` query parameter and never accepts caller-controlled headers.
pub struct LogsHttpClient {
    http: Client,
    credential_provider: Arc<dyn CredentialProvider>,
    config: LogsHttpClientConfig,
}

impl LogsHttpClient {
    /// Construct a client using the exact reviewed Logs origin.
    pub fn new(
        credential_provider: Arc<dyn CredentialProvider>,
        cloud: AzureCloud,
        subscription: SubscriptionId,
        tenant: TenantId,
        policy: PolicyBundle,
    ) -> Result<Self, HttpError> {
        let config = LogsHttpClientConfig::new(
            cloud,
            subscription,
            tenant,
            TokenAudience::LogAnalytics,
            policy,
        )?;
        Self::from_config(credential_provider, config)
    }

    /// Construct a client from an immutable Logs configuration.
    pub fn from_config(
        credential_provider: Arc<dyn CredentialProvider>,
        config: LogsHttpClientConfig,
    ) -> Result<Self, HttpError> {
        let http = Client::builder()
            .no_proxy()
            .redirect(RedirectPolicy::none())
            .timeout(config.limits.timeout())
            .build()
            .map_err(|_| HttpError::ClientBuild)?;
        Ok(Self {
            http,
            credential_provider,
            config,
        })
    }

    /// Construct a client against an explicit loopback-only origin.
    pub fn with_loopback_origin(
        credential_provider: Arc<dyn CredentialProvider>,
        cloud: AzureCloud,
        subscription: SubscriptionId,
        tenant: TenantId,
        origin: LogsOrigin,
        policy: PolicyBundle,
    ) -> Result<Self, HttpError> {
        let config = LogsHttpClientConfig::with_origin(
            cloud,
            subscription,
            tenant,
            TokenAudience::LogAnalytics,
            origin,
            policy,
        )?;
        Self::from_config(credential_provider, config)
    }

    /// The immutable execution configuration.
    pub fn config(&self) -> &LogsHttpClientConfig {
        &self.config
    }

    /// Execute one host-owned Logs Query request.
    pub async fn execute(&self, request: LogsHttpRequest) -> Result<HttpResponse, HttpError> {
        self.execute_with_identity_pin(request, None).await
    }

    /// Execute while pinning the credential identity to a context lifetime.
    pub async fn execute_with_identity_pin(
        &self,
        request: LogsHttpRequest,
        identity_pin: Option<&CredentialIdentityPin>,
    ) -> Result<HttpResponse, HttpError> {
        if request.body.len() > self.config.limits.request_body_bytes() {
            return Err(HttpError::RequestBodyTooLarge {
                limit: self.config.limits.request_body_bytes(),
            });
        }
        let route = self
            .config
            .policy
            .classify(
                self.config.cloud,
                RoutePurpose::LogsQuery,
                HttpMethod::Post,
                &request.target,
                LOGS_QUERY_API_VERSION,
            )
            .map_err(HttpError::PolicyDenied)?;
        let retryable_route = retryable_route(route);
        let url = build_logs_request_url(&self.config.origin, &request.target)?;

        let mut token_request = TokenRequest::new(
            self.config.cloud,
            self.config.tenant.clone(),
            self.config.subscription.clone(),
            self.config.audience,
        );
        if let Some(identity_pin) = identity_pin {
            token_request = token_request.with_identity_pin(identity_pin);
        }
        let credential = self
            .credential_provider
            .acquire(token_request.clone())
            .await
            .map_err(HttpError::Credential)?;
        if let (Some(identity_pin), Some(identity)) = (identity_pin, credential.identity()) {
            identity_pin
                .check(&token_request, identity)
                .await
                .map_err(HttpError::Credential)?;
        }

        let mut auth_bytes = Vec::with_capacity(b"Bearer ".len() + credential.secret().len());
        auth_bytes.extend_from_slice(b"Bearer ");
        auth_bytes.extend_from_slice(credential.secret().as_bytes());
        let authorization = HeaderValue::from_bytes(&auth_bytes)
            .map_err(|_| HttpError::Credential(CredentialError::EmptyToken));
        auth_bytes.zeroize();
        let authorization = authorization?;

        execute_with_retries(
            &self.http,
            PreparedRequest {
                method: Method::POST,
                url,
                authorization,
                headers: vec![(
                    HeaderName::from_static("content-type"),
                    HeaderValue::from_static("application/json"),
                )],
                body: request.body,
                retryable: retryable_route,
            },
            self.config.limits,
            self.config.limits.response_body_bytes(),
        )
        .await
    }
}

fn validate_api_version(value: &str) -> Result<(), HttpError> {
    if value.trim().is_empty()
        || value != value.trim()
        || value.chars().any(char::is_control)
        || value.contains(['?', '#', '&', '='])
    {
        return Err(HttpError::InvalidApiVersion);
    }
    Ok(())
}

fn verify_subscription_scope(
    target: &RelativeRequestTarget,
    selected_subscription: &str,
) -> Result<(), HttpError> {
    let segments = target.segments();
    if segments
        .first()
        .is_some_and(|segment| segment.eq_ignore_ascii_case("subscriptions"))
        && let Some(target_subscription) = segments.get(1)
        && !target_subscription.eq_ignore_ascii_case(selected_subscription)
    {
        return Err(HttpError::SubscriptionMismatch);
    }
    Ok(())
}

fn build_request_url(
    origin: &RequestOrigin,
    target: &RelativeRequestTarget,
    api_version: &str,
) -> Result<Url, HttpError> {
    let canonical_target = target.to_string();
    let mut url = origin
        .url()
        .join(&canonical_target)
        .map_err(|_| HttpError::InvalidRequestUrl)?;

    // `RelativeRequestTarget` rejects caller-provided api-version pairs.  Add
    // exactly one separately serialized pair after canonicalizing all other
    // query values, and verify that URL joining did not leave the origin.
    url.query_pairs_mut()
        .append_pair("api-version", api_version);
    if !same_origin(&url, origin.url()) || url.username() != "" || url.password().is_some() {
        return Err(HttpError::OriginMismatch);
    }
    Ok(url)
}

fn build_logs_request_url(
    origin: &LogsOrigin,
    target: &RelativeRequestTarget,
) -> Result<Url, HttpError> {
    let url = origin
        .url()
        .join(&target.to_string())
        .map_err(|_| HttpError::InvalidRequestUrl)?;
    if !same_origin(&url, origin.url())
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(HttpError::OriginMismatch);
    }
    Ok(url)
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme().eq_ignore_ascii_case(right.scheme())
        && left.host_str().is_some_and(|left_host| {
            right
                .host_str()
                .is_some_and(|right_host| left_host.eq_ignore_ascii_case(right_host))
        })
        && left.port_or_known_default() == right.port_or_known_default()
}

fn validate_headers(headers: &[(String, String)]) -> Result<(), HttpError> {
    let mut seen = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        let parsed = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| HttpError::InvalidHeader { name: name.clone() })?;
        let lower = parsed.as_str().to_ascii_lowercase();
        if forbidden_request_header(&lower) {
            return Err(HttpError::ForbiddenHeader { name: lower });
        }
        if value.chars().any(char::is_control) {
            return Err(HttpError::InvalidHeaderValue { name: lower });
        }
        if seen.iter().any(|existing: &String| existing == &lower) {
            return Err(HttpError::DuplicateHeader { name: lower });
        }
        seen.push(lower);
    }
    Ok(())
}

fn forbidden_request_header(name: &str) -> bool {
    matches!(
        name,
        "authorization"
            | "proxy-authorization"
            | "host"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "forwarded"
            | "via"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-port"
            | "x-forwarded-proto"
            | "x-forwarded-server"
            | "x-real-ip"
            | "cookie"
            | "set-cookie"
    )
}

fn reqwest_method(method: HttpMethod) -> Method {
    match method {
        HttpMethod::Get => Method::GET,
        HttpMethod::Post => Method::POST,
        HttpMethod::Put => Method::PUT,
        HttpMethod::Patch => Method::PATCH,
        HttpMethod::Delete => Method::DELETE,
    }
}

fn safe_response_headers(headers: &reqwest::header::HeaderMap) -> BTreeMap<String, String> {
    const SAFE_HEADERS: &[&str] = &[
        "content-length",
        "content-type",
        "etag",
        "last-modified",
        "request-id",
        "retry-after",
        "x-ms-correlation-request-id",
        "x-ms-ratelimit-remaining-subscription-reads",
        "x-ms-request-id",
    ];

    headers
        .iter()
        .filter_map(|(name, value)| {
            let name = name.as_str();
            if !SAFE_HEADERS.contains(&name) || value.len() > MAX_SAFE_HEADER_VALUE_BYTES {
                return None;
            }
            let value = value.to_str().ok()?;
            if name == "retry-after" {
                if value.len() > MAX_SAFE_RETRY_AFTER_BYTES {
                    return None;
                }
                let delay = parse_retry_after(value)?;
                if delay > MAX_RETRY_BACKOFF {
                    return None;
                }
            }
            (!value.chars().any(char::is_control)).then(|| (name.to_owned(), value.to_owned()))
        })
        .collect()
}

async fn read_response_body(
    response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, HttpError> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| HttpError::ResponseRead)?;
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(HttpError::ResponseBodyTooLarge { limit });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

struct PreparedRequest {
    method: Method,
    url: Url,
    authorization: HeaderValue,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: Vec<u8>,
    retryable: bool,
}

async fn execute_with_retries(
    client: &Client,
    request: PreparedRequest,
    limits: HttpLimits,
    response_body_limit: usize,
) -> Result<HttpResponse, HttpError> {
    let retry_policy = limits.retry_policy();
    let started = std::time::Instant::now();
    let mut attempts = 0_u32;
    let mut last_response = None;

    loop {
        let elapsed = started.elapsed();
        let Some(remaining) = retry_policy.max_elapsed().checked_sub(elapsed) else {
            return last_response
                .map(|response: HttpResponse| {
                    Ok(response.with_retry_count(attempts.saturating_sub(1)))
                })
                .unwrap_or(Err(HttpError::Timeout));
        };
        if remaining.is_zero() {
            return last_response
                .map(|response: HttpResponse| {
                    Ok(response.with_retry_count(attempts.saturating_sub(1)))
                })
                .unwrap_or(Err(HttpError::Timeout));
        }
        attempts = attempts.saturating_add(1);
        let attempt_timeout = limits.timeout().min(remaining);
        let response = time::timeout(
            attempt_timeout,
            send_once(client, &request, response_body_limit),
        )
        .await
        .map_err(|_| retry_failed(HttpError::Timeout, attempts.saturating_sub(1)))?
        .map_err(|error| retry_failed(error, attempts.saturating_sub(1)))?;

        let retry_count = attempts.saturating_sub(1);
        let retryable_status = response.status == 429 || (500..=599).contains(&response.status);
        if !request.retryable || !retryable_status || attempts >= retry_policy.max_attempts() {
            return Ok(response.with_retry_count(retry_count));
        }

        let delay = retry_delay(&retry_policy, retry_count, &response);
        let remaining = retry_policy
            .max_elapsed()
            .checked_sub(started.elapsed())
            .unwrap_or_default();
        if delay >= remaining {
            return Ok(response.with_retry_count(retry_count));
        }
        last_response = Some(response);
        time::sleep(delay).await;
    }
}

async fn send_once(
    client: &Client,
    request: &PreparedRequest,
    body_limit: usize,
) -> Result<HttpResponse, HttpError> {
    let mut builder = client
        .request(request.method.clone(), request.url.clone())
        .header(AUTHORIZATION, request.authorization.clone());
    for (name, value) in &request.headers {
        builder = builder.header(name.clone(), value.clone());
    }
    let response = builder
        .body(request.body.clone())
        .send()
        .await
        .map_err(|_| HttpError::RequestSend)?;
    if response.status().is_redirection() {
        return Err(HttpError::RedirectDenied);
    }

    let status = response.status();
    let headers = safe_response_headers(response.headers());
    if response
        .content_length()
        .is_some_and(|length| length > body_limit as u64)
    {
        return Err(HttpError::ResponseBodyTooLarge { limit: body_limit });
    }

    let body = read_response_body(response, body_limit).await?;
    Ok(HttpResponse::from_parts(status.as_u16(), headers, body))
}

fn retry_failed(error: HttpError, retry_count: u32) -> HttpError {
    if retry_count == 0 {
        error
    } else {
        HttpError::RetryFailed {
            retry_count,
            source: Box::new(error),
        }
    }
}

fn retryable_route(route: &crate::policy::ReviewedRoute) -> bool {
    if route.tier() == crate::policy::ArmTier::Write {
        return false;
    }
    matches!(
        (route.purpose(), route.method()),
        (RoutePurpose::Request, HttpMethod::Get)
            | (RoutePurpose::Internal, HttpMethod::Get)
            | (RoutePurpose::MetricsSingle, HttpMethod::Get)
            | (RoutePurpose::ResourceGraph, HttpMethod::Post)
            | (RoutePurpose::MetricsBatch, HttpMethod::Post)
            | (RoutePurpose::LogsQuery, HttpMethod::Post)
    )
}

fn retry_delay(policy: &RetryPolicy, retry_count: u32, response: &HttpResponse) -> Duration {
    response
        .headers()
        .get("retry-after")
        .and_then(|value| parse_retry_after(value))
        .map(|delay| delay.min(policy.max_backoff()))
        .unwrap_or_else(|| exponential_backoff(policy, retry_count))
}

fn parse_retry_after(value: &str) -> Option<Duration> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    parse_http_date(value)
}

fn parse_http_date(value: &str) -> Option<Duration> {
    let mut comma_parts = value.splitn(2, ',');
    comma_parts.next()?;
    let fields = comma_parts.next()?.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 5 || fields[4] != "GMT" {
        return None;
    }
    if fields[0].len() > 2 || fields[2].len() != 4 {
        return None;
    }
    let day = fields[0].parse::<u32>().ok()?;
    let month = match fields[1] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year = fields[2].parse::<i64>().ok()?;
    let mut time_parts = fields[3].split(':');
    let hour = time_parts.next()?.parse::<u64>().ok()?;
    let minute = time_parts.next()?.parse::<u64>().ok()?;
    let second = time_parts.next()?.parse::<u64>().ok()?;
    if time_parts.next().is_some() || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    if days < 0 {
        return Some(Duration::ZERO);
    }
    let seconds = u64::try_from(days).ok()?.checked_mul(86_400)?;
    let seconds = seconds
        .checked_add(hour.checked_mul(3_600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)?;
    let target = UNIX_EPOCH.checked_add(Duration::from_secs(seconds))?;
    match target.duration_since(SystemTime::now()) {
        Ok(delay) => Some(delay),
        Err(_) => Some(Duration::ZERO),
    }
}

fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) {
        return None;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day == 0 || day > month_days {
        return None;
    }
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 {
        year / 400
    } else {
        (year - 399) / 400
    };
    let year_of_era = year - era * 400;
    let month_prime = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

fn exponential_backoff(policy: &RetryPolicy, retry_count: u32) -> Duration {
    let exponent = retry_count.min(127);
    let multiplier = 1_u128.checked_shl(exponent).unwrap_or(u128::MAX);
    let nanos = policy
        .initial_backoff()
        .as_nanos()
        .saturating_mul(multiplier)
        .min(policy.max_backoff().as_nanos());
    duration_from_nanos(nanos)
}

fn duration_from_nanos(nanos: u128) -> Duration {
    let seconds = nanos / 1_000_000_000;
    if seconds > u128::from(u64::MAX) {
        return Duration::MAX;
    }
    Duration::new(seconds as u64, (nanos % 1_000_000_000) as u32)
}

/// Errors returned by the HTTP boundary.
///
/// Variants intentionally contain no request body, response body, URL query,
/// credential, or transport-library source error.  This keeps both `Display`
/// and derived `Debug` safe for logs and structured MCP results.
#[derive(Debug, Error)]
pub enum HttpError {
    /// A caller target failed the relative-target parser.
    #[error("invalid request target")]
    InvalidTarget(#[source] InvalidRequestTarget),
    /// The separately supplied API version is malformed.
    #[error("invalid api-version")]
    InvalidApiVersion,
    /// The selected audience is not the reviewed audience for the selected Azure service.
    #[error("invalid token audience for the selected Azure service")]
    InvalidAudience,
    /// A metrics region is not a valid reviewed regional host label.
    #[error("invalid metrics region")]
    InvalidMetricsRegion,
    /// The built-in cloud manifest contained an unusable origin.
    #[error("invalid reviewed cloud origin")]
    InvalidManifestOrigin,
    /// A loopback test origin was not a root loopback URL.
    #[error("invalid loopback test origin")]
    InvalidLoopbackOrigin,
    /// The origin and selected cloud were inconsistent.
    #[error("request origin does not belong to the selected cloud")]
    OriginCloudMismatch,
    /// The final joined URL no longer has the selected origin.
    #[error("request origin validation failed")]
    OriginMismatch,
    /// URL construction failed after canonicalization.
    #[error("request URL could not be constructed")]
    InvalidRequestUrl,
    /// A reviewed route did not permit this method, target, and API version.
    #[error("request denied by route policy: {0}")]
    PolicyDenied(PolicyDenial),
    /// A subscription-scoped target did not use the selected subscription.
    #[error("request target subscription does not match the selected subscription")]
    SubscriptionMismatch,
    /// A caller attempted to supply a credential, routing, or hop-by-hop header.
    #[error("request header `{name}` is not permitted")]
    ForbiddenHeader { name: String },
    /// A caller header name was invalid.
    #[error("request header `{name}` is invalid")]
    InvalidHeader { name: String },
    /// A caller header value was invalid.
    #[error("request header value for `{name}` is invalid")]
    InvalidHeaderValue { name: String },
    /// Duplicate request headers are rejected to keep signing deterministic.
    #[error("request header `{name}` was supplied more than once")]
    DuplicateHeader { name: String },
    /// The request body exceeded the configured cap.
    #[error("request body exceeds the configured limit of {limit} bytes")]
    RequestBodyTooLarge { limit: usize },
    /// The response body exceeded the configured cap.
    #[error("response body exceeds the configured limit of {limit} bytes")]
    ResponseBodyTooLarge { limit: usize },
    /// A zero-valued execution limit was supplied.
    #[error("invalid HTTP limit: {field}")]
    InvalidLimits { field: &'static str },
    /// The reqwest client could not be built.
    #[error("HTTP client could not be built")]
    ClientBuild,
    /// Credential acquisition failed.  The wrapped error is sanitized by the
    /// credential module and contains no token material.
    #[error("credential acquisition failed: {0}")]
    Credential(#[source] CredentialError),
    /// The network exchange exceeded the configured timeout.
    #[error("HTTP request timed out")]
    Timeout,
    /// The request could not be sent.
    #[error("HTTP request could not be sent")]
    RequestSend,
    /// A later transport failure occurred after one or more transient
    /// responses.  The retry count remains available to the host audit record.
    #[error("HTTP request failed after {retry_count} retries: {source}")]
    RetryFailed {
        retry_count: u32,
        #[source]
        source: Box<HttpError>,
    },
    /// The response body could not be read.
    #[error("HTTP response body could not be read")]
    ResponseRead,
    /// Redirects are never followed or accepted as an execution result.
    #[error("HTTP redirects are not permitted")]
    RedirectDenied,
}

impl HttpError {
    /// Number of retries already attempted before this error was returned.
    pub const fn retry_count(&self) -> u32 {
        match self {
            Self::RetryFailed { retry_count, .. } => *retry_count,
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    const SUBSCRIPTION: &str = "11111111-1111-1111-1111-111111111111";
    const OTHER_SUBSCRIPTION: &str = "22222222-2222-2222-2222-222222222222";
    const TENANT: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const API_VERSION: &str = "2024-01-01";
    const AUDIENCE: TokenAudience = TokenAudience::Arm;

    #[derive(Default)]
    struct FakeCredentials {
        calls: AtomicUsize,
        requests: Mutex<Vec<TokenRequest>>,
    }

    impl CredentialProvider for FakeCredentials {
        fn acquire<'a>(&'a self, request: TokenRequest) -> CredentialFuture<'a> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.requests.lock().await.push(request);
                BearerCredential::new("synthetic-token")
            })
        }
    }

    fn policy() -> PolicyBundle {
        PolicyBundle::new(
            "test-http-v1",
            vec![
                crate::policy::ReviewedRoute::new(
                    AzureCloud::AzureCloud,
                    RoutePurpose::Request,
                    HttpMethod::Get,
                    "/subscriptions/{subscription}/resourceGroups/{group}",
                    [API_VERSION],
                    "Microsoft.Resources/subscriptions/resourceGroups/read",
                    crate::policy::ArmTier::Inspect,
                )
                .expect("valid route"),
                crate::policy::ReviewedRoute::new(
                    AzureCloud::AzureCloud,
                    RoutePurpose::ResourceGraph,
                    HttpMethod::Post,
                    "/subscriptions/{subscription}/providers/Microsoft.ResourceGraph/resources",
                    [API_VERSION],
                    "Microsoft.ResourceGraph/resources/action",
                    crate::policy::ArmTier::Inspect,
                )
                .expect("valid route"),
            ],
        )
        .expect("valid policy")
    }

    fn ids() -> (SubscriptionId, TenantId) {
        (
            SubscriptionId::new(SUBSCRIPTION).expect("valid subscription"),
            TenantId::new(TENANT).expect("valid tenant"),
        )
    }

    async fn loopback_server(response: &'static str) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("one loopback request");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let count = stream.read(&mut buffer).await.expect("read request");
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..count]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");
            request
        });
        (format!("http://{address}/"), task)
    }

    async fn loopback_sequence_server(
        responses: Vec<&'static str>,
    ) -> (String, tokio::task::JoinHandle<Vec<Vec<u8>>>) {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let task = tokio::spawn(async move {
            let mut requests = Vec::with_capacity(responses.len());
            for response in responses {
                let (mut stream, _) = listener.accept().await.expect("loopback request");
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                loop {
                    let count = stream.read(&mut buffer).await.expect("read request");
                    if count == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..count]);
                    if let Some(header_end) = request
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .map(|position| position + 4)
                    {
                        let content_length = String::from_utf8_lossy(&request[..header_end])
                            .lines()
                            .find_map(|line| {
                                line.strip_prefix("Content-Length:")
                                    .or_else(|| line.strip_prefix("content-length:"))
                                    .and_then(|value| value.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if request.len() >= header_end.saturating_add(content_length) {
                            break;
                        }
                    }
                }
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write response");
                requests.push(request);
            }
            requests
        });
        (format!("http://{address}/"), task)
    }

    async fn paging_loopback_server<F>(
        responses: F,
    ) -> (String, tokio::task::JoinHandle<Vec<Vec<u8>>>)
    where
        F: FnOnce(&str) -> Vec<(String, Duration)>,
    {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let base = format!("http://{address}/");
        let responses = responses(&base);
        let task = tokio::spawn(async move {
            let mut requests = Vec::with_capacity(responses.len());
            for (response, delay) in responses {
                let (mut stream, _) = listener.accept().await.expect("loopback request");
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                loop {
                    let count = stream.read(&mut buffer).await.expect("read request");
                    if count == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..count]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                time::sleep(delay).await;
                // A paging elapsed-time test can close the client before the
                // delayed synthetic response is written.
                let _ = stream.write_all(response.as_bytes()).await;
                requests.push(request);
            }
            requests
        });
        (base, task)
    }

    fn json_http_response(body: &str, remaining_reads: Option<u64>) -> String {
        let rate_header = remaining_reads
            .map(|value| format!("X-MS-Ratelimit-Remaining-Subscription-Reads: {value}\r\n"))
            .unwrap_or_default();
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{rate_header}Content-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    fn paging_policy() -> PolicyBundle {
        PolicyBundle::new(
            "test-paging-v1",
            vec![
                crate::policy::ReviewedRoute::new(
                    AzureCloud::AzureCloud,
                    RoutePurpose::Request,
                    HttpMethod::Get,
                    "/subscriptions/{subscription}/resourceGroups/{group}",
                    [API_VERSION],
                    "Microsoft.Resources/subscriptions/resourceGroups/read",
                    crate::policy::ArmTier::Inspect,
                )
                .expect("valid route")
                .with_query_parameters(["$skiptoken", "marker"])
                .expect("continuation query"),
                crate::policy::ReviewedRoute::new(
                    AzureCloud::AzureCloud,
                    RoutePurpose::Request,
                    HttpMethod::Get,
                    "/subscriptions/{subscription}/providers/{namespace}",
                    [API_VERSION],
                    "Microsoft.Resources/subscriptions/providers/read",
                    crate::policy::ArmTier::Inspect,
                )
                .expect("valid escape route"),
            ],
        )
        .expect("valid paging policy")
    }

    fn paging_request() -> HttpRequest {
        HttpRequest::get(
            &format!("/subscriptions/{SUBSCRIPTION}/resourceGroups/prod"),
            API_VERSION,
        )
        .expect("paging request")
    }

    fn client_for(provider: Arc<FakeCredentials>, origin: &str) -> HttpClient {
        let (subscription, tenant) = ids();
        let origin =
            ArmOrigin::loopback_from_str(AzureCloud::AzureCloud, origin).expect("loopback origin");
        HttpClient::with_loopback_origin(
            provider,
            AzureCloud::AzureCloud,
            subscription,
            tenant,
            AUDIENCE,
            origin,
            policy(),
        )
        .expect("client")
    }

    fn client_for_with_limits(
        provider: Arc<FakeCredentials>,
        origin: &str,
        policy: PolicyBundle,
        limits: HttpLimits,
    ) -> HttpClient {
        let (subscription, tenant) = ids();
        let origin =
            ArmOrigin::loopback_from_str(AzureCloud::AzureCloud, origin).expect("loopback origin");
        let config = HttpClientConfig::with_origin(
            AzureCloud::AzureCloud,
            subscription,
            tenant,
            AUDIENCE,
            origin,
            policy,
        )
        .expect("config")
        .with_limits(limits)
        .expect("limits");
        HttpClient::from_config(provider, config).expect("client")
    }

    fn fast_retry_limits(max_attempts: u32) -> HttpLimits {
        HttpLimits::new(1024, 1024, Duration::from_secs(2)).with_retry_policy(RetryPolicy::new(
            max_attempts,
            Duration::from_secs(1),
            Duration::ZERO,
            Duration::from_millis(50),
        ))
    }

    #[test]
    fn manifest_origins_are_exact_and_do_not_contact_the_clouds() {
        let commercial = ArmOrigin::for_cloud(AzureCloud::AzureCloud).expect("commercial origin");
        let government =
            ArmOrigin::for_cloud(AzureCloud::AzureUSGovernment).expect("government origin");
        assert_eq!(commercial.as_str(), "https://management.azure.com/");
        assert_eq!(government.as_str(), "https://management.usgovcloudapi.net/");
        assert_eq!(
            manifest_origin(AzureCloud::AzureCloud)
                .expect("commercial URL")
                .as_str(),
            "https://management.azure.com/"
        );
        assert_eq!(
            manifest_origin(AzureCloud::AzureUSGovernment)
                .expect("government URL")
                .as_str(),
            "https://management.usgovcloudapi.net/"
        );
    }

    #[test]
    fn metrics_origins_are_exact_per_cloud_and_region() {
        let commercial = MetricsOrigin::for_cloud(AzureCloud::AzureCloud, "EastUS")
            .expect("commercial metrics origin");
        let government = MetricsOrigin::for_cloud(AzureCloud::AzureUSGovernment, "usgov-virginia")
            .expect("government metrics origin");
        assert_eq!(
            commercial.as_str(),
            "https://eastus.metrics.monitor.azure.com/"
        );
        assert_eq!(
            government.as_str(),
            "https://usgov-virginia.metrics.monitor.azure.us/"
        );
        assert!(matches!(
            MetricsOrigin::for_cloud(AzureCloud::AzureCloud, "east_us"),
            Err(HttpError::InvalidMetricsRegion)
        ));
        assert!(matches!(
            MetricsOrigin::for_cloud(AzureCloud::AzureCloud, "https://evil.example"),
            Err(HttpError::InvalidMetricsRegion)
        ));
    }

    #[tokio::test]
    async fn retries_transient_statuses_for_reviewed_gets_and_reports_count() {
        let (base, server) = loopback_sequence_server(vec![
            "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 0\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
        ])
        .await;
        let provider = Arc::new(FakeCredentials::default());
        let client =
            client_for_with_limits(provider.clone(), &base, policy(), fast_retry_limits(3));
        let request = HttpRequest::get(
            &format!("/subscriptions/{SUBSCRIPTION}/resourceGroups/prod"),
            API_VERSION,
        )
        .expect("request");

        let response = client.execute(request).await.expect("successful retry");
        let requests = server.await.expect("server task");
        assert_eq!(requests.len(), 3);
        assert_eq!(response.status(), 200);
        assert_eq!(response.retry_count(), 2);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn retries_read_only_resource_graph_post_but_not_generic_post() {
        let (base, server) = loopback_sequence_server(vec![
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
        ])
        .await;
        let client = client_for_with_limits(
            Arc::new(FakeCredentials::default()),
            &base,
            policy(),
            fast_retry_limits(2),
        );
        let target = RelativeRequestTarget::parse(
            "/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.ResourceGraph/resources",
        )
        .expect("graph target");
        let request = HttpRequest::for_purpose(
            RoutePurpose::ResourceGraph,
            HttpMethod::Post,
            target,
            API_VERSION,
        )
        .expect("request")
        .with_body(br#"{"query":"resources | take 1"}"#.to_vec());

        let response = client.execute(request).await.expect("successful retry");
        let requests = server.await.expect("server task");
        assert_eq!(requests.len(), 2);
        assert_eq!(response.retry_count(), 1);

        let (base, server) = loopback_sequence_server(vec![
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
        ])
        .await;
        let generic_post_policy = PolicyBundle::new(
            "test-http-post-v1",
            vec![
                crate::policy::ReviewedRoute::new(
                    AzureCloud::AzureCloud,
                    RoutePurpose::Request,
                    HttpMethod::Post,
                    "/subscriptions/{subscription}/resourceGroups/{group}/action",
                    [API_VERSION],
                    "Microsoft.Resources/resourceGroups/action",
                    crate::policy::ArmTier::Inspect,
                )
                .expect("valid route"),
            ],
        )
        .expect("valid policy");
        let client = client_for_with_limits(
            Arc::new(FakeCredentials::default()),
            &base,
            generic_post_policy,
            fast_retry_limits(2),
        );
        let target = RelativeRequestTarget::parse(&format!(
            "/subscriptions/{SUBSCRIPTION}/resourceGroups/prod/action"
        ))
        .expect("target");
        let request =
            HttpRequest::for_purpose(RoutePurpose::Request, HttpMethod::Post, target, API_VERSION)
                .expect("request");
        let response = client.execute(request).await.expect("response");
        let requests = server.await.expect("server task");
        assert_eq!(requests.len(), 1);
        assert_eq!(response.status(), 503);
        assert_eq!(response.retry_count(), 0);
    }

    #[tokio::test]
    async fn retry_attempts_are_capped() {
        let (base, server) = loopback_sequence_server(vec![
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n",
        ])
        .await;
        let client = client_for_with_limits(
            Arc::new(FakeCredentials::default()),
            &base,
            policy(),
            fast_retry_limits(2),
        );
        let request = HttpRequest::get(
            &format!("/subscriptions/{SUBSCRIPTION}/resourceGroups/prod"),
            API_VERSION,
        )
        .expect("request");
        let response = client.execute(request).await.expect("bounded response");
        let requests = server.await.expect("server task");
        assert_eq!(requests.len(), 2);
        assert_eq!(response.status(), 502);
        assert_eq!(response.retry_count(), 1);
    }

    #[tokio::test]
    async fn auth_and_other_client_errors_are_never_retried() {
        for response_text in [
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
        ] {
            let (base, server) = loopback_sequence_server(vec![response_text]).await;
            let client = client_for_with_limits(
                Arc::new(FakeCredentials::default()),
                &base,
                policy(),
                fast_retry_limits(3),
            );
            let request = HttpRequest::get(
                &format!("/subscriptions/{SUBSCRIPTION}/resourceGroups/prod"),
                API_VERSION,
            )
            .expect("request");
            let response = client.execute(request).await.expect("response");
            let requests = server.await.expect("server task");
            assert_eq!(requests.len(), 1);
            assert_eq!(response.retry_count(), 0);
        }
    }

    #[test]
    fn retry_after_is_bounded_and_backoff_is_exponential() {
        let mut headers = BTreeMap::new();
        headers.insert("retry-after".to_owned(), "100".to_owned());
        let response = HttpResponse::from_parts(429, headers, Vec::new());
        let policy = RetryPolicy::new(
            3,
            Duration::from_secs(1),
            Duration::from_millis(20),
            Duration::from_millis(50),
        );
        assert_eq!(
            retry_delay(&policy, 1, &response),
            Duration::from_millis(50)
        );

        let response = HttpResponse::from_parts(503, BTreeMap::new(), Vec::new());
        assert_eq!(
            retry_delay(&policy, 0, &response),
            Duration::from_millis(20)
        );
        assert_eq!(
            retry_delay(&policy, 1, &response),
            Duration::from_millis(40)
        );
        assert_eq!(
            retry_delay(&policy, 2, &response),
            Duration::from_millis(50)
        );

        let mut headers = BTreeMap::new();
        headers.insert(
            "retry-after".to_owned(),
            "Sun, 06 Nov 1994 08:49:37 GMT".to_owned(),
        );
        let response = HttpResponse::from_parts(429, headers, Vec::new());
        assert_eq!(retry_delay(&policy, 1, &response), Duration::ZERO);
    }

    #[test]
    fn safe_headers_keep_only_bounded_retry_after_values() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "retry-after",
            reqwest::header::HeaderValue::from_static("31"),
        );
        assert!(!safe_response_headers(&headers).contains_key("retry-after"));

        headers.insert(
            "retry-after",
            reqwest::header::HeaderValue::from_static("30"),
        );
        assert_eq!(
            safe_response_headers(&headers).get("retry-after"),
            Some(&"30".to_owned())
        );
    }

    #[test]
    fn retry_policy_rejects_unbounded_controls() {
        for policy in [
            RetryPolicy::new(
                MAX_RETRY_ATTEMPTS + 1,
                Duration::from_secs(1),
                Duration::ZERO,
                Duration::ZERO,
            ),
            RetryPolicy::new(
                1,
                MAX_RETRY_ELAPSED + Duration::from_nanos(1),
                Duration::ZERO,
                Duration::ZERO,
            ),
            RetryPolicy::new(
                1,
                Duration::from_secs(1),
                Duration::ZERO,
                MAX_RETRY_BACKOFF + Duration::from_nanos(1),
            ),
        ] {
            assert!(matches!(
                HttpLimits::new(1, 1, Duration::from_secs(1))
                    .with_retry_policy(policy)
                    .validate(),
                Err(HttpError::InvalidLimits { .. })
            ));
        }
    }

    #[tokio::test]
    async fn retry_transport_errors_preserve_prior_retry_count() {
        let (base, server) =
            loopback_server("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n").await;
        let client = client_for_with_limits(
            Arc::new(FakeCredentials::default()),
            &base,
            policy(),
            fast_retry_limits(2),
        );
        let request = HttpRequest::get(
            &format!("/subscriptions/{SUBSCRIPTION}/resourceGroups/prod"),
            API_VERSION,
        )
        .expect("request");
        let error = client
            .execute(request)
            .await
            .expect_err("second attempt fails");
        let _ = server.await.expect("first response server");
        assert_eq!(error.retry_count(), 1);
        assert!(matches!(error, HttpError::RetryFailed { .. }));
    }

    #[tokio::test]
    async fn bounded_paging_follows_same_route_and_retains_page_transport_facts() {
        let (base, server) = paging_loopback_server(|base| {
            let first = serde_json::json!({
                "value": [{"id": 1}],
                "nextLink": format!(
                    "{base}subscriptions/{SUBSCRIPTION}/resourceGroups/prod?%24skiptoken=second&api-version={API_VERSION}"
                )
            })
            .to_string();
            let second = serde_json::json!({"value": [{"id": 2}]}).to_string();
            vec![
                (
                    "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 0\r\nContent-Length: 0\r\n\r\n"
                        .to_owned(),
                    Duration::ZERO,
                ),
                (json_http_response(&first, Some(99)), Duration::ZERO),
                (json_http_response(&second, Some(98)), Duration::ZERO),
            ]
        })
        .await;
        let provider = Arc::new(FakeCredentials::default());
        let client = client_for_with_limits(
            provider.clone(),
            &base,
            paging_policy(),
            fast_retry_limits(2),
        );

        let response = client
            .execute_paged(paging_request(), PagingLimits::default())
            .await
            .expect("bounded pages");
        let requests = server.await.expect("paging server");
        assert_eq!(requests.len(), 3);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            response.items(),
            &[serde_json::json!({"id": 1}), serde_json::json!({"id": 2})]
        );
        assert_eq!(response.pages().len(), 2);
        assert_eq!(response.retry_count(), 1);
        assert_eq!(response.pages()[0].retry_count(), 1);
        assert_eq!(response.pages()[0].remaining_subscription_reads(), Some(99));
        assert_eq!(response.pages()[1].remaining_subscription_reads(), Some(98));
        assert_eq!(response.pages()[0].item_count(), 1);
        assert!(response.response_body_bytes() > 0);
        let second_request = String::from_utf8_lossy(&requests[2]);
        assert!(second_request.contains(
            "GET /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/prod?%24skiptoken=second&api-version=2024-01-01 HTTP/1.1"
        ));
    }

    #[tokio::test]
    async fn paging_cycle_detection_uses_the_effective_canonical_target() {
        let (base, server) = paging_loopback_server(|base| {
            let first = serde_json::json!({
                "value": [{"id": 1}],
                "nextLink": format!(
                    "{base}subscriptions/{SUBSCRIPTION}/resourceGroups/prod?marker=%61&%24skiptoken=second&api-version={API_VERSION}"
                )
            })
            .to_string();
            let second = serde_json::json!({
                "value": [{"id": 2}],
                "nextLink": format!(
                    "{base}subscriptions/{SUBSCRIPTION}/resourceGroups/prod?%24skiptoken=second&marker=a&api-version={API_VERSION}"
                )
            })
            .to_string();
            vec![
                (json_http_response(&first, None), Duration::ZERO),
                (json_http_response(&second, None), Duration::ZERO),
            ]
        })
        .await;
        let provider = Arc::new(FakeCredentials::default());
        let client = client_for_with_limits(
            provider.clone(),
            &base,
            paging_policy(),
            fast_retry_limits(1),
        );

        assert!(matches!(
            client
                .execute_paged(paging_request(), PagingLimits::default())
                .await,
            Err(PagingError::ContinuationCycle)
        ));
        assert_eq!(server.await.expect("cycle server").len(), 2);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn paged_upstream_status_preserves_final_retry_count() {
        let (base, server) = paging_loopback_server(|_| {
            vec![
                (
                    "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n".to_owned(),
                    Duration::ZERO,
                ),
                (
                    "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n".to_owned(),
                    Duration::ZERO,
                ),
            ]
        })
        .await;
        let provider = Arc::new(FakeCredentials::default());
        let client = client_for_with_limits(
            provider.clone(),
            &base,
            paging_policy(),
            fast_retry_limits(2),
        );

        let error = client
            .execute_paged(paging_request(), PagingLimits::default())
            .await
            .expect_err("final status is an error");
        assert_eq!(error.retry_count(), 1);
        assert!(matches!(
            error,
            PagingError::UpstreamStatus {
                status: 503,
                retry_count: 1
            }
        ));
        assert_eq!(server.await.expect("status server").len(), 2);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn paging_rejects_cross_origin_continuations_before_a_second_credential() {
        let (base, server) = paging_loopback_server(|_| {
            let body = serde_json::json!({
                "value": [{"id": 1}],
                "nextLink": format!(
                    "http://127.0.0.1:9/subscriptions/{SUBSCRIPTION}/resourceGroups/prod?%24skiptoken=second&api-version={API_VERSION}"
                )
            })
            .to_string();
            vec![(json_http_response(&body, None), Duration::ZERO)]
        })
        .await;
        let provider = Arc::new(FakeCredentials::default());
        let client = client_for_with_limits(
            provider.clone(),
            &base,
            paging_policy(),
            fast_retry_limits(1),
        );

        assert!(matches!(
            client
                .execute_paged(paging_request(), PagingLimits::default())
                .await,
            Err(PagingError::ContinuationOriginMismatch)
        ));
        assert_eq!(server.await.expect("paging server").len(), 1);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn paging_rejects_a_continuation_into_another_reviewed_route() {
        let (base, server) = paging_loopback_server(|base| {
            let body = serde_json::json!({
                "value": [{"id": 1}],
                "nextLink": format!(
                    "{base}subscriptions/{SUBSCRIPTION}/providers/Microsoft.Compute?api-version={API_VERSION}"
                )
            })
            .to_string();
            vec![(json_http_response(&body, None), Duration::ZERO)]
        })
        .await;
        let provider = Arc::new(FakeCredentials::default());
        let client = client_for_with_limits(
            provider.clone(),
            &base,
            paging_policy(),
            fast_retry_limits(1),
        );

        assert!(matches!(
            client
                .execute_paged(paging_request(), PagingLimits::default())
                .await,
            Err(PagingError::ContinuationRouteMismatch)
        ));
        assert_eq!(server.await.expect("paging server").len(), 1);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn paging_enforces_page_item_and_aggregate_byte_caps() {
        let (base, server) = paging_loopback_server(|base| {
            let body = serde_json::json!({
                "value": [{"id": 1}],
                "nextLink": format!(
                    "{base}subscriptions/{SUBSCRIPTION}/resourceGroups/prod?%24skiptoken=second&api-version={API_VERSION}"
                )
            })
            .to_string();
            vec![(json_http_response(&body, None), Duration::ZERO)]
        })
        .await;
        let client = client_for_with_limits(
            Arc::new(FakeCredentials::default()),
            &base,
            paging_policy(),
            fast_retry_limits(1),
        );
        let limits = PagingLimits::new(1, 10, 1024, Duration::from_secs(1));
        assert!(matches!(
            client.execute_paged(paging_request(), limits).await,
            Err(PagingError::PageLimitExceeded { limit: 1 })
        ));
        assert_eq!(server.await.expect("page-cap server").len(), 1);

        let (base, server) = paging_loopback_server(|_| {
            let body = serde_json::json!({"value": [{"id": 1}, {"id": 2}]}).to_string();
            vec![(json_http_response(&body, None), Duration::ZERO)]
        })
        .await;
        let client = client_for_with_limits(
            Arc::new(FakeCredentials::default()),
            &base,
            paging_policy(),
            fast_retry_limits(1),
        );
        let limits = PagingLimits::new(2, 1, 1024, Duration::from_secs(1));
        assert!(matches!(
            client.execute_paged(paging_request(), limits).await,
            Err(PagingError::ItemLimitExceeded { limit: 1 })
        ));
        assert_eq!(server.await.expect("item-cap server").len(), 1);

        let body = serde_json::json!({"value": [{"id": 1}]}).to_string();
        let byte_limit = body.len() - 1;
        let expected_body = body.clone();
        let (base, server) = paging_loopback_server(move |_| {
            vec![(json_http_response(&expected_body, None), Duration::ZERO)]
        })
        .await;
        let client = client_for_with_limits(
            Arc::new(FakeCredentials::default()),
            &base,
            paging_policy(),
            fast_retry_limits(1),
        );
        let limits = PagingLimits::new(2, 10, byte_limit, Duration::from_secs(1));
        assert!(matches!(
            client.execute_paged(paging_request(), limits).await,
            Err(PagingError::ByteLimitExceeded { limit }) if limit == byte_limit
        ));
        assert_eq!(server.await.expect("byte-cap server").len(), 1);
    }

    #[tokio::test]
    async fn paging_narrows_transport_buffering_to_the_remaining_byte_budget() {
        let paging_limit = 32;
        let (base, server) = paging_loopback_server(|_| {
            let body = serde_json::json!({
                "value": [],
                "padding": "x".repeat(256)
            })
            .to_string();
            vec![(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}"
                ),
                Duration::ZERO,
            )]
        })
        .await;
        let provider = Arc::new(FakeCredentials::default());
        let transport_limits =
            HttpLimits::new(1024, 1024, Duration::from_secs(1)).with_retry_policy(
                RetryPolicy::new(1, Duration::from_secs(1), Duration::ZERO, Duration::ZERO),
            );
        let client =
            client_for_with_limits(provider.clone(), &base, paging_policy(), transport_limits);
        assert!(client.config().limits().response_body_bytes() > paging_limit);
        let limits = PagingLimits::new(2, 10, paging_limit, Duration::from_secs(1));

        assert!(matches!(
            client.execute_paged(paging_request(), limits).await,
            Err(PagingError::ByteLimitExceeded { limit }) if limit == paging_limit
        ));
        assert_eq!(server.await.expect("byte-bound server").len(), 1);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn paging_elapsed_cap_covers_the_initial_exchange() {
        let (base, server) = paging_loopback_server(|_| {
            let body = serde_json::json!({"value": []}).to_string();
            vec![(json_http_response(&body, None), Duration::from_millis(100))]
        })
        .await;
        let provider = Arc::new(FakeCredentials::default());
        let client = client_for_with_limits(
            provider.clone(),
            &base,
            paging_policy(),
            fast_retry_limits(1),
        );
        let limits = PagingLimits::new(2, 10, 1024, Duration::from_millis(10));
        assert!(matches!(
            client.execute_paged(paging_request(), limits).await,
            Err(PagingError::ElapsedLimitExceeded)
        ));
        assert_eq!(server.await.expect("elapsed-cap server").len(), 1);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn paging_rejects_unbounded_limits_before_credentials_or_network() {
        let (base, server) = paging_loopback_server(|_| {
            vec![(json_http_response(r#"{"value":[]}"#, None), Duration::ZERO)]
        })
        .await;
        let provider = Arc::new(FakeCredentials::default());
        let client = client_for_with_limits(
            provider.clone(),
            &base,
            paging_policy(),
            fast_retry_limits(1),
        );
        let limits = PagingLimits::new(MAX_PAGING_PAGES + 1, 1, 1, Duration::from_millis(1));
        assert!(matches!(
            client.execute_paged(paging_request(), limits).await,
            Err(PagingError::InvalidLimits {
                field: "page limit"
            })
        ));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[test]
    fn http_limits_reject_response_caps_above_the_absolute_ceiling() {
        assert!(matches!(
            HttpLimits::new(1, MAX_RESPONSE_BODY_LIMIT + 1, Duration::from_secs(1)).validate(),
            Err(HttpError::InvalidLimits {
                field: "response body limit"
            })
        ));
    }

    #[tokio::test]
    async fn metrics_loopback_uses_data_plane_audience_and_batch_route() {
        let (base, server) = loopback_server(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        )
        .await;
        let provider = Arc::new(FakeCredentials::default());
        let (subscription, tenant) = ids();
        let origin = MetricsOrigin::loopback_from_str(
            AzureCloud::AzureUSGovernment,
            "usgov-virginia",
            &base,
        )
        .expect("metrics loopback origin");
        let client = HttpClient::from_config(
            provider.clone(),
            HttpClientConfig::with_metrics_origin(
                AzureCloud::AzureUSGovernment,
                subscription,
                tenant,
                origin,
                crate::routes::v0_policy().expect("policy"),
            )
            .expect("metrics config"),
        )
        .expect("metrics client");
        let target = RelativeRequestTarget::parse(
            "/subscriptions/11111111-1111-1111-1111-111111111111/metrics:getBatch?metricnamespace=Microsoft.Compute&metricnames=Percentage%20CPU",
        )
        .expect("batch target");
        let request = HttpRequest::for_purpose(
            RoutePurpose::MetricsBatch,
            HttpMethod::Post,
            target,
            crate::routes::METRICS_API_VERSION,
        )
        .expect("request")
        .with_header("Content-Type", "application/json")
        .with_body(br#"{"resourceids":["/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.Compute/virtualMachines/vm"]}"#.to_vec());
        client.execute(request).await.expect("metrics response");
        let raw_request_bytes = server.await.expect("server task");
        let raw_request = String::from_utf8_lossy(&raw_request_bytes);
        assert!(raw_request.contains("POST /subscriptions/11111111-1111-1111-1111-111111111111/metrics%3AgetBatch?metricnamespace=Microsoft.Compute&metricnames=Percentage+CPU&api-version=2023-10-01 HTTP/1.1"));
        let requests = provider.requests.lock().await;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].cloud, AzureCloud::AzureUSGovernment);
        assert_eq!(requests[0].audience, TokenAudience::Metrics);
        assert_eq!(requests[0].resource(), "https://metrics.monitor.azure.us/");
    }

    #[tokio::test]
    async fn loopback_request_is_signed_with_explicit_identity_and_audience() {
        let (base, server) = loopback_server(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-MS-Request-ID: req-1\r\nContent-Length: 2\r\n\r\nok",
        )
        .await;
        let provider = Arc::new(FakeCredentials::default());
        let client = client_for(provider.clone(), &base);
        let request = HttpRequest::get(
            &format!("/subscriptions/{SUBSCRIPTION}/resourceGroups/prod"),
            API_VERSION,
        )
        .expect("request");

        let response = client.execute(request).await.expect("successful response");
        let raw_request = server.await.expect("server task");
        let raw_request = String::from_utf8_lossy(&raw_request);
        assert!(raw_request.contains("GET /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/prod?api-version=2024-01-01 HTTP/1.1"));
        assert!(raw_request.contains("authorization: Bearer synthetic-token"));
        assert_eq!(response.status(), 200);
        assert_eq!(response.body(), b"ok");
        assert_eq!(
            response.headers().get("x-ms-request-id"),
            Some(&"req-1".to_owned())
        );

        let requests = provider.requests.lock().await;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].cloud, AzureCloud::AzureCloud);
        assert_eq!(requests[0].tenant_id.as_str(), TENANT);
        assert_eq!(requests[0].subscription_id.as_str(), SUBSCRIPTION);
        assert_eq!(requests[0].audience, TokenAudience::Arm);
    }

    #[test]
    fn logs_manifest_origins_are_exact_and_separate_from_arm() {
        let commercial = LogsOrigin::for_cloud(AzureCloud::AzureCloud).expect("commercial logs");
        let government =
            LogsOrigin::for_cloud(AzureCloud::AzureUSGovernment).expect("government logs");
        assert_eq!(commercial.as_str(), "https://api.loganalytics.azure.com/");
        assert_eq!(government.as_str(), "https://api.loganalytics.us/");
        assert_eq!(
            TokenAudience::LogAnalytics.resource(AzureCloud::AzureCloud),
            "https://api.loganalytics.io"
        );
        assert_eq!(
            TokenAudience::LogAnalytics.resource(AzureCloud::AzureUSGovernment),
            "https://api.loganalytics.us"
        );
    }

    #[tokio::test]
    async fn local_denials_happen_before_credential_acquisition() {
        let (base, server) = loopback_server("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        let provider = Arc::new(FakeCredentials::default());
        let client = client_for(provider.clone(), &base);

        let unknown_route =
            HttpRequest::get("/providers/Microsoft.Compute/virtualMachines", API_VERSION)
                .expect("request");
        assert!(matches!(
            client.execute(unknown_route).await,
            Err(HttpError::PolicyDenied(PolicyDenial::UnknownRoute))
        ));

        let mismatched_subscription = HttpRequest::get(
            &format!("/subscriptions/{OTHER_SUBSCRIPTION}/resourceGroups/prod"),
            API_VERSION,
        )
        .expect("request");
        assert!(matches!(
            client.execute(mismatched_subscription).await,
            Err(HttpError::SubscriptionMismatch)
        ));

        let unknown_api_version = HttpRequest::get(
            &format!("/subscriptions/{SUBSCRIPTION}/resourceGroups/prod"),
            "2099-01-01",
        )
        .expect("request");
        assert!(matches!(
            client.execute(unknown_api_version).await,
            Err(HttpError::PolicyDenied(PolicyDenial::UnknownRoute))
        ));

        let forbidden_header = HttpRequest::get(
            &format!("/subscriptions/{SUBSCRIPTION}/resourceGroups/prod"),
            API_VERSION,
        )
        .expect("request")
        .with_header("Authorization", "Bearer should-not-be-accepted");
        assert!(matches!(
            client.execute(forbidden_header).await,
            Err(HttpError::ForbiddenHeader { .. })
        ));

        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn body_and_response_caps_and_redirects_are_fail_closed() {
        let (base, server) =
            loopback_server("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody").await;
        let provider = Arc::new(FakeCredentials::default());
        let client = client_for(provider.clone(), &base);
        let config = client
            .config()
            .clone()
            .with_limits(HttpLimits::new(2, 3, Duration::from_secs(5)))
            .expect("limits");
        let limited = HttpClient::from_config(provider.clone(), config).expect("limited client");
        let request = HttpRequest::post(
            &format!("/subscriptions/{SUBSCRIPTION}/providers/Microsoft.ResourceGraph/resources"),
            API_VERSION,
        )
        .expect("request")
        .with_body(b"toolong".to_vec());
        assert!(matches!(
            limited.execute(request).await,
            Err(HttpError::RequestBodyTooLarge { limit: 2 })
        ));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        server.abort();

        let (base, server) =
            loopback_server("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody").await;
        let provider = Arc::new(FakeCredentials::default());
        let config = HttpClientConfig::with_origin(
            AzureCloud::AzureCloud,
            ids().0,
            ids().1,
            AUDIENCE,
            ArmOrigin::loopback_from_str(AzureCloud::AzureCloud, &base).expect("origin"),
            policy(),
        )
        .expect("config")
        .with_limits(HttpLimits::new(100, 3, Duration::from_secs(5)))
        .expect("limits");
        let limited = HttpClient::from_config(provider.clone(), config).expect("client");
        let request = HttpRequest::get(
            &format!("/subscriptions/{SUBSCRIPTION}/resourceGroups/prod"),
            API_VERSION,
        )
        .expect("request");
        assert!(matches!(
            limited.execute(request).await,
            Err(HttpError::ResponseBodyTooLarge { limit: 3 })
        ));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        server.abort();

        let (base, server) = loopback_server(
            "HTTP/1.1 302 Found\r\nLocation: https://management.azure.com/elsewhere\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        let provider = Arc::new(FakeCredentials::default());
        let client = client_for(provider.clone(), &base);
        let request = HttpRequest::get(
            &format!("/subscriptions/{SUBSCRIPTION}/resourceGroups/prod"),
            API_VERSION,
        )
        .expect("request");
        assert!(matches!(
            client.execute(request).await,
            Err(HttpError::RedirectDenied)
        ));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[test]
    fn token_material_never_appears_in_debug_or_display_errors() {
        let token = "ultra-secret-token";
        let credential = BearerCredential::new(token).expect("credential");
        assert!(!format!("{credential:?}").contains(token));

        let error = HttpError::Credential(CredentialError::EmptyToken);
        assert!(!format!("{error:?}").contains(token));
        assert!(!error.to_string().contains(token));
        let response = HttpResponse {
            status: 200,
            headers: BTreeMap::new(),
            body: token.as_bytes().to_vec(),
            retry_count: 0,
        };
        assert!(!format!("{response:?}").contains(token));
    }

    #[test]
    fn loopback_origin_rejects_non_loopback_injection() {
        let url = Url::parse("https://management.azure.com/").expect("URL");
        assert!(matches!(
            ArmOrigin::loopback(AzureCloud::AzureCloud, url),
            Err(HttpError::InvalidLoopbackOrigin)
        ));
    }
}
