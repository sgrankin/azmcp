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
use std::time::Duration;

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
use crate::target::{InvalidRequestTarget, RelativeRequestTarget};

/// The default upper bound for a request body.
pub const DEFAULT_REQUEST_BODY_LIMIT: usize = 1024 * 1024;
/// The default upper bound for a response body.
pub const DEFAULT_RESPONSE_BODY_LIMIT: usize = 8 * 1024 * 1024;
/// The default wall-clock timeout for one ARM HTTP exchange.
pub const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

const MAX_SAFE_HEADER_VALUE_BYTES: usize = 4096;

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
}

impl HttpLimits {
    /// Construct explicit limits.  All limits must be non-zero.
    pub const fn new(
        request_body_bytes: usize,
        response_body_bytes: usize,
        timeout: Duration,
    ) -> Self {
        Self {
            request_body_bytes,
            response_body_bytes,
            timeout,
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

    fn validate(self) -> Result<Self, HttpError> {
        if self.request_body_bytes == 0 {
            return Err(HttpError::InvalidLimits {
                field: "request body limit",
            });
        }
        if self.response_body_bytes == 0 {
            return Err(HttpError::InvalidLimits {
                field: "response body limit",
            });
        }
        if self.timeout.is_zero() {
            return Err(HttpError::InvalidLimits { field: "timeout" });
        }
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
}

impl HttpResponse {
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
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body_len", &self.body.len())
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
    origin: ArmOrigin,
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
        if origin.cloud() != cloud {
            return Err(HttpError::OriginCloudMismatch);
        }
        if !origin.is_loopback_override() {
            let expected = ArmOrigin::for_cloud(cloud)?;
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
    pub fn origin(&self) -> &ArmOrigin {
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
        validate_api_version(&request.api_version)?;
        if request.body.len() > self.config.limits.request_body_bytes() {
            return Err(HttpError::RequestBodyTooLarge {
                limit: self.config.limits.request_body_bytes(),
            });
        }
        validate_headers(&request.headers)?;

        // Route classification is a hard gate.  There is intentionally no
        // generic GET/POST fallback for paths absent from the reviewed bundle.
        self.config
            .policy
            .classify(
                self.config.cloud,
                request.purpose,
                request.method,
                &request.target,
                &request.api_version,
            )
            .map_err(HttpError::PolicyDenied)?;

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
        let mut builder = self
            .http
            .request(method, url)
            .header(AUTHORIZATION, authorization);
        for (name, value) in request.headers {
            // Header validation has already run and this conversion cannot
            // contain the bearer value, which is held in a separate object.
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| HttpError::InvalidHeader { name })?;
            let value =
                HeaderValue::from_str(&value).map_err(|_| HttpError::InvalidHeaderValue {
                    name: name.to_string(),
                })?;
            builder = builder.header(name, value);
        }
        let builder = builder.body(request.body);

        let body_limit = self.config.limits.response_body_bytes();
        time::timeout(self.config.limits.timeout(), async move {
            let response = builder.send().await.map_err(|_| HttpError::RequestSend)?;
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
            Ok(HttpResponse {
                status: status.as_u16(),
                headers,
                body,
            })
        })
        .await
        .map_err(|_| HttpError::Timeout)?
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
    origin: &ArmOrigin,
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
    /// The selected audience is not the reviewed ARM audience for the cloud.
    #[error("invalid ARM token audience")]
    InvalidAudience,
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
    /// The response body could not be read.
    #[error("HTTP response body could not be read")]
    ResponseRead,
    /// Redirects are never followed or accepted as an execution result.
    #[error("HTTP redirects are not permitted")]
    RedirectDenied,
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
