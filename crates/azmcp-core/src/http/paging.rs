//! Bounded following of service-provided ARM continuations.
//!
//! A continuation is never accepted as caller input. The only entry point
//! takes an ordinary reviewed request, extracts `nextLink` from its upstream
//! response, and re-enters the complete HTTP policy boundary for every page.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;
use thiserror::Error;
use url::Url;

use super::{HttpClient, HttpError, HttpRequest, HttpResponse, build_request_url, same_origin};
use crate::credential::CredentialIdentityPin;
use crate::policy::{ArmTier, HttpMethod, ReviewedRoute};
use crate::target::RelativeRequestTarget;

/// Default maximum number of response pages in one operation.
pub const DEFAULT_PAGING_PAGES: usize = 32;
/// Default maximum number of collected array items in one operation.
pub const DEFAULT_PAGING_ITEMS: usize = 50_000;
/// Default maximum aggregate response-body bytes in one operation.
pub const DEFAULT_PAGING_BYTES: usize = 16 * 1024 * 1024;
/// Default wall-clock budget for requests, retries, and parsing.
pub const DEFAULT_PAGING_ELAPSED: Duration = Duration::from_secs(60);

/// Absolute server ceiling for a caller-selected page cap.
pub const MAX_PAGING_PAGES: usize = 256;
/// Absolute server ceiling for a caller-selected item cap.
pub const MAX_PAGING_ITEMS: usize = 1_000_000;
/// Absolute server ceiling for aggregate response-body bytes.
pub const MAX_PAGING_BYTES: usize = 64 * 1024 * 1024;
/// Absolute server ceiling for one paged operation's wall-clock budget.
pub const MAX_PAGING_ELAPSED: Duration = Duration::from_secs(5 * 60);

const MAX_CONTINUATION_BYTES: usize = 16 * 1024;

/// Resource ceilings for one paged operation.
///
/// The fields are private so embedders cannot bypass validation. Construction
/// is inert; validation happens before the initial request acquires a token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PagingLimits {
    max_pages: usize,
    max_items: usize,
    max_bytes: usize,
    max_elapsed: Duration,
}

impl PagingLimits {
    /// Construct explicit paging ceilings.
    pub const fn new(
        max_pages: usize,
        max_items: usize,
        max_bytes: usize,
        max_elapsed: Duration,
    ) -> Self {
        Self {
            max_pages,
            max_items,
            max_bytes,
            max_elapsed,
        }
    }

    /// Maximum response pages, including the initial response.
    pub const fn max_pages(self) -> usize {
        self.max_pages
    }

    /// Maximum items collected across every page's `value` array.
    pub const fn max_items(self) -> usize {
        self.max_items
    }

    /// Maximum aggregate bytes across successful response bodies.
    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }

    /// Maximum wall-clock duration across requests, retries, and parsing.
    pub const fn max_elapsed(self) -> Duration {
        self.max_elapsed
    }

    fn validate(self) -> Result<Self, PagingError> {
        if self.max_pages == 0 || self.max_pages > MAX_PAGING_PAGES {
            return Err(PagingError::InvalidLimits {
                field: "page limit",
            });
        }
        if self.max_items == 0 || self.max_items > MAX_PAGING_ITEMS {
            return Err(PagingError::InvalidLimits {
                field: "item limit",
            });
        }
        if self.max_bytes == 0 || self.max_bytes > MAX_PAGING_BYTES {
            return Err(PagingError::InvalidLimits {
                field: "aggregate response byte limit",
            });
        }
        if self.max_elapsed.is_zero() || self.max_elapsed > MAX_PAGING_ELAPSED {
            return Err(PagingError::InvalidLimits {
                field: "elapsed-time limit",
            });
        }
        Ok(self)
    }
}

impl Default for PagingLimits {
    fn default() -> Self {
        Self::new(
            DEFAULT_PAGING_PAGES,
            DEFAULT_PAGING_ITEMS,
            DEFAULT_PAGING_BYTES,
            DEFAULT_PAGING_ELAPSED,
        )
    }
}

/// Per-page transport facts retained for rate and audit visibility.
///
/// Continuation URLs and response values are deliberately absent. A future
/// host helper can emit one durable call row per page without retaining raw
/// resource paths or service-provided continuation tokens.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PagedHttpPage {
    status: u16,
    response_body_bytes: usize,
    item_count: usize,
    duration_ms: u64,
    retry_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    remaining_subscription_reads: Option<u64>,
}

impl PagedHttpPage {
    /// HTTP status returned for this page.
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Raw response-body bytes counted against the aggregate cap.
    pub const fn response_body_bytes(&self) -> usize {
        self.response_body_bytes
    }

    /// Items contributed by this page's `value` array.
    pub const fn item_count(&self) -> usize {
        self.item_count
    }

    /// Bounded page duration, including transport retries.
    pub const fn duration_ms(&self) -> u64 {
        self.duration_ms
    }

    /// Retry attempts made before the final response for this page.
    pub const fn retry_count(&self) -> u32 {
        self.retry_count
    }

    /// ARM subscription-read budget reported on this page, when present.
    pub const fn remaining_subscription_reads(&self) -> Option<u64> {
        self.remaining_subscription_reads
    }
}

/// Fully collected, bounded items plus per-page transport metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PagedHttpResponse {
    items: Vec<Value>,
    pages: Vec<PagedHttpPage>,
    response_body_bytes: usize,
}

impl PagedHttpResponse {
    /// Collected values in service page order.
    pub fn items(&self) -> &[Value] {
        &self.items
    }

    /// Consume the response and return its collected values.
    pub fn into_items(self) -> Vec<Value> {
        self.items
    }

    /// Per-page transport metadata in request order.
    pub fn pages(&self) -> &[PagedHttpPage] {
        &self.pages
    }

    /// Aggregate raw response-body bytes.
    pub const fn response_body_bytes(&self) -> usize {
        self.response_body_bytes
    }

    /// Aggregate retries across all pages.
    pub fn retry_count(&self) -> u32 {
        self.pages
            .iter()
            .fold(0_u32, |total, page| total.saturating_add(page.retry_count))
    }
}

/// A fail-closed paging failure.
#[derive(Debug, Error)]
pub enum PagingError {
    /// The initial or continuation request failed at the ordinary HTTP gate.
    #[error(transparent)]
    Http(#[from] HttpError),
    /// Paging is limited to closed, headerless and bodyless reviewed GETs.
    #[error("paging requires a headerless, bodyless reviewed GET operation")]
    UnsafeOperation,
    /// A configured paging ceiling is zero or above the server maximum.
    #[error("invalid paging limit: {field}")]
    InvalidLimits { field: &'static str },
    /// The upstream returned an unsuccessful final status.
    #[error("paged upstream request returned HTTP {status} after {retry_count} retries")]
    UpstreamStatus { status: u16, retry_count: u32 },
    /// A successful page was not a JSON object with a `value` array.
    #[error("paged upstream response has an invalid JSON shape")]
    InvalidResponse,
    /// A service continuation was malformed or omitted its fixed API version.
    #[error("service continuation is malformed")]
    InvalidContinuation,
    /// A service continuation did not use the selected exact origin.
    #[error("service continuation changed the reviewed request origin")]
    ContinuationOriginMismatch,
    /// A service continuation changed API version.
    #[error("service continuation changed the reviewed API version")]
    ContinuationVersionMismatch,
    /// A service continuation left the initial reviewed route.
    #[error("service continuation left the initial reviewed route")]
    ContinuationRouteMismatch,
    /// A service continuation repeated a URL already seen in this operation.
    #[error("service continuation formed a cycle")]
    ContinuationCycle,
    /// The response advertised another page after the page ceiling.
    #[error("paged response exceeds the configured limit of {limit} pages")]
    PageLimitExceeded { limit: usize },
    /// Appending a page would exceed the item ceiling.
    #[error("paged response exceeds the configured limit of {limit} items")]
    ItemLimitExceeded { limit: usize },
    /// Appending a page would exceed the aggregate response-byte ceiling.
    #[error("paged response exceeds the configured limit of {limit} bytes")]
    ByteLimitExceeded { limit: usize },
    /// The operation exhausted its wall-clock budget.
    #[error("paged response exceeded the configured elapsed-time limit")]
    ElapsedLimitExceeded,
}

impl PagingError {
    /// Number of retries completed before an HTTP failure, when available.
    pub const fn retry_count(&self) -> u32 {
        match self {
            Self::Http(error) => error.retry_count(),
            Self::UpstreamStatus { retry_count, .. } => *retry_count,
            _ => 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RouteIdentity(ReviewedRoute);

impl RouteIdentity {
    fn from_route(route: &ReviewedRoute) -> Self {
        Self(route.clone())
    }

    fn matches(&self, route: &ReviewedRoute) -> bool {
        &self.0 == route
    }

    fn purpose(&self) -> crate::policy::RoutePurpose {
        self.0.purpose()
    }

    fn method(&self) -> HttpMethod {
        self.0.method()
    }
}

struct ParsedPage {
    items: Vec<Value>,
    next_link: Option<String>,
}

impl HttpClient {
    /// Execute a reviewed GET and transparently follow bounded upstream
    /// `nextLink` values.
    ///
    /// There is intentionally no continuation argument. Every continuation
    /// originates in a successful upstream response and must retain the exact
    /// origin, API version, purpose, and reviewed route of the initial request.
    pub async fn execute_paged(
        &self,
        request: HttpRequest,
        limits: PagingLimits,
    ) -> Result<PagedHttpResponse, PagingError> {
        self.execute_paged_with_identity_pin(request, limits, None)
            .await
    }

    /// Execute a paged request while pinning credential identity to a context.
    pub async fn execute_paged_with_identity_pin(
        &self,
        request: HttpRequest,
        limits: PagingLimits,
        identity_pin: Option<&CredentialIdentityPin>,
    ) -> Result<PagedHttpResponse, PagingError> {
        let limits = limits.validate()?;
        if request.method != HttpMethod::Get
            || !request.body.is_empty()
            || !request.headers.is_empty()
        {
            return Err(PagingError::UnsafeOperation);
        }
        let initial_route = self
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
        if initial_route.tier() == ArmTier::Write {
            return Err(PagingError::UnsafeOperation);
        }
        let route_identity = RouteIdentity::from_route(initial_route);
        let initial_api_version = request.api_version.clone();
        let started = Instant::now();
        let initial_key = canonical_request_key(self, &request.target, &initial_api_version)?;
        let mut next_request = request;
        let mut seen_targets = HashSet::from([initial_key]);
        let mut items = Vec::new();
        let mut pages = Vec::new();
        let mut response_body_bytes = 0_usize;

        loop {
            let remaining = limits
                .max_elapsed
                .checked_sub(started.elapsed())
                .filter(|remaining| !remaining.is_zero())
                .ok_or(PagingError::ElapsedLimitExceeded)?;
            let remaining_bytes = limits
                .max_bytes
                .checked_sub(response_body_bytes)
                .filter(|remaining| *remaining > 0)
                .ok_or(PagingError::ByteLimitExceeded {
                    limit: limits.max_bytes,
                })?;
            let response_body_limit = self
                .config
                .limits
                .response_body_bytes()
                .min(remaining_bytes);
            let page_started = Instant::now();
            let response = tokio::time::timeout(
                remaining,
                self.execute_with_identity_pin_and_response_limit(
                    next_request,
                    identity_pin,
                    response_body_limit,
                ),
            )
            .await
            .map_err(|_| PagingError::ElapsedLimitExceeded)?
            .map_err(|error| {
                if response_body_limit == remaining_bytes && response_too_large(&error) {
                    PagingError::ByteLimitExceeded {
                        limit: limits.max_bytes,
                    }
                } else {
                    PagingError::Http(error)
                }
            })?;
            let duration_ms = milliseconds(page_started.elapsed());
            if !(200..300).contains(&response.status()) {
                return Err(PagingError::UpstreamStatus {
                    status: response.status(),
                    retry_count: response.retry_count(),
                });
            }
            response_body_bytes = response_body_bytes
                .checked_add(response.body().len())
                .filter(|bytes| *bytes <= limits.max_bytes)
                .ok_or(PagingError::ByteLimitExceeded {
                    limit: limits.max_bytes,
                })?;
            let parsed = parse_page(&response)?;
            let item_count = parsed.items.len();
            let next_item_count = items
                .len()
                .checked_add(item_count)
                .filter(|count| *count <= limits.max_items)
                .ok_or(PagingError::ItemLimitExceeded {
                    limit: limits.max_items,
                })?;
            items.reserve(next_item_count.saturating_sub(items.len()));
            items.extend(parsed.items);
            pages.push(page_metadata(&response, item_count, duration_ms));
            if started.elapsed() >= limits.max_elapsed {
                return Err(PagingError::ElapsedLimitExceeded);
            }

            let Some(next_link) = parsed.next_link else {
                return Ok(PagedHttpResponse {
                    items,
                    pages,
                    response_body_bytes,
                });
            };
            if pages.len() >= limits.max_pages {
                return Err(PagingError::PageLimitExceeded {
                    limit: limits.max_pages,
                });
            }
            let (request, canonical_key) =
                continuation_request(self, &next_link, &initial_api_version, &route_identity)?;
            if !seen_targets.insert(canonical_key) {
                return Err(PagingError::ContinuationCycle);
            }
            next_request = request;
        }
    }
}

fn parse_page(response: &HttpResponse) -> Result<ParsedPage, PagingError> {
    let mut body = serde_json::from_slice::<Value>(response.body())
        .map_err(|_| PagingError::InvalidResponse)?;
    let object = body.as_object_mut().ok_or(PagingError::InvalidResponse)?;
    let items = match object.remove("value") {
        Some(Value::Array(items)) => items,
        _ => return Err(PagingError::InvalidResponse),
    };
    let next_link = match object.remove("nextLink") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) if !value.is_empty() => Some(value),
        Some(_) => return Err(PagingError::InvalidResponse),
    };
    Ok(ParsedPage { items, next_link })
}

fn page_metadata(response: &HttpResponse, item_count: usize, duration_ms: u64) -> PagedHttpPage {
    PagedHttpPage {
        status: response.status(),
        response_body_bytes: response.body().len(),
        item_count,
        duration_ms,
        retry_count: response.retry_count(),
        remaining_subscription_reads: response
            .headers()
            .get("x-ms-ratelimit-remaining-subscription-reads")
            .and_then(|value| value.parse().ok()),
    }
}

fn continuation_request(
    client: &HttpClient,
    next_link: &str,
    initial_api_version: &str,
    initial_route: &RouteIdentity,
) -> Result<(HttpRequest, String), PagingError> {
    if next_link.len() > MAX_CONTINUATION_BYTES
        || next_link != next_link.trim()
        || next_link.chars().any(char::is_control)
    {
        return Err(PagingError::InvalidContinuation);
    }
    let url = Url::parse(next_link).map_err(|_| PagingError::InvalidContinuation)?;
    if !same_origin(&url, client.config.origin.url())
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(PagingError::ContinuationOriginMismatch);
    }
    if !has_valid_percent_encoding(url.path())
        || url
            .query()
            .is_some_and(|query| !has_valid_percent_encoding(query))
    {
        return Err(PagingError::InvalidContinuation);
    }

    let mut api_version = None;
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in url.query_pairs() {
        if name.eq_ignore_ascii_case("api-version") {
            if api_version.replace(value.into_owned()).is_some() {
                return Err(PagingError::InvalidContinuation);
            }
        } else {
            serializer.append_pair(&name, &value);
        }
    }
    let api_version = api_version.ok_or(PagingError::InvalidContinuation)?;
    if api_version != initial_api_version {
        return Err(PagingError::ContinuationVersionMismatch);
    }
    let query = serializer.finish();
    let target_text = if query.is_empty() {
        url.path().to_owned()
    } else {
        format!("{}?{query}", url.path())
    };
    let target =
        RelativeRequestTarget::parse(&target_text).map_err(|_| PagingError::InvalidContinuation)?;
    let route = client
        .config
        .policy
        .classify(
            client.config.cloud,
            initial_route.purpose(),
            initial_route.method(),
            &target,
            &api_version,
        )
        .map_err(|_| PagingError::ContinuationRouteMismatch)?;
    if !initial_route.matches(route) {
        return Err(PagingError::ContinuationRouteMismatch);
    }

    let request = HttpRequest::for_purpose(
        initial_route.purpose(),
        initial_route.method(),
        target,
        api_version,
    )?;
    let canonical_key = canonical_request_key(client, &request.target, &request.api_version)?;
    Ok((request, canonical_key))
}

fn canonical_request_key(
    client: &HttpClient,
    target: &RelativeRequestTarget,
    api_version: &str,
) -> Result<String, PagingError> {
    let mut query = target.query().to_vec();
    query.sort();
    let target_text = if query.is_empty() {
        target.path().to_owned()
    } else {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&query)
            .finish();
        format!("{}?{query}", target.path())
    };
    let canonical_target =
        RelativeRequestTarget::parse(&target_text).map_err(|_| PagingError::InvalidContinuation)?;
    build_request_url(&client.config.origin, &canonical_target, api_version)
        .map(|url| url.to_string())
        .map_err(|_| PagingError::InvalidContinuation)
}

fn response_too_large(error: &HttpError) -> bool {
    match error {
        HttpError::ResponseBodyTooLarge { .. } => true,
        HttpError::RetryFailed { source, .. } => response_too_large(source),
        _ => false,
    }
}

fn has_valid_percent_encoding(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

fn milliseconds(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
