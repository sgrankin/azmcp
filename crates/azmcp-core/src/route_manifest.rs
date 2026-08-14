//! Checked-in source data for the reviewed route and schema bundle.
//!
//! The manifest is the single source for both executable route policy and
//! offline discovery metadata.  It is deliberately parsed and validated at
//! the boundary before either consumer can advertise or execute a row.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    cloud::AzureCloud,
    policy::{ArmTier, HttpMethod, PolicyBundle, ReviewedRoute, RoutePurpose},
};

/// Repository-relative path of the checked-in reviewed source fixture.
pub const V1_MANIFEST_PATH: &str = "fixtures/reviewed-routes/v1-observability-1.json";
const V1_MANIFEST_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../",
    "fixtures/reviewed-routes/v1-observability-1.json"
));

/// The only manifest format understood by this binary.
pub const V1_MANIFEST_FORMAT: u32 = 1;
/// Stable identity of the checked-in route review.
pub const V1_MANIFEST_ID: &str = "v1-observability-1";
/// The policy version emitted by this manifest.
pub const V1_POLICY_VERSION: &str = "v1-observability-1";
/// The policy hash recorded with the checked-in review.
pub const V1_POLICY_HASH: &str =
    "sha256:d3655b57f92a18efdfc375446425e9e8d6ade644c2036c333e2f276cbd45c8bf";
/// The source fixture is pinned to the review's parent revision.
pub const V1_SOURCE_KIND: &str = "checked-in-reviewed-fixture";
/// Revision from which this initial v1 route fixture was reviewed.
pub const V1_SOURCE_REVISION: &str = "d13b7291813c0a17ebcfa0a0eca5f3dcaf71eb48";

const MAX_MANIFEST_BYTES: usize = 512 * 1024;
const MAX_ROUTES: usize = 256;
const MAX_SCHEMAS: usize = 256;
const MAX_STRING_BYTES: usize = 4 * 1024;
const MAX_API_VERSIONS: usize = 32;
const MAX_QUERY_PARAMETERS: usize = 64;
const MAX_SCHEMA_BYTES: usize = 64 * 1024;

/// The top-level review metadata and its two joined source collections.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RouteManifest {
    pub(crate) format_version: u32,
    pub(crate) manifest_id: String,
    pub(crate) policy_version: String,
    pub(crate) policy_hash: String,
    pub(crate) source: ManifestSource,
    pub(crate) routes: Vec<ManifestRoute>,
    pub(crate) schemas: Vec<ManifestSchema>,
}

/// Provenance for rows imported from a pinned upstream operation export.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ManifestUpstreamSource {
    pub(crate) kind: String,
    pub(crate) repository: String,
    pub(crate) revision: String,
    pub(crate) path: String,
    /// SHA-256 of the raw upstream file named by the provenance fields.
    pub(crate) source_sha256: String,
    /// SHA-256 of the normalized export with its own hash cleared.
    pub(crate) catalog_sha256: String,
    pub(crate) review_id: String,
    pub(crate) review_revision: String,
    /// SHA-256 of the canonical review join with its own hash cleared.
    pub(crate) review_sha256: String,
}

/// The pinned provenance of a checked-in route fixture.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ManifestSource {
    pub(crate) kind: String,
    pub(crate) revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) upstream: Option<ManifestUpstreamSource>,
}

/// One source row that becomes a [`ReviewedRoute`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ManifestRoute {
    pub cloud: AzureCloud,
    pub purpose: ManifestRoutePurpose,
    pub method: HttpMethod,
    pub path_template: String,
    pub api_versions: Vec<String>,
    pub rbac_action: String,
    pub arm_tier: ArmTier,
    #[serde(default)]
    pub allowed_query_parameters: Vec<String>,
}

/// Entry points are intentionally distinct so discovery can describe helper
/// calls without making their server-owned routes callable through
/// caller-authored `az.request` code.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ManifestRoutePurpose {
    Request,
    ResourceGraph,
    LogsQuery,
    Internal,
    MetricsSingle,
    MetricsBatch,
}

impl ManifestRoutePurpose {
    pub(crate) fn route_purpose(self) -> RoutePurpose {
        match self {
            Self::Request => RoutePurpose::Request,
            Self::ResourceGraph => RoutePurpose::ResourceGraph,
            Self::LogsQuery => RoutePurpose::LogsQuery,
            Self::Internal => RoutePurpose::Internal,
            Self::MetricsSingle => RoutePurpose::MetricsSingle,
            Self::MetricsBatch => RoutePurpose::MetricsBatch,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::ResourceGraph => "resourceGraph",
            Self::LogsQuery => "logsQuery",
            Self::Internal => "internal",
            Self::MetricsSingle => "metricsSingle",
            Self::MetricsBatch => "metricsBatch",
        }
    }
}

/// Offline schema metadata joined to one discoverable route row.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ManifestSchema {
    pub entry_id: String,
    pub resource_type: String,
    pub operation: String,
    pub purpose: ManifestRoutePurpose,
    pub display_name: String,
    pub description: String,
    pub cli_equivalent: Option<String>,
    pub cloud: AzureCloud,
    pub method: HttpMethod,
    pub canonical_path_template: String,
    pub request_path_template: String,
    pub api_versions: Vec<String>,
    pub rbac_action: String,
    pub arm_tier: ArmTier,
    pub data_plane_grant: Option<String>,
    pub argument_schema: Option<Value>,
    pub request_body_schema: Option<Value>,
    pub response_body_schema: Option<Value>,
}

/// Why a checked-in manifest could not be loaded.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ManifestError {
    #[error("route manifest is too large")]
    TooLarge,
    #[error("route manifest JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("route manifest format version is unsupported")]
    UnsupportedFormat,
    #[error("route manifest identity is not pinned")]
    UnpinnedIdentity,
    #[error("route manifest policyHash does not match its canonical content; expected {expected}")]
    PolicyHashMismatch { expected: String },
    #[error("route manifest source is not pinned")]
    UnpinnedSource,
    #[error("route manifest contains no routes or too many routes")]
    InvalidRouteCount,
    #[error("route manifest contains too many schema entries")]
    InvalidSchemaCount,
    #[error("route {index} is invalid: {reason}")]
    InvalidRoute { index: usize, reason: String },
    #[error("route {index} duplicates another route")]
    DuplicateRoute { index: usize },
    #[error("schema {index} is invalid: {reason}")]
    InvalidSchema { index: usize, reason: String },
    #[error("schema {index} duplicates another entry")]
    DuplicateSchema { index: usize },
    #[error("schema {index} does not describe a reviewed discoverable route")]
    SchemaNotDiscoverable { index: usize },
    #[error("a reviewed discoverable route has no schema entry")]
    MissingSchema,
    #[error("route manifest cannot serialize deterministically: {0}")]
    Serialization(String),
    #[error("route manifest is not in canonical byte form")]
    NonCanonical,
    #[error("generated policy bundle is invalid: {0}")]
    InvalidPolicy(String),
}

/// Parse and semantically validate arbitrary manifest bytes.
pub fn parse_manifest(bytes: &[u8]) -> Result<RouteManifest, ManifestError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ManifestError::TooLarge);
    }
    let manifest = serde_json::from_slice(bytes)
        .map_err(|error| ManifestError::InvalidJson(error.to_string()))?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

/// Parse a generated manifest while allowing the route generator to calculate
/// a new policy hash before its caller chooses to pin that hash.  Runtime
/// callers must use [`parse_manifest`], which requires the checked-in policy
/// identity.
pub fn parse_manifest_for_generation(bytes: &[u8]) -> Result<RouteManifest, ManifestError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ManifestError::TooLarge);
    }
    let manifest = serde_json::from_slice(bytes)
        .map_err(|error| ManifestError::InvalidJson(error.to_string()))?;
    validate_manifest_for_generation(&manifest)?;
    Ok(manifest)
}

/// Validate the manifest's pinned identity, route shape, and route/schema join.
pub fn validate_manifest(manifest: &RouteManifest) -> Result<(), ManifestError> {
    validate_manifest_with_hash(manifest, true)
}

/// Validate generated content before its policy hash is installed as the
/// checked-in constant.  This remains crate-visible so the offline importer
/// can build a new fixture without weakening runtime parsing.
pub(crate) fn validate_manifest_for_generation(
    manifest: &RouteManifest,
) -> Result<(), ManifestError> {
    validate_manifest_with_hash(manifest, false)
}

fn validate_manifest_with_hash(
    manifest: &RouteManifest,
    require_pinned_hash: bool,
) -> Result<(), ManifestError> {
    if manifest.format_version != V1_MANIFEST_FORMAT
        || manifest.manifest_id != V1_MANIFEST_ID
        || manifest.policy_version != V1_POLICY_VERSION
    {
        return Err(ManifestError::UnpinnedIdentity);
    }
    if manifest.source.kind != V1_SOURCE_KIND || manifest.source.revision != V1_SOURCE_REVISION {
        return Err(ManifestError::UnpinnedSource);
    }
    if manifest
        .source
        .upstream
        .as_ref()
        .is_some_and(|source| !valid_upstream_source(source))
    {
        return Err(ManifestError::UnpinnedSource);
    }
    if manifest.routes.is_empty() || manifest.routes.len() > MAX_ROUTES {
        return Err(ManifestError::InvalidRouteCount);
    }
    if manifest.schemas.len() > MAX_SCHEMAS {
        return Err(ManifestError::InvalidSchemaCount);
    }

    let mut route_keys = BTreeSet::new();
    for (index, route) in manifest.routes.iter().enumerate() {
        if route.allowed_query_parameters.len() > MAX_QUERY_PARAMETERS
            || route
                .allowed_query_parameters
                .iter()
                .any(|name| !bounded(name, 128))
        {
            return Err(ManifestError::InvalidRoute {
                index,
                reason: "query parameter policy is empty, overlarge, or unbounded".to_owned(),
            });
        }
        if manifest.routes[..index]
            .iter()
            .any(|previous| executable_selectors_overlap(previous, route))
        {
            return Err(ManifestError::DuplicateRoute { index });
        }
        let reviewed = reviewed_route(route)
            .map_err(|reason| ManifestError::InvalidRoute { index, reason })?;
        let key = route_identity(route);
        if !route_keys.insert(key) {
            return Err(ManifestError::DuplicateRoute { index });
        }
        if reviewed.allowed_query_parameters() != route.allowed_query_parameters.as_slice() {
            return Err(ManifestError::InvalidRoute {
                index,
                reason: "query parameters must be sorted and unique".to_owned(),
            });
        }
    }

    let discoverable_routes = manifest
        .routes
        .iter()
        .filter(|route| discoverable(route.purpose))
        .collect::<Vec<_>>();
    let mut schema_ids = BTreeSet::new();
    let mut matched_routes = BTreeSet::new();
    for (index, schema) in manifest.schemas.iter().enumerate() {
        validate_schema(schema).map_err(|reason| ManifestError::InvalidSchema { index, reason })?;
        if !schema_ids.insert(schema.entry_id.clone()) {
            return Err(ManifestError::DuplicateSchema { index });
        }
        let Some((route_index, route)) =
            discoverable_routes.iter().enumerate().find(|(_, route)| {
                route.cloud == schema.cloud
                    && route.purpose == schema.purpose
                    && route.method == schema.method
                    && route.path_template == schema.canonical_path_template
                    && route.api_versions == schema.api_versions
                    && route.rbac_action == schema.rbac_action
                    && route.arm_tier == schema.arm_tier
            })
        else {
            return Err(ManifestError::SchemaNotDiscoverable { index });
        };
        if expected_request_path(route).is_none_or(|path| path != schema.request_path_template) {
            return Err(ManifestError::InvalidSchema {
                index,
                reason: "request path is not representable by its execution surface".to_owned(),
            });
        }
        if !matched_routes.insert(route_index) {
            return Err(ManifestError::DuplicateSchema { index });
        }
    }
    if matched_routes.len() != discoverable_routes.len() {
        return Err(ManifestError::MissingSchema);
    }
    if require_pinned_hash && manifest.policy_hash != V1_POLICY_HASH {
        return Err(ManifestError::UnpinnedIdentity);
    }
    let expected = computed_policy_hash(manifest)?;
    if manifest.policy_hash != expected {
        return Err(ManifestError::PolicyHashMismatch { expected });
    }
    Ok(())
}

/// Return the checked-in fixture after applying the same fail-closed checks
/// used by the CI tool.
pub fn checked_in_manifest() -> Result<RouteManifest, ManifestError> {
    let manifest = parse_manifest(V1_MANIFEST_BYTES)?;
    if canonical_manifest_bytes(&manifest)? != V1_MANIFEST_BYTES {
        return Err(ManifestError::NonCanonical);
    }
    Ok(manifest)
}

/// Return the exact source bytes embedded in the core library.
pub const fn checked_in_manifest_bytes() -> &'static [u8] {
    V1_MANIFEST_BYTES
}

/// Serialize a manifest using stable field and collection ordering.
pub fn canonical_manifest_bytes(manifest: &RouteManifest) -> Result<Vec<u8>, ManifestError> {
    let mut normalized = manifest.clone();
    normalized.routes.sort_by_key(route_sort_key);
    normalized
        .schemas
        .sort_by(|left, right| left.entry_id.cmp(&right.entry_id));
    let mut bytes = serde_json::to_vec_pretty(&normalized)
        .map_err(|error| ManifestError::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Compute the content-bound policy identity over a canonical manifest with
/// its self-referential `policyHash` field cleared.
pub fn computed_policy_hash(manifest: &RouteManifest) -> Result<String, ManifestError> {
    let mut normalized = manifest.clone();
    normalized.policy_hash.clear();
    normalized.routes.sort_by_key(route_sort_key);
    normalized
        .schemas
        .sort_by(|left, right| left.entry_id.cmp(&right.entry_id));
    let bytes = serde_json::to_vec(&normalized)
        .map_err(|error| ManifestError::Serialization(error.to_string()))?;
    let digest = Sha256::digest(bytes);
    Ok(format!("sha256:{digest:x}"))
}

/// Build the executable route policy from the validated source rows.
pub fn policy(manifest: &RouteManifest) -> Result<PolicyBundle, ManifestError> {
    validate_manifest(manifest)?;
    let routes = manifest
        .routes
        .iter()
        .map(reviewed_route)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|reason| ManifestError::InvalidPolicy(reason.to_owned()))?;
    PolicyBundle::new(manifest.policy_version.clone(), routes)
        .map_err(|error| ManifestError::InvalidPolicy(error.to_string()))
}

/// Count rows by entry point for deterministic CI output and tests.
pub fn route_count(manifest: &RouteManifest) -> usize {
    manifest.routes.len()
}

/// Count schema entries in a validated source manifest.
pub fn schema_count(manifest: &RouteManifest) -> usize {
    manifest.schemas.len()
}

/// The manifest's policy version.
pub fn policy_version(manifest: &RouteManifest) -> &str {
    &manifest.policy_version
}

/// Return the schema rows for conversion by the offline schema index.
pub fn schemas(manifest: &RouteManifest) -> &[ManifestSchema] {
    &manifest.schemas
}

impl RouteManifest {
    pub(crate) fn routes(&self) -> impl Iterator<Item = &ManifestRoute> {
        self.routes.iter()
    }

    pub(crate) fn schemas(&self) -> &[ManifestSchema] {
        &self.schemas
    }

    pub(crate) fn append_reviewed_rows(
        &mut self,
        routes: Vec<ManifestRoute>,
        schemas: Vec<ManifestSchema>,
        source: ManifestUpstreamSource,
    ) {
        self.routes.extend(routes);
        self.schemas.extend(schemas);
        self.source.upstream = Some(source);
        self.policy_hash.clear();
    }

    pub(crate) fn clear_policy_hash(&mut self) {
        self.policy_hash.clear();
    }

    pub(crate) fn set_policy_hash(&mut self, value: String) {
        self.policy_hash = value;
    }
}

fn reviewed_route(route: &ManifestRoute) -> Result<ReviewedRoute, String> {
    let query_parameters = route.allowed_query_parameters.clone();
    let reviewed = ReviewedRoute::new(
        route.cloud,
        route.purpose.route_purpose(),
        route.method,
        &route.path_template,
        route.api_versions.iter().cloned(),
        route.rbac_action.clone(),
        route.arm_tier,
    )
    .map_err(|error| error.to_string())?;
    reviewed
        .with_query_parameters(query_parameters)
        .map_err(|error| error.to_string())
}

fn validate_schema(schema: &ManifestSchema) -> Result<(), String> {
    for (name, value, maximum) in [
        ("entry id", schema.entry_id.as_str(), 256),
        ("resource type", schema.resource_type.as_str(), 256),
        ("operation", schema.operation.as_str(), 128),
        ("display name", schema.display_name.as_str(), 256),
        ("description", schema.description.as_str(), 2_048),
        (
            "canonical path",
            schema.canonical_path_template.as_str(),
            1_024,
        ),
        ("request path", schema.request_path_template.as_str(), 1_024),
        ("rbac action", schema.rbac_action.as_str(), 512),
    ] {
        if !bounded(value, maximum) {
            return Err(format!(
                "{name} is empty, overlong, or contains control characters"
            ));
        }
    }
    if schema
        .cli_equivalent
        .as_deref()
        .is_some_and(|value| !bounded(value, 512))
        || schema
            .data_plane_grant
            .as_deref()
            .is_some_and(|value| !bounded(value, 128))
    {
        return Err(
            "optional metadata is empty, overlong, or contains control characters".to_owned(),
        );
    }
    if schema.api_versions.is_empty() || schema.api_versions.len() > MAX_API_VERSIONS {
        return Err("API version list is empty or overlarge".to_owned());
    }
    if schema
        .api_versions
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
        || schema
            .api_versions
            .iter()
            .any(|version| !bounded(version, 64))
    {
        return Err("API versions must be sorted, unique, and bounded".to_owned());
    }
    if schema
        .argument_schema
        .as_ref()
        .is_none_or(|value| !valid_closed_object_schema(value))
        || schema
            .request_body_schema
            .as_ref()
            .is_some_and(|value| !valid_closed_object_schema(value))
        || schema
            .response_body_schema
            .as_ref()
            .is_some_and(|value| !valid_schema(value))
    {
        return Err("schema must be an inline bounded JSON object without references".to_owned());
    }
    let expected_grant =
        (schema.purpose == ManifestRoutePurpose::LogsQuery).then_some("logs.query");
    if (schema.purpose == ManifestRoutePurpose::MetricsBatch
        || schema.purpose == ManifestRoutePurpose::LogsQuery)
        != schema.request_body_schema.is_some()
        || schema.data_plane_grant.as_deref() != expected_grant
        || !schema_cloud_is_exact(schema)
    {
        return Err("argument schema shape does not match its execution surface".to_owned());
    }
    Ok(())
}

fn valid_schema(schema: &Value) -> bool {
    schema.is_object()
        && !contains_ref(schema)
        && serde_json::to_vec(schema).is_ok_and(|bytes| bytes.len() <= MAX_SCHEMA_BYTES)
}

fn valid_closed_object_schema(schema: &Value) -> bool {
    if !valid_schema(schema)
        || schema.get("type").and_then(Value::as_str) != Some("object")
        || schema.get("additionalProperties").and_then(Value::as_bool) != Some(false)
    {
        return false;
    }
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return false;
    };
    let Some(required) = schema.get("required").and_then(Value::as_array) else {
        return false;
    };
    let mut seen = BTreeSet::new();
    required.iter().all(|name| {
        name.as_str()
            .is_some_and(|name| properties.contains_key(name) && seen.insert(name))
    })
}

fn schema_cloud_is_exact(schema: &ManifestSchema) -> bool {
    schema
        .argument_schema
        .as_ref()
        .and_then(|schema| schema.get("properties"))
        .and_then(|properties| properties.get("cloud"))
        .and_then(|cloud| cloud.get("enum"))
        .and_then(Value::as_array)
        .is_some_and(|values| {
            values.as_slice() == [Value::String(schema.cloud.as_str().to_owned())]
        })
}

fn contains_ref(value: &Value) -> bool {
    match value {
        Value::Object(values) => {
            values
                .keys()
                .any(|key| matches!(key.as_str(), "$ref" | "$dynamicRef" | "$recursiveRef"))
                || values.values().any(contains_ref)
        }
        Value::Array(values) => values.iter().any(contains_ref),
        _ => false,
    }
}

fn bounded(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum.min(MAX_STRING_BYTES)
        && !value.chars().any(char::is_control)
}

fn valid_upstream_source(source: &ManifestUpstreamSource) -> bool {
    [
        (&source.kind, 128),
        (&source.repository, 512),
        (&source.revision, 256),
        (&source.path, 1_024),
        (&source.review_id, 256),
        (&source.review_revision, 256),
    ]
    .into_iter()
    .all(|(value, maximum)| bounded(value, maximum))
        && valid_sha256(&source.source_sha256)
        && valid_sha256(&source.catalog_sha256)
        && valid_sha256(&source.review_sha256)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .chars()
            .all(|character| character.is_ascii_hexdigit())
}

fn executable_selectors_overlap(left: &ManifestRoute, right: &ManifestRoute) -> bool {
    left.cloud == right.cloud
        && left.purpose == right.purpose
        && left.method == right.method
        && left.path_template == right.path_template
        && left
            .api_versions
            .iter()
            .any(|version| right.api_versions.iter().any(|other| version == other))
}

fn discoverable(purpose: ManifestRoutePurpose) -> bool {
    matches!(
        purpose,
        ManifestRoutePurpose::Request
            | ManifestRoutePurpose::MetricsSingle
            | ManifestRoutePurpose::MetricsBatch
            | ManifestRoutePurpose::LogsQuery
    )
}

fn expected_request_path(route: &ManifestRoute) -> Option<String> {
    if route.purpose != ManifestRoutePurpose::Request {
        Some(route.path_template.clone())
    } else if route.path_template == "/subscriptions/{subscription}" {
        Some("/".to_owned())
    } else {
        route
            .path_template
            .strip_prefix("/subscriptions/{subscription}")
            .filter(|path| !path.is_empty())
            .map(ToOwned::to_owned)
    }
}

fn route_identity(route: &ManifestRoute) -> String {
    format!(
        "{}|{}|{:?}|{}|{}|{}|{:?}",
        route.cloud.as_str(),
        route.purpose.as_str(),
        route.method,
        route.path_template,
        route.api_versions.join(","),
        route.rbac_action,
        route.arm_tier,
    )
}

fn route_sort_key(route: &ManifestRoute) -> String {
    format!(
        "{}|{}",
        match route.purpose {
            ManifestRoutePurpose::Request => 0,
            ManifestRoutePurpose::ResourceGraph => 1,
            ManifestRoutePurpose::LogsQuery => 2,
            ManifestRoutePurpose::Internal => 3,
            ManifestRoutePurpose::MetricsSingle => 4,
            ManifestRoutePurpose::MetricsBatch => 5,
        },
        route_identity(route),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_in_manifest_is_canonical_and_joins_both_sources() {
        let manifest = checked_in_manifest().expect("checked-in route fixture");
        assert_eq!(route_count(&manifest), 16);
        assert_eq!(schema_count(&manifest), 10);
        assert_eq!(policy_version(&manifest), V1_POLICY_VERSION);
        assert_eq!(
            canonical_manifest_bytes(&manifest).unwrap(),
            V1_MANIFEST_BYTES
        );

        let policy = policy(&manifest).expect("generated policy");
        let purposes =
            policy
                .routes()
                .iter()
                .fold(std::collections::HashMap::new(), |mut counts, route| {
                    *counts.entry(route.purpose()).or_insert(0usize) += 1;
                    counts
                });
        assert_eq!(purposes.get(&RoutePurpose::Request), Some(&4));
        assert_eq!(purposes.get(&RoutePurpose::ResourceGraph), Some(&2));
        assert_eq!(purposes.get(&RoutePurpose::LogsQuery), Some(&2));
        assert_eq!(purposes.get(&RoutePurpose::Internal), Some(&4));
        assert_eq!(purposes.get(&RoutePurpose::MetricsSingle), Some(&2));
        assert_eq!(purposes.get(&RoutePurpose::MetricsBatch), Some(&2));
    }

    #[test]
    fn malformed_manifest_fails_closed_before_policy_construction() {
        let mut manifest = checked_in_manifest().expect("fixture");
        manifest.routes[0].purpose = ManifestRoutePurpose::MetricsSingle;
        assert!(matches!(
            validate_manifest(&manifest),
            Err(ManifestError::DuplicateRoute { .. })
                | Err(ManifestError::SchemaNotDiscoverable { .. })
                | Err(ManifestError::MissingSchema)
        ));

        let mut bytes = checked_in_manifest_bytes().to_vec();
        bytes[0] = b'[';
        assert!(matches!(
            parse_manifest(&bytes),
            Err(ManifestError::InvalidJson(_))
        ));
    }

    #[test]
    fn nondiscoverable_rows_cannot_gain_schema_metadata() {
        let mut manifest = checked_in_manifest().expect("fixture");
        manifest.schemas[0].canonical_path_template =
            "/providers/Microsoft.ResourceGraph/resources".to_owned();
        assert!(matches!(
            validate_manifest(&manifest),
            Err(ManifestError::SchemaNotDiscoverable { .. })
                | Err(ManifestError::InvalidSchema { .. })
        ));
    }

    #[test]
    fn helper_schema_shape_and_nested_references_fail_closed() {
        let mut manifest = checked_in_manifest().expect("fixture");
        let helper = manifest
            .schemas
            .iter_mut()
            .find(|schema| schema.purpose == ManifestRoutePurpose::MetricsSingle)
            .expect("metrics helper");
        helper.data_plane_grant = Some("unexpected".to_owned());
        assert!(matches!(
            validate_manifest(&manifest),
            Err(ManifestError::InvalidSchema { .. })
        ));

        let mut manifest = checked_in_manifest().expect("fixture");
        let helper = manifest
            .schemas
            .iter_mut()
            .find(|schema| schema.purpose == ManifestRoutePurpose::MetricsSingle)
            .expect("metrics helper");
        helper.argument_schema.as_mut().expect("arguments")["properties"]["cloud"]["enum"] =
            serde_json::json!(["AzureCloud", "AzureUSGovernment"]);
        assert!(matches!(
            validate_manifest(&manifest),
            Err(ManifestError::InvalidSchema { .. })
        ));

        let mut manifest = checked_in_manifest().expect("fixture");
        let helper = manifest
            .schemas
            .iter_mut()
            .find(|schema| schema.purpose == ManifestRoutePurpose::MetricsSingle)
            .expect("metrics helper");
        helper.argument_schema.as_mut().expect("arguments")["properties"]["resourceId"]["$dynamicRef"] =
            serde_json::json!("https://example.invalid/schema");
        assert!(matches!(
            validate_manifest(&manifest),
            Err(ManifestError::InvalidSchema { .. })
        ));

        let mut manifest = checked_in_manifest().expect("fixture");
        let helper = manifest
            .schemas
            .iter_mut()
            .find(|schema| schema.purpose == ManifestRoutePurpose::MetricsSingle)
            .expect("metrics helper");
        helper
            .argument_schema
            .as_mut()
            .and_then(Value::as_object_mut)
            .expect("argument object")
            .insert("additionalProperties".to_owned(), Value::Bool(true));
        assert!(matches!(
            validate_manifest(&manifest),
            Err(ManifestError::InvalidSchema { .. })
        ));
    }

    #[test]
    fn policy_hash_is_bound_to_route_and_schema_content() {
        let mut manifest = checked_in_manifest().expect("fixture");
        manifest.schemas[0].display_name.push_str(" changed");
        assert!(matches!(
            validate_manifest(&manifest),
            Err(ManifestError::PolicyHashMismatch { .. })
        ));

        let mut manifest = checked_in_manifest().expect("fixture");
        manifest.routes[0].rbac_action.push_str("/changed");
        assert!(matches!(
            validate_manifest(&manifest),
            Err(ManifestError::SchemaNotDiscoverable { .. })
                | Err(ManifestError::PolicyHashMismatch { .. })
        ));
    }

    #[test]
    fn overlapping_selector_cannot_bypass_rbac_or_query_metadata() {
        let mut manifest = checked_in_manifest().expect("fixture");
        let mut duplicate = manifest.routes[0].clone();
        duplicate.rbac_action = "different/read".to_owned();
        duplicate.allowed_query_parameters = vec!["$expand".to_owned()];
        manifest.routes.push(duplicate);
        assert!(matches!(
            validate_manifest(&manifest),
            Err(ManifestError::DuplicateRoute { .. })
        ));
    }

    #[test]
    fn source_identity_is_pinned_and_unknown_fields_are_rejected() {
        let mut manifest = checked_in_manifest().expect("fixture");
        manifest.source.revision = "different-review".to_owned();
        assert_eq!(
            validate_manifest(&manifest),
            Err(ManifestError::UnpinnedSource)
        );

        let bytes = br#"{
            "formatVersion": 1,
            "manifestId": "v1-observability-1",
            "policyVersion": "v1-observability-1",
            "policyHash": "sha256:d3655b57f92a18efdfc375446425e9e8d6ade644c2036c333e2f276cbd45c8bf",
            "source": {"kind": "checked-in-reviewed-fixture", "revision": "d13b7291813c0a17ebcfa0a0eca5f3dcaf71eb48"},
            "routes": [],
            "schemas": [],
            "unexpected": true
        }"#;
        assert!(matches!(
            parse_manifest(bytes),
            Err(ManifestError::InvalidJson(_))
        ));
    }
}
