//! Offline import contract for a reviewed subset of Azure REST operations.
//!
//! The upstream corpus is deliberately an input to the route generator, not a
//! runtime dependency.  A candidate operation is inert until an explicit
//! review row joins it to a cloud and a caller-authored `az.request` entry.
//! The importer accepts only read-only GET operations without request bodies;
//! mutating, body-bearing, and unreviewed candidates remain unavailable.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    cloud::AzureCloud,
    policy::{
        ArmTier, ExecutableSelector, HttpMethod, ReviewedRoute, RoutePurpose,
        executable_selectors_overlap,
    },
    route_manifest::{
        ManifestRoute, ManifestRoutePurpose, ManifestSchema, ManifestUpstreamSource, RouteManifest,
    },
};

/// Repository-relative path of the checked-in upstream export fixture.
pub const UPSTREAM_CATALOG_PATH: &str = "fixtures/upstream/azure-rest-operations-v1.json";
/// Repository-relative path of the checked-in human review join.
pub const UPSTREAM_REVIEW_PATH: &str = "fixtures/upstream/azure-rest-review-v1.json";
/// The only upstream export format understood by this importer.
pub const UPSTREAM_FORMAT_VERSION: u32 = 1;
/// The only review format understood by this importer.
pub const REVIEW_FORMAT_VERSION: u32 = 1;
/// The source label required for a checked-in, offline contract fixture.
pub const UPSTREAM_SOURCE_KIND: &str = "synthetic-upstream-contract";
/// The pinned revision label for the checked-in contract fixture.
pub const UPSTREAM_SOURCE_REVISION: &str = "synthetic-azure-rest-api-specs-v1";
/// The source label for a normalized export from the official REST OpenAPI.
pub const REAL_UPSTREAM_SOURCE_KIND: &str = "azure-rest-openapi";
/// The pinned review identifier for the checked-in join.
pub const UPSTREAM_REVIEW_ID: &str = "azure-rest-review-v1";
/// The pinned revision label for the checked-in review join.
pub const UPSTREAM_REVIEW_REVISION: &str = "synthetic-route-review-v1";

const MAX_CATALOG_BYTES: usize = 256 * 1024;
const MAX_OPERATIONS: usize = 256;
const MAX_REVIEWS: usize = 256;
const MAX_STRING_BYTES: usize = 4 * 1024;
const MAX_PATH_BYTES: usize = 1_024;
const MAX_API_VERSIONS: usize = 32;
const MAX_API_VERSION_BYTES: usize = 64;
const MAX_SCHEMA_BYTES: usize = 64 * 1024;
const SUBSCRIPTION_PREFIX: &str = "/subscriptions/{subscription}";

/// A content-addressed export of upstream Azure REST/provider-operation data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpstreamCatalog {
    format_version: u32,
    source: UpstreamSource,
    operations: Vec<UpstreamOperation>,
}

/// Provenance for one offline upstream export.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpstreamSource {
    kind: String,
    repository: String,
    revision: String,
    path: String,
    /// SHA-256 of the raw upstream source file named by repository/revision/path.
    source_sha256: String,
    /// SHA-256 of this normalized export with `catalogSha256` cleared.
    catalog_sha256: String,
}

/// A source operation before the explicit review join.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpstreamOperation {
    pub operation_id: String,
    pub provider_namespace: String,
    pub resource_type: String,
    pub operation: String,
    pub method: HttpMethod,
    pub path_template: String,
    pub api_versions: Vec<String>,
    #[serde(default)]
    pub request_body_schema: Option<Value>,
    #[serde(default)]
    pub response_body_schema: Option<Value>,
}

/// A review file joins source operation identifiers to exact cloud-specific
/// discovery metadata.  No operation is imported without one of these rows.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReviewBundle {
    format_version: u32,
    review_id: String,
    source: ReviewSource,
    upstream: UpstreamPin,
    /// Independent provider-operation evidence for the manually reviewed
    /// RBAC action.  This is deliberately not part of the OpenAPI operation
    /// export and is never used to derive the action name.
    rbac_evidence: RbacEvidencePin,
    /// SHA-256 of this canonical review with `reviewSha256` cleared.
    review_sha256: String,
    operations: Vec<ReviewOperation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ReviewSource {
    kind: String,
    revision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct UpstreamPin {
    repository: String,
    revision: String,
    path: String,
    source_sha256: String,
    catalog_sha256: String,
}

/// A separately pinned provider-operation artifact used as evidence for a
/// manually reviewed RBAC action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RbacEvidencePin {
    kind: String,
    repository: String,
    revision: String,
    path: String,
    source_sha256: String,
}

/// One human-reviewed source operation and its exact v0 execution metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReviewOperation {
    pub operation_id: String,
    pub entry_id: String,
    pub display_name: String,
    pub description: String,
    #[serde(default)]
    pub cli_equivalent: Option<String>,
    pub cloud: AzureCloud,
    pub arm_tier: ArmTier,
    /// Provider-operation authorization is a separate reviewed input; Azure
    /// REST OpenAPI operation metadata does not establish this action.
    pub rbac_action: String,
    #[serde(default)]
    pub allowed_query_parameters: Vec<String>,
}

/// Why a pinned upstream import was rejected.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum UpstreamError {
    #[error("upstream catalog is too large")]
    TooLarge,
    #[error("upstream catalog JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("upstream catalog format version is unsupported")]
    UnsupportedCatalogFormat,
    #[error("upstream review format version is unsupported")]
    UnsupportedReviewFormat,
    #[error("upstream provenance is not pinned")]
    UnpinnedSource,
    #[error("RBAC evidence provenance is not pinned")]
    UnpinnedRbacEvidence,
    #[error("upstream catalog hash does not match its canonical content")]
    CatalogHashMismatch,
    #[error("upstream review does not pin the imported catalog")]
    ReviewSourceMismatch,
    #[error("upstream review hash does not match its canonical content")]
    ReviewHashMismatch,
    #[error("upstream catalog contains no operations or too many operations")]
    InvalidOperationCount,
    #[error("upstream review contains too many operations")]
    InvalidReviewCount,
    #[error("upstream operation {index} is invalid: {reason}")]
    InvalidOperation { index: usize, reason: String },
    #[error("upstream operation {index} duplicates another operation")]
    DuplicateOperation { index: usize },
    #[error("review operation {index} is invalid: {reason}")]
    InvalidReview { index: usize, reason: String },
    #[error("review operation {index} duplicates another operation")]
    DuplicateReview { index: usize },
    #[error("review operation {index} references an unknown source operation")]
    UnknownOperation { index: usize },
    #[error("review operation {index} is not a supported read-only GET route")]
    UnsupportedOperation { index: usize },
    #[error("review operation {index} requests an unsupported ARM tier")]
    UnsupportedTier { index: usize },
    #[error("review operation {index} has a route that is not subscription-scoped")]
    UnrepresentablePath { index: usize },
    #[error("imported route or schema collides with the reviewed manifest")]
    Collision,
    #[error("generated manifest is invalid after upstream import: {0}")]
    Manifest(String),
    #[error("upstream fixture cannot serialize deterministically: {0}")]
    Serialization(String),
    #[error("upstream fixture is not in canonical byte form")]
    NonCanonical,
}

/// Parse and validate an upstream export.
pub fn parse_catalog(bytes: &[u8]) -> Result<UpstreamCatalog, UpstreamError> {
    if bytes.len() > MAX_CATALOG_BYTES {
        return Err(UpstreamError::TooLarge);
    }
    let catalog = serde_json::from_slice(bytes)
        .map_err(|error| UpstreamError::InvalidJson(error.to_string()))?;
    validate_catalog(&catalog)?;
    Ok(catalog)
}

/// Parse and validate a review join.
pub fn parse_review(bytes: &[u8]) -> Result<ReviewBundle, UpstreamError> {
    if bytes.len() > MAX_CATALOG_BYTES {
        return Err(UpstreamError::TooLarge);
    }
    let review = serde_json::from_slice(bytes)
        .map_err(|error| UpstreamError::InvalidJson(error.to_string()))?;
    validate_review(&review)?;
    Ok(review)
}

/// Validate source provenance, operation shape, and deterministic uniqueness.
pub fn validate_catalog(catalog: &UpstreamCatalog) -> Result<(), UpstreamError> {
    if catalog.format_version != UPSTREAM_FORMAT_VERSION {
        return Err(UpstreamError::UnsupportedCatalogFormat);
    }
    validate_source(&catalog.source)?;
    if catalog.operations.is_empty() || catalog.operations.len() > MAX_OPERATIONS {
        return Err(UpstreamError::InvalidOperationCount);
    }
    let mut ids = BTreeSet::new();
    for (index, operation) in catalog.operations.iter().enumerate() {
        validate_operation(operation)
            .map_err(|reason| UpstreamError::InvalidOperation { index, reason })?;
        if !ids.insert(operation.operation_id.clone()) {
            return Err(UpstreamError::DuplicateOperation { index });
        }
    }
    let expected = computed_catalog_hash(catalog)?;
    if catalog.source.catalog_sha256 != expected {
        return Err(UpstreamError::CatalogHashMismatch);
    }
    Ok(())
}

/// Validate that a review is pinned to the exact parsed catalog identity.
pub fn validate_review(review: &ReviewBundle) -> Result<(), UpstreamError> {
    if review.format_version != REVIEW_FORMAT_VERSION {
        return Err(UpstreamError::UnsupportedReviewFormat);
    }
    if !bounded(&review.review_id, 256)
        || review.source.kind != "manual-route-review"
        || !bounded(&review.source.revision, 256)
        || !bounded(&review.upstream.repository, 512)
        || !bounded(&review.upstream.revision, 256)
        || !bounded(&review.upstream.path, 1_024)
        || !valid_sha256(&review.upstream.source_sha256)
        || !valid_sha256(&review.upstream.catalog_sha256)
    {
        return Err(UpstreamError::UnpinnedSource);
    }
    if !valid_rbac_evidence(&review.rbac_evidence) {
        return Err(UpstreamError::UnpinnedRbacEvidence);
    }
    if review.operations.len() > MAX_REVIEWS {
        return Err(UpstreamError::InvalidReviewCount);
    }
    let mut operation_clouds = BTreeSet::new();
    let mut entry_ids = BTreeSet::new();
    for (index, operation) in review.operations.iter().enumerate() {
        validate_review_operation(operation)
            .map_err(|reason| UpstreamError::InvalidReview { index, reason })?;
        if !operation_clouds.insert((operation.operation_id.clone(), operation.cloud))
            || !entry_ids.insert(operation.entry_id.clone())
        {
            return Err(UpstreamError::DuplicateReview { index });
        }
    }
    let expected = computed_review_hash(review)?;
    if review.review_sha256 != expected {
        return Err(UpstreamError::ReviewHashMismatch);
    }
    Ok(())
}

/// Return deterministic canonical bytes for an upstream fixture.
pub fn canonical_catalog_bytes(catalog: &UpstreamCatalog) -> Result<Vec<u8>, UpstreamError> {
    let mut normalized = catalog.clone();
    normalized
        .operations
        .sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
    let mut bytes = serde_json::to_vec_pretty(&normalized)
        .map_err(|error| UpstreamError::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Compute the source content hash after clearing its self-referential field.
pub fn computed_catalog_hash(catalog: &UpstreamCatalog) -> Result<String, UpstreamError> {
    let mut normalized = catalog.clone();
    normalized.source.catalog_sha256.clear();
    normalized
        .operations
        .sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
    let bytes = serde_json::to_vec(&normalized)
        .map_err(|error| UpstreamError::Serialization(error.to_string()))?;
    let digest = Sha256::digest(bytes);
    Ok(format!("sha256:{digest:x}"))
}

/// Return deterministic canonical bytes for a review join.
pub fn canonical_review_bytes(review: &ReviewBundle) -> Result<Vec<u8>, UpstreamError> {
    let mut normalized = review.clone();
    normalized.operations.sort_by_key(review_operation_key);
    let mut bytes = serde_json::to_vec_pretty(&normalized)
        .map_err(|error| UpstreamError::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Compute the review content hash after clearing its self-referential field.
pub fn computed_review_hash(review: &ReviewBundle) -> Result<String, UpstreamError> {
    let mut normalized = review.clone();
    normalized.review_sha256.clear();
    normalized.operations.sort_by_key(review_operation_key);
    let bytes = serde_json::to_vec(&normalized)
        .map_err(|error| UpstreamError::Serialization(error.to_string()))?;
    let digest = Sha256::digest(bytes);
    Ok(format!("sha256:{digest:x}"))
}

/// Merge the explicit review join into a seed route manifest.
///
/// This is the only function that can turn upstream candidates into
/// executable/discoverable rows.  It rejects all reviewed non-GET, body-bearing,
/// non-inspection, and non-subscription-scoped operations.
pub fn merge_into_manifest(
    manifest: &mut RouteManifest,
    catalog: &UpstreamCatalog,
    review: &ReviewBundle,
) -> Result<usize, UpstreamError> {
    validate_catalog(catalog)?;
    validate_review(review)?;
    if review.upstream.repository != catalog.source.repository
        || review.upstream.revision != catalog.source.revision
        || review.upstream.path != catalog.source.path
        || review.upstream.source_sha256 != catalog.source.source_sha256
        || review.upstream.catalog_sha256 != catalog.source.catalog_sha256
    {
        return Err(UpstreamError::ReviewSourceMismatch);
    }
    let by_id = catalog
        .operations
        .iter()
        .map(|operation| (operation.operation_id.as_str(), operation))
        .collect::<std::collections::BTreeMap<_, _>>();
    let route_keys = manifest.routes().map(route_key).collect::<BTreeSet<_>>();
    let schema_ids = manifest
        .schemas()
        .iter()
        .map(|schema| schema.entry_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut added_routes: Vec<ManifestRoute> = Vec::new();
    let mut added_schemas = Vec::new();
    for (index, selected) in review.operations.iter().enumerate() {
        let Some(operation) = by_id.get(selected.operation_id.as_str()) else {
            return Err(UpstreamError::UnknownOperation { index });
        };
        if operation.method != HttpMethod::Get || operation.request_body_schema.is_some() {
            return Err(UpstreamError::UnsupportedOperation { index });
        }
        if selected.arm_tier != ArmTier::Inspect {
            return Err(UpstreamError::UnsupportedTier { index });
        }
        let Some(request_path) = operation.path_template.strip_prefix(SUBSCRIPTION_PREFIX) else {
            return Err(UpstreamError::UnrepresentablePath { index });
        };
        if request_path.is_empty() || !request_path.starts_with('/') {
            return Err(UpstreamError::UnrepresentablePath { index });
        }
        let route = ManifestRoute {
            cloud: selected.cloud,
            purpose: ManifestRoutePurpose::Request,
            method: HttpMethod::Get,
            path_template: operation.path_template.clone(),
            api_versions: operation.api_versions.clone(),
            rbac_action: selected.rbac_action.clone(),
            arm_tier: ArmTier::Inspect,
            allowed_query_parameters: selected.allowed_query_parameters.clone(),
        };
        if !manifest.routes().any(|known| {
            executable_selectors_overlap(
                &ExecutableSelector::new(
                    known.cloud,
                    known.purpose.route_purpose(),
                    known.method,
                    &known.path_template,
                    &known.api_versions,
                ),
                &ExecutableSelector::new(
                    route.cloud,
                    route.purpose.route_purpose(),
                    route.method,
                    &route.path_template,
                    &route.api_versions,
                ),
            )
        }) && !added_routes.iter().any(|known| {
            executable_selectors_overlap(
                &ExecutableSelector::new(
                    known.cloud,
                    known.purpose.route_purpose(),
                    known.method,
                    &known.path_template,
                    &known.api_versions,
                ),
                &ExecutableSelector::new(
                    route.cloud,
                    route.purpose.route_purpose(),
                    route.method,
                    &route.path_template,
                    &route.api_versions,
                ),
            )
        }) && !route_keys.contains(&route_key(&route))
            && !added_routes
                .iter()
                .any(|known| route_key(known) == route_key(&route))
        {
            added_routes.push(route.clone());
        } else {
            return Err(UpstreamError::Collision);
        }
        if schema_ids.contains(selected.entry_id.as_str())
            || added_schemas
                .iter()
                .any(|schema: &ManifestSchema| schema.entry_id == selected.entry_id)
        {
            return Err(UpstreamError::Collision);
        }
        added_schemas.push(ManifestSchema {
            entry_id: selected.entry_id.clone(),
            resource_type: operation.resource_type.clone(),
            operation: operation.operation.clone(),
            purpose: ManifestRoutePurpose::Request,
            display_name: selected.display_name.clone(),
            description: selected.description.clone(),
            cli_equivalent: selected.cli_equivalent.clone(),
            cloud: selected.cloud,
            method: HttpMethod::Get,
            canonical_path_template: operation.path_template.clone(),
            request_path_template: request_path.to_owned(),
            api_versions: operation.api_versions.clone(),
            rbac_action: selected.rbac_action.clone(),
            arm_tier: ArmTier::Inspect,
            data_plane_grant: None,
            argument_schema: Some(request_argument_schema(
                selected.cloud,
                request_path,
                &operation.api_versions,
                &operation.path_template,
            )),
            request_body_schema: None,
            // Upstream response models are intentionally not advertised in
            // v0 until checked-in fixtures exercise their exact shape.
            response_body_schema: None,
        });
    }
    let count = added_routes.len();
    manifest.append_reviewed_rows(
        added_routes,
        added_schemas,
        ManifestUpstreamSource {
            kind: catalog.source.kind.clone(),
            repository: catalog.source.repository.clone(),
            revision: catalog.source.revision.clone(),
            path: catalog.source.path.clone(),
            source_sha256: catalog.source.source_sha256.clone(),
            catalog_sha256: catalog.source.catalog_sha256.clone(),
            review_id: review.review_id.clone(),
            review_revision: review.source.revision.clone(),
            review_sha256: review.review_sha256.clone(),
            rbac_evidence: crate::route_manifest::ManifestRbacEvidence {
                kind: review.rbac_evidence.kind.clone(),
                repository: review.rbac_evidence.repository.clone(),
                revision: review.rbac_evidence.revision.clone(),
                path: review.rbac_evidence.path.clone(),
                source_sha256: review.rbac_evidence.source_sha256.clone(),
            },
        },
    );
    manifest.set_source_revision(crate::route_manifest::V1_SOURCE_REVISION);
    let policy_hash = crate::route_manifest::computed_policy_hash(manifest)
        .map_err(|error| UpstreamError::Manifest(error.to_string()))?;
    manifest.set_policy_hash(policy_hash);
    crate::route_manifest::validate_manifest_for_generation(manifest)
        .map_err(|error| UpstreamError::Manifest(error.to_string()))?;
    Ok(count)
}

/// Generate an expanded manifest from an immutable seed and pinned inputs.
///
/// The generated output is never used as an input.  This keeps deletion or
/// revision of a review row deterministic and prevents stale output rows from
/// silently becoming executable policy.
pub fn generate_manifest(
    seed: &RouteManifest,
    catalog: &UpstreamCatalog,
    review: &ReviewBundle,
) -> Result<RouteManifest, UpstreamError> {
    crate::route_manifest::validate_manifest_for_generation(seed)
        .map_err(|error| UpstreamError::Manifest(error.to_string()))?;
    validate_catalog(catalog)?;
    validate_review(review)?;
    let mut generated = seed.clone();
    generated.clear_policy_hash();
    merge_into_manifest(&mut generated, catalog, review)?;
    Ok(generated)
}

/// Read-only accessors used by the route generator and tests.
pub fn source(catalog: &UpstreamCatalog) -> &UpstreamSource {
    &catalog.source
}

/// Read-only access to source operations for deterministic test fixtures.
pub fn operations(catalog: &UpstreamCatalog) -> &[UpstreamOperation] {
    &catalog.operations
}

fn validate_source(source: &UpstreamSource) -> Result<(), UpstreamError> {
    if !matches!(
        source.kind.as_str(),
        UPSTREAM_SOURCE_KIND | REAL_UPSTREAM_SOURCE_KIND
    ) || !bounded(&source.repository, 512)
        || !bounded(&source.revision, 256)
        || !bounded(&source.path, 1_024)
        || !valid_sha256(&source.source_sha256)
        || !valid_sha256(&source.catalog_sha256)
    {
        return Err(UpstreamError::UnpinnedSource);
    }
    Ok(())
}

fn validate_operation(operation: &UpstreamOperation) -> Result<(), String> {
    for (name, value, maximum) in [
        ("operation id", operation.operation_id.as_str(), 256),
        (
            "provider namespace",
            operation.provider_namespace.as_str(),
            256,
        ),
        ("resource type", operation.resource_type.as_str(), 256),
        ("operation", operation.operation.as_str(), 128),
        (
            "path template",
            operation.path_template.as_str(),
            MAX_PATH_BYTES,
        ),
    ] {
        if !bounded(value, maximum) {
            return Err(format!("{name} is empty, overlong, or contains controls"));
        }
    }
    if operation.api_versions.is_empty()
        || operation.api_versions.len() > MAX_API_VERSIONS
        || operation
            .api_versions
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || operation
            .api_versions
            .iter()
            .any(|value| !bounded(value, MAX_API_VERSION_BYTES))
    {
        return Err("API versions must be sorted, unique, and bounded".to_owned());
    }
    if operation
        .request_body_schema
        .as_ref()
        .is_some_and(|schema| !bounded_schema(schema))
        || operation
            .response_body_schema
            .as_ref()
            .is_some_and(|schema| !bounded_schema(schema))
    {
        return Err("body schemas must be bounded JSON objects without references".to_owned());
    }
    if ReviewedRoute::new(
        AzureCloud::AzureCloud,
        RoutePurpose::Request,
        operation.method,
        &operation.path_template,
        operation.api_versions.iter().cloned(),
        "import/read",
        ArmTier::Inspect,
    )
    .is_err()
    {
        return Err("path template is malformed or exceeds its segment limits".to_owned());
    }
    Ok(())
}

fn validate_review_operation(operation: &ReviewOperation) -> Result<(), String> {
    for (name, value, maximum) in [
        ("operation id", operation.operation_id.as_str(), 256),
        ("entry id", operation.entry_id.as_str(), 256),
        ("display name", operation.display_name.as_str(), 256),
        ("description", operation.description.as_str(), 2_048),
    ] {
        if !bounded(value, maximum) {
            return Err(format!("{name} is empty, overlong, or contains controls"));
        }
    }
    if operation
        .cli_equivalent
        .as_deref()
        .is_some_and(|value| !bounded(value, 512))
        || operation.allowed_query_parameters.len() > 64
        || operation
            .allowed_query_parameters
            .iter()
            .any(|value| !bounded(value, 128))
        || operation
            .allowed_query_parameters
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err("review metadata is overlarge or not sorted".to_owned());
    }
    if !bounded(&operation.rbac_action, 512) {
        return Err("provider RBAC action is empty, overlong, or contains controls".to_owned());
    }
    Ok(())
}

fn bounded(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum.min(MAX_STRING_BYTES)
        && !value.chars().any(char::is_control)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .chars()
            .all(|character| character.is_ascii_hexdigit())
}

fn valid_rbac_evidence(evidence: &RbacEvidencePin) -> bool {
    bounded(&evidence.kind, 128)
        && bounded(&evidence.repository, 512)
        && bounded(&evidence.revision, 256)
        && bounded(&evidence.path, 1_024)
        && valid_sha256(&evidence.source_sha256)
}

fn review_operation_key(operation: &ReviewOperation) -> (String, String, AzureCloud) {
    (
        operation.entry_id.clone(),
        operation.operation_id.clone(),
        operation.cloud,
    )
}

fn bounded_schema(schema: &Value) -> bool {
    schema.is_object()
        && !contains_ref(schema)
        && serde_json::to_vec(schema).is_ok_and(|bytes| bytes.len() <= MAX_SCHEMA_BYTES)
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

fn route_key(route: &ManifestRoute) -> String {
    format!(
        "{}|{:?}|{:?}|{}|{}|{}|{}|{:?}",
        route.cloud.as_str(),
        route.purpose,
        route.method,
        route.path_template,
        route.api_versions.join(","),
        route.rbac_action,
        route.allowed_query_parameters.join(","),
        route.arm_tier
    )
}

fn request_argument_schema(
    cloud: AzureCloud,
    request_path: &str,
    api_versions: &[String],
    canonical_path: &str,
) -> Value {
    let api_version = if api_versions.len() == 1 {
        json!({"const": api_versions[0]})
    } else {
        json!({"enum": api_versions})
    };
    let mut properties = Map::new();
    properties.insert("cloud".to_owned(), json!({"enum": [cloud.as_str()]}));
    properties.insert("method".to_owned(), json!({"const": "GET"}));
    properties.insert(
        "path".to_owned(),
        json!({
            "description": format!("Relative az.request path matching {request_path}; the host prepends the selected subscription for {canonical_path}."),
            "maxLength": 16384,
            "minLength": 1,
            "type": "string"
        }),
    );
    properties.insert(
        "subscription".to_owned(),
        json!({
            "pattern": "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$",
            "type": "string"
        }),
    );
    properties.insert("apiVersion".to_owned(), api_version);
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": false,
        "properties": properties,
        "required": ["cloud", "method", "path", "apiVersion"],
        "title": format!("az.request arguments for {canonical_path}"),
        "type": "object"
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_manifest;

    const CATALOG_BYTES: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/upstream/azure-rest-operations-v1.json"
    ));
    const REVIEW_BYTES: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/upstream/azure-rest-review-v1.json"
    ));

    fn fixtures() -> (UpstreamCatalog, ReviewBundle) {
        (
            parse_catalog(CATALOG_BYTES).expect("upstream fixture"),
            parse_review(REVIEW_BYTES).expect("review fixture"),
        )
    }

    #[test]
    fn pinned_fixture_has_provenance_and_imports_only_explicit_get_reviews() {
        let (catalog, review) = fixtures();
        assert_eq!(source(&catalog).kind, UPSTREAM_SOURCE_KIND);
        assert_eq!(source(&catalog).revision, UPSTREAM_SOURCE_REVISION);
        assert_eq!(review.review_id, UPSTREAM_REVIEW_ID);
        assert_eq!(review.source.revision, UPSTREAM_REVIEW_REVISION);

        let base = route_manifest::checked_in_seed_manifest().expect("base manifest");
        let expanded = generate_manifest(&base, &catalog, &review).expect("expanded manifest");
        assert_eq!(route_manifest::route_count(&expanded), 18);
        assert_eq!(route_manifest::schema_count(&expanded), 12);
        assert!(
            route_manifest::schemas(&expanded)
                .iter()
                .any(|schema| schema.entry_id == "AzureCloud.storageAccounts.get")
        );
        assert!(
            route_manifest::schemas(&expanded)
                .iter()
                .any(|schema| schema.entry_id == "AzureUSGovernment.storageAccounts.get")
        );
        assert!(
            !route_manifest::schemas(&expanded)
                .iter()
                .any(|schema| schema.entry_id.contains("list"))
        );

        let storage = route_manifest::schemas(&expanded)
            .iter()
            .find(|schema| schema.entry_id == "AzureCloud.storageAccounts.get")
            .expect("storage schema");
        assert!(storage.request_body_schema.is_none());
        assert!(storage.response_body_schema.is_none());
    }

    #[test]
    fn unreviewed_candidate_never_enters_discovery() {
        let (catalog, review) = fixtures();
        let base = route_manifest::checked_in_seed_manifest().expect("base manifest");
        let expanded = generate_manifest(&base, &catalog, &review).expect("expanded manifest");
        assert!(
            route_manifest::schemas(&expanded)
                .iter()
                .all(|schema| schema.operation != "list")
        );
    }

    #[test]
    fn mutating_and_body_bearing_review_rows_fail_closed() {
        let (catalog, review) = fixtures();
        for operation_id in [
            "Storage_StorageAccounts_Create",
            "Storage_StorageAccounts_GetWithBody",
            "Storage_StorageAccounts_ListKeys",
        ] {
            let mut selected = review.clone();
            selected.operations.push(ReviewOperation {
                operation_id: operation_id.to_owned(),
                entry_id: format!("AzureCloud.test.{operation_id}"),
                display_name: "test".to_owned(),
                description: "test".to_owned(),
                cli_equivalent: None,
                cloud: AzureCloud::AzureCloud,
                arm_tier: ArmTier::Inspect,
                rbac_action: "Microsoft.Storage/storageAccounts/read".to_owned(),
                allowed_query_parameters: Vec::new(),
            });
            selected.review_sha256 = computed_review_hash(&selected).expect("review hash");
            let base = route_manifest::checked_in_seed_manifest().expect("base manifest");
            assert!(matches!(
                generate_manifest(&base, &catalog, &selected),
                Err(UpstreamError::UnsupportedOperation { .. })
            ));
        }
    }

    #[test]
    fn write_tier_review_rows_fail_closed() {
        let (catalog, mut review) = fixtures();
        review.operations[0].arm_tier = ArmTier::Write;
        review.review_sha256 = computed_review_hash(&review).expect("review hash");
        let base = route_manifest::checked_in_seed_manifest().expect("base manifest");
        assert!(matches!(
            generate_manifest(&base, &catalog, &review),
            Err(UpstreamError::UnsupportedTier { .. })
        ));
    }

    #[test]
    fn review_identity_is_operation_and_cloud_with_unique_entry_ids() {
        let (catalog, mut review) = fixtures();
        review.operations[1].cloud = review.operations[0].cloud;
        assert!(matches!(
            validate_review(&review),
            Err(UpstreamError::DuplicateReview { .. })
        ));

        let mut review = fixtures().1;
        review.operations[1].entry_id = review.operations[0].entry_id.clone();
        assert!(matches!(
            validate_review(&review),
            Err(UpstreamError::DuplicateReview { .. })
        ));
        assert_eq!(operations(&catalog).len(), 5);
    }

    #[test]
    fn catalog_and_external_source_pins_are_checked_separately() {
        let (mut catalog, _review) = fixtures();
        catalog.operations[0].operation.push_str("Changed");
        assert!(matches!(
            validate_catalog(&catalog),
            Err(UpstreamError::CatalogHashMismatch)
        ));

        let (catalog, mut review) = fixtures();
        review.upstream.source_sha256 =
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_owned();
        review.review_sha256 = computed_review_hash(&review).expect("review hash");
        let base = route_manifest::checked_in_seed_manifest().expect("base manifest");
        assert!(matches!(
            generate_manifest(&base, &catalog, &review),
            Err(UpstreamError::ReviewSourceMismatch)
        ));

        let (_, mut review) = fixtures();
        review.rbac_evidence.source_sha256 = "not-a-sha256-pin".to_owned();
        assert_eq!(
            validate_review(&review),
            Err(UpstreamError::UnpinnedRbacEvidence)
        );
    }

    #[test]
    fn deleted_review_row_disappears_from_pure_generation() {
        let (catalog, mut review) = fixtures();
        review.operations.pop();
        review.review_sha256 = computed_review_hash(&review).expect("review hash");
        let base = route_manifest::checked_in_seed_manifest().expect("base manifest");
        let generated = generate_manifest(&base, &catalog, &review).expect("generated manifest");
        assert_eq!(route_manifest::route_count(&generated), 17);
        assert_eq!(route_manifest::schema_count(&generated), 11);
        assert!(
            !route_manifest::schemas(&generated)
                .iter()
                .any(|schema| schema.entry_id == "AzureUSGovernment.storageAccounts.get")
        );
    }

    #[test]
    fn changed_review_revision_and_hash_are_persisted() {
        let (catalog, mut review) = fixtures();
        review.source.revision = "synthetic-route-review-v2".to_owned();
        review.review_sha256 = computed_review_hash(&review).expect("review hash");
        let expected_hash = review.review_sha256.clone();
        let base = route_manifest::checked_in_seed_manifest().expect("base manifest");
        let generated = generate_manifest(&base, &catalog, &review).expect("generated manifest");
        let source = generated
            .source
            .upstream
            .as_ref()
            .expect("upstream provenance");
        assert_eq!(source.review_revision, "synthetic-route-review-v2");
        assert_eq!(source.review_sha256, expected_hash);
    }

    #[test]
    fn review_hash_detects_changed_rows() {
        let (catalog, mut review) = fixtures();
        review.operations[0].description.push_str(" changed");
        assert!(matches!(
            validate_review(&review),
            Err(UpstreamError::ReviewHashMismatch)
        ));
        assert!(validate_catalog(&catalog).is_ok());
    }

    #[test]
    fn catalog_rejects_duplicate_resource_uri_or_overlong_templates() {
        for path_template in [
            "/subscriptions/{subscription}/{resourceUri}/{resourceUri}/providers/Test",
            &format!(
                "/{}",
                (0..65)
                    .map(|index| format!("segment{index}"))
                    .collect::<Vec<_>>()
                    .join("/")
            ),
        ] {
            let (mut catalog, _) = fixtures();
            catalog.operations[0].path_template = path_template.to_owned();
            catalog.source.catalog_sha256 = computed_catalog_hash(&catalog).expect("catalog hash");
            assert!(matches!(
                validate_catalog(&catalog),
                Err(UpstreamError::InvalidOperation { .. })
            ));
        }
    }

    #[test]
    fn generation_rejects_semantically_overlapping_reviewed_routes() {
        for path_template in [
            "/subscriptions/{subscription}/PROVIDERS/{provider}",
            "/subscriptions/{subscription}/{other}/providers",
        ] {
            let (mut catalog, mut review) = fixtures();
            catalog.operations[0].path_template = path_template.to_owned();
            catalog.operations[0].api_versions = vec!["2021-04-01".to_owned()];
            catalog.source.catalog_sha256 = computed_catalog_hash(&catalog).expect("catalog hash");
            review.upstream.catalog_sha256 = catalog.source.catalog_sha256.clone();
            review.review_sha256 = computed_review_hash(&review).expect("review hash");
            let base = route_manifest::checked_in_seed_manifest().expect("base manifest");
            let result = generate_manifest(&base, &catalog, &review);
            assert!(
                matches!(result, Err(UpstreamError::Collision)),
                "{path_template}: {result:?}"
            );
        }
    }
}
