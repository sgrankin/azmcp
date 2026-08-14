//! Offline discovery metadata for reviewed request and helper routes.
//!
//! Sources are checked against the executable policy when the index is built;
//! discovery therefore cannot become a second authorization table.

use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use thiserror::Error;

use crate::{
    cloud::AzureCloud,
    context::{Context, LogsScope},
    credential::TokenAudience,
    policy::{ArmTier, HttpMethod, PolicyBundle, ReviewedRoute, RoutePurpose},
    route_manifest,
    routes::V0_POLICY_HASH,
};

pub const MAX_QUERY_BYTES: usize = 256;
pub const DEFAULT_SEARCH_LIMIT: usize = 20;
pub const MAX_SEARCH_LIMIT: usize = 50;
pub const MAX_ENTRY_ID_BYTES: usize = 256;
pub const MAX_RESOURCE_TYPE_BYTES: usize = 256;
pub const MAX_OPERATION_BYTES: usize = 128;
pub const MAX_DISPLAY_NAME_BYTES: usize = 256;
pub const MAX_DESCRIPTION_BYTES: usize = 2_048;
pub const MAX_CLI_EQUIVALENT_BYTES: usize = 512;
pub const MAX_PATH_TEMPLATE_BYTES: usize = 1_024;
pub const MAX_API_VERSIONS: usize = 32;
pub const MAX_API_VERSION_BYTES: usize = 64;
pub const MAX_RBAC_ACTION_BYTES: usize = 512;
pub const MAX_DATA_PLANE_GRANT_BYTES: usize = 128;
pub const MAX_DATA_PLANE_BYTES: usize = 128;
pub const MAX_DATA_SCOPE_BYTES: usize = 128;
pub const MAX_AUDIENCE_BYTES: usize = 256;
pub const MAX_EXECUTION_SURFACE_BYTES: usize = 64;
pub const MAX_QUERY_PARAMETERS: usize = 64;
pub const MAX_QUERY_PARAMETER_BYTES: usize = 128;
const MAX_SCHEMA_BYTES: usize = 64 * 1024;
const SUBSCRIPTION_ROUTE: &str = "/subscriptions/{subscription}";

/// Source metadata for one reviewed operation.
///
/// Policy-owned fields are compared with the route bundle by
/// [`SchemaIndex::from_policy`]. A missing body schema means that the
/// bootstrap catalog has metadata only; it is not an invented response.
#[derive(Clone, Debug, PartialEq)]
pub struct SchemaSource {
    pub entry_id: String,
    pub resource_type: String,
    pub operation: String,
    pub purpose: RoutePurpose,
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

#[derive(Clone, Debug, PartialEq)]
struct Entry {
    source: SchemaSource,
    allowed_query_parameters: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaAccess {
    pub executable: bool,
    pub denial_reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaSearchHit {
    pub entry_id: String,
    pub resource_type: String,
    pub operation: String,
    pub execution_surface: String,
    pub display_name: String,
    pub description: String,
    pub cli_equivalent: Option<String>,
    pub cloud: AzureCloud,
    pub audience: String,
    pub method: HttpMethod,
    pub path_template: String,
    pub canonical_path_template: String,
    pub api_versions: Vec<String>,
    pub rbac_action: String,
    pub arm_tier: ArmTier,
    pub data_plane_grant: Option<String>,
    pub data_plane: Option<String>,
    pub data_scope: Option<String>,
    pub allowed_query_parameters: Vec<String>,
    pub access: SchemaAccess,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SchemaSearchResult {
    pub policy_version: String,
    pub results: Vec<SchemaSearchHit>,
    pub omitted: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaDetails {
    pub entry_id: String,
    pub resource_type: String,
    pub operation: String,
    pub execution_surface: String,
    pub display_name: String,
    pub description: String,
    pub cli_equivalent: Option<String>,
    pub cloud: AzureCloud,
    pub audience: String,
    pub method: HttpMethod,
    pub path_template: String,
    pub canonical_path_template: String,
    pub api_version: String,
    pub api_versions: Vec<String>,
    pub rbac_action: String,
    pub arm_tier: ArmTier,
    pub data_plane_grant: Option<String>,
    pub data_plane: Option<String>,
    pub data_scope: Option<String>,
    pub allowed_query_parameters: Vec<String>,
    pub argument_schema: Option<Value>,
    pub request_body_schema: Option<Value>,
    pub response_body_schema: Option<Value>,
    pub schema_availability: String,
    pub access: SchemaAccess,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SchemaError {
    #[error("schema search query is empty or too large")]
    InvalidQuery,
    #[error("schema search limit is outside the supported range")]
    InvalidLimit,
    #[error("schema cloud is not bound by the context")]
    CloudNotBound,
    #[error("schema entry was not found")]
    EntryNotFound,
    #[error("schema API version is not reviewed for this entry")]
    ApiVersionNotFound,
    #[error("schema index does not match the context policy version")]
    PolicyMismatch,
    #[error("schema source contains a duplicate entry identifier")]
    DuplicateEntry,
    #[error("schema source does not match a reviewed route")]
    UnreviewedSource,
    #[error("reviewed route has no schema metadata")]
    MissingSource,
    #[error("schema source path is not representable by its execution surface")]
    UnrepresentablePath,
    #[error("schema source contains an invalid or overlarge JSON schema")]
    InvalidSchema,
    #[error("checked-in route manifest is invalid: {0}")]
    Manifest(String),
}

/// Immutable, offline schema metadata tied to one policy bundle.
#[derive(Clone, Debug, PartialEq)]
pub struct SchemaIndex {
    policy_hash: String,
    policy_version: String,
    entries: Vec<Entry>,
}

impl SchemaIndex {
    pub fn from_policy(
        policy: &PolicyBundle,
        policy_hash: impl Into<String>,
        sources: impl IntoIterator<Item = SchemaSource>,
    ) -> Result<Self, SchemaError> {
        let policy_hash = policy_hash.into();
        if policy_hash.is_empty() {
            return Err(SchemaError::UnreviewedSource);
        }
        let discoverable_routes = policy
            .routes()
            .iter()
            .enumerate()
            .filter(|(_, route)| discoverable(route.purpose()))
            .collect::<Vec<_>>();
        let mut seen_ids = BTreeSet::new();
        let mut used_routes = BTreeSet::new();
        let mut entries = Vec::new();

        for source in sources {
            if source.entry_id.is_empty() || !seen_ids.insert(source.entry_id.clone()) {
                return Err(SchemaError::DuplicateEntry);
            }
            validate_source(&source)?;
            let Some((route_index, route)) = discoverable_routes.iter().find(|(_, route)| {
                route.cloud() == source.cloud
                    && route.purpose() == source.purpose
                    && route.method() == source.method
                    && route.path_template() == source.canonical_path_template
                    && route.api_versions() == source.api_versions.as_slice()
                    && route.rbac_action() == source.rbac_action
                    && route.tier() == source.arm_tier
            }) else {
                return Err(SchemaError::UnreviewedSource);
            };
            if !used_routes.insert(*route_index) {
                return Err(SchemaError::DuplicateEntry);
            }
            if expected_path(route) != source.request_path_template {
                return Err(SchemaError::UnrepresentablePath);
            }
            if source.data_plane_grant.as_deref() != required_data_plane_grant(route.purpose()) {
                return Err(SchemaError::UnreviewedSource);
            }
            validate_query_parameters(route.allowed_query_parameters())?;
            entries.push(Entry {
                source,
                allowed_query_parameters: route.allowed_query_parameters().to_vec(),
            });
        }

        if used_routes.len() != discoverable_routes.len() {
            return Err(SchemaError::MissingSource);
        }
        entries.sort_by(|left, right| left.source.entry_id.cmp(&right.source.entry_id));
        Ok(Self {
            policy_hash,
            policy_version: policy.version().to_owned(),
            entries,
        })
    }

    pub fn v0(policy: &PolicyBundle) -> Result<Self, SchemaError> {
        Self::from_policy(policy, V0_POLICY_HASH, v0_sources()?)
    }

    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }

    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    pub fn search(
        &self,
        context: &Context,
        query: &str,
        cloud: Option<AzureCloud>,
        limit: usize,
    ) -> Result<SchemaSearchResult, SchemaError> {
        self.ensure_policy(context)?;
        if query.trim().is_empty() || query.len() > MAX_QUERY_BYTES {
            return Err(SchemaError::InvalidQuery);
        }
        if !(1..=MAX_SEARCH_LIMIT).contains(&limit) {
            return Err(SchemaError::InvalidLimit);
        }
        let bound_clouds = bound_clouds(context);
        if cloud.is_some_and(|cloud| !bound_clouds.contains(&cloud)) {
            return Err(SchemaError::CloudNotBound);
        }
        let terms = query_terms(query);
        let mut scored = self
            .entries
            .iter()
            .filter(|entry| {
                bound_clouds.contains(&entry.source.cloud)
                    && cloud.is_none_or(|cloud| cloud == entry.source.cloud)
            })
            .filter_map(|entry| {
                score_entry(entry, &terms).map(|score| {
                    (
                        score,
                        entry.source.entry_id.clone(),
                        search_hit(entry, access(entry, context)),
                    )
                })
            })
            .collect::<Vec<_>>();
        scored.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
        let omitted = scored.len().saturating_sub(limit);
        Ok(SchemaSearchResult {
            policy_version: self.policy_version.clone(),
            results: scored
                .into_iter()
                .take(limit)
                .map(|(_, _, hit)| hit)
                .collect(),
            omitted,
        })
    }

    pub fn get(
        &self,
        context: &Context,
        entry_id: &str,
        api_version: &str,
    ) -> Result<SchemaDetails, SchemaError> {
        self.ensure_policy(context)?;
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.source.entry_id == entry_id)
            .ok_or(SchemaError::EntryNotFound)?;
        if !bound_clouds(context).contains(&entry.source.cloud) {
            return Err(SchemaError::CloudNotBound);
        }
        if !entry
            .source
            .api_versions
            .iter()
            .any(|version| version == api_version)
        {
            return Err(SchemaError::ApiVersionNotFound);
        }
        let source = &entry.source;
        Ok(SchemaDetails {
            entry_id: source.entry_id.clone(),
            resource_type: source.resource_type.clone(),
            operation: source.operation.clone(),
            execution_surface: execution_surface(source.purpose).to_owned(),
            display_name: source.display_name.clone(),
            description: source.description.clone(),
            cli_equivalent: source.cli_equivalent.clone(),
            cloud: source.cloud,
            audience: audience(source.cloud, source.purpose).to_owned(),
            method: source.method,
            path_template: source.request_path_template.clone(),
            canonical_path_template: source.canonical_path_template.clone(),
            api_version: api_version.to_owned(),
            api_versions: source.api_versions.clone(),
            rbac_action: source.rbac_action.clone(),
            arm_tier: source.arm_tier,
            data_plane_grant: source.data_plane_grant.clone(),
            data_plane: data_plane(source.purpose).map(ToOwned::to_owned),
            data_scope: data_scope(source.purpose).map(ToOwned::to_owned),
            allowed_query_parameters: entry.allowed_query_parameters.clone(),
            argument_schema: source.argument_schema.clone(),
            request_body_schema: source.request_body_schema.clone(),
            response_body_schema: source.response_body_schema.clone(),
            schema_availability: if source.response_body_schema.is_some() {
                "full"
            } else {
                "metadataOnly"
            }
            .to_owned(),
            access: access(entry, context),
        })
    }

    fn ensure_policy(&self, context: &Context) -> Result<(), SchemaError> {
        (context.policy_hash() == self.policy_hash
            && context.policy_version() == self.policy_version)
            .then_some(())
            .ok_or(SchemaError::PolicyMismatch)
    }
}

fn validate_source(source: &SchemaSource) -> Result<(), SchemaError> {
    if !discoverable(source.purpose)
        || (source.purpose != RoutePurpose::Request && source.argument_schema.is_none())
    {
        return Err(SchemaError::MissingSource);
    }
    if !bounded(&source.entry_id, MAX_ENTRY_ID_BYTES)
        || !bounded(&source.resource_type, MAX_RESOURCE_TYPE_BYTES)
        || !bounded(&source.operation, MAX_OPERATION_BYTES)
        || !bounded(&source.display_name, MAX_DISPLAY_NAME_BYTES)
        || !bounded(&source.description, MAX_DESCRIPTION_BYTES)
        || source
            .cli_equivalent
            .as_ref()
            .is_some_and(|value| !bounded(value, MAX_CLI_EQUIVALENT_BYTES))
        || !bounded(&source.canonical_path_template, MAX_PATH_TEMPLATE_BYTES)
        || !bounded(&source.request_path_template, MAX_PATH_TEMPLATE_BYTES)
        || source.api_versions.is_empty()
        || source.api_versions.len() > MAX_API_VERSIONS
        || source
            .api_versions
            .iter()
            .any(|value| !bounded(value, MAX_API_VERSION_BYTES))
        || !bounded(&source.rbac_action, MAX_RBAC_ACTION_BYTES)
        || source
            .data_plane_grant
            .as_ref()
            .is_some_and(|value| !bounded(value, MAX_DATA_PLANE_GRANT_BYTES))
    {
        return Err(SchemaError::UnreviewedSource);
    }
    if source
        .argument_schema
        .as_ref()
        .is_none_or(|schema| !valid_closed_object_schema(schema))
        || source
            .request_body_schema
            .as_ref()
            .is_some_and(|schema| !valid_closed_object_schema(schema))
        || source
            .response_body_schema
            .as_ref()
            .is_some_and(|schema| !valid_schema(schema))
    {
        return Err(SchemaError::InvalidSchema);
    }
    Ok(())
}

fn validate_query_parameters(values: &[String]) -> Result<(), SchemaError> {
    if values.len() > MAX_QUERY_PARAMETERS
        || values
            .iter()
            .any(|value| !bounded(value, MAX_QUERY_PARAMETER_BYTES))
    {
        return Err(SchemaError::UnreviewedSource);
    }
    Ok(())
}

fn bounded(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

fn valid_schema(schema: &Value) -> bool {
    schema.is_object()
        && !contains_ref(schema)
        && serde_json::to_vec(schema).is_ok_and(|json| json.len() <= MAX_SCHEMA_BYTES)
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

fn expected_path(route: &ReviewedRoute) -> String {
    let canonical = route.path_template();
    if route.purpose() != RoutePurpose::Request {
        canonical.to_owned()
    } else if canonical == SUBSCRIPTION_ROUTE {
        "/".to_owned()
    } else {
        canonical
            .strip_prefix("/subscriptions/{subscription}")
            .map_or_else(String::new, ToOwned::to_owned)
    }
}

fn discoverable(purpose: RoutePurpose) -> bool {
    matches!(
        purpose,
        RoutePurpose::Request
            | RoutePurpose::MetricsSingle
            | RoutePurpose::MetricsBatch
            | RoutePurpose::LogsQuery
    )
}

fn execution_surface(purpose: RoutePurpose) -> &'static str {
    match purpose {
        RoutePurpose::Request => "az.request",
        RoutePurpose::MetricsSingle => "az.metrics.single",
        RoutePurpose::MetricsBatch => "az.metrics.batch",
        RoutePurpose::LogsQuery => "az.logs.query",
        RoutePurpose::ResourceGraph => "az.graph",
        RoutePurpose::Internal => "internal",
    }
}

fn audience(cloud: AzureCloud, purpose: RoutePurpose) -> &'static str {
    let token_audience = match purpose {
        RoutePurpose::MetricsBatch => TokenAudience::Metrics,
        RoutePurpose::LogsQuery => TokenAudience::LogAnalytics,
        RoutePurpose::Request
        | RoutePurpose::ResourceGraph
        | RoutePurpose::Internal
        | RoutePurpose::MetricsSingle => TokenAudience::Arm,
    };
    token_audience.resource(cloud)
}

fn required_data_plane_grant(purpose: RoutePurpose) -> Option<&'static str> {
    match purpose {
        RoutePurpose::LogsQuery => Some("logs.query"),
        RoutePurpose::Request
        | RoutePurpose::ResourceGraph
        | RoutePurpose::Internal
        | RoutePurpose::MetricsSingle
        | RoutePurpose::MetricsBatch => None,
    }
}

fn data_plane(purpose: RoutePurpose) -> Option<&'static str> {
    match purpose {
        RoutePurpose::MetricsBatch => Some("metrics"),
        RoutePurpose::LogsQuery => Some("logs.query"),
        RoutePurpose::Request
        | RoutePurpose::ResourceGraph
        | RoutePurpose::Internal
        | RoutePurpose::MetricsSingle => None,
    }
}

fn data_scope(purpose: RoutePurpose) -> Option<&'static str> {
    match purpose {
        RoutePurpose::MetricsSingle | RoutePurpose::MetricsBatch => Some("boundSubscription"),
        RoutePurpose::LogsQuery => Some("allAccessible"),
        RoutePurpose::Request | RoutePurpose::ResourceGraph | RoutePurpose::Internal => None,
    }
}

fn bound_clouds(context: &Context) -> BTreeSet<AzureCloud> {
    context
        .resolved_bindings()
        .iter()
        .map(|binding| binding.cloud())
        .collect()
}

fn access(entry: &Entry, context: &Context) -> SchemaAccess {
    let source = &entry.source;
    if context.arm_tier() < source.arm_tier {
        return SchemaAccess {
            executable: false,
            denial_reason: Some("arm_tier_required".to_owned()),
        };
    }
    if source
        .data_plane_grant
        .as_ref()
        .is_some_and(|grant| !context.data_planes().iter().any(|known| known == grant))
    {
        return SchemaAccess {
            executable: false,
            denial_reason: Some("data_plane_grant_required".to_owned()),
        };
    }
    if source.purpose == RoutePurpose::LogsQuery
        && !matches!(
            context.logs_scopes().get(&source.cloud),
            Some(LogsScope::AllAccessible)
        )
    {
        return SchemaAccess {
            executable: false,
            denial_reason: Some("data_scope_required".to_owned()),
        };
    }
    SchemaAccess {
        executable: true,
        denial_reason: None,
    }
}

fn search_hit(entry: &Entry, access: SchemaAccess) -> SchemaSearchHit {
    let source = &entry.source;
    SchemaSearchHit {
        entry_id: source.entry_id.clone(),
        resource_type: source.resource_type.clone(),
        operation: source.operation.clone(),
        execution_surface: execution_surface(source.purpose).to_owned(),
        display_name: source.display_name.clone(),
        description: source.description.clone(),
        cli_equivalent: source.cli_equivalent.clone(),
        cloud: source.cloud,
        audience: audience(source.cloud, source.purpose).to_owned(),
        method: source.method,
        path_template: source.request_path_template.clone(),
        canonical_path_template: source.canonical_path_template.clone(),
        api_versions: source.api_versions.clone(),
        rbac_action: source.rbac_action.clone(),
        arm_tier: source.arm_tier,
        data_plane_grant: source.data_plane_grant.clone(),
        data_plane: data_plane(source.purpose).map(ToOwned::to_owned),
        data_scope: data_scope(source.purpose).map(ToOwned::to_owned),
        allowed_query_parameters: entry.allowed_query_parameters.clone(),
        access,
    }
}

fn query_terms(query: &str) -> Vec<String> {
    query
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|term| !term.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn score_entry(entry: &Entry, terms: &[String]) -> Option<usize> {
    let source = &entry.source;
    let fields = [
        (source.resource_type.as_str(), 100),
        (source.operation.as_str(), 90),
        (execution_surface(source.purpose), 90),
        (source.cli_equivalent.as_deref().unwrap_or_default(), 80),
        (source.request_path_template.as_str(), 60),
        (source.display_name.as_str(), 40),
        (source.description.as_str(), 10),
    ];
    let mut score = 0;
    for term in terms {
        let mut term_score = fields
            .iter()
            .filter(|(field, _)| {
                field
                    .split(|character: char| !character.is_ascii_alphanumeric())
                    .any(|word| word.eq_ignore_ascii_case(term))
            })
            .map(|(_, weight)| *weight)
            .max()
            .unwrap_or_default();
        if term_score == 0
            && fields
                .iter()
                .any(|(field, _)| field.to_ascii_lowercase().contains(term))
        {
            term_score = 1;
        }
        score += term_score;
    }
    (score > 0).then_some(score)
}

fn v0_sources() -> Result<Vec<SchemaSource>, SchemaError> {
    let manifest = route_manifest::checked_in_manifest()
        .map_err(|error| SchemaError::Manifest(error.to_string()))?;
    Ok(route_manifest::schemas(&manifest)
        .iter()
        .map(|source| SchemaSource {
            entry_id: source.entry_id.clone(),
            resource_type: source.resource_type.clone(),
            operation: source.operation.clone(),
            purpose: source.purpose.route_purpose(),
            display_name: source.display_name.clone(),
            description: source.description.clone(),
            cli_equivalent: source.cli_equivalent.clone(),
            cloud: source.cloud,
            method: source.method,
            canonical_path_template: source.canonical_path_template.clone(),
            request_path_template: source.request_path_template.clone(),
            api_versions: source.api_versions.clone(),
            rbac_action: source.rbac_action.clone(),
            arm_tier: source.arm_tier,
            data_plane_grant: source.data_plane_grant.clone(),
            argument_schema: source.argument_schema.clone(),
            request_body_schema: source.request_body_schema.clone(),
            response_body_schema: source.response_body_schema.clone(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{CloudBinding, SubscriptionId, TenantId},
        context::{
            ContextOptions, ContextRegistry, GraphScope, Identity, LogsScope, RegistryConfig,
        },
        routes::PROVIDERS_API_VERSION,
    };
    use std::{collections::BTreeMap, time::Duration};

    const SUBSCRIPTION: &str = "11111111-1111-1111-1111-111111111111";
    const TENANT: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const PROVIDER_ROUTE: &str = "/subscriptions/{subscription}/providers/{namespace}";

    fn policy() -> PolicyBundle {
        crate::routes::v0_policy().expect("v0 policy")
    }

    fn context(policy_version: &str) -> Context {
        context_with_policy(V0_POLICY_HASH, policy_version)
    }

    fn context_with_policy(policy_hash: &str, policy_version: &str) -> Context {
        context_with_grants(policy_hash, policy_version, false, false)
    }

    fn context_with_logs_grant(policy_hash: &str, policy_version: &str) -> Context {
        context_with_grants(policy_hash, policy_version, true, true)
    }

    fn context_with_logs_grant_without_scope(policy_hash: &str, policy_version: &str) -> Context {
        context_with_grants(policy_hash, policy_version, true, false)
    }

    fn context_with_grants(
        policy_hash: &str,
        policy_version: &str,
        logs_grant: bool,
        logs_scope: bool,
    ) -> Context {
        let registry = ContextRegistry::new(RegistryConfig::new(
            2,
            Duration::from_secs(60),
            Duration::from_secs(600),
        ))
        .expect("registry");
        let binding = CloudBinding::new(
            SubscriptionId::new(SUBSCRIPTION).expect("subscription"),
            Some(TenantId::new(TENANT).expect("tenant")),
        )
        .resolve(AzureCloud::AzureCloud, &[])
        .expect("binding");
        let options = ContextOptions::new(
            Identity::User,
            ArmTier::Inspect,
            if logs_grant {
                vec!["logs.query".to_owned()]
            } else {
                Vec::new()
            },
            vec![binding],
            policy_hash,
            policy_version,
        )
        .expect("options")
        .with_graph_scopes(BTreeMap::from([(
            AzureCloud::AzureCloud,
            GraphScope::Subscriptions(vec![
                SubscriptionId::new(SUBSCRIPTION).expect("subscription"),
            ]),
        )]))
        .expect("scopes");
        let options = if logs_scope {
            options
                .with_logs_scopes(BTreeMap::from([(
                    AzureCloud::AzureCloud,
                    LogsScope::AllAccessible,
                )]))
                .expect("logs scope")
        } else {
            options
        };
        registry
            .open(options, std::time::Instant::now())
            .expect("context")
    }

    #[test]
    fn bootstrap_index_contains_helpers_and_metadata_only_response_schemas() {
        let index = SchemaIndex::v0(&policy()).expect("index");
        let context = context(crate::routes::V0_POLICY_VERSION);
        let result = index
            .search(&context, "namespace", Some(AzureCloud::AzureCloud), 50)
            .expect("search");
        assert_eq!(result.results.len(), 1);
        assert_eq!(
            index
                .search(&context, "metrics.single", Some(AzureCloud::AzureCloud), 50)
                .expect("metrics search")
                .results[0]
                .execution_surface,
            "az.metrics.single"
        );
        assert!(
            index
                .get(&context, "AzureCloud.providers.get", PROVIDERS_API_VERSION)
                .expect("details")
                .response_body_schema
                .is_none()
        );
    }

    #[test]
    fn search_is_deterministic_and_context_filtered() {
        let index = SchemaIndex::v0(&policy()).expect("index");
        let context = context(crate::routes::V0_POLICY_VERSION);
        let first = index
            .search(&context, "namespace", None, DEFAULT_SEARCH_LIMIT)
            .expect("search");
        assert_eq!(
            first,
            index
                .search(&context, "namespace", None, 20)
                .expect("search")
        );
        assert_eq!(first.results.len(), 1);
        assert!(first.results[0].access.executable);
        assert_eq!(first.results[0].path_template, "/providers/{namespace}");
        assert_eq!(
            index.search(
                &context,
                "namespace",
                Some(AzureCloud::AzureUSGovernment),
                1
            ),
            Err(SchemaError::CloudNotBound)
        );
    }

    #[test]
    fn helper_entries_expose_closed_arguments_audience_scope_and_access() {
        let index = SchemaIndex::v0(&policy()).expect("index");
        let inspect = context(crate::routes::V0_POLICY_VERSION);
        let single = index
            .get(
                &inspect,
                "AzureCloud.metrics.single",
                crate::routes::METRICS_API_VERSION,
            )
            .expect("single details");
        assert_eq!(single.execution_surface, "az.metrics.single");
        assert_eq!(single.audience, "https://management.azure.com/");
        assert_eq!(single.data_plane, None);
        assert_eq!(single.data_scope.as_deref(), Some("boundSubscription"));
        let single_arguments = single.argument_schema.expect("single arguments");
        assert_eq!(
            single_arguments["required"],
            json!(["cloud", "resourceId", "metricNames"])
        );
        assert_eq!(single_arguments["additionalProperties"], json!(false));
        assert_eq!(
            single_arguments["properties"]["cloud"]["enum"],
            json!(["AzureCloud"])
        );

        let request = index
            .get(
                &inspect,
                "AzureCloud.providers.get",
                crate::routes::PROVIDERS_API_VERSION,
            )
            .expect("request details");
        let request_arguments = request.argument_schema.expect("az.request arguments");
        assert_eq!(request.execution_surface, "az.request");
        assert_eq!(request_arguments["additionalProperties"], json!(false));
        assert_eq!(request_arguments["properties"]["method"]["const"], "GET");
        assert_eq!(
            request_arguments["properties"]["apiVersion"]["const"],
            "2021-04-01"
        );
        assert!(request_arguments["properties"].get("headers").is_none());
        assert!(request_arguments["properties"].get("body").is_none());

        let batch = index
            .get(
                &inspect,
                "AzureCloud.metrics.batch",
                crate::routes::METRICS_API_VERSION,
            )
            .expect("batch details");
        assert_eq!(batch.execution_surface, "az.metrics.batch");
        assert_eq!(batch.audience, "https://metrics.monitor.azure.com/");
        assert_eq!(batch.data_plane.as_deref(), Some("metrics"));
        assert_eq!(batch.data_scope.as_deref(), Some("boundSubscription"));
        assert_eq!(
            batch.argument_schema.expect("batch arguments")["required"],
            json!([
                "cloud",
                "region",
                "resourceIds",
                "metricNamespace",
                "metricNames"
            ])
        );

        let denied_logs = index
            .get(
                &inspect,
                "AzureCloud.logs.query",
                crate::routes::LOGS_QUERY_API_VERSION,
            )
            .expect("logs details");
        assert_eq!(denied_logs.execution_surface, "az.logs.query");
        assert_eq!(denied_logs.audience, "https://api.loganalytics.io");
        assert_eq!(denied_logs.data_plane.as_deref(), Some("logs.query"));
        assert_eq!(denied_logs.data_scope.as_deref(), Some("allAccessible"));
        assert_eq!(
            denied_logs.access,
            SchemaAccess {
                executable: false,
                denial_reason: Some("data_plane_grant_required".to_owned()),
            }
        );
        let grant_without_scope = index
            .get(
                &context_with_logs_grant_without_scope(
                    V0_POLICY_HASH,
                    crate::routes::V0_POLICY_VERSION,
                ),
                "AzureCloud.logs.query",
                crate::routes::LOGS_QUERY_API_VERSION,
            )
            .expect("logs details without scope");
        assert_eq!(
            grant_without_scope.access,
            SchemaAccess {
                executable: false,
                denial_reason: Some("data_scope_required".to_owned()),
            }
        );
        let allowed_logs = index
            .get(
                &context_with_logs_grant(V0_POLICY_HASH, crate::routes::V0_POLICY_VERSION),
                "AzureCloud.logs.query",
                crate::routes::LOGS_QUERY_API_VERSION,
            )
            .expect("granted logs details");
        assert!(allowed_logs.access.executable);
        assert_eq!(allowed_logs.access.denial_reason, None);
    }

    #[test]
    fn get_requires_an_exact_reviewed_version() {
        let index = SchemaIndex::v0(&policy()).expect("index");
        let context = context(crate::routes::V0_POLICY_VERSION);
        assert_eq!(
            index.get(&context, "AzureCloud.providers.get", "2025-01-01"),
            Err(SchemaError::ApiVersionNotFound)
        );
        let details = index
            .get(&context, "AzureCloud.providers.get", PROVIDERS_API_VERSION)
            .expect("details");
        assert_eq!(details.path_template, "/providers/{namespace}");
        assert_eq!(details.canonical_path_template, PROVIDER_ROUTE);
    }

    #[test]
    fn index_rejects_unreviewed_incomplete_and_mismatched_sources() {
        let mut sources = v0_sources().expect("checked-in schema fixture");
        sources.pop();
        assert_eq!(
            SchemaIndex::from_policy(&policy(), V0_POLICY_HASH, sources),
            Err(SchemaError::MissingSource)
        );
        let mut sources = v0_sources().expect("checked-in schema fixture");
        sources[0].canonical_path_template = "/subscriptions/{subscription}/unknown".to_owned();
        assert_eq!(
            SchemaIndex::from_policy(&policy(), V0_POLICY_HASH, sources),
            Err(SchemaError::UnreviewedSource)
        );
        assert_eq!(
            SchemaIndex::v0(&policy()).expect("index").search(
                &context("other-policy"),
                "provider",
                None,
                1
            ),
            Err(SchemaError::PolicyMismatch)
        );
        assert_eq!(
            SchemaIndex::v0(&policy()).expect("index").search(
                &context_with_policy(
                    "different-policy-contents",
                    crate::routes::V0_POLICY_VERSION,
                ),
                "provider",
                None,
                1
            ),
            Err(SchemaError::PolicyMismatch)
        );

        let mut sources = v0_sources().expect("checked-in schema fixture");
        sources[0].description = "x".repeat(MAX_DESCRIPTION_BYTES + 1);
        assert_eq!(
            SchemaIndex::from_policy(&policy(), V0_POLICY_HASH, sources),
            Err(SchemaError::UnreviewedSource)
        );
    }
}
