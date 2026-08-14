//! Offline discovery metadata for the reviewed `az.request` routes.
//!
//! Sources are checked against the executable policy when the index is built;
//! discovery therefore cannot become a second authorization table.

use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::{
    cloud::AzureCloud,
    context::Context,
    policy::{ArmTier, HttpMethod, PolicyBundle, RoutePurpose},
    routes::{PROVIDERS_API_VERSION, SUBSCRIPTIONS_API_VERSION, V0_POLICY_HASH},
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
pub const MAX_QUERY_PARAMETERS: usize = 64;
pub const MAX_QUERY_PARAMETER_BYTES: usize = 128;
const MAX_SCHEMA_BYTES: usize = 64 * 1024;
const SUBSCRIPTION_ROUTE: &str = "/subscriptions/{subscription}";
const PROVIDER_ROUTE: &str = "/subscriptions/{subscription}/providers/{namespace}";

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
    pub display_name: String,
    pub description: String,
    pub cli_equivalent: Option<String>,
    pub cloud: AzureCloud,
    pub method: HttpMethod,
    pub path_template: String,
    pub canonical_path_template: String,
    pub api_versions: Vec<String>,
    pub rbac_action: String,
    pub arm_tier: ArmTier,
    pub data_plane_grant: Option<String>,
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
    pub display_name: String,
    pub description: String,
    pub cli_equivalent: Option<String>,
    pub cloud: AzureCloud,
    pub method: HttpMethod,
    pub path_template: String,
    pub canonical_path_template: String,
    pub api_version: String,
    pub api_versions: Vec<String>,
    pub rbac_action: String,
    pub arm_tier: ArmTier,
    pub data_plane_grant: Option<String>,
    pub allowed_query_parameters: Vec<String>,
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
    #[error("schema source does not match a reviewed Request route")]
    UnreviewedSource,
    #[error("reviewed Request route has no schema metadata")]
    MissingSource,
    #[error("schema source path is not representable by az.request")]
    UnrepresentablePath,
    #[error("schema source contains an invalid or overlarge JSON schema")]
    InvalidSchema,
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
        let request_routes = policy
            .routes()
            .iter()
            .enumerate()
            .filter(|(_, route)| route.purpose() == RoutePurpose::Request)
            .collect::<Vec<_>>();
        let mut seen_ids = BTreeSet::new();
        let mut used_routes = BTreeSet::new();
        let mut entries = Vec::new();

        for source in sources {
            if source.entry_id.is_empty() || !seen_ids.insert(source.entry_id.clone()) {
                return Err(SchemaError::DuplicateEntry);
            }
            validate_source(&source)?;
            let Some((route_index, route)) = request_routes.iter().find(|(_, route)| {
                route.cloud() == source.cloud
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
            if expected_request_path(route.path_template()) != source.request_path_template {
                return Err(SchemaError::UnrepresentablePath);
            }
            validate_query_parameters(route.allowed_query_parameters())?;
            entries.push(Entry {
                source,
                allowed_query_parameters: route.allowed_query_parameters().to_vec(),
            });
        }

        if used_routes.len() != request_routes.len() {
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
        Self::from_policy(policy, V0_POLICY_HASH, v0_sources())
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
            display_name: source.display_name.clone(),
            description: source.description.clone(),
            cli_equivalent: source.cli_equivalent.clone(),
            cloud: source.cloud,
            method: source.method,
            path_template: source.request_path_template.clone(),
            canonical_path_template: source.canonical_path_template.clone(),
            api_version: api_version.to_owned(),
            api_versions: source.api_versions.clone(),
            rbac_action: source.rbac_action.clone(),
            arm_tier: source.arm_tier,
            data_plane_grant: source.data_plane_grant.clone(),
            allowed_query_parameters: entry.allowed_query_parameters.clone(),
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
        .request_body_schema
        .as_ref()
        .is_some_and(|schema| !valid_schema(schema))
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
        && schema.get("$ref").is_none()
        && serde_json::to_vec(schema).is_ok_and(|json| json.len() <= MAX_SCHEMA_BYTES)
}

fn expected_request_path(canonical: &str) -> String {
    if canonical == SUBSCRIPTION_ROUTE {
        "/".to_owned()
    } else {
        canonical
            .strip_prefix("/subscriptions/{subscription}")
            .map_or_else(String::new, ToOwned::to_owned)
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
        display_name: source.display_name.clone(),
        description: source.description.clone(),
        cli_equivalent: source.cli_equivalent.clone(),
        cloud: source.cloud,
        method: source.method,
        path_template: source.request_path_template.clone(),
        canonical_path_template: source.canonical_path_template.clone(),
        api_versions: source.api_versions.clone(),
        rbac_action: source.rbac_action.clone(),
        arm_tier: source.arm_tier,
        data_plane_grant: source.data_plane_grant.clone(),
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

fn v0_sources() -> Vec<SchemaSource> {
    [AzureCloud::AzureCloud, AzureCloud::AzureUSGovernment]
        .into_iter()
        .flat_map(|cloud| {
            [
                SchemaSource {
                    entry_id: format!("{}.subscriptions.get", cloud.as_str()),
                    resource_type: "Microsoft.Resources/subscriptions".to_owned(),
                    operation: "get".to_owned(),
                    display_name: "Get subscription".to_owned(),
                    description: "Read the selected subscription's metadata and state.".to_owned(),
                    cli_equivalent: Some(
                        "az account show --subscription <subscriptionId>".to_owned(),
                    ),
                    cloud,
                    method: HttpMethod::Get,
                    canonical_path_template: SUBSCRIPTION_ROUTE.to_owned(),
                    request_path_template: "/".to_owned(),
                    api_versions: vec![SUBSCRIPTIONS_API_VERSION.to_owned()],
                    rbac_action: "Microsoft.Resources/subscriptions/read".to_owned(),
                    arm_tier: ArmTier::Inspect,
                    data_plane_grant: None,
                    request_body_schema: None,
                    response_body_schema: None,
                },
                SchemaSource {
                    entry_id: format!("{}.providers.get", cloud.as_str()),
                    resource_type: "Microsoft.Resources/providers".to_owned(),
                    operation: "get".to_owned(),
                    display_name: "Get provider metadata".to_owned(),
                    description:
                        "Read API versions and resource types exposed by one provider namespace."
                            .to_owned(),
                    cli_equivalent: Some(
                        "az provider show --namespace <namespace> --subscription <subscriptionId>"
                            .to_owned(),
                    ),
                    cloud,
                    method: HttpMethod::Get,
                    canonical_path_template: PROVIDER_ROUTE.to_owned(),
                    request_path_template: "/providers/{namespace}".to_owned(),
                    api_versions: vec![PROVIDERS_API_VERSION.to_owned()],
                    rbac_action: "Microsoft.Resources/subscriptions/providers/read".to_owned(),
                    arm_tier: ArmTier::Inspect,
                    data_plane_grant: None,
                    request_body_schema: None,
                    response_body_schema: None,
                },
            ]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{CloudBinding, SubscriptionId, TenantId},
        context::{ContextOptions, ContextRegistry, GraphScope, Identity, RegistryConfig},
    };
    use std::{collections::BTreeMap, time::Duration};

    const SUBSCRIPTION: &str = "11111111-1111-1111-1111-111111111111";
    const TENANT: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

    fn policy() -> PolicyBundle {
        crate::routes::v0_policy().expect("v0 policy")
    }

    fn context(policy_version: &str) -> Context {
        context_with_policy(V0_POLICY_HASH, policy_version)
    }

    fn context_with_policy(policy_hash: &str, policy_version: &str) -> Context {
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
            Vec::new(),
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
        registry
            .open(options, std::time::Instant::now())
            .expect("context")
    }

    #[test]
    fn bootstrap_index_is_request_only_and_metadata_only() {
        let index = SchemaIndex::v0(&policy()).expect("index");
        let context = context(crate::routes::V0_POLICY_VERSION);
        let result = index
            .search(&context, "get", Some(AzureCloud::AzureCloud), 50)
            .expect("search");
        assert_eq!(result.results.len(), 2);
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
            .search(&context, "provider", None, DEFAULT_SEARCH_LIMIT)
            .expect("search");
        assert_eq!(
            first,
            index
                .search(&context, "provider", None, 20)
                .expect("search")
        );
        assert_eq!(first.results.len(), 1);
        assert!(first.results[0].access.executable);
        assert_eq!(first.results[0].path_template, "/providers/{namespace}");
        assert_eq!(
            index.search(&context, "provider", Some(AzureCloud::AzureUSGovernment), 1),
            Err(SchemaError::CloudNotBound)
        );
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
        let mut sources = v0_sources();
        sources.pop();
        assert_eq!(
            SchemaIndex::from_policy(&policy(), V0_POLICY_HASH, sources),
            Err(SchemaError::MissingSource)
        );
        let mut sources = v0_sources();
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

        let mut sources = v0_sources();
        sources[0].description = "x".repeat(MAX_DESCRIPTION_BYTES + 1);
        assert_eq!(
            SchemaIndex::from_policy(&policy(), V0_POLICY_HASH, sources),
            Err(SchemaError::UnreviewedSource)
        );
    }
}
