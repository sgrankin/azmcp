//! Reviewed Azure route bundle built from the checked-in v1 manifest.

use crate::policy::{InvalidPolicyBundle, InvalidRoute, PolicyBundle};
use crate::route_manifest::{self, ManifestError};

/// Version of the checked-in observability route review.
pub const V1_POLICY_VERSION: &str = route_manifest::V1_POLICY_VERSION;
/// Stable identity of the checked-in observability policy contents.
pub const V1_POLICY_HASH: &str = route_manifest::V1_POLICY_HASH;
/// Compatibility alias for callers that still use the v0 route accessor.
pub const V0_POLICY_VERSION: &str = V1_POLICY_VERSION;

pub const SUBSCRIPTIONS_API_VERSION: &str = "2020-01-01";
pub const PROVIDERS_API_VERSION: &str = "2021-04-01";
pub const RESOURCE_GRAPH_API_VERSION: &str = "2022-10-01";
/// Compatibility alias for callers that still use the v0 policy identity.
pub const V0_POLICY_HASH: &str = V1_POLICY_HASH;
/// Pinned ARM metrics API version from azure-rest-api-specs commit
/// f05d9ee6113a6536cc39c374608c8daf007b1d38.
pub const METRICS_API_VERSION: &str = "2023-10-01";

pub const LOGS_QUERY_API_VERSION: &str = "v1";
pub const LOGS_QUERY_RBAC_ACTION: &str = "Microsoft.OperationalInsights/workspaces/query/read";

/// Construct the route bundle from the checked-in, pinned v1 source manifest.
///
/// Resource Graph, metrics, and Logs Query rows retain distinct purposes in the
/// manifest. They therefore cannot become caller-authored `az.request` rows
/// merely because their paths happen to be valid ARM targets.
pub fn v1_policy() -> Result<PolicyBundle, V0PolicyError> {
    let manifest = route_manifest::checked_in_manifest()?;
    Ok(route_manifest::policy(&manifest)?)
}

/// Compatibility accessor for the v1 policy while existing callers migrate.
pub fn v0_policy() -> Result<PolicyBundle, V0PolicyError> {
    v1_policy()
}

/// A checked-in route bundle invariant failed during construction.
#[derive(Debug, thiserror::Error)]
pub enum V0PolicyError {
    #[error("invalid reviewed v0 route: {0}")]
    Route(#[from] InvalidRoute),
    #[error("invalid reviewed v0 policy bundle: {0}")]
    Bundle(#[from] InvalidPolicyBundle),
    #[error("invalid checked-in reviewed route manifest: {0}")]
    Manifest(#[from] ManifestError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cloud::AzureCloud,
        policy::{HttpMethod, PolicyDenial, RoutePurpose},
        target::RelativeRequestTarget,
    };

    #[test]
    fn exact_routes_are_available_in_both_clouds() {
        let policy = v0_policy().expect("checked-in policy is valid");
        for cloud in [AzureCloud::AzureCloud, AzureCloud::AzureUSGovernment] {
            let subscription =
                RelativeRequestTarget::parse("/subscriptions/11111111-1111-1111-1111-111111111111")
                    .expect("target");
            assert!(
                policy
                    .classify(
                        cloud,
                        RoutePurpose::Internal,
                        HttpMethod::Get,
                        &subscription,
                        SUBSCRIPTIONS_API_VERSION,
                    )
                    .is_ok()
            );
            let graph =
                RelativeRequestTarget::parse("/providers/Microsoft.ResourceGraph/resources")
                    .expect("target");
            assert!(
                policy
                    .classify(
                        cloud,
                        RoutePurpose::ResourceGraph,
                        HttpMethod::Post,
                        &graph,
                        RESOURCE_GRAPH_API_VERSION,
                    )
                    .is_ok()
            );
            let logs = RelativeRequestTarget::parse(
                "/v1/workspaces/11111111-1111-1111-1111-111111111111/query",
            )
            .expect("logs query target");
            assert!(
                policy
                    .classify(
                        cloud,
                        RoutePurpose::LogsQuery,
                        HttpMethod::Post,
                        &logs,
                        LOGS_QUERY_API_VERSION,
                    )
                    .is_ok()
            );
            assert_eq!(
                policy.classify(
                    cloud,
                    RoutePurpose::Request,
                    HttpMethod::Post,
                    &logs,
                    LOGS_QUERY_API_VERSION,
                ),
                Err(PolicyDenial::UnknownRoute)
            );
        }
    }

    #[test]
    fn graph_route_is_not_a_generic_request_escape_hatch() {
        let policy = v0_policy().expect("checked-in policy is valid");
        let graph = RelativeRequestTarget::parse("/providers/Microsoft.ResourceGraph/resources")
            .expect("target");
        assert_eq!(
            policy.classify(
                AzureCloud::AzureCloud,
                RoutePurpose::Request,
                HttpMethod::Post,
                &graph,
                RESOURCE_GRAPH_API_VERSION,
            ),
            Err(PolicyDenial::UnknownRoute)
        );
    }

    #[test]
    fn unknown_versions_methods_and_paths_are_denied() {
        let policy = v0_policy().expect("checked-in policy is valid");
        let target = RelativeRequestTarget::parse(
            "/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.Compute",
        )
        .expect("target");
        for (method, version) in [
            (HttpMethod::Post, PROVIDERS_API_VERSION),
            (HttpMethod::Get, "2025-01-01"),
        ] {
            assert_eq!(
                policy.classify(
                    AzureCloud::AzureCloud,
                    RoutePurpose::Request,
                    method,
                    &target,
                    version,
                ),
                Err(PolicyDenial::UnknownRoute)
            );
        }
    }

    #[test]
    fn metrics_routes_cover_single_resource_and_subscription_batch_shapes() {
        let policy = v0_policy().expect("checked-in policy is valid");
        for cloud in [AzureCloud::AzureCloud, AzureCloud::AzureUSGovernment] {
            let single = RelativeRequestTarget::parse(
                "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm/providers/Microsoft.Insights/metrics?metricnames=Percentage%20CPU&$filter=Location%20eq%20%27west%27",
            )
            .expect("single metrics target");
            assert_eq!(
                policy
                    .classify(
                        cloud,
                        RoutePurpose::MetricsSingle,
                        HttpMethod::Get,
                        &single,
                        METRICS_API_VERSION,
                    )
                    .expect("single metrics route")
                    .rbac_action(),
                "Microsoft.Insights/Metrics/Read"
            );
            assert_eq!(
                policy.classify(
                    cloud,
                    RoutePurpose::Request,
                    HttpMethod::Get,
                    &single,
                    METRICS_API_VERSION,
                ),
                Err(PolicyDenial::UnknownRoute)
            );

            let batch = RelativeRequestTarget::parse(
                "/subscriptions/11111111-1111-1111-1111-111111111111/metrics:getBatch?metricnamespace=Microsoft.Compute&metricnames=Percentage%20CPU&filter=Location%20eq%20%27west%27",
            )
            .expect("batch metrics target");
            assert!(
                policy
                    .classify(
                        cloud,
                        RoutePurpose::MetricsBatch,
                        HttpMethod::Post,
                        &batch,
                        METRICS_API_VERSION,
                    )
                    .is_ok()
            );
            assert_eq!(
                policy.classify(
                    cloud,
                    RoutePurpose::MetricsBatch,
                    HttpMethod::Get,
                    &batch,
                    METRICS_API_VERSION,
                ),
                Err(PolicyDenial::UnknownRoute)
            );
            assert_eq!(
                policy.classify(
                    cloud,
                    RoutePurpose::Request,
                    HttpMethod::Post,
                    &batch,
                    METRICS_API_VERSION,
                ),
                Err(PolicyDenial::UnknownRoute)
            );
            let unknown_query = RelativeRequestTarget::parse(
                "/subscriptions/11111111-1111-1111-1111-111111111111/metrics:getBatch?resourceids=x",
            )
            .expect("target");
            assert_eq!(
                policy.classify(
                    cloud,
                    RoutePurpose::MetricsBatch,
                    HttpMethod::Post,
                    &unknown_query,
                    METRICS_API_VERSION,
                ),
                Err(PolicyDenial::UnknownRoute)
            );
        }
    }
}
