//! Small, reviewed v0 ARM route bundle.

use crate::cloud::AzureCloud;
use crate::policy::{
    ArmTier, HttpMethod, InvalidPolicyBundle, InvalidRoute, PolicyBundle, ReviewedRoute,
    RoutePurpose,
};

/// Version of the checked-in bootstrap route review.
pub const V0_POLICY_VERSION: &str = "v0-bootstrap-1";

pub const SUBSCRIPTIONS_API_VERSION: &str = "2020-01-01";
pub const PROVIDERS_API_VERSION: &str = "2021-04-01";
pub const RESOURCE_GRAPH_API_VERSION: &str = "2022-10-01";
/// Stable identity of the checked-in bootstrap policy contents.
pub const V0_POLICY_HASH: &str = "v0-bootstrap-1";
/// Pinned ARM metrics API version from azure-rest-api-specs commit
/// f05d9ee6113a6536cc39c374608c8daf007b1d38.
pub const METRICS_API_VERSION: &str = "2023-10-01";

/// Query controls reviewed from the 2023-10-01 ARM metrics operation.
const METRICS_SINGLE_QUERY_PARAMETERS: &[&str] = &[
    "timespan",
    "interval",
    "metricnames",
    "aggregation",
    "top",
    "orderby",
    "$filter",
    "resultType",
    "metricnamespace",
    "AutoAdjustTimegrain",
    "ValidateDimensions",
    "rollupby",
];

/// Query controls reviewed from the 2023-10-01 metrics:getBatch operation in
/// azure-rest-api-specs commit
/// 3c0811c51be6cb34f4e151ee333439bfbfac354e.
const METRICS_BATCH_QUERY_PARAMETERS: &[&str] = &[
    "starttime",
    "endtime",
    "interval",
    "metricnamespace",
    "metricnames",
    "aggregation",
    "top",
    "orderby",
    "filter",
    "rollupby",
];

/// Construct the deliberately small route bundle used by the first v0 scenarios.
///
/// Resource Graph has its own purpose so caller-authored `az.request` cannot reach
/// the tenant-scoped POST without the graph operation's separate body/scope checks.
pub fn v0_policy() -> Result<PolicyBundle, V0PolicyError> {
    let mut routes = Vec::new();
    for cloud in [AzureCloud::AzureCloud, AzureCloud::AzureUSGovernment] {
        for purpose in [RoutePurpose::Request, RoutePurpose::Internal] {
            routes.push(ReviewedRoute::new(
                cloud,
                purpose,
                HttpMethod::Get,
                "/subscriptions/{subscription}",
                [SUBSCRIPTIONS_API_VERSION],
                "Microsoft.Resources/subscriptions/read",
                ArmTier::Inspect,
            )?);
            routes.push(ReviewedRoute::new(
                cloud,
                purpose,
                HttpMethod::Get,
                "/subscriptions/{subscription}/providers/{namespace}",
                [PROVIDERS_API_VERSION],
                "Microsoft.Resources/subscriptions/providers/read",
                ArmTier::Inspect,
            )?);
        }
        routes.push(ReviewedRoute::new(
            cloud,
            RoutePurpose::ResourceGraph,
            HttpMethod::Post,
            "/providers/Microsoft.ResourceGraph/resources",
            [RESOURCE_GRAPH_API_VERSION],
            "Microsoft.ResourceGraph/resources/read",
            ArmTier::Inspect,
        )?);
        routes.push(
            ReviewedRoute::new(
                cloud,
                RoutePurpose::MetricsSingle,
                HttpMethod::Get,
                "/{resourceUri}/providers/Microsoft.Insights/metrics",
                [METRICS_API_VERSION],
                "Microsoft.Insights/Metrics/Read",
                ArmTier::Inspect,
            )?
            .with_query_parameters(METRICS_SINGLE_QUERY_PARAMETERS.iter().copied())?,
        );
        routes.push(
            ReviewedRoute::new(
                cloud,
                RoutePurpose::MetricsBatch,
                HttpMethod::Post,
                "/subscriptions/{subscription}/metrics:getBatch",
                [METRICS_API_VERSION],
                "Microsoft.Insights/Metrics/Read",
                ArmTier::Inspect,
            )?
            .with_query_parameters(METRICS_BATCH_QUERY_PARAMETERS.iter().copied())?,
        );
    }
    Ok(PolicyBundle::new(V0_POLICY_VERSION, routes)?)
}

/// A checked-in route bundle invariant failed during construction.
#[derive(Debug, thiserror::Error)]
pub enum V0PolicyError {
    #[error("invalid reviewed v0 route: {0}")]
    Route(#[from] InvalidRoute),
    #[error("invalid reviewed v0 policy bundle: {0}")]
    Bundle(#[from] InvalidPolicyBundle),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyDenial;
    use crate::target::RelativeRequestTarget;

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
