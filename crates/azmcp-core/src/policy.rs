//! Fail-closed matching against reviewed ARM route rows.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::cloud::AzureCloud;
use crate::target::RelativeRequestTarget;

const MAX_TEMPLATE_SEGMENTS: usize = 64;

/// HTTP methods represented in the reviewed route bundle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    /// Retrieve a resource representation.
    Get,
    /// Submit an action or query.
    Post,
    /// Create or replace a resource.
    Put,
    /// Partially update a resource.
    Patch,
    /// Delete a resource.
    Delete,
}

/// The ARM capability required by a reviewed route.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ArmTier {
    /// Non-secret control-plane inspection.
    Inspect,
    /// Secret-bearing control-plane reads.
    Read,
    /// A mutation that must be planned and separately applied.
    Write,
}

/// The reviewed entry point allowed to invoke a route.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RoutePurpose {
    /// Caller-authored `az.request` code.
    Request,
    /// The first-class `az.graph` operation, whose body has separate scope validation.
    ResourceGraph,
    /// The first-class `az.logs.query` operation, whose body is host-owned.
    LogsQuery,
    /// Server-owned validation and metadata calls.
    Internal,
    /// Server-owned single-resource Azure Monitor Metrics calls.
    MetricsSingle,
    /// Server-owned multi-resource Azure Monitor Metrics calls.
    MetricsBatch,
}

/// One reviewed and executable route-policy row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewedRoute {
    cloud: AzureCloud,
    purpose: RoutePurpose,
    method: HttpMethod,
    template: RouteTemplate,
    api_versions: Vec<String>,
    rbac_action: String,
    tier: ArmTier,
    allowed_query_parameters: Vec<String>,
}

impl ReviewedRoute {
    /// Construct a reviewed row from checked-in policy data.
    pub fn new(
        cloud: AzureCloud,
        purpose: RoutePurpose,
        method: HttpMethod,
        path_template: &str,
        api_versions: impl IntoIterator<Item = impl Into<String>>,
        rbac_action: impl Into<String>,
        tier: ArmTier,
    ) -> Result<Self, InvalidRoute> {
        let api_versions = api_versions.into_iter().map(Into::into).collect::<Vec<_>>();
        if api_versions.is_empty() || api_versions.iter().any(String::is_empty) {
            return Err(InvalidRoute::ApiVersions);
        }
        let rbac_action = rbac_action.into();
        if rbac_action.is_empty() {
            return Err(InvalidRoute::RbacAction);
        }
        Ok(Self {
            cloud,
            purpose,
            method,
            template: RouteTemplate::parse(path_template)?,
            api_versions,
            rbac_action,
            tier,
            allowed_query_parameters: Vec::new(),
        })
    }

    /// Allow an exact, reviewed set of query parameter names on this route.
    pub fn with_query_parameters(
        mut self,
        names: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, InvalidRoute> {
        let mut names = names.into_iter().map(Into::into).collect::<Vec<_>>();
        if names.iter().any(|name| {
            name.is_empty()
                || name.eq_ignore_ascii_case("api-version")
                || name.chars().any(char::is_control)
        }) {
            return Err(InvalidRoute::QueryParameters);
        }
        names.sort_by_key(|name| name.to_ascii_lowercase());
        if names
            .windows(2)
            .any(|pair| pair[0].eq_ignore_ascii_case(&pair[1]))
        {
            return Err(InvalidRoute::QueryParameters);
        }
        self.allowed_query_parameters = names;
        Ok(self)
    }

    /// The cloud whose exact origin and provider metadata reviewed this row.
    pub fn cloud(&self) -> AzureCloud {
        self.cloud
    }

    /// The trusted entry point reviewed for this route.
    pub fn purpose(&self) -> RoutePurpose {
        self.purpose
    }

    /// The reviewed HTTP method.
    pub fn method(&self) -> HttpMethod {
        self.method
    }

    /// The checked-in path template.
    pub fn path_template(&self) -> &str {
        &self.template.source
    }

    /// The exact API versions reviewed for this route.
    pub fn api_versions(&self) -> &[String] {
        &self.api_versions
    }

    /// The reviewed RBAC operation name.
    pub fn rbac_action(&self) -> &str {
        &self.rbac_action
    }

    /// The required ARM tier.
    pub fn tier(&self) -> ArmTier {
        self.tier
    }

    /// The exact query parameter names reviewed for this route.
    pub fn allowed_query_parameters(&self) -> &[String] {
        &self.allowed_query_parameters
    }

    fn matches(
        &self,
        cloud: AzureCloud,
        purpose: RoutePurpose,
        method: HttpMethod,
        target: &RelativeRequestTarget,
        api_version: &str,
    ) -> bool {
        self.cloud == cloud
            && self.purpose == purpose
            && self.method == method
            && self
                .api_versions
                .iter()
                .any(|version| version == api_version)
            && self.template.matches(target.segments())
            && target.query().iter().all(|(name, _)| {
                self.allowed_query_parameters
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(name))
            })
    }
}

/// A fixed collection of reviewed routes selected when an execution context opens.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyBundle {
    version: String,
    routes: Vec<ReviewedRoute>,
}

impl PolicyBundle {
    /// Construct a fixed policy bundle. The version is recorded in every call log.
    pub fn new(
        version: impl Into<String>,
        routes: Vec<ReviewedRoute>,
    ) -> Result<Self, InvalidPolicyBundle> {
        let version = version.into();
        if version.is_empty() {
            return Err(InvalidPolicyBundle::Version);
        }
        if routes.is_empty() {
            return Err(InvalidPolicyBundle::Routes);
        }
        for (index, route) in routes.iter().enumerate() {
            if routes[..index]
                .iter()
                .any(|previous| executable_selectors_overlap(previous, route))
            {
                return Err(InvalidPolicyBundle::OverlappingRoutes);
            }
        }
        Ok(Self { version, routes })
    }

    /// The immutable bundle version or content hash.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Every reviewed route in this immutable bundle.
    pub fn routes(&self) -> &[ReviewedRoute] {
        &self.routes
    }

    /// Classify a request by its most-specific reviewed route.
    pub fn classify(
        &self,
        cloud: AzureCloud,
        purpose: RoutePurpose,
        method: HttpMethod,
        target: &RelativeRequestTarget,
        api_version: &str,
    ) -> Result<&ReviewedRoute, PolicyDenial> {
        let mut best: Option<(&ReviewedRoute, usize)> = None;
        let mut best_is_ambiguous = false;
        for route in &self.routes {
            if !route.matches(cloud, purpose, method, target, api_version) {
                continue;
            }
            let specificity = route.template.literal_count;
            match best {
                None => best = Some((route, specificity)),
                Some((_, current)) if specificity > current => {
                    best = Some((route, specificity));
                    best_is_ambiguous = false;
                }
                Some((_, current)) if specificity == current => {
                    best_is_ambiguous = true;
                }
                Some(_) => {}
            }
        }
        if best_is_ambiguous {
            return Err(PolicyDenial::AmbiguousRoute);
        }
        best.map(|(route, _)| route)
            .ok_or(PolicyDenial::UnknownRoute)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RouteTemplate {
    source: String,
    segments: Vec<TemplateSegment>,
    literal_count: usize,
}

impl RouteTemplate {
    fn parse(value: &str) -> Result<Self, InvalidRoute> {
        if !value.starts_with('/')
            || value.starts_with("//")
            || value.len() == 1
            || value.ends_with('/')
            || value.contains("//")
            || value.contains(['?', '#', '\\', '%'])
        {
            return Err(InvalidRoute::PathTemplate);
        }

        let mut literal_count = 0;
        let mut resource_uri_count = 0;
        if value.split('/').skip(1).count() > MAX_TEMPLATE_SEGMENTS {
            return Err(InvalidRoute::PathTemplate);
        }
        let segments = value
            .split('/')
            .skip(1)
            .map(|segment| {
                if let Some(parameter) = segment
                    .strip_prefix('{')
                    .and_then(|segment| segment.strip_suffix('}'))
                {
                    if parameter.is_empty()
                        || !parameter
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                    {
                        return Err(InvalidRoute::PathTemplate);
                    }
                    if parameter == "resourceUri" {
                        resource_uri_count += 1;
                        if resource_uri_count > 1 {
                            return Err(InvalidRoute::PathTemplate);
                        }
                        Ok(TemplateSegment::TailParameter(parameter.to_owned()))
                    } else {
                        Ok(TemplateSegment::Parameter(parameter.to_owned()))
                    }
                } else if segment.contains(['{', '}']) || segment.chars().any(char::is_control) {
                    Err(InvalidRoute::PathTemplate)
                } else {
                    literal_count += 1;
                    Ok(TemplateSegment::Literal(segment.to_owned()))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            source: value.to_owned(),
            segments,
            literal_count,
        })
    }

    fn matches(&self, request_segments: &[String]) -> bool {
        if self.segments.len() > request_segments.len() {
            return false;
        }
        Self::matches_segments(
            &self.segments,
            request_segments,
            0,
            0,
            &std::collections::BTreeMap::new(),
        )
    }

    fn matches_segments(
        expected: &[TemplateSegment],
        actual: &[String],
        expected_index: usize,
        actual_index: usize,
        parameters: &std::collections::BTreeMap<String, String>,
    ) -> bool {
        if expected_index == expected.len() {
            return actual_index == actual.len();
        }
        match &expected[expected_index] {
            TemplateSegment::TailParameter(_) => {
                // A resource URI is the only reviewed multi-segment route
                // parameter. It must leave the provider-extension suffix
                // available for exact matching and must contain at least one
                // segment so the route cannot match an empty resource.
                let remaining = expected.len().saturating_sub(expected_index + 1);
                if actual.len() < actual_index + remaining + 1 {
                    return false;
                }
                let max_consumed = actual.len() - actual_index - remaining;
                (1..=max_consumed).any(|consumed| {
                    let mut parameters = parameters.clone();
                    parameters.insert(
                        "resourceUri".to_owned(),
                        actual[actual_index..actual_index + consumed].join("/"),
                    );
                    Self::matches_segments(
                        expected,
                        actual,
                        expected_index + 1,
                        actual_index + consumed,
                        &parameters,
                    )
                })
            }
            TemplateSegment::Literal(literal) => {
                actual
                    .get(actual_index)
                    .is_some_and(|value| literal.eq_ignore_ascii_case(value))
                    && Self::matches_segments(
                        expected,
                        actual,
                        expected_index + 1,
                        actual_index + 1,
                        parameters,
                    )
            }
            TemplateSegment::Parameter(name) => {
                let Some(value) = actual.get(actual_index) else {
                    return false;
                };
                if value.is_empty() {
                    return false;
                }
                if parameters
                    .get(name)
                    .is_some_and(|previous| !previous.eq_ignore_ascii_case(value))
                {
                    return false;
                }
                let mut parameters = parameters.clone();
                parameters.insert(name.clone(), value.clone());
                Self::matches_segments(
                    expected,
                    actual,
                    expected_index + 1,
                    actual_index + 1,
                    &parameters,
                )
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TemplateSegment {
    Literal(String),
    Parameter(String),
    TailParameter(String),
}

/// A checked-in route row was malformed and cannot be loaded.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum InvalidRoute {
    /// Route templates are absolute paths made of literals and whole-segment parameters.
    #[error("invalid reviewed path template")]
    PathTemplate,
    /// Every reviewed row must name at least one exact API version.
    #[error("reviewed route must contain non-empty API versions")]
    ApiVersions,
    /// Every reviewed row must name the RBAC operation it enforces.
    #[error("reviewed route must contain an RBAC action")]
    RbacAction,
    /// Query parameter names are exact, unique, and never include `api-version`.
    #[error("reviewed route contains invalid query parameter policy")]
    QueryParameters,
}

/// A policy bundle cannot be installed without identity and executable content.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum InvalidPolicyBundle {
    /// The bundle version or content hash is required for audit records.
    #[error("policy bundle version must not be empty")]
    Version,
    /// An empty bundle is almost certainly a packaging error.
    #[error("policy bundle must contain at least one reviewed route")]
    Routes,
    /// Two rows with the same executable selector cannot vary authorization or query metadata.
    #[error("policy bundle contains overlapping executable route selectors")]
    OverlappingRoutes,
}

fn executable_selectors_overlap(left: &ReviewedRoute, right: &ReviewedRoute) -> bool {
    left.cloud == right.cloud
        && left.purpose == right.purpose
        && left.method == right.method
        && left.template.source == right.template.source
        && left
            .api_versions
            .iter()
            .any(|version| right.api_versions.iter().any(|other| version == other))
}

/// A request failed to resolve to one unambiguous reviewed route.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PolicyDenial {
    /// No reviewed row matches the method, target, and API version.
    #[error("request does not match a reviewed route")]
    UnknownRoute,
    /// Equally specific reviewed rows matched, so allowing either would be unsafe.
    #[error("request matches multiple equally specific reviewed routes")]
    AmbiguousRoute,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(template: &str, action: &str) -> ReviewedRoute {
        ReviewedRoute::new(
            AzureCloud::AzureCloud,
            RoutePurpose::Request,
            HttpMethod::Get,
            template,
            ["2024-01-01"],
            action,
            ArmTier::Inspect,
        )
        .expect("valid test route")
    }

    #[test]
    fn chooses_the_most_specific_reviewed_route() {
        let bundle = PolicyBundle::new(
            "test-v1",
            vec![
                route(
                    "/subscriptions/{subscription}/providers/{namespace}",
                    "generic/read",
                ),
                route(
                    "/subscriptions/{other}/providers/{provider}",
                    "other-generic/read",
                ),
                route(
                    "/subscriptions/{subscription}/providers/Microsoft.Sql",
                    "Microsoft.Sql/read",
                ),
            ],
        )
        .expect("valid bundle");
        let target = RelativeRequestTarget::parse("/subscriptions/sub/providers/%4dicr%6fsoft.Sql")
            .expect("valid encoded target");

        let matched = bundle
            .classify(
                AzureCloud::AzureCloud,
                RoutePurpose::Request,
                HttpMethod::Get,
                &target,
                "2024-01-01",
            )
            .expect("one reviewed route");

        assert_eq!(matched.rbac_action(), "Microsoft.Sql/read");
        assert_eq!(
            matched.path_template(),
            "/subscriptions/{subscription}/providers/Microsoft.Sql"
        );
        assert_eq!(matched.tier(), ArmTier::Inspect);
    }

    #[test]
    fn denies_unknown_method_path_and_api_version() {
        let bundle = PolicyBundle::new(
            "test-v1",
            vec![route(
                "/subscriptions/{subscription}/resourceGroups/{group}",
                "Microsoft.Resources/subscriptions/resourceGroups/read",
            )],
        )
        .expect("valid bundle");
        let known = RelativeRequestTarget::parse("/subscriptions/sub/resourceGroups/prod")
            .expect("valid target");
        let unknown = RelativeRequestTarget::parse("/subscriptions/sub/providers/Microsoft.Sql")
            .expect("valid target");

        assert_eq!(
            bundle.classify(
                AzureCloud::AzureCloud,
                RoutePurpose::Request,
                HttpMethod::Post,
                &known,
                "2024-01-01"
            ),
            Err(PolicyDenial::UnknownRoute)
        );
        assert_eq!(
            bundle.classify(
                AzureCloud::AzureCloud,
                RoutePurpose::Request,
                HttpMethod::Get,
                &unknown,
                "2024-01-01"
            ),
            Err(PolicyDenial::UnknownRoute)
        );
        assert_eq!(
            bundle.classify(
                AzureCloud::AzureCloud,
                RoutePurpose::Request,
                HttpMethod::Get,
                &known,
                "2025-01-01"
            ),
            Err(PolicyDenial::UnknownRoute)
        );
    }

    #[test]
    fn denies_an_ambiguous_reviewed_join() {
        let bundle = PolicyBundle::new(
            "test-v1",
            vec![
                route("/subscriptions/{first}/providers/{second}", "first/read"),
                route(
                    "/subscriptions/{other}/providers/{namespace}",
                    "second/read",
                ),
            ],
        )
        .expect("valid bundle");
        let target = RelativeRequestTarget::parse("/subscriptions/sub/providers/Example")
            .expect("valid target");

        assert_eq!(
            bundle.classify(
                AzureCloud::AzureCloud,
                RoutePurpose::Request,
                HttpMethod::Get,
                &target,
                "2024-01-01"
            ),
            Err(PolicyDenial::AmbiguousRoute)
        );
    }

    #[test]
    fn rejects_malformed_checked_in_rows() {
        for template in [
            "subscriptions/{subscription}",
            "/subscriptions//{subscription}",
            "/subscriptions/{subscription}/",
            "/subscriptions/{subscription-id}",
            "/subscriptions/{subscription}?api-version=x",
        ] {
            assert_eq!(
                ReviewedRoute::new(
                    AzureCloud::AzureCloud,
                    RoutePurpose::Request,
                    HttpMethod::Get,
                    template,
                    ["2024-01-01"],
                    "read",
                    ArmTier::Inspect,
                ),
                Err(InvalidRoute::PathTemplate),
                "{template}"
            );
        }
    }

    #[test]
    fn binds_routes_to_cloud_and_reviewed_query_names() {
        let route = route(
            "/subscriptions/{subscription}/providers/Microsoft.Resources",
            "resources/read",
        )
        .with_query_parameters(["$filter"])
        .expect("valid query policy");
        let bundle = PolicyBundle::new("test-v1", vec![route]).expect("valid bundle");
        let allowed = RelativeRequestTarget::parse(
            "/subscriptions/sub/providers/Microsoft.Resources?$filter=name%20eq%20x",
        )
        .expect("valid target");
        let denied = RelativeRequestTarget::parse(
            "/subscriptions/sub/providers/Microsoft.Resources?$expand=details",
        )
        .expect("valid target");

        assert!(
            bundle
                .classify(
                    AzureCloud::AzureCloud,
                    RoutePurpose::Request,
                    HttpMethod::Get,
                    &allowed,
                    "2024-01-01"
                )
                .is_ok()
        );
        assert_eq!(
            bundle.classify(
                AzureCloud::AzureUSGovernment,
                RoutePurpose::Request,
                HttpMethod::Get,
                &allowed,
                "2024-01-01"
            ),
            Err(PolicyDenial::UnknownRoute)
        );
        assert_eq!(
            bundle.classify(
                AzureCloud::AzureCloud,
                RoutePurpose::ResourceGraph,
                HttpMethod::Get,
                &allowed,
                "2024-01-01"
            ),
            Err(PolicyDenial::UnknownRoute)
        );
        assert_eq!(
            bundle.classify(
                AzureCloud::AzureCloud,
                RoutePurpose::Request,
                HttpMethod::Get,
                &denied,
                "2024-01-01"
            ),
            Err(PolicyDenial::UnknownRoute)
        );
    }

    #[test]
    fn rejects_overlapping_selectors_before_query_or_rbac_metadata() {
        let first = route(
            "/subscriptions/{subscription}/providers/Microsoft.Storage/storageAccounts/{name}",
            "Microsoft.Storage/storageAccounts/read",
        )
        .with_query_parameters(["$expand"])
        .expect("valid query policy");
        let second = route(
            "/subscriptions/{subscription}/providers/Microsoft.Storage/storageAccounts/{name}",
            "different/read",
        );

        assert_eq!(
            PolicyBundle::new("test-v1", vec![first, second]),
            Err(InvalidPolicyBundle::OverlappingRoutes)
        );
    }

    #[test]
    fn limits_resource_uri_tail_parameters() {
        let duplicate = ReviewedRoute::new(
            AzureCloud::AzureCloud,
            RoutePurpose::Request,
            HttpMethod::Get,
            "/subscriptions/{subscription}/{resourceUri}/{resourceUri}/providers/Test",
            ["2024-01-01"],
            "read",
            ArmTier::Inspect,
        );
        assert_eq!(duplicate, Err(InvalidRoute::PathTemplate));

        let long_path = format!(
            "/{}",
            (0..65)
                .map(|index| format!("segment{index}"))
                .collect::<Vec<_>>()
                .join("/")
        );
        assert_eq!(
            ReviewedRoute::new(
                AzureCloud::AzureCloud,
                RoutePurpose::Request,
                HttpMethod::Get,
                &long_path,
                ["2024-01-01"],
                "read",
                ArmTier::Inspect,
            ),
            Err(InvalidRoute::PathTemplate)
        );
    }
}
