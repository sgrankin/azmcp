//! Immutable azmcp configuration.
//!
//! Configuration describes bindings; it never selects an active cloud.  A
//! cloud is a key in the binding map and must be supplied explicitly by the
//! caller.  A configured primary tenant may be omitted because v0 can resolve
//! it from exactly one unambiguous cached account candidate later.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use thiserror::Error;

use crate::{accounts::SubscriptionCandidate, cloud::AzureCloud};

/// A validated Azure subscription identifier.
///
/// Keeping IDs as validated newtypes prevents an empty or whitespace-bearing
/// value from entering a fixed binding or allowlist while still serializing as
/// the ordinary TOML string.  Synthetic profile fixtures may use readable
/// identifiers; Azure itself validates the GUID shape when the binding is
/// validated against the control plane.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SubscriptionId(String);

impl SubscriptionId {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidAzureId> {
        let value = value.into();
        validate_id("subscription", &value)?;
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for SubscriptionId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for SubscriptionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for SubscriptionId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SubscriptionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

/// A validated Entra tenant identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TenantId(String);

impl TenantId {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidAzureId> {
        let value = value.into();
        validate_id("tenant", &value)?;
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for TenantId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for TenantId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TenantId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

fn validate_id(kind: &'static str, value: &str) -> Result<(), InvalidAzureId> {
    let valid = value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        });

    if valid {
        Ok(())
    } else {
        Err(InvalidAzureId {
            kind,
            value: value.to_owned(),
        })
    }
}

/// An invalid subscription or tenant identifier.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("invalid {kind} identifier `{value}`; expected a canonical UUID")]
pub struct InvalidAzureId {
    kind: &'static str,
    value: String,
}

/// One fixed subscription/tenant pair in a cloud's allowlist.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionTenantPair {
    subscription: SubscriptionId,
    tenant: TenantId,
}

impl SubscriptionTenantPair {
    pub fn new(subscription: SubscriptionId, tenant: TenantId) -> Self {
        Self {
            subscription,
            tenant,
        }
    }

    pub fn from_strings(
        subscription: impl Into<String>,
        tenant: impl Into<String>,
    ) -> Result<Self, InvalidAzureId> {
        Ok(Self::new(
            SubscriptionId::new(subscription)?,
            TenantId::new(tenant)?,
        ))
    }

    pub fn subscription(&self) -> &SubscriptionId {
        &self.subscription
    }

    pub fn subscription_id(&self) -> &str {
        self.subscription.as_str()
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn tenant_id(&self) -> &str {
        self.tenant.as_str()
    }
}

/// A cloud's immutable configured binding and its fixed additional allowlist.
///
/// The primary subscription is required.  The primary tenant is optional only
/// for the documented auto-discovery path: the account cache must later yield
/// exactly one candidate.  Additional allowlist entries are explicit pairs and
/// therefore always require both IDs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CloudBinding {
    subscription: SubscriptionId,
    #[serde(default)]
    tenant: Option<TenantId>,
    #[serde(default)]
    allowed_subscriptions: Vec<SubscriptionTenantPair>,
}

impl CloudBinding {
    pub fn new(subscription: SubscriptionId, tenant: Option<TenantId>) -> Self {
        Self {
            subscription,
            tenant,
            allowed_subscriptions: Vec::new(),
        }
    }

    pub fn with_allowed_subscriptions(
        subscription: SubscriptionId,
        tenant: Option<TenantId>,
        allowed_subscriptions: Vec<SubscriptionTenantPair>,
    ) -> Result<Self, BindingError> {
        let binding = Self {
            subscription,
            tenant,
            allowed_subscriptions,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn subscription(&self) -> &SubscriptionId {
        &self.subscription
    }

    pub fn subscription_id(&self) -> &str {
        self.subscription.as_str()
    }

    pub fn tenant(&self) -> Option<&TenantId> {
        self.tenant.as_ref()
    }

    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant.as_ref().map(TenantId::as_str)
    }

    /// Additional explicitly configured pairs, excluding the primary binding.
    pub fn configured_allowed_subscriptions(&self) -> &[SubscriptionTenantPair] {
        &self.allowed_subscriptions
    }

    /// The fixed allowlist once the primary tenant is known.
    ///
    /// If the primary tenant is still absent, only explicitly configured
    /// additional pairs can be returned; callers must resolve the primary
    /// binding before making a request for it.
    pub fn fixed_allowed_subscriptions(&self) -> Vec<SubscriptionTenantPair> {
        let mut pairs = Vec::with_capacity(self.allowed_subscriptions.len() + 1);
        if let Some(tenant) = &self.tenant {
            pairs.push(SubscriptionTenantPair::new(
                self.subscription.clone(),
                tenant.clone(),
            ));
        }
        pairs.extend(self.allowed_subscriptions.iter().cloned());
        pairs
    }

    pub fn validate(&self) -> Result<(), BindingError> {
        let mut seen = BTreeMap::<SubscriptionId, TenantId>::new();
        for pair in &self.allowed_subscriptions {
            if pair.subscription == self.subscription {
                return Err(BindingError::DuplicateSubscription {
                    subscription: self.subscription.clone(),
                });
            }

            if let Some(previous_tenant) =
                seen.insert(pair.subscription.clone(), pair.tenant.clone())
            {
                if previous_tenant == pair.tenant {
                    return Err(BindingError::DuplicatePair {
                        subscription: pair.subscription.clone(),
                        tenant: pair.tenant.clone(),
                    });
                }
                return Err(BindingError::AmbiguousSubscription {
                    subscription: pair.subscription.clone(),
                    first_tenant: previous_tenant,
                    second_tenant: pair.tenant.clone(),
                });
            }
        }
        Ok(())
    }

    /// Resolve a missing primary tenant from cached candidates.
    ///
    /// Full account candidates are filtered here by exact cloud and configured
    /// subscription. No candidate means discovery failed; more than one is
    /// ambiguous, even if two routes happen to carry the same tenant ID.
    pub fn resolve(
        &self,
        cloud: AzureCloud,
        candidates: &[SubscriptionCandidate],
    ) -> Result<ResolvedCloudBinding, BindingResolutionError> {
        let tenant = match &self.tenant {
            Some(tenant) => tenant.clone(),
            None => {
                let matching = candidates
                    .iter()
                    .filter(|candidate| {
                        candidate.environment_name() == cloud.as_str()
                            && candidate
                                .subscription_id()
                                .eq_ignore_ascii_case(self.subscription_id())
                    })
                    .collect::<Vec<_>>();
                match matching.as_slice() {
                    [] => return Err(BindingResolutionError::MissingTenant { cloud }),
                    [candidate] => TenantId::new(candidate.tenant_id())
                        .map_err(|_| BindingResolutionError::InvalidTenantCandidate { cloud })?,
                    candidates => {
                        return Err(BindingResolutionError::AmbiguousTenant {
                            cloud,
                            candidate_count: candidates.len(),
                        });
                    }
                }
            }
        };

        Ok(ResolvedCloudBinding {
            cloud,
            subscription: self.subscription.clone(),
            tenant: tenant.clone(),
            allowed_subscriptions: self.fixed_allowed_subscriptions_with(tenant.clone()),
        })
    }

    fn fixed_allowed_subscriptions_with(&self, tenant: TenantId) -> Vec<SubscriptionTenantPair> {
        let mut pairs = Vec::with_capacity(self.allowed_subscriptions.len() + 1);
        pairs.push(SubscriptionTenantPair::new(
            self.subscription.clone(),
            tenant,
        ));
        pairs.extend(self.allowed_subscriptions.iter().cloned());
        pairs
    }
}

impl<'de> Deserialize<'de> for CloudBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct UnvalidatedCloudBinding {
            subscription: SubscriptionId,
            #[serde(default)]
            tenant: Option<TenantId>,
            #[serde(default)]
            allowed_subscriptions: Vec<SubscriptionTenantPair>,
        }

        let value = UnvalidatedCloudBinding::deserialize(deserializer)?;
        Self::with_allowed_subscriptions(
            value.subscription,
            value.tenant,
            value.allowed_subscriptions,
        )
        .map_err(D::Error::custom)
    }
}

/// A cloud binding after its primary tenant has been resolved.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedCloudBinding {
    cloud: AzureCloud,
    subscription: SubscriptionId,
    tenant: TenantId,
    allowed_subscriptions: Vec<SubscriptionTenantPair>,
}

impl ResolvedCloudBinding {
    pub fn cloud(&self) -> AzureCloud {
        self.cloud
    }

    pub fn subscription(&self) -> &SubscriptionId {
        &self.subscription
    }

    pub fn subscription_id(&self) -> &str {
        self.subscription.as_str()
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn tenant_id(&self) -> &str {
        self.tenant.as_str()
    }

    pub fn allowed_subscriptions(&self) -> &[SubscriptionTenantPair] {
        &self.allowed_subscriptions
    }
}

/// Errors found while validating one cloud binding.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BindingError {
    #[error("subscription `{subscription}` is listed more than once")]
    DuplicateSubscription { subscription: SubscriptionId },
    #[error("subscription `{subscription}` has duplicate tenant `{tenant}`")]
    DuplicatePair {
        subscription: SubscriptionId,
        tenant: TenantId,
    },
    #[error(
        "subscription `{subscription}` has ambiguous tenants `{first_tenant}` and `{second_tenant}`"
    )]
    AmbiguousSubscription {
        subscription: SubscriptionId,
        first_tenant: TenantId,
        second_tenant: TenantId,
    },
}

/// Errors from resolving an omitted primary tenant through account discovery.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BindingResolutionError {
    #[error("cloud {cloud} has no tenant candidate for its configured subscription")]
    MissingTenant { cloud: AzureCloud },
    #[error("cloud {cloud} has {candidate_count} ambiguous tenant candidates")]
    AmbiguousTenant {
        cloud: AzureCloud,
        candidate_count: usize,
    },
    #[error("cloud {cloud} has an invalid tenant candidate for its configured subscription")]
    InvalidTenantCandidate { cloud: AzureCloud },
}

/// Root TOML configuration.
///
/// An omitted `clouds` table is valid: an account-discovery layer may later
/// auto-bind a cloud with exactly one enabled cached subscription candidate.
/// It does not create an active cloud or a default binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    clouds: BTreeMap<AzureCloud, CloudBinding>,
}

impl Config {
    pub fn empty() -> Self {
        Self {
            clouds: BTreeMap::new(),
        }
    }

    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input)?;
        config.validate()?;
        Ok(config)
    }

    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        Self::from_toml(input)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        for (cloud, binding) in &self.clouds {
            binding
                .validate()
                .map_err(|source| ConfigError::InvalidBinding {
                    cloud: *cloud,
                    source,
                })?;
        }
        Ok(())
    }

    pub fn clouds(&self) -> &BTreeMap<AzureCloud, CloudBinding> {
        &self.clouds
    }

    pub fn binding(&self, cloud: AzureCloud) -> Option<&CloudBinding> {
        self.clouds.get(&cloud)
    }

    pub fn resolve_binding(
        &self,
        cloud: AzureCloud,
        candidates: &[SubscriptionCandidate],
    ) -> Result<Option<ResolvedCloudBinding>, BindingResolutionError> {
        self.binding(cloud)
            .map(|binding| binding.resolve(cloud, candidates))
            .transpose()
    }
}

/// Configuration parsing and validation failures.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid TOML configuration: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("invalid binding for cloud {cloud}: {source}")]
    InvalidBinding {
        cloud: AzureCloud,
        #[source]
        source: BindingError,
    },
}

/// Explicit aliases used by callers that prefer the product name in a type.
pub type AzmcpConfig = Config;
pub type AzureConfig = Config;
pub type AllowedSubscription = SubscriptionTenantPair;
pub type SubscriptionBinding = CloudBinding;
pub type SubscriptionTenant = SubscriptionTenantPair;
pub type SubscriptionTenantBinding = SubscriptionTenantPair;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::AccountKey;

    const SUB_COMMERCIAL: &str = "11111111-1111-1111-1111-111111111111";
    const TENANT_COMMERCIAL: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const SUB_GOVERNMENT: &str = "22222222-2222-2222-2222-222222222222";
    const TENANT_GOVERNMENT: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    const SUB_EXTRA: &str = "33333333-3333-3333-3333-333333333333";
    const TENANT_EXTRA: &str = "cccccccc-cccc-cccc-cccc-cccccccccccc";

    fn candidate(
        cloud: AzureCloud,
        subscription: &str,
        tenant: &str,
        user: &str,
    ) -> SubscriptionCandidate {
        SubscriptionCandidate {
            key: AccountKey::new(cloud.as_str(), tenant, subscription, user),
            name: "synthetic".to_owned(),
            state: "Enabled".to_owned(),
            user_type: Some("user".to_owned()),
        }
    }

    #[test]
    fn parses_valid_two_cloud_configuration() {
        let config = Config::from_toml(&format!(
            r#"
                [clouds.AzureCloud]
                subscription = "{SUB_COMMERCIAL}"
                tenant = "{TENANT_COMMERCIAL}"

                [[clouds.AzureCloud.allowed_subscriptions]]
                subscription = "{SUB_EXTRA}"
                tenant = "{TENANT_EXTRA}"

                [clouds.AzureUSGovernment]
                subscription = "{SUB_GOVERNMENT}"
                tenant = "{TENANT_GOVERNMENT}"
            "#
        ))
        .expect("synthetic two-cloud configuration is valid");

        assert_eq!(config.clouds().len(), 2);
        let commercial = config
            .binding(AzureCloud::AzureCloud)
            .expect("commercial binding");
        assert_eq!(commercial.subscription_id(), SUB_COMMERCIAL);
        assert_eq!(commercial.tenant_id(), Some(TENANT_COMMERCIAL));
        assert_eq!(commercial.fixed_allowed_subscriptions().len(), 2);
        assert_eq!(
            config
                .binding(AzureCloud::AzureUSGovernment)
                .expect("Government binding")
                .tenant_id(),
            Some(TENANT_GOVERNMENT)
        );
    }

    #[test]
    fn missing_primary_tenant_is_left_for_unambiguous_discovery() {
        let config = Config::from_toml(&format!(
            r#"
                [clouds.AzureCloud]
                subscription = "{SUB_COMMERCIAL}"
            "#
        ))
        .expect("tenant discovery is permitted for the primary binding");
        let binding = config
            .binding(AzureCloud::AzureCloud)
            .expect("commercial binding");
        assert_eq!(binding.tenant(), None);

        let selected = candidate(
            AzureCloud::AzureCloud,
            SUB_COMMERCIAL,
            TENANT_COMMERCIAL,
            "alice@example.test",
        );
        let resolved = binding
            .resolve(AzureCloud::AzureCloud, std::slice::from_ref(&selected))
            .expect("one candidate resolves the omitted tenant");
        assert_eq!(resolved.tenant_id(), TENANT_COMMERCIAL);
        assert!(
            binding
                .resolve(AzureCloud::AzureCloud, &[])
                .expect_err("no candidate must not guess")
                .to_string()
                .contains("no tenant candidate")
        );
        assert!(
            binding
                .resolve(
                    AzureCloud::AzureCloud,
                    &[
                        selected,
                        candidate(
                            AzureCloud::AzureCloud,
                            SUB_COMMERCIAL,
                            TENANT_GOVERNMENT,
                            "guest@example.test",
                        ),
                    ]
                )
                .expect_err("multiple candidates are ambiguous")
                .to_string()
                .contains("ambiguous")
        );
    }

    #[test]
    fn rejects_duplicate_and_ambiguous_allowed_pairs() {
        let duplicate = format!(
            r#"
                [clouds.AzureCloud]
                subscription = "{SUB_COMMERCIAL}"
                tenant = "{TENANT_COMMERCIAL}"

                [[clouds.AzureCloud.allowed_subscriptions]]
                subscription = "{SUB_EXTRA}"
                tenant = "{TENANT_EXTRA}"

                [[clouds.AzureCloud.allowed_subscriptions]]
                subscription = "{SUB_EXTRA}"
                tenant = "{TENANT_EXTRA}"
            "#
        );
        let error = Config::from_toml(&duplicate).expect_err("duplicate pair must fail");
        assert!(error.to_string().contains("duplicate tenant"));

        let ambiguous = format!(
            r#"
                [clouds.AzureCloud]
                subscription = "{SUB_COMMERCIAL}"
                tenant = "{TENANT_COMMERCIAL}"

                [[clouds.AzureCloud.allowed_subscriptions]]
                subscription = "{SUB_EXTRA}"
                tenant = "{TENANT_EXTRA}"

                [[clouds.AzureCloud.allowed_subscriptions]]
                subscription = "{SUB_EXTRA}"
                tenant = "{TENANT_GOVERNMENT}"
            "#
        );
        let error = Config::from_toml(&ambiguous).expect_err("ambiguous pair must fail");
        assert!(error.to_string().contains("ambiguous tenants"));

        assert!(
            toml::from_str::<CloudBinding>(&format!(
                r#"
                    subscription = "{SUB_COMMERCIAL}"
                    tenant = "{TENANT_COMMERCIAL}"

                    [[allowed_subscriptions]]
                    subscription = "{SUB_EXTRA}"
                    tenant = "{TENANT_EXTRA}"

                    [[allowed_subscriptions]]
                    subscription = "{SUB_EXTRA}"
                    tenant = "{TENANT_EXTRA}"
                "#
            ))
            .is_err(),
            "direct serde construction must enforce binding invariants"
        );
    }

    #[test]
    fn rejects_duplicate_primary_and_unsupported_fields_or_values() {
        let duplicate_primary = format!(
            r#"
                [clouds.AzureCloud]
                subscription = "{SUB_COMMERCIAL}"
                tenant = "{TENANT_COMMERCIAL}"

                [[clouds.AzureCloud.allowed_subscriptions]]
                subscription = "{SUB_COMMERCIAL}"
                tenant = "{TENANT_COMMERCIAL}"
            "#
        );
        assert!(
            Config::from_toml(&duplicate_primary)
                .expect_err("primary pair cannot be repeated")
                .to_string()
                .contains("listed more than once")
        );

        let unsupported_field = format!(
            r#"
                [clouds.AzureCloud]
                subscription = "{SUB_COMMERCIAL}"
                tenant = "{TENANT_COMMERCIAL}"
                active = true
            "#
        );
        assert!(
            Config::from_toml(&unsupported_field)
                .expect_err("unsupported config fields must fail")
                .to_string()
                .contains("unknown field")
        );

        let unsupported_cloud = format!(
            r#"
                [clouds.AzureChinaCloud]
                subscription = "{SUB_COMMERCIAL}"
                tenant = "{TENANT_COMMERCIAL}"
            "#
        );
        assert!(
            Config::from_toml(&unsupported_cloud)
                .expect_err("v0 must reject unknown clouds")
                .to_string()
                .contains("AzureChinaCloud")
        );

        let missing_extra_tenant = format!(
            r#"
                [clouds.AzureCloud]
                subscription = "{SUB_COMMERCIAL}"
                tenant = "{TENANT_COMMERCIAL}"

                [[clouds.AzureCloud.allowed_subscriptions]]
                subscription = "{SUB_EXTRA}"
            "#
        );
        assert!(
            Config::from_toml(&missing_extra_tenant)
                .expect_err("additional allowlist pairs require a tenant")
                .to_string()
                .contains("missing field `tenant`")
        );
    }

    #[test]
    fn empty_configuration_does_not_select_a_default_cloud() {
        let config = Config::from_toml("").expect("empty config is valid");
        assert!(config.clouds().is_empty());
        assert!(config.binding(AzureCloud::AzureCloud).is_none());
        assert!(config.binding(AzureCloud::AzureUSGovernment).is_none());
    }

    #[test]
    fn identifiers_reject_empty_or_whitespace_values() {
        assert!(SubscriptionId::new(SUB_COMMERCIAL).is_ok());
        assert!(TenantId::new(TENANT_COMMERCIAL).is_ok());
        assert!(SubscriptionId::new("synthetic-subscription").is_err());
        assert!(TenantId::new("").is_err());
        assert!(TenantId::new(" tenant ").is_err());
    }

    #[test]
    fn identifiers_are_normalized_for_case_insensitive_comparison() {
        let upper = SubscriptionId::new("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")
            .expect("uppercase UUID is valid");
        assert_eq!(upper.as_str(), "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    }
}
