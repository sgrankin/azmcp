//! Azure CLI account-profile discovery.

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;
use thiserror::Error;

const MAX_PROFILE_BYTES: usize = 16 * 1024 * 1024;

/// The fields that distinguish one cached Azure CLI account from another.
///
/// `subscription_id` alone is not a sufficient key: the same subscription can
/// be reachable through more than one tenant or user route, and subscriptions
/// from different clouds can use the same human-facing name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccountKey {
    /// The Azure CLI cloud name, for example `AzureCloud`.
    pub environment_name: String,
    /// The Entra tenant that owns the subscription route.
    pub tenant_id: String,
    /// The Azure subscription identifier.
    pub subscription_id: String,
    /// The account name recorded by Azure CLI (`user.name`).
    pub user_name: String,
}

impl AccountKey {
    /// Construct a key from the four fields persisted by Azure CLI.
    pub fn new(
        environment_name: impl Into<String>,
        tenant_id: impl Into<String>,
        subscription_id: impl Into<String>,
        user_name: impl Into<String>,
    ) -> Self {
        Self {
            environment_name: environment_name.into(),
            tenant_id: tenant_id.into(),
            subscription_id: subscription_id.into(),
            user_name: user_name.into(),
        }
    }
}

impl fmt::Display for AccountKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} / {} / {} / {}",
            self.environment_name, self.tenant_id, self.subscription_id, self.user_name
        )
    }
}

/// One enabled, real subscription discovered in `azureProfile.json`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SubscriptionCandidate {
    /// The complete identity key used to index this candidate.
    pub key: AccountKey,
    /// The display name reported by Azure CLI.
    pub name: String,
    /// The cached state. Candidates returned by [`parse_azure_profile`] are
    /// always `Enabled` (case is preserved from the profile).
    pub state: String,
    /// The Azure CLI user type, when present (`user`, `servicePrincipal`, ...).
    pub user_type: Option<String>,
}

impl SubscriptionCandidate {
    /// The cloud associated with this candidate.
    pub fn environment_name(&self) -> &str {
        &self.key.environment_name
    }

    /// The tenant associated with this candidate.
    pub fn tenant_id(&self) -> &str {
        &self.key.tenant_id
    }

    /// The subscription identifier.
    pub fn subscription_id(&self) -> &str {
        &self.key.subscription_id
    }

    /// The account name associated with this candidate.
    pub fn user_name(&self) -> &str {
        &self.key.user_name
    }
}

/// A keyed view of every usable subscription in an Azure CLI profile.
///
/// Values are vectors intentionally. Azure CLI normally emits one record per
/// key, but silently overwriting a duplicate profile record would turn a
/// discovery inconsistency into an unsafe implicit choice.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AccountIndex {
    by_key: BTreeMap<AccountKey, Vec<SubscriptionCandidate>>,
}

impl AccountIndex {
    fn from_candidates(candidates: impl IntoIterator<Item = SubscriptionCandidate>) -> Self {
        let mut by_key: BTreeMap<AccountKey, Vec<SubscriptionCandidate>> = BTreeMap::new();
        for candidate in candidates {
            by_key
                .entry(candidate.key.clone())
                .or_default()
                .push(candidate);
        }
        Self { by_key }
    }

    /// Return the complete keyed index.
    pub fn by_key(&self) -> &BTreeMap<AccountKey, Vec<SubscriptionCandidate>> {
        &self.by_key
    }

    /// Return all candidates, in deterministic key order.
    pub fn candidates(&self) -> impl Iterator<Item = &SubscriptionCandidate> {
        self.by_key.values().flatten()
    }

    /// Return candidates for one cloud, in deterministic key order.
    pub fn candidates_for(&self, environment_name: &str) -> Vec<&SubscriptionCandidate> {
        self.candidates()
            .filter(|candidate| candidate.environment_name() == environment_name)
            .collect()
    }

    /// Look up one exact account key.
    pub fn get(&self, key: &AccountKey) -> Option<&[SubscriptionCandidate]> {
        self.by_key.get(key).map(Vec::as_slice)
    }

    /// Resolve the automatic per-cloud binding.
    ///
    /// Exactly one cached candidate is required. A missing or ambiguous cloud
    /// never falls back to `isDefault`, subscription name, or insertion order.
    pub fn resolve(
        &self,
        environment_name: &str,
    ) -> Result<&SubscriptionCandidate, AccountResolutionError> {
        let candidates = self.candidates_for(environment_name);
        match candidates.as_slice() {
            [] => Err(AccountResolutionError::NoEnabledSubscription {
                environment_name: environment_name.to_owned(),
            }),
            [candidate] => Ok(candidate),
            _ => Err(AccountResolutionError::Ambiguous {
                environment_name: environment_name.to_owned(),
                candidates: candidates.into_iter().cloned().collect(),
            }),
        }
    }

    /// Number of keyed entries in the index.
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    /// Whether the index contains no usable subscription candidates.
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }
}

/// A profile binding failure that callers must surface instead of guessing.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AccountResolutionError {
    /// The selected cloud has no enabled subscription in the cache.
    #[error("no enabled subscription candidate for cloud {environment_name}")]
    NoEnabledSubscription { environment_name: String },
    /// More than one candidate is available for the selected cloud.
    #[error("ambiguous subscription binding for cloud {environment_name}: {candidates:?}")]
    Ambiguous {
        environment_name: String,
        candidates: Vec<SubscriptionCandidate>,
    },
}

/// Errors encountered while decoding an Azure CLI profile.
#[derive(Debug, Error)]
pub enum AccountProfileError {
    /// The profile exceeds the parser's bounded local-cache input.
    #[error("azureProfile.json exceeds the 16 MiB size limit")]
    TooLarge,
    /// The profile is not UTF-8 after removing an optional BOM.
    #[error("azureProfile.json is not valid UTF-8")]
    InvalidUtf8,
    /// The profile is not valid JSON or has the wrong top-level shape.
    #[error("azureProfile.json is not valid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
}

#[derive(Debug, Deserialize)]
struct AzureProfile {
    subscriptions: Vec<ProfileSubscription>,
}

#[derive(Debug, Deserialize)]
struct ProfileSubscription {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(rename = "tenantId", default)]
    tenant_id: Option<String>,
    #[serde(rename = "environmentName", default)]
    environment_name: Option<String>,
    #[serde(default)]
    user: Option<ProfileUser>,
}

#[derive(Debug, Deserialize)]
struct ProfileUser {
    #[serde(default)]
    name: Option<String>,
    #[serde(rename = "type", default)]
    user_type: Option<String>,
}

/// Parse synthetic or caller-supplied `azureProfile.json` bytes.
///
/// Azure CLI profiles may begin with a UTF-8 BOM. The `isDefault` field is
/// deliberately not represented or consulted: it is process-global mutable
/// state and cannot be a safe binding source. Disabled records, records with
/// missing identity fields, and tenant-only pseudo-accounts are filtered out.
pub fn parse_azure_profile(bytes: &[u8]) -> Result<AccountIndex, AccountProfileError> {
    if bytes.len() > MAX_PROFILE_BYTES {
        return Err(AccountProfileError::TooLarge);
    }
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let text = std::str::from_utf8(bytes).map_err(|_| AccountProfileError::InvalidUtf8)?;
    let profile: AzureProfile = serde_json::from_str(text)?;

    let candidates = profile
        .subscriptions
        .into_iter()
        .filter_map(subscription_candidate)
        .collect::<Vec<_>>();

    Ok(AccountIndex::from_candidates(candidates))
}

/// Alias emphasizing that the parser accepts bytes rather than reading any
/// ambient Azure CLI path.
pub fn parse_azure_profile_bytes(bytes: &[u8]) -> Result<AccountIndex, AccountProfileError> {
    parse_azure_profile(bytes)
}

fn subscription_candidate(subscription: ProfileSubscription) -> Option<SubscriptionCandidate> {
    let state = subscription.state?;
    if !state.eq_ignore_ascii_case("enabled") {
        return None;
    }

    let subscription_id = non_empty(subscription.id?)?;
    let name = non_empty(subscription.name?)?;
    let tenant_id = non_empty(subscription.tenant_id?)?;
    let environment_name = non_empty(subscription.environment_name?)?;
    let user = subscription.user?;
    let user_name = non_empty(user.name?)?;

    // `az login --allow-no-subscriptions` records tenant-only accounts as
    // `N/A(tenant level account)` rather than a subscription ID. They are
    // useful to `az account tenant list`, but cannot bind an ARM subscription.
    if is_tenant_level_account(&subscription_id) || is_tenant_level_account(&name) {
        return None;
    }

    Some(SubscriptionCandidate {
        key: AccountKey::new(environment_name, tenant_id, subscription_id, user_name),
        name,
        state,
        user_type: user.user_type.and_then(non_empty),
    })
}

fn non_empty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

fn is_tenant_level_account(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized == "n/a" || normalized.contains("tenant level account")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bom_ignores_default_and_filters_non_subscriptions() {
        let profile = br#"{
            "subscriptions": [
                {
                    "id": "sub-enabled",
                    "name": "Enabled",
                    "state": "Enabled",
                    "tenantId": "tenant-a",
                    "environmentName": "AzureCloud",
                    "isDefault": false,
                    "user": {"name": "alice@example.test", "type": "user"}
                },
                {
                    "id": "sub-default-but-valid",
                    "name": "Default flag is irrelevant",
                    "state": "Enabled",
                    "tenantId": "tenant-a",
                    "environmentName": "AzureCloud",
                    "isDefault": true,
                    "user": {"name": "alice@example.test", "type": "user"}
                },
                {
                    "id": "sub-disabled",
                    "name": "Disabled",
                    "state": "Disabled",
                    "tenantId": "tenant-a",
                    "environmentName": "AzureCloud",
                    "user": {"name": "alice@example.test", "type": "user"}
                },
                {
                    "id": "N/A(tenant level account)",
                    "name": "N/A(tenant level account)",
                    "state": "Enabled",
                    "tenantId": "tenant-a",
                    "environmentName": "AzureCloud",
                    "user": {"name": "alice@example.test", "type": "user"}
                }
            ]
        }"#;

        let mut with_bom = b"\xef\xbb\xbf".to_vec();
        with_bom.extend_from_slice(profile);
        let index = parse_azure_profile(&with_bom).expect("synthetic profile parses");

        assert_eq!(index.len(), 2);
        assert_eq!(index.candidates_for("AzureCloud").len(), 2);
        assert!(
            index
                .candidates()
                .all(|candidate| candidate.state.eq_ignore_ascii_case("enabled"))
        );
        assert!(
            index
                .candidates()
                .all(|candidate| candidate.subscription_id() != "sub-disabled")
        );
    }

    #[test]
    fn ambiguous_cloud_does_not_choose_by_default_flag_or_order() {
        let profile = br#"{
            "subscriptions": [
                {"id":"sub-a","name":"A","state":"Enabled","tenantId":"tenant","environmentName":"AzureCloud","isDefault":true,"user":{"name":"a","type":"user"}},
                {"id":"sub-b","name":"B","state":"Enabled","tenantId":"tenant","environmentName":"AzureCloud","isDefault":false,"user":{"name":"b","type":"user"}}
            ]
        }"#;
        let index = parse_azure_profile(profile).expect("synthetic profile parses");

        let error = index
            .resolve("AzureCloud")
            .expect_err("two candidates are ambiguous");
        match error {
            AccountResolutionError::Ambiguous {
                environment_name,
                candidates,
            } => {
                assert_eq!(environment_name, "AzureCloud");
                assert_eq!(candidates.len(), 2);
            }
            other => panic!("unexpected resolution result: {other:?}"),
        }
    }

    #[test]
    fn duplicate_keys_are_retained_as_explicit_ambiguity() {
        let profile = br#"{
            "subscriptions": [
                {"id":"sub","name":"first","state":"Enabled","tenantId":"tenant","environmentName":"AzureCloud","user":{"name":"user"}},
                {"id":"sub","name":"second","state":"Enabled","tenantId":"tenant","environmentName":"AzureCloud","user":{"name":"user"}}
            ]
        }"#;
        let index = parse_azure_profile(profile).expect("synthetic profile parses");
        assert_eq!(index.by_key().len(), 1);
        assert_eq!(index.candidates_for("AzureCloud").len(), 2);
        assert!(matches!(
            index.resolve("AzureCloud"),
            Err(AccountResolutionError::Ambiguous { .. })
        ));
    }

    #[test]
    fn malformed_utf8_and_json_are_rejected() {
        assert!(matches!(
            parse_azure_profile(&[0xff]),
            Err(AccountProfileError::InvalidUtf8)
        ));
        assert!(parse_azure_profile(b"not json").is_err());
    }

    #[test]
    fn btree_key_is_the_complete_binding_identity() {
        use std::collections::BTreeSet;

        let key = AccountKey::new("AzureCloud", "tenant", "subscription", "user");
        let mut set = BTreeSet::new();
        assert!(set.insert(key.clone()));
        assert!(!set.insert(key));
    }
}
