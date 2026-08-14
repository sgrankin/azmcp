//! Explicit Azure cloud metadata and identifiers.
//!
//! Cloud selection is intentionally a value, rather than process state.  v0
//! ships only the two reviewed Azure clouds; callers must carry one of these
//! values on every operation.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The Azure clouds supported by the v0 reviewed manifest set.
///
/// There is deliberately no `Default` implementation.  An omitted cloud is
/// an input error, not an invitation to use commercial Azure.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum AzureCloud {
    /// Commercial Azure.
    #[serde(rename = "AzureCloud")]
    AzureCloud,
    /// Azure Government.
    #[serde(rename = "AzureUSGovernment")]
    AzureUSGovernment,
}

impl AzureCloud {
    /// Alias for the commercial manifest variant when a call site prefers a
    /// descriptive constant over the Azure CLI spelling.
    pub const COMMERCIAL: Self = Self::AzureCloud;
    /// Alias for the Government manifest variant when a call site prefers a
    /// descriptive constant over the Azure CLI spelling.
    pub const GOVERNMENT: Self = Self::AzureUSGovernment;

    /// The exact Azure CLI/configuration spelling for this cloud.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AzureCloud => "AzureCloud",
            Self::AzureUSGovernment => "AzureUSGovernment",
        }
    }

    /// Return the reviewed, immutable manifest for this cloud.
    ///
    /// The two manifests are written independently.  In particular, the
    /// Government endpoint values are not produced by replacing a suffix in
    /// the commercial values.
    pub fn manifest(self) -> CloudManifest {
        match self {
            Self::AzureCloud => CloudManifest::azure_cloud(),
            Self::AzureUSGovernment => CloudManifest::azure_us_government(),
        }
    }

    /// Compatibility spelling for callers that want to emphasize that these
    /// are reviewed built-ins rather than user-provided metadata.
    pub fn reviewed_manifest(self) -> CloudManifest {
        self.manifest()
    }
}

impl fmt::Display for AzureCloud {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AzureCloud {
    type Err = UnknownCloud;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "AzureCloud" => Ok(Self::AzureCloud),
            "AzureUSGovernment" => Ok(Self::AzureUSGovernment),
            value => Err(UnknownCloud(value.to_owned())),
        }
    }
}

/// Returned when a cloud name is outside the closed v0 manifest set.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("unsupported Azure cloud `{0}`; v0 supports only AzureCloud and AzureUSGovernment")]
pub struct UnknownCloud(pub String);

/// A reviewed cloud manifest with exact endpoint values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudManifest {
    cloud: AzureCloud,
    metadata_url: String,
    resource_manager: String,
    active_directory: String,
    authentication: AuthenticationManifest,
    suffixes: EndpointSuffixes,
    data_plane: DataPlaneEndpoints,
}

impl CloudManifest {
    fn azure_cloud() -> Self {
        Self {
            cloud: AzureCloud::AzureCloud,
            metadata_url: AZURE_CLOUD_METADATA_URL.to_owned(),
            resource_manager: AZURE_CLOUD_RESOURCE_MANAGER.to_owned(),
            active_directory: AZURE_CLOUD_ACTIVE_DIRECTORY.to_owned(),
            authentication: AuthenticationManifest {
                authority: AZURE_CLOUD_ACTIVE_DIRECTORY.to_owned(),
                audiences: vec![
                    AZURE_CLOUD_ARM_AUDIENCE.to_owned(),
                    AZURE_CLOUD_METRICS_AUDIENCE.to_owned(),
                    AZURE_CLOUD_LOGS_AUDIENCE.to_owned(),
                ],
            },
            suffixes: EndpointSuffixes {
                management: "management.azure.com".to_owned(),
                key_vault: "vault.azure.net".to_owned(),
                sql: "database.windows.net".to_owned(),
                storage: "blob.core.windows.net".to_owned(),
            },
            data_plane: DataPlaneEndpoints {
                resource_graph: AZURE_CLOUD_RESOURCE_GRAPH.to_owned(),
                metrics: "metrics.monitor.azure.com".to_owned(),
                logs_query: AZURE_CLOUD_LOGS_QUERY.to_owned(),
                logs_token_resource: AZURE_CLOUD_LOGS_AUDIENCE.to_owned(),
            },
        }
    }

    fn azure_us_government() -> Self {
        Self {
            cloud: AzureCloud::AzureUSGovernment,
            metadata_url: AZURE_US_GOVERNMENT_METADATA_URL.to_owned(),
            resource_manager: AZURE_US_GOVERNMENT_RESOURCE_MANAGER.to_owned(),
            active_directory: AZURE_US_GOVERNMENT_ACTIVE_DIRECTORY.to_owned(),
            authentication: AuthenticationManifest {
                authority: AZURE_US_GOVERNMENT_ACTIVE_DIRECTORY.to_owned(),
                audiences: vec![
                    AZURE_US_GOVERNMENT_ARM_AUDIENCE.to_owned(),
                    AZURE_US_GOVERNMENT_METRICS_AUDIENCE.to_owned(),
                    AZURE_US_GOVERNMENT_LOGS_AUDIENCE.to_owned(),
                ],
            },
            suffixes: EndpointSuffixes {
                management: "management.usgovcloudapi.net".to_owned(),
                key_vault: "vault.usgovcloudapi.net".to_owned(),
                sql: "database.usgovcloudapi.net".to_owned(),
                storage: "blob.core.usgovcloudapi.net".to_owned(),
            },
            data_plane: DataPlaneEndpoints {
                resource_graph: AZURE_US_GOVERNMENT_RESOURCE_GRAPH.to_owned(),
                metrics: "metrics.monitor.azure.us".to_owned(),
                logs_query: AZURE_US_GOVERNMENT_LOGS_QUERY.to_owned(),
                logs_token_resource: AZURE_US_GOVERNMENT_LOGS_AUDIENCE.to_owned(),
            },
        }
    }

    /// The cloud represented by this manifest.
    pub const fn cloud(&self) -> AzureCloud {
        self.cloud
    }

    /// The pinned metadata bootstrap URL.
    pub fn metadata_url(&self) -> &str {
        &self.metadata_url
    }

    /// The exact ARM origin for this cloud.
    pub fn resource_manager(&self) -> &str {
        &self.resource_manager
    }

    /// The Entra authority for this cloud.
    pub fn active_directory(&self) -> &str {
        &self.active_directory
    }

    /// Authentication authority and audiences.
    pub const fn authentication(&self) -> &AuthenticationManifest {
        &self.authentication
    }

    /// DNS suffixes explicitly reviewed for this cloud.
    pub const fn suffixes(&self) -> &EndpointSuffixes {
        &self.suffixes
    }

    /// Explicitly supported data-plane endpoints.
    pub const fn data_plane(&self) -> &DataPlaneEndpoints {
        &self.data_plane
    }
}

/// Authentication values associated with a cloud manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationManifest {
    authority: String,
    audiences: Vec<String>,
}

impl AuthenticationManifest {
    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub fn audiences(&self) -> &[String] {
        &self.audiences
    }
}

/// Explicit DNS suffixes used by supported endpoint families.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointSuffixes {
    management: String,
    key_vault: String,
    sql: String,
    storage: String,
}

impl EndpointSuffixes {
    pub fn management(&self) -> &str {
        &self.management
    }

    pub fn key_vault(&self) -> &str {
        &self.key_vault
    }

    pub fn sql(&self) -> &str {
        &self.sql
    }

    pub fn storage(&self) -> &str {
        &self.storage
    }
}

/// Data-plane endpoints explicitly included in the v0 manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DataPlaneEndpoints {
    resource_graph: String,
    metrics: String,
    logs_query: String,
    logs_token_resource: String,
}

impl DataPlaneEndpoints {
    pub fn resource_graph(&self) -> &str {
        &self.resource_graph
    }

    /// The exact regional metrics host suffix for this cloud.
    pub fn metrics(&self) -> &str {
        &self.metrics
    }

    /// The exact Log Analytics Query API origin for this cloud.
    pub fn logs_query(&self) -> &str {
        &self.logs_query
    }

    /// The exact OAuth resource used to acquire a Log Analytics token.
    pub fn logs_token_resource(&self) -> &str {
        &self.logs_token_resource
    }
}

pub const AZURE_CLOUD_METADATA_URL: &str =
    "https://management.azure.com/metadata/endpoints?api-version=2020-01-01";
pub const AZURE_CLOUD_RESOURCE_MANAGER: &str = "https://management.azure.com/";
pub const AZURE_CLOUD_ACTIVE_DIRECTORY: &str = "https://login.microsoftonline.com/";
pub const AZURE_CLOUD_ARM_AUDIENCE: &str = "https://management.azure.com/";
pub const AZURE_CLOUD_METRICS_AUDIENCE: &str = "https://metrics.monitor.azure.com/";
pub const AZURE_CLOUD_RESOURCE_GRAPH: &str =
    "https://management.azure.com/providers/Microsoft.ResourceGraph/resources";
pub const AZURE_CLOUD_LOGS_QUERY: &str = "https://api.loganalytics.azure.com/";
pub const AZURE_CLOUD_LOGS_AUDIENCE: &str = "https://api.loganalytics.io";

pub const AZURE_US_GOVERNMENT_METADATA_URL: &str =
    "https://management.usgovcloudapi.net/metadata/endpoints?api-version=2020-01-01";
pub const AZURE_US_GOVERNMENT_RESOURCE_MANAGER: &str = "https://management.usgovcloudapi.net/";
pub const AZURE_US_GOVERNMENT_ACTIVE_DIRECTORY: &str = "https://login.microsoftonline.us/";
pub const AZURE_US_GOVERNMENT_ARM_AUDIENCE: &str = "https://management.usgovcloudapi.net/";
pub const AZURE_US_GOVERNMENT_METRICS_AUDIENCE: &str = "https://metrics.monitor.azure.us/";
pub const AZURE_US_GOVERNMENT_RESOURCE_GRAPH: &str =
    "https://management.usgovcloudapi.net/providers/Microsoft.ResourceGraph/resources";
pub const AZURE_US_GOVERNMENT_LOGS_QUERY: &str = "https://api.loganalytics.us/";
pub const AZURE_US_GOVERNMENT_LOGS_AUDIENCE: &str = "https://api.loganalytics.us";

/// Short alias for the closed v0 cloud value.
pub type Cloud = AzureCloud;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_reviewed_cloud_names_parse() {
        assert_eq!("AzureCloud".parse(), Ok(AzureCloud::AzureCloud));
        assert_eq!(
            "AzureUSGovernment".parse(),
            Ok(AzureCloud::AzureUSGovernment)
        );
        assert!("AzureGovernment".parse::<AzureCloud>().is_err());
        assert!("".parse::<AzureCloud>().is_err());
    }

    #[test]
    fn reviewed_manifests_keep_cloud_endpoints_explicit() {
        let commercial = AzureCloud::AzureCloud.manifest();
        let government = AzureCloud::AzureUSGovernment.manifest();

        assert_eq!(commercial.cloud(), AzureCloud::AzureCloud);
        assert_eq!(government.cloud(), AzureCloud::AzureUSGovernment);
        assert_eq!(commercial.resource_manager(), AZURE_CLOUD_RESOURCE_MANAGER);
        assert_eq!(
            government.resource_manager(),
            AZURE_US_GOVERNMENT_RESOURCE_MANAGER
        );
        assert_eq!(commercial.active_directory(), AZURE_CLOUD_ACTIVE_DIRECTORY);
        assert_eq!(
            government.active_directory(),
            AZURE_US_GOVERNMENT_ACTIVE_DIRECTORY
        );
        assert_ne!(
            commercial.suffixes().management(),
            government.suffixes().management()
        );
        assert_ne!(
            commercial.data_plane().resource_graph(),
            government.data_plane().resource_graph()
        );
        assert_eq!(commercial.data_plane().logs_query(), AZURE_CLOUD_LOGS_QUERY);
        assert_eq!(
            government.data_plane().logs_query(),
            AZURE_US_GOVERNMENT_LOGS_QUERY
        );
        assert_eq!(
            commercial.data_plane().logs_token_resource(),
            AZURE_CLOUD_LOGS_AUDIENCE
        );
        assert_eq!(
            government.data_plane().logs_token_resource(),
            AZURE_US_GOVERNMENT_LOGS_AUDIENCE
        );
    }

    #[test]
    fn manifest_serializes_for_diagnostics() {
        let manifest = AzureCloud::AzureUSGovernment.manifest();
        let encoded = serde_json::to_string(&manifest).expect("manifest serializes");
        assert!(encoded.contains(AZURE_US_GOVERNMENT_RESOURCE_MANAGER));
        assert!(encoded.contains(AZURE_US_GOVERNMENT_ACTIVE_DIRECTORY));
    }

    #[test]
    fn unknown_cloud_is_rejected_by_serde() {
        let error = serde_json::from_str::<AzureCloud>(r#""AzureChinaCloud""#)
            .expect_err("v0 must reject unsupported clouds");
        assert!(error.to_string().contains("AzureChinaCloud"));
    }
}
