//! v0 MCP tool contracts.

use std::sync::Arc;

use rmcp::model::{JsonObject, Tool, ToolAnnotations};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use azmcp_core::cloud::AzureCloud;

pub const ACCOUNTS_TOOL: &str = "azure_accounts";
pub const CONTEXT_OPEN_TOOL: &str = "azure_context_open";
pub const CONTEXT_CLOSE_TOOL: &str = "azure_context_close";
pub const RUN_TOOL: &str = "azure_run";

pub const DEFAULT_RUN_TIMEOUT_MS: u64 = 60_000;
pub const MAX_RUN_TIMEOUT_MS: u64 = 3_600_000;
pub const MAX_CODE_BYTES: usize = 256 * 1024;

/// Empty input for cached account discovery.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AccountsArgs {}

/// The only identity implemented by v0.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
pub enum UserIdentity {
    #[serde(rename = "user")]
    User,
}

/// The only ARM tier implemented by v0.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
pub enum InspectTier {
    #[serde(rename = "inspect")]
    Inspect,
}

/// A caller override for one cloud binding.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BindingArgs {
    pub subscription: String,
    #[serde(default)]
    pub tenant: Option<String>,
}

/// Closed binding keys for the two reviewed v0 clouds.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BindingOverrides {
    #[serde(rename = "AzureCloud", default)]
    pub commercial: Option<BindingArgs>,
    #[serde(rename = "AzureUSGovernment", default)]
    pub government: Option<BindingArgs>,
}

impl BindingOverrides {
    pub fn iter(&self) -> impl Iterator<Item = (AzureCloud, &BindingArgs)> {
        [
            self.commercial
                .as_ref()
                .map(|binding| (AzureCloud::AzureCloud, binding)),
            self.government
                .as_ref()
                .map(|binding| (AzureCloud::AzureUSGovernment, binding)),
        ]
        .into_iter()
        .flatten()
    }
}

/// One additional fixed subscription/tenant pair.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AllowedSubscriptionArgs {
    pub subscription: String,
    pub tenant: String,
}

/// Additional request and explicit-graph subscriptions by reviewed cloud.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedSubscriptionOverrides {
    #[serde(rename = "AzureCloud", default)]
    pub commercial: Vec<AllowedSubscriptionArgs>,
    #[serde(rename = "AzureUSGovernment", default)]
    pub government: Vec<AllowedSubscriptionArgs>,
}

impl AllowedSubscriptionOverrides {
    pub fn get(&self, cloud: AzureCloud) -> &[AllowedSubscriptionArgs] {
        match cloud {
            AzureCloud::AzureCloud => &self.commercial,
            AzureCloud::AzureUSGovernment => &self.government,
        }
    }
}

/// A Resource Graph subscription set declared at context open.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSubscriptionsArgs {
    pub subscriptions: Vec<String>,
}

/// The explicit Resource Graph fleet-wide scope.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphAllAccessibleArgs {
    pub scope: AllAccessibleScope,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub enum AllAccessibleScope {
    #[serde(rename = "allAccessible")]
    AllAccessible,
}

/// Exactly one of an explicit subscription set or `allAccessible`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum GraphScopeArgs {
    Subscriptions(GraphSubscriptionsArgs),
    AllAccessible(GraphAllAccessibleArgs),
}

/// Resource Graph scopes by reviewed cloud.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphScopeOverrides {
    #[serde(rename = "AzureCloud", default)]
    pub commercial: Option<GraphScopeArgs>,
    #[serde(rename = "AzureUSGovernment", default)]
    pub government: Option<GraphScopeArgs>,
}

impl GraphScopeOverrides {
    pub fn get(&self, cloud: AzureCloud) -> Option<&GraphScopeArgs> {
        match cloud {
            AzureCloud::AzureCloud => self.commercial.as_ref(),
            AzureCloud::AzureUSGovernment => self.government.as_ref(),
        }
    }
}

/// Input for an immutable inspect-only execution context.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ContextOpenArgs {
    #[serde(default)]
    pub identity: Option<UserIdentity>,
    #[serde(default)]
    pub arm_tier: Option<InspectTier>,
    #[serde(default)]
    pub data_planes: Vec<Value>,
    #[serde(default)]
    pub bindings: BindingOverrides,
    #[serde(default)]
    pub allowed_subscriptions: AllowedSubscriptionOverrides,
    #[serde(default)]
    pub graph_scopes: GraphScopeOverrides,
}

impl ContextOpenArgs {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.data_planes.is_empty() {
            return Err("v0 dataPlanes must be empty");
        }
        for cloud in [AzureCloud::AzureCloud, AzureCloud::AzureUSGovernment] {
            let additional = self.allowed_subscriptions.get(cloud);
            if additional.iter().enumerate().any(|(index, item)| {
                additional[..index]
                    .iter()
                    .any(|prior| prior.subscription.eq_ignore_ascii_case(&item.subscription))
            }) {
                return Err("allowedSubscriptions contains a duplicate subscription");
            }
            if let Some(GraphScopeArgs::Subscriptions(scope)) = self.graph_scopes.get(cloud)
                && (scope.subscriptions.is_empty()
                    || scope.subscriptions.iter().enumerate().any(|(index, item)| {
                        scope.subscriptions[..index]
                            .iter()
                            .any(|prior| prior.eq_ignore_ascii_case(item))
                    }))
            {
                return Err("graphScopes subscriptions must be non-empty and unique");
            }
        }
        Ok(())
    }
}

/// Input for immediate context disposal.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ContextCloseArgs {
    pub context_id: String,
}

/// Input for one JavaScript turn in a retained context.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RunArgs {
    pub context_id: String,
    pub code: String,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl RunArgs {
    pub fn timeout_ms(&self) -> Result<u64, &'static str> {
        let timeout = self.timeout_ms.unwrap_or(DEFAULT_RUN_TIMEOUT_MS);
        if timeout == 0 || timeout > MAX_RUN_TIMEOUT_MS {
            return Err("timeoutMs is outside the v0 range");
        }
        if self.code.len() > MAX_CODE_BYTES {
            return Err("code exceeds the v0 size limit");
        }
        Ok(timeout)
    }
}

/// The exact deterministic v0 catalog. The server advertises it only after all four
/// handlers are wired in the running server.
pub fn catalog() -> Vec<Tool> {
    vec![accounts(), context_open(), context_close(), run()]
}

fn accounts() -> Tool {
    tool(
        ACCOUNTS_TOOL,
        "Enumerate cached Azure CLI subscription candidates across reviewed clouds without acquiring tokens or selecting a current account.",
        empty_object_schema(),
        json!({
            "type": "object",
            "properties": {
                "accounts": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "cloud": cloud_schema(),
                            "tenantId": uuid_schema(),
                            "subscriptionId": uuid_schema(),
                            "name": {"type": "string"},
                            "user": {"type": "string"},
                            "state": {"type": "string"},
                            "tokenStatus": {"const": "unknown"}
                        },
                        "required": ["cloud", "tenantId", "subscriptionId", "name", "user", "state", "tokenStatus"],
                        "additionalProperties": false
                    }
                }
            },
            "required": ["accounts"],
            "additionalProperties": false
        }),
        annotations(true, true, false),
    )
}

fn context_open() -> Tool {
    tool(
        CONTEXT_OPEN_TOOL,
        "Open a persistent, inspect-only JavaScript context with immutable Azure cloud bindings. Cloud is never defaulted inside a run.",
        json!({
            "type": "object",
            "properties": {
                "identity": {"const": "user", "default": "user"},
                "armTier": {"const": "inspect", "default": "inspect"},
                "dataPlanes": {"type": "array", "maxItems": 0, "default": []},
                "bindings": bindings_schema(),
                "allowedSubscriptions": allowed_subscriptions_schema(),
                "graphScopes": graph_scopes_schema()
            },
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "contextId": context_id_schema(),
                "identity": {"const": "user"},
                "armTier": {"const": "inspect"},
                "dataPlanes": {"type": "array", "maxItems": 0},
                "resolvedBindings": {"type": "array", "minItems": 1, "items": resolved_binding_schema()},
                "allowedSubscriptions": allowed_subscriptions_schema(),
                "graphScopes": graph_scopes_schema(),
                "expiresAt": {"type": "string", "format": "date-time"}
            },
            "required": ["contextId", "identity", "armTier", "dataPlanes", "resolvedBindings", "allowedSubscriptions", "graphScopes", "expiresAt"],
            "additionalProperties": false
        }),
        annotations(true, false, false),
    )
}

fn context_close() -> Tool {
    tool(
        CONTEXT_CLOSE_TOOL,
        "Immediately dispose a retained Azure JavaScript context and its worker process.",
        json!({
            "type": "object",
            "properties": {"contextId": context_id_schema()},
            "required": ["contextId"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {"closed": {"const": true}},
            "required": ["closed"],
            "additionalProperties": false
        }),
        annotations(true, true, false),
    )
}

fn run() -> Tool {
    tool(
        RUN_TOOL,
        "Execute JavaScript in a retained inspect-only context. Use az.graph for fleet inventory and az.request only for reviewed ARM routes.",
        json!({
            "type": "object",
            "properties": {
                "contextId": context_id_schema(),
                "code": {"type": "string", "maxLength": MAX_CODE_BYTES},
                "timeoutMs": {"type": "integer", "minimum": 1, "maximum": MAX_RUN_TIMEOUT_MS, "default": DEFAULT_RUN_TIMEOUT_MS}
            },
            "required": ["contextId", "code"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "value": {},
                "console": {"type": "array", "items": {"type": "string"}},
                "consoleOmitted": {"type": "integer", "minimum": 0},
                "calls": {"type": "array", "items": {"type": "object"}},
                "callsOmitted": {"type": "integer", "minimum": 0},
                "context": {"type": "object"},
                "sensitivity": {"enum": ["public", "customerData", "secret"]},
                "correlationId": {"type": "string"}
            },
            "required": ["value", "console", "consoleOmitted", "calls", "callsOmitted", "context", "sensitivity", "correlationId"],
            "additionalProperties": false
        }),
        annotations(true, false, true),
    )
}

fn tool(
    name: &'static str,
    description: &'static str,
    input: Value,
    output: Value,
    annotations: ToolAnnotations,
) -> Tool {
    Tool::new(name, description, schema(input))
        .with_raw_output_schema(schema(output))
        .with_annotations(annotations)
}

fn annotations(read_only: bool, idempotent: bool, open_world: bool) -> ToolAnnotations {
    ToolAnnotations::new()
        .read_only(read_only)
        .destructive(false)
        .idempotent(idempotent)
        .open_world(open_world)
}

fn schema(mut value: Value) -> Arc<JsonObject> {
    let object = value.as_object_mut().expect("static schema is an object");
    object.insert(
        "$schema".to_owned(),
        Value::String("https://json-schema.org/draft/2020-12/schema".to_owned()),
    );
    Arc::new(std::mem::take(object))
}

fn empty_object_schema() -> Value {
    json!({"type": "object", "properties": {}, "additionalProperties": false})
}

fn cloud_schema() -> Value {
    json!({"enum": ["AzureCloud", "AzureUSGovernment"]})
}

fn uuid_schema() -> Value {
    json!({
        "type": "string",
        "pattern": "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
    })
}

fn context_id_schema() -> Value {
    json!({"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"})
}

fn binding_schema() -> Value {
    json!({
        "type": "object",
        "properties": {"subscription": uuid_schema(), "tenant": uuid_schema()},
        "required": ["subscription"],
        "additionalProperties": false
    })
}

fn bindings_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "AzureCloud": binding_schema(),
            "AzureUSGovernment": binding_schema()
        },
        "additionalProperties": false
    })
}

fn subscription_tenant_schema() -> Value {
    json!({
        "type": "object",
        "properties": {"subscription": uuid_schema(), "tenant": uuid_schema()},
        "required": ["subscription", "tenant"],
        "additionalProperties": false
    })
}

fn allowed_subscriptions_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "AzureCloud": {"type": "array", "items": subscription_tenant_schema(), "uniqueItems": true},
            "AzureUSGovernment": {"type": "array", "items": subscription_tenant_schema(), "uniqueItems": true}
        },
        "additionalProperties": false
    })
}

fn graph_scope_schema() -> Value {
    json!({
        "oneOf": [
            {
                "type": "object",
                "properties": {
                    "subscriptions": {"type": "array", "minItems": 1, "uniqueItems": true, "items": uuid_schema()}
                },
                "required": ["subscriptions"],
                "additionalProperties": false
            },
            {
                "type": "object",
                "properties": {"scope": {"const": "allAccessible"}},
                "required": ["scope"],
                "additionalProperties": false
            }
        ]
    })
}

fn graph_scopes_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "AzureCloud": graph_scope_schema(),
            "AzureUSGovernment": graph_scope_schema()
        },
        "additionalProperties": false
    })
}

fn resolved_binding_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "cloud": cloud_schema(),
            "subscription": uuid_schema(),
            "tenant": uuid_schema()
        },
        "required": ["cloud", "subscription", "tenant"],
        "additionalProperties": false
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_deterministic_modern_and_ref_free() {
        let first = serde_json::to_value(catalog()).unwrap();
        assert_eq!(first, serde_json::to_value(catalog()).unwrap());
        assert_eq!(catalog().len(), 4);
        let encoded = serde_json::to_string(&first).unwrap();
        assert!(!encoded.contains("$ref"));
        assert_eq!(encoded.matches("2020-12").count(), 8);
    }

    #[test]
    fn v0_inputs_reject_future_and_unknown_values() {
        assert!(serde_json::from_value::<AccountsArgs>(json!({"current": true})).is_err());
        assert!(serde_json::from_value::<ContextOpenArgs>(json!({"identity": "reader"})).is_err());
        assert!(serde_json::from_value::<ContextOpenArgs>(json!({"armTier": "read"})).is_err());
        let args: ContextOpenArgs =
            serde_json::from_value(json!({"dataPlanes": ["logs.query"]})).unwrap();
        assert!(args.validate().is_err());
        assert!(
            serde_json::from_value::<ContextCloseArgs>(json!({"contextId": "x", "force": true}))
                .is_err()
        );
    }

    #[test]
    fn run_validation_matches_schema_bounds() {
        let args: RunArgs =
            serde_json::from_value(json!({"contextId": "x", "code": "1+1"})).unwrap();
        assert_eq!(args.timeout_ms(), Ok(DEFAULT_RUN_TIMEOUT_MS));
        let args = RunArgs {
            context_id: "x".to_owned(),
            code: "x".repeat(MAX_CODE_BYTES + 1),
            timeout_ms: None,
        };
        assert!(args.timeout_ms().is_err());
    }
}
