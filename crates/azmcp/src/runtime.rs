//! Inert production dependency assembly.
//!
//! Startup resolves paths and parses azmcp's own configuration. The Azure CLI
//! profile remains lazy, and neither credentials nor network are touched until
//! a caller explicitly opens or uses an Azure context.

use std::{ffi::OsString, path::PathBuf, sync::Arc};

use azmcp_core::{config::Config, credential::AzureCliBroker, routes};

use crate::{
    app::{
        Application, FileProfileSource, HttpBindingValidator, ProcessWorkerFactory,
        default_registry,
    },
    artifacts::{ArtifactStore, FileArtifactStore},
    audit::{
        AuditSink, DEFAULT_MAX_AUDIT_BYTES, DEFAULT_RETAINED_AUDIT_FILES, FileAuditConfig,
        FileAuditLog,
    },
    host::{HttpClientFactory, ReviewedHttpClientFactory},
};

pub async fn production_application() -> anyhow::Result<Application> {
    let config = load_config().await?;
    let artifact_store: Arc<dyn ArtifactStore> =
        Arc::new(FileArtifactStore::new(artifact_root(&config)?)?);
    let profile = FileProfileSource::new(azure_profile_path()?);
    let worker = ProcessWorkerFactory::new(std::env::current_exe()?);
    let broker = Arc::new(AzureCliBroker::new(
        std::env::var_os("AZMCP_AZ_EXECUTABLE").unwrap_or_else(|| OsString::from("az")),
    ));
    let cli_probe = broker.probe().await?;
    if !cli_probe.agent_session_attribution_active() {
        anyhow::bail!("Azure CLI agent-session attribution is unavailable");
    }
    let policy = routes::v0_policy()?;
    let schema_index = Arc::new(azmcp_core::schema::SchemaIndex::v0(&policy)?);
    let clients: Arc<dyn HttpClientFactory> =
        Arc::new(ReviewedHttpClientFactory::new(broker, policy.clone()));
    let audit: Arc<dyn AuditSink> = Arc::new(FileAuditLog::new(audit_config()?));
    let validator = Arc::new(
        HttpBindingValidator::new(Arc::clone(&clients)).with_audit_sink(
            Arc::clone(&audit),
            routes::V0_POLICY_HASH,
            policy.version(),
        ),
    );
    let application = Application::from_arcs_with_host_clients_and_schema(
        config,
        default_registry()?,
        Arc::new(profile),
        validator,
        Arc::new(worker),
        clients,
        schema_index,
        routes::V0_POLICY_HASH,
        policy.version(),
    )?
    .with_audit_sink(audit)
    .with_artifact_store(artifact_store);
    Ok(application)
}

fn artifact_root(config: &Config) -> anyhow::Result<PathBuf> {
    if let Some(root) = config.artifacts().root() {
        return Ok(root.to_path_buf());
    }
    if let Some(root) = nonempty_env_path("XDG_DATA_HOME")? {
        return Ok(root.join("azmcp/artifacts"));
    }
    Ok(home_dir()?.join(".local/share/azmcp/artifacts"))
}

fn audit_config() -> anyhow::Result<FileAuditConfig> {
    let path = if let Some(path) = nonempty_env_path("AZMCP_AUDIT_LOG")? {
        path
    } else if let Some(root) = nonempty_env_path("XDG_STATE_HOME")? {
        root.join("azmcp/requests.jsonl")
    } else {
        home_dir()?.join(".local/state/azmcp/requests.jsonl")
    };
    FileAuditConfig::new(
        path,
        positive_env_number("AZMCP_AUDIT_MAX_BYTES", DEFAULT_MAX_AUDIT_BYTES)?,
        positive_env_number("AZMCP_AUDIT_RETAINED_FILES", DEFAULT_RETAINED_AUDIT_FILES)?,
    )
    .map_err(Into::into)
}

async fn load_config() -> anyhow::Result<Config> {
    let path = config_path()?;
    match tokio::fs::read_to_string(&path).await {
        Ok(contents) => Config::from_toml(&contents).map_err(Into::into),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Config::empty()),
        Err(error) => Err(error.into()),
    }
}

fn config_path() -> anyhow::Result<PathBuf> {
    if let Some(path) = nonempty_env_path("AZMCP_CONFIG")? {
        return Ok(path);
    }
    if let Some(root) = nonempty_env_path("XDG_CONFIG_HOME")? {
        return Ok(root.join("azmcp/config.toml"));
    }
    Ok(home_dir()?.join(".config/azmcp/config.toml"))
}

fn azure_profile_path() -> anyhow::Result<PathBuf> {
    if let Some(path) = nonempty_env_path("AZMCP_AZURE_PROFILE")? {
        return Ok(path);
    }
    if let Some(root) = nonempty_env_path("AZURE_CONFIG_DIR")? {
        return Ok(root.join("azureProfile.json"));
    }
    Ok(home_dir()?.join(".azure/azureProfile.json"))
}

fn home_dir() -> anyhow::Result<PathBuf> {
    nonempty_env_path("HOME")?.ok_or_else(|| anyhow::anyhow!("HOME is not set"))
}

fn nonempty_env_path(name: &'static str) -> anyhow::Result<Option<PathBuf>> {
    match std::env::var_os(name) {
        None => Ok(None),
        Some(value) if value.is_empty() => Err(anyhow::anyhow!("{name} must not be empty")),
        Some(value) => Ok(Some(PathBuf::from(value))),
    }
}

fn positive_env_number<T>(name: &'static str, default: T) -> anyhow::Result<T>
where
    T: std::str::FromStr + Copy,
{
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|_| anyhow::anyhow!("{name} must be a positive integer")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(anyhow::anyhow!("{name} must contain Unicode text"))
        }
    }
}
