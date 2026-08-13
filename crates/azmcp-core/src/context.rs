//! Explicit application execution contexts.
//!
//! MCP requests are independent, but the application may intentionally retain
//! state between calls.  [`ContextRegistry`] is the small state boundary for
//! that application state: each context has an opaque bearer handle, immutable
//! authority, and one active lease at a time.  This module does not execute
//! JavaScript; the lease is the boundary a future worker can use to do so.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::config::ResolvedCloudBinding;
pub use crate::policy::ArmTier;

const HANDLE_BYTES: usize = 32;
const HANDLE_LENGTH: usize = 43;
const HANDLE_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The only identity exposed by the v0 context surface.
///
/// Keeping unsupported identities out of this enum prevents them from being
/// accidentally advertised or accepted before their credential paths exist.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Identity {
    /// The explicitly selected local Azure CLI user identity.
    User,
}

/// A validated v0 context-open request.
///
/// `data_planes` is retained as an explicit input so later versions can add
/// reviewed grants without changing the context shape.  v0 accepts only an
/// empty list.  The resolved bindings and policy values are copied into the
/// opened context and cannot be changed through the registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextOptions {
    identity: Identity,
    arm_tier: ArmTier,
    data_planes: Vec<String>,
    resolved_bindings: Vec<ResolvedCloudBinding>,
    policy_hash: String,
    policy_version: String,
}

impl ContextOptions {
    /// Construct and validate the v0 context options.
    pub fn new(
        identity: Identity,
        arm_tier: ArmTier,
        data_planes: Vec<String>,
        resolved_bindings: Vec<ResolvedCloudBinding>,
        policy_hash: impl Into<String>,
        policy_version: impl Into<String>,
    ) -> Result<Self, ContextOptionsError> {
        let options = Self {
            identity,
            arm_tier,
            data_planes,
            resolved_bindings,
            policy_hash: policy_hash.into(),
            policy_version: policy_version.into(),
        };
        options.validate()?;
        Ok(options)
    }

    /// Validate the closed v0 option set.
    pub fn validate(&self) -> Result<(), ContextOptionsError> {
        if self.identity != Identity::User {
            return Err(ContextOptionsError::UnsupportedIdentity);
        }
        if self.arm_tier != ArmTier::Inspect {
            return Err(ContextOptionsError::UnsupportedArmTier);
        }
        if !self.data_planes.is_empty() {
            return Err(ContextOptionsError::DataPlanesNotSupported);
        }
        if self.policy_hash.is_empty() {
            return Err(ContextOptionsError::EmptyPolicyHash);
        }
        if self.policy_version.is_empty() {
            return Err(ContextOptionsError::EmptyPolicyVersion);
        }

        let mut clouds = HashSet::with_capacity(self.resolved_bindings.len());
        for binding in &self.resolved_bindings {
            if !clouds.insert(binding.cloud()) {
                return Err(ContextOptionsError::DuplicateCloudBinding);
            }
        }
        Ok(())
    }

    /// The selected identity.
    pub const fn identity(&self) -> Identity {
        self.identity
    }

    /// The maximum ARM capability for this context.
    pub const fn arm_tier(&self) -> ArmTier {
        self.arm_tier
    }

    /// Data-plane grants requested at open.
    pub fn data_planes(&self) -> &[String] {
        &self.data_planes
    }

    /// Resolved per-cloud bindings captured at open.
    pub fn resolved_bindings(&self) -> &[ResolvedCloudBinding] {
        &self.resolved_bindings
    }

    /// The immutable policy content hash.
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }

    /// The immutable policy bundle version.
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }
}

/// Why a context-open request is outside the implemented v0 surface.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContextOptionsError {
    /// v0 authenticates through the selected Azure CLI user only.
    #[error("v0 context identity must be user")]
    UnsupportedIdentity,
    /// v0 executes inspect-only ARM routes.
    #[error("v0 context ARM tier must be inspect")]
    UnsupportedArmTier,
    /// v0 has no data-plane capability grants.
    #[error("v0 context data planes must be empty")]
    DataPlanesNotSupported,
    /// Audit records require a policy content hash.
    #[error("context policy hash must not be empty")]
    EmptyPolicyHash,
    /// Audit records require a policy bundle version.
    #[error("context policy version must not be empty")]
    EmptyPolicyVersion,
    /// A context may contain at most one resolved binding per cloud.
    #[error("context cannot contain duplicate cloud bindings")]
    DuplicateCloudBinding,
}

/// Limits and expiry policy for a [`ContextRegistry`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryConfig {
    /// Maximum number of retained contexts, including busy contexts.
    pub max_contexts: usize,
    /// Duration after the last successful lease before idle eviction.
    pub idle_ttl: Duration,
    /// Maximum duration after opening before absolute eviction.
    pub absolute_ttl: Duration,
}

impl RegistryConfig {
    /// Construct registry limits.  A zero TTL is valid and makes a context
    /// immediately expired, which is useful for deterministic tests and
    /// callers that intentionally disable retention.
    pub const fn new(max_contexts: usize, idle_ttl: Duration, absolute_ttl: Duration) -> Self {
        Self {
            max_contexts,
            idle_ttl,
            absolute_ttl,
        }
    }

    fn validate(self) -> Result<(), RegistryConfigError> {
        if self.max_contexts == 0 {
            return Err(RegistryConfigError::ZeroCapacity);
        }
        Ok(())
    }
}

/// A malformed registry configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RegistryConfigError {
    /// A zero-sized registry could never open a context.
    #[error("context registry capacity must be greater than zero")]
    ZeroCapacity,
}

/// An opaque, cryptographically random context bearer handle.
///
/// Handles contain 256 bits of randomness and use unpadded base64url
/// characters only.  The `Debug` representation is redacted so accidental
/// diagnostics do not copy a bearer capability into logs.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContextId(String);

impl ContextId {
    /// Parse a handle received from a caller.
    pub fn parse(value: impl AsRef<str>) -> Result<Self, InvalidContextId> {
        let value = value.as_ref();
        if value.len() != HANDLE_LENGTH
            || !value.bytes().all(|byte| HANDLE_ALPHABET.contains(&byte))
        {
            return Err(InvalidContextId);
        }
        Ok(Self(value.to_owned()))
    }

    /// Return the bearer value for an explicit protocol response.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn generate() -> Result<Self, ContextRegistryError> {
        let mut bytes = [0_u8; HANDLE_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| ContextRegistryError::RandomHandle)?;
        Ok(Self(encode_handle(&bytes)))
    }
}

impl AsRef<str> for ContextId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ContextId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Debug for ContextId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContextId(<redacted>)")
    }
}

/// A malformed context handle supplied to a parser or deserializer.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("invalid context handle")]
pub struct InvalidContextId;

/// The immutable state retained for one application context.
///
/// Lifecycle timestamps are updated by the registry when a lease is acquired;
/// authority fields are copied at open and never changed afterward.
#[derive(Clone, Eq, PartialEq)]
pub struct Context {
    id: ContextId,
    identity: Identity,
    arm_tier: ArmTier,
    data_planes: Vec<String>,
    resolved_bindings: Vec<ResolvedCloudBinding>,
    policy_hash: String,
    policy_version: String,
    created_at: Instant,
    last_used_at: Instant,
    absolute_expires_at: Instant,
    idle_expires_at: Instant,
}

impl Context {
    /// The opaque handle used on each subsequent application call.
    pub fn id(&self) -> &ContextId {
        &self.id
    }

    /// The identity fixed at open.
    pub const fn identity(&self) -> Identity {
        self.identity
    }

    /// The ARM capability fixed at open.
    pub const fn arm_tier(&self) -> ArmTier {
        self.arm_tier
    }

    /// The data-plane grants fixed at open.  This is empty for every v0
    /// context.
    pub fn data_planes(&self) -> &[String] {
        &self.data_planes
    }

    /// The resolved cloud bindings fixed at open.
    pub fn resolved_bindings(&self) -> &[ResolvedCloudBinding] {
        &self.resolved_bindings
    }

    /// The policy content hash fixed at open.
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }

    /// The policy bundle version fixed at open.
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    /// Time at which the context was opened.
    pub const fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Time of the last successful lease acquisition.
    pub const fn last_used_at(&self) -> Instant {
        self.last_used_at
    }

    /// Absolute deadline, which never moves after open.
    pub const fn absolute_expires_at(&self) -> Instant {
        self.absolute_expires_at
    }

    /// Idle deadline, refreshed by a successful lease acquisition.
    pub const fn idle_expires_at(&self) -> Instant {
        self.idle_expires_at
    }

    /// The earlier of the idle and absolute deadlines.
    pub fn expires_at(&self) -> Instant {
        if self.idle_expires_at < self.absolute_expires_at {
            self.idle_expires_at
        } else {
            self.absolute_expires_at
        }
    }

    /// Whether the supplied clock instant is at or beyond either deadline.
    fn is_expired(&self, now: Instant) -> bool {
        now >= self.absolute_expires_at || now >= self.idle_expires_at
    }
}

impl fmt::Debug for Context {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Context")
            .field("id", &"<redacted>")
            .field("identity", &self.identity)
            .field("arm_tier", &self.arm_tier)
            .field("data_planes", &self.data_planes)
            .field("resolved_bindings", &self.resolved_bindings)
            .field("policy_hash", &self.policy_hash)
            .field("policy_version", &self.policy_version)
            .field("created_at", &self.created_at)
            .field("last_used_at", &self.last_used_at)
            .field("absolute_expires_at", &self.absolute_expires_at)
            .field("idle_expires_at", &self.idle_expires_at)
            .finish()
    }
}

struct ContextEntry {
    context: Context,
    busy: bool,
}

struct RegistryState {
    contexts: HashMap<String, ContextEntry>,
    evicted_handles: VecDeque<String>,
}

impl RegistryState {
    fn new() -> Self {
        Self {
            contexts: HashMap::new(),
            evicted_handles: VecDeque::new(),
        }
    }
}

struct RegistryInner {
    config: RegistryConfig,
    state: Mutex<RegistryState>,
}

/// Thread-safe registry of bounded, explicitly leased application contexts.
#[derive(Clone)]
pub struct ContextRegistry {
    inner: Arc<RegistryInner>,
}

impl ContextRegistry {
    /// Create an empty registry with fixed capacity and expiry policy.
    pub fn new(config: RegistryConfig) -> Result<Self, ContextRegistryError> {
        config
            .validate()
            .map_err(ContextRegistryError::InvalidConfig)?;
        Ok(Self {
            inner: Arc::new(RegistryInner {
                config,
                state: Mutex::new(RegistryState::new()),
            }),
        })
    }

    /// Open a context at an explicit clock instant.
    pub fn open(
        &self,
        options: ContextOptions,
        now: Instant,
    ) -> Result<Context, ContextRegistryError> {
        options
            .validate()
            .map_err(ContextRegistryError::InvalidOptions)?;

        let mut state = self.lock_state();
        evict_expired_locked(&self.inner.config, &mut state, now);
        if state.contexts.len() >= self.inner.config.max_contexts {
            return Err(ContextRegistryError::Capacity);
        }

        let id = loop {
            let candidate = ContextId::generate()?;
            if !state.contexts.contains_key(candidate.as_str()) {
                break candidate;
            }
        };
        let context = Context {
            id: id.clone(),
            identity: options.identity,
            arm_tier: options.arm_tier,
            data_planes: options.data_planes,
            resolved_bindings: options.resolved_bindings,
            policy_hash: options.policy_hash,
            policy_version: options.policy_version,
            created_at: now,
            last_used_at: now,
            absolute_expires_at: deadline(now, self.inner.config.absolute_ttl),
            idle_expires_at: deadline(now, self.inner.config.idle_ttl),
        };
        state.contexts.insert(
            id.0.clone(),
            ContextEntry {
                context: context.clone(),
                busy: false,
            },
        );
        Ok(context)
    }

    /// Acquire the exclusive lease for a context at an explicit clock instant.
    ///
    /// The returned guard releases the busy state in `Drop`, so callers do not
    /// need a cancellation or panic cleanup path of their own.
    pub fn lease<H: AsRef<str>>(
        &self,
        handle: H,
        now: Instant,
    ) -> Result<ContextLease, ContextRegistryError> {
        let handle = handle.as_ref();
        let mut state = self.lock_state();
        if !state.contexts.contains_key(handle) {
            return if state.evicted_handles.iter().any(|known| known == handle) {
                Err(ContextRegistryError::ContextEvicted)
            } else {
                Err(ContextRegistryError::NotFound)
            };
        }
        let entry = state
            .contexts
            .get_mut(handle)
            .expect("context presence checked above");

        if entry.busy {
            return Err(ContextRegistryError::ContextBusy);
        }
        if entry.context.is_expired(now) {
            state.contexts.remove(handle);
            remember_evicted(&self.inner.config, &mut state, handle);
            return Err(ContextRegistryError::ContextEvicted);
        }

        entry.busy = true;
        if now >= entry.context.last_used_at {
            entry.context.last_used_at = now;
            entry.context.idle_expires_at = deadline(now, self.inner.config.idle_ttl);
        }
        Ok(ContextLease {
            registry: self.clone(),
            handle: entry.context.id.clone(),
            context: entry.context.clone(),
            released: false,
        })
    }

    /// Execute one synchronous operation while holding the exclusive lease.
    ///
    /// If `operation` panics, normal Rust unwinding still drops the lease and
    /// makes a later acquisition possible.
    pub fn execute<H, F, R>(
        &self,
        handle: H,
        now: Instant,
        operation: F,
    ) -> Result<R, ContextRegistryError>
    where
        H: AsRef<str>,
        F: FnOnce(&Context) -> R,
    {
        let lease = self.lease(handle, now)?;
        Ok(operation(lease.context()))
    }

    /// Close and dispose a context immediately, even if it is currently busy.
    pub fn close<H: AsRef<str>>(&self, handle: H) -> Result<(), ContextRegistryError> {
        let handle = handle.as_ref();
        let mut state = self.lock_state();
        if state.contexts.remove(handle).is_some() {
            Ok(())
        } else if state.evicted_handles.iter().any(|known| known == handle) {
            Err(ContextRegistryError::ContextEvicted)
        } else {
            Err(ContextRegistryError::NotFound)
        }
    }

    /// Remove every idle or absolutely expired, non-busy context.
    ///
    /// A busy lease protects its context until it is released.  This avoids
    /// invalidating an in-flight worker operation; the next acquisition then
    /// observes the expiry and evicts it before returning.
    pub fn evict_expired(&self, now: Instant) -> usize {
        let mut state = self.lock_state();
        evict_expired_locked(&self.inner.config, &mut state, now)
    }

    fn lock_state(&self) -> MutexGuard<'_, RegistryState> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn release(&self, handle: &str) {
        let mut state = self.lock_state();
        if let Some(entry) = state.contexts.get_mut(handle) {
            entry.busy = false;
        }
    }
}

/// An exclusive RAII lease over one context.
pub struct ContextLease {
    registry: ContextRegistry,
    handle: ContextId,
    context: Context,
    released: bool,
}

impl ContextLease {
    /// The immutable context snapshot associated with this lease.
    pub fn context(&self) -> &Context {
        &self.context
    }

    /// Explicitly release the lease now.  Dropping an unreleased lease has
    /// exactly the same effect.
    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if !self.released {
            self.registry.release(self.handle.as_str());
            self.released = true;
        }
    }
}

impl fmt::Debug for ContextLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextLease")
            .field("context", &self.context)
            .field("released", &self.released)
            .finish()
    }
}

impl Drop for ContextLease {
    fn drop(&mut self) {
        self.release_inner();
    }
}

/// Errors from opening, looking up, leasing, and closing contexts.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContextRegistryError {
    /// The registry configuration cannot retain any contexts.
    #[error("invalid context registry configuration: {0}")]
    InvalidConfig(RegistryConfigError),
    /// The requested v0 authority is not implemented.
    #[error("invalid v0 context options: {0}")]
    InvalidOptions(ContextOptionsError),
    /// No slot is available after expired contexts were removed.
    #[error("context registry is at capacity")]
    Capacity,
    /// The handle is not retained and has not been identified as evicted.
    #[error("context was not found")]
    NotFound,
    /// The handle was removed because its idle or absolute deadline elapsed.
    #[error("context was evicted")]
    ContextEvicted,
    /// Another lease currently owns the context's single execution turn.
    #[error("context is busy")]
    ContextBusy,
    /// The operating system rejected entropy acquisition for a new handle.
    #[error("failed to generate cryptographically random context handle")]
    RandomHandle,
}

fn deadline(now: Instant, duration: Duration) -> Instant {
    now.checked_add(duration).unwrap_or(now)
}

fn evict_expired_locked(config: &RegistryConfig, state: &mut RegistryState, now: Instant) -> usize {
    let expired = state
        .contexts
        .iter()
        .filter_map(|(handle, entry)| {
            (!entry.busy && entry.context.is_expired(now)).then_some(handle.clone())
        })
        .collect::<Vec<_>>();
    let count = expired.len();
    for handle in expired {
        state.contexts.remove(&handle);
        remember_evicted(config, state, &handle);
    }
    count
}

fn remember_evicted(config: &RegistryConfig, state: &mut RegistryState, handle: &str) {
    if state.evicted_handles.iter().any(|known| known == handle) {
        return;
    }
    while state.evicted_handles.len() >= config.max_contexts {
        state.evicted_handles.pop_front();
    }
    state.evicted_handles.push_back(handle.to_owned());
}

fn encode_handle(bytes: &[u8; HANDLE_BYTES]) -> String {
    let mut encoded = String::with_capacity(HANDLE_LENGTH);
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in bytes {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            encoded.push(HANDLE_ALPHABET[((accumulator >> bits) & 0x3f) as usize] as char);
        }
    }
    if bits > 0 {
        encoded.push(HANDLE_ALPHABET[((accumulator << (6 - bits)) & 0x3f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::AzureCloud;
    use crate::config::{CloudBinding, SubscriptionId, TenantId};

    const SUBSCRIPTION: &str = "11111111-1111-1111-1111-111111111111";
    const TENANT: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

    fn options() -> ContextOptions {
        let binding = CloudBinding::new(
            SubscriptionId::new(SUBSCRIPTION).expect("valid subscription"),
            Some(TenantId::new(TENANT).expect("valid tenant")),
        )
        .resolve(AzureCloud::AzureCloud, &[])
        .expect("resolved binding");
        ContextOptions::new(
            Identity::User,
            ArmTier::Inspect,
            Vec::new(),
            vec![binding],
            "sha256:test",
            "policy-v0",
        )
        .expect("valid v0 options")
    }

    fn registry(
        max_contexts: usize,
        idle_ttl: Duration,
        absolute_ttl: Duration,
    ) -> ContextRegistry {
        ContextRegistry::new(RegistryConfig::new(max_contexts, idle_ttl, absolute_ttl))
            .expect("valid registry limits")
    }

    #[test]
    fn open_captures_immutable_authority_and_expiry_values() {
        let now = Instant::now();
        let registry = registry(2, Duration::from_secs(10), Duration::from_secs(60));
        let context = registry.open(options(), now).expect("context opens");

        assert_eq!(context.identity(), Identity::User);
        assert_eq!(context.arm_tier(), ArmTier::Inspect);
        assert!(context.data_planes().is_empty());
        assert_eq!(context.resolved_bindings().len(), 1);
        assert_eq!(context.policy_hash(), "sha256:test");
        assert_eq!(context.policy_version(), "policy-v0");
        assert_eq!(context.created_at(), now);
        assert_eq!(context.last_used_at(), now);
        assert_eq!(context.idle_expires_at(), now + Duration::from_secs(10));
        assert_eq!(context.absolute_expires_at(), now + Duration::from_secs(60));
    }

    #[test]
    fn registry_enforces_fixed_capacity() {
        let now = Instant::now();
        let registry = registry(1, Duration::from_secs(30), Duration::from_secs(60));
        registry.open(options(), now).expect("first context opens");
        assert_eq!(
            registry.open(options(), now).expect_err("cap applies"),
            ContextRegistryError::Capacity
        );
    }

    #[test]
    fn lease_is_exclusive_and_drop_releases_it() {
        let now = Instant::now();
        let registry = registry(1, Duration::from_secs(30), Duration::from_secs(60));
        let context = registry.open(options(), now).expect("context opens");
        let lease = registry.lease(context.id(), now).expect("first lease");
        assert_eq!(
            registry
                .lease(context.id(), now)
                .expect_err("second lease is busy"),
            ContextRegistryError::ContextBusy
        );
        drop(lease);
        let _second = registry.lease(context.id(), now).expect("drop releases");
    }

    #[test]
    fn execute_releases_after_panic() {
        let now = Instant::now();
        let registry = registry(1, Duration::from_secs(30), Duration::from_secs(60));
        let context = registry.open(options(), now).expect("context opens");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            registry
                .execute(context.id(), now, |_| -> () { panic!("test panic") })
                .expect("lease acquired");
        }));
        assert!(result.is_err());
        registry
            .lease(context.id(), now)
            .expect("panic dropped the lease");
    }

    #[test]
    fn close_disposes_even_a_busy_context() {
        let now = Instant::now();
        let registry = registry(1, Duration::from_secs(30), Duration::from_secs(60));
        let context = registry.open(options(), now).expect("context opens");
        let lease = registry.lease(context.id(), now).expect("lease acquired");
        registry.close(context.id()).expect("close is immediate");
        assert_eq!(
            registry
                .lease(context.id(), now)
                .expect_err("closed context is gone"),
            ContextRegistryError::NotFound
        );
        drop(lease);
    }

    #[test]
    fn idle_expiry_is_refreshed_by_lease_and_then_evicted() {
        let start = Instant::now();
        let registry = registry(1, Duration::from_secs(10), Duration::from_secs(60));
        let context = registry.open(options(), start).expect("context opens");
        let touch = start + Duration::from_secs(9);
        drop(registry.lease(context.id(), touch).expect("touch lease"));
        assert_eq!(registry.evict_expired(start + Duration::from_secs(18)), 0);
        assert_eq!(registry.evict_expired(start + Duration::from_secs(19)), 1);
        assert_eq!(
            registry
                .lease(context.id(), start + Duration::from_secs(19))
                .expect_err("idle context is evicted"),
            ContextRegistryError::ContextEvicted
        );
    }

    #[test]
    fn absolute_expiry_wins_over_idle_refresh() {
        let start = Instant::now();
        let registry = registry(1, Duration::from_secs(100), Duration::from_secs(10));
        let context = registry.open(options(), start).expect("context opens");
        drop(
            registry
                .lease(context.id(), start + Duration::from_secs(9))
                .expect("touch lease"),
        );
        assert_eq!(registry.evict_expired(start + Duration::from_secs(10)), 1);
        assert_eq!(
            registry
                .lease(context.id(), start + Duration::from_secs(10))
                .expect_err("absolute expiry is fixed"),
            ContextRegistryError::ContextEvicted
        );
    }

    #[test]
    fn generated_handles_are_random_and_url_safe() {
        let now = Instant::now();
        let registry = registry(2, Duration::from_secs(30), Duration::from_secs(60));
        let first = registry.open(options(), now).expect("first context");
        let second = registry.open(options(), now).expect("second context");
        assert_ne!(first.id(), second.id());
        for id in [first.id(), second.id()] {
            assert_eq!(id.as_str().len(), HANDLE_LENGTH);
            assert!(
                id.as_str()
                    .bytes()
                    .all(|byte| HANDLE_ALPHABET.contains(&byte))
            );
            assert_eq!(
                ContextId::parse(id.as_str()).expect("generated handle"),
                *id
            );
        }
    }

    #[test]
    fn v0_options_reject_later_identity_tier_and_data_planes() {
        let binding = options().resolved_bindings().to_vec();
        assert_eq!(
            ContextOptions::new(
                Identity::User,
                ArmTier::Read,
                Vec::new(),
                binding.clone(),
                "hash",
                "version",
            )
            .expect_err("read is not v0"),
            ContextOptionsError::UnsupportedArmTier
        );
        assert_eq!(
            ContextOptions::new(
                Identity::User,
                ArmTier::Inspect,
                vec!["logs.query".to_owned()],
                binding,
                "hash",
                "version",
            )
            .expect_err("data planes are not v0"),
            ContextOptionsError::DataPlanesNotSupported
        );
    }

    #[test]
    fn errors_do_not_include_bearer_handle() {
        let now = Instant::now();
        let registry = registry(1, Duration::from_secs(30), Duration::from_secs(60));
        let context = registry.open(options(), now).expect("context opens");
        let error = registry
            .lease(context.id(), now + Duration::from_secs(60))
            .expect_err("expired context");
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains(context.id().as_str()));
        assert!(!debug.contains(context.id().as_str()));
    }
}
