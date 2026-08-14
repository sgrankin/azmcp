//! Context-owned storage for bounded large-result references.
//!
//! A reference is an opaque capability to one immutable JSON value. The
//! application materializes bounded worker candidates here and exposes only a
//! structural envelope at the MCP boundary. Rehydration is mediated by the
//! worker protocol, so a token is useful only to its owning context.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    time::{Duration, Instant},
};

use serde_json::Value;

/// Number of random bytes used to construct a reference identifier.
pub const REF_ID_BYTES: usize = 32;
/// Prefix used to distinguish reference identifiers from ordinary strings.
pub const REF_ID_PREFIX: &str = "ref_";

/// Default lifetime for one stored reference.
pub const DEFAULT_REF_TTL: Duration = Duration::from_secs(5 * 60);
/// Default number of references retained by one context.
pub const DEFAULT_REF_MAX_ENTRIES: usize = 32;
/// Default aggregate encoded-byte budget for one context's references.
pub const DEFAULT_REF_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Default encoded-byte budget for one reference value. This stays below the
/// worker's 512 KiB parent-input ceiling, leaving room for protocol framing.
pub const DEFAULT_REF_MAX_VALUE_BYTES: usize = 480 * 1024;
/// Default encoded-byte budget for one bounded read.
pub const DEFAULT_REF_MAX_READ_BYTES: usize = 480 * 1024;

/// Hard upper bound for a context's reference count.
pub const MAX_REF_ENTRIES: usize = 256;
/// Hard upper bound for a context's aggregate reference storage.
pub const MAX_REF_BYTES: usize = 16 * 1024 * 1024;
/// Hard upper bound for one stored reference value. Keep this aligned with the
/// bounded worker candidate and rehydration protocol.
pub const MAX_REF_VALUE_BYTES: usize = 480 * 1024;
/// Hard upper bound for one reference read.
pub const MAX_REF_READ_BYTES: usize = 480 * 1024;
/// Hard upper bound for a reference lifetime.
pub const MAX_REF_TTL: Duration = Duration::from_secs(30 * 60);

/// An opaque, random reference capability.
///
/// The actual token is available only through [`RefId::as_str`], which is an
/// explicit handoff for the worker rehydration protocol. Formatting an ID for
/// diagnostics never emits that token.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct RefId(String);

impl RefId {
    /// Parse an opaque reference token received from the worker ref bridge.
    pub fn parse(value: &str) -> Result<Self, InvalidRefId> {
        let expected_bytes = REF_ID_PREFIX.len() + REF_ID_BYTES * 2;
        if value.len() != expected_bytes || !value.starts_with(REF_ID_PREFIX) {
            return Err(InvalidRefId);
        }
        if value[REF_ID_PREFIX.len()..]
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(InvalidRefId);
        }
        Ok(Self(value.to_owned()))
    }

    /// Return the opaque token for the explicit worker ref handoff.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn generate() -> Result<Self, RefStoreError> {
        let mut bytes = [0_u8; REF_ID_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| RefStoreError::RandomId)?;
        let mut value = String::with_capacity(REF_ID_PREFIX.len() + REF_ID_BYTES * 2);
        value.push_str(REF_ID_PREFIX);
        for byte in bytes {
            value.push_str(&format!("{byte:02x}"));
        }
        Ok(Self(value))
    }
}

impl AsRef<str> for RefId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for RefId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RefId(<redacted>)")
    }
}

impl fmt::Display for RefId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-ref-id>")
    }
}

/// A malformed or non-canonical reference token.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid reference id")]
pub struct InvalidRefId;

/// Bounded storage controls for one context's references.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RefStoreLimits {
    /// Maximum number of retained reference values.
    pub max_entries: usize,
    /// Maximum aggregate encoded size of retained values.
    pub max_bytes: usize,
    /// Lifetime of a retained value from insertion.
    pub ttl: Duration,
    /// Maximum encoded size of one inserted value.
    pub max_value_bytes: usize,
    /// Maximum encoded size permitted for one read.
    pub max_read_bytes: usize,
}

impl RefStoreLimits {
    /// Construct explicit bounded reference controls.
    pub const fn new(
        max_entries: usize,
        max_bytes: usize,
        ttl: Duration,
        max_value_bytes: usize,
        max_read_bytes: usize,
    ) -> Self {
        Self {
            max_entries,
            max_bytes,
            ttl,
            max_value_bytes,
            max_read_bytes,
        }
    }

    fn validate(self) -> Result<Self, RefStoreError> {
        if self.max_entries == 0 || self.max_entries > MAX_REF_ENTRIES {
            return Err(RefStoreError::InvalidLimits {
                field: "reference entry limit",
            });
        }
        if self.max_bytes == 0 || self.max_bytes > MAX_REF_BYTES {
            return Err(RefStoreError::InvalidLimits {
                field: "reference byte limit",
            });
        }
        if self.ttl.is_zero() || self.ttl > MAX_REF_TTL {
            return Err(RefStoreError::InvalidLimits {
                field: "reference TTL",
            });
        }
        if self.max_value_bytes == 0
            || self.max_value_bytes > MAX_REF_VALUE_BYTES
            || self.max_value_bytes > self.max_bytes
        {
            return Err(RefStoreError::InvalidLimits {
                field: "reference value limit",
            });
        }
        if self.max_read_bytes == 0
            || self.max_read_bytes > MAX_REF_READ_BYTES
            || self.max_read_bytes > self.max_value_bytes
        {
            return Err(RefStoreError::InvalidLimits {
                field: "reference read limit",
            });
        }
        Ok(self)
    }
}

impl Default for RefStoreLimits {
    fn default() -> Self {
        Self::new(
            DEFAULT_REF_MAX_ENTRIES,
            DEFAULT_REF_MAX_BYTES,
            DEFAULT_REF_TTL,
            DEFAULT_REF_MAX_VALUE_BYTES,
            DEFAULT_REF_MAX_READ_BYTES,
        )
    }
}

struct StoredRef {
    value: Value,
    encoded_bytes: usize,
    expires_at: Instant,
}

/// Context-scoped, FIFO-evicting reference storage.
pub struct RefStore {
    limits: RefStoreLimits,
    entries: HashMap<RefId, StoredRef>,
    order: VecDeque<RefId>,
    bytes: usize,
}

impl RefStore {
    /// Construct an empty store after validating every bound.
    pub fn new(limits: RefStoreLimits) -> Result<Self, RefStoreError> {
        let limits = limits.validate()?;
        Ok(Self {
            limits,
            entries: HashMap::new(),
            order: VecDeque::new(),
            bytes: 0,
        })
    }

    /// Construct an empty store using the conservative defaults.
    pub fn with_defaults() -> Self {
        Self::new(RefStoreLimits::default()).expect("default reference limits are valid")
    }

    /// Store one immutable JSON value and return its opaque capability.
    pub fn put(&mut self, value: Value, now: Instant) -> Result<RefId, RefStoreError> {
        let encoded_bytes = serde_json::to_vec(&value)
            .map_err(|_| RefStoreError::UnserializableValue)?
            .len();
        if encoded_bytes > self.limits.max_value_bytes {
            return Err(RefStoreError::ValueTooLarge {
                bytes: encoded_bytes,
                limit: self.limits.max_value_bytes,
            });
        }

        self.evict_expired(now);
        while self.entries.len() >= self.limits.max_entries
            || self.bytes.saturating_add(encoded_bytes) > self.limits.max_bytes
        {
            if !self.evict_oldest() {
                return Err(RefStoreError::Capacity);
            }
        }

        let id = self.unique_id()?;
        let expires_at = now
            .checked_add(self.limits.ttl)
            .unwrap_or_else(Instant::now);
        self.bytes = self.bytes.saturating_add(encoded_bytes);
        self.order.push_back(id.clone());
        self.entries.insert(
            id.clone(),
            StoredRef {
                value,
                encoded_bytes,
                expires_at,
            },
        );
        Ok(id)
    }

    /// Read a stored value using the store's maximum read bound.
    pub fn get(&mut self, id: &RefId, now: Instant) -> Result<Value, RefStoreError> {
        self.read(id, self.limits.max_read_bytes, now)
    }

    /// Read one value only when its encoded size fits the caller's bound.
    pub fn read(
        &mut self,
        id: &RefId,
        max_bytes: usize,
        now: Instant,
    ) -> Result<Value, RefStoreError> {
        if max_bytes == 0 || max_bytes > self.limits.max_read_bytes {
            return Err(RefStoreError::InvalidReadLimit {
                limit: self.limits.max_read_bytes,
            });
        }
        let expired = self
            .entries
            .get(id)
            .is_some_and(|entry| entry.expires_at <= now);
        self.evict_expired(now);
        if expired {
            return Err(RefStoreError::Expired);
        }
        let entry = self.entries.get(id).ok_or(RefStoreError::NotFound)?;
        if entry.encoded_bytes > max_bytes {
            return Err(RefStoreError::ReadTooLarge {
                bytes: entry.encoded_bytes,
                limit: max_bytes,
            });
        }
        Ok(entry.value.clone())
    }

    /// Remove expired values and return the number removed.
    pub fn evict_expired(&mut self, now: Instant) -> usize {
        let expired = self
            .entries
            .iter()
            .filter_map(|(id, entry)| (entry.expires_at <= now).then_some(id.clone()))
            .collect::<Vec<_>>();
        let removed = expired.len();
        for id in expired {
            self.remove(&id);
        }
        removed
    }

    /// Return the earliest expiry among retained values.
    pub fn next_expiry(&self) -> Option<Instant> {
        self.entries.values().map(|entry| entry.expires_at).min()
    }

    #[cfg(test)]
    fn fifo_metadata_len(&self) -> usize {
        self.order.len()
    }

    /// Number of retained values. Expired values are removed when an operation
    /// observes them; call [`Self::evict_expired`] to sweep proactively.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no values are currently retained.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Aggregate encoded size of currently retained values.
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// Validated limits used by this store.
    pub const fn limits(&self) -> RefStoreLimits {
        self.limits
    }

    /// Dispose every retained value without changing the configured limits.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
        self.bytes = 0;
    }

    fn unique_id(&self) -> Result<RefId, RefStoreError> {
        for _ in 0..4 {
            let id = RefId::generate()?;
            if !self.entries.contains_key(&id) {
                return Ok(id);
            }
        }
        Err(RefStoreError::RandomId)
    }

    fn evict_oldest(&mut self) -> bool {
        while let Some(id) = self.order.pop_front() {
            if self.remove(&id).is_some() {
                return true;
            }
        }
        false
    }

    fn remove(&mut self, id: &RefId) -> Option<StoredRef> {
        let entry = self.entries.remove(id)?;
        self.order.retain(|queued| queued != id);
        self.bytes = self.bytes.saturating_sub(entry.encoded_bytes);
        Some(entry)
    }
}

impl Default for RefStore {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl fmt::Debug for RefStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RefStore")
            .field("limits", &self.limits)
            .field("entries", &self.entries.len())
            .field("bytes", &self.bytes)
            .finish()
    }
}

/// Errors from creating, storing, evicting, or reading references.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RefStoreError {
    /// A configured bound was zero, inconsistent, or above its hard cap.
    #[error("invalid reference store limit: {field}")]
    InvalidLimits { field: &'static str },
    /// A JSON value could not be encoded for size accounting.
    #[error("reference value is not serializable")]
    UnserializableValue,
    /// One value exceeded the configured per-value bound.
    #[error("reference value exceeds the {limit}-byte limit ({bytes} bytes)")]
    ValueTooLarge { bytes: usize, limit: usize },
    /// The configured entry or aggregate byte budget could not admit a value.
    #[error("reference store capacity is exhausted")]
    Capacity,
    /// The random source did not produce a reference ID.
    #[error("reference ID generation failed")]
    RandomId,
    /// The requested reference is absent or has already been evicted.
    #[error("reference was not found")]
    NotFound,
    /// The requested reference expired before it was read.
    #[error("reference expired")]
    Expired,
    /// A requested read exceeded the store's configured read bound.
    #[error("reference read limit is {limit} bytes")]
    InvalidReadLimit { limit: usize },
    /// The stored value is larger than the caller's read bound.
    #[error("reference value exceeds the read limit of {limit} bytes ({bytes} bytes)")]
    ReadTooLarge { bytes: usize, limit: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> RefStoreLimits {
        RefStoreLimits::new(2, 64, Duration::from_secs(10), 48, 32)
    }

    #[test]
    fn references_are_opaque_and_redacted_in_formatting() {
        let mut store = RefStore::new(limits()).expect("limits");
        let id = store
            .put(serde_json::json!({"value": "private"}), Instant::now())
            .expect("reference");
        assert!(id.as_str().starts_with(REF_ID_PREFIX));
        assert_eq!(id.as_str().len(), REF_ID_PREFIX.len() + REF_ID_BYTES * 2);
        assert!(!format!("{id:?}").contains(id.as_str()));
        assert!(!format!("{id}").contains(id.as_str()));
        assert!(!format!("{store:?}").contains(id.as_str()));
        assert!(RefId::parse(id.as_str()).is_ok());
        assert!(RefId::parse("ref_not-a-reference").is_err());
    }

    #[test]
    fn values_are_isolated_between_stores() {
        let now = Instant::now();
        let mut first = RefStore::new(limits()).expect("limits");
        let id = first.put(serde_json::json!([1, 2, 3]), now).expect("ref");
        let mut second = RefStore::new(limits()).expect("limits");
        assert_eq!(second.get(&id, now), Err(RefStoreError::NotFound));
        drop(first);
        assert_eq!(second.get(&id, now), Err(RefStoreError::NotFound));
    }

    #[test]
    fn ttl_and_capacity_evict_values_without_unbounded_growth() {
        let now = Instant::now();
        let mut store = RefStore::new(limits()).expect("limits");
        let first = store.put(serde_json::json!("first"), now).expect("ref");
        assert_eq!(store.len(), 1);
        assert_eq!(
            store.get(&first, now + Duration::from_secs(10)),
            Err(RefStoreError::Expired)
        );
        assert!(store.is_empty());
        assert_eq!(store.bytes(), 0);

        let first = store.put(serde_json::json!("first"), now).expect("ref");
        let second = store.put(serde_json::json!("second"), now).expect("ref");
        let third = store.put(serde_json::json!("third"), now).expect("ref");
        assert_eq!(store.len(), 2);
        assert_eq!(store.get(&first, now), Err(RefStoreError::NotFound));
        assert_eq!(store.get(&second, now), Ok(serde_json::json!("second")));
        assert_eq!(store.get(&third, now), Ok(serde_json::json!("third")));
    }

    #[test]
    fn expired_entries_do_not_leave_fifo_metadata_behind() {
        let now = Instant::now();
        let mut store = RefStore::new(RefStoreLimits::new(4, 256, Duration::from_secs(1), 48, 48))
            .expect("limits");
        for index in 0..128 {
            store
                .put(serde_json::json!({"index": index}), now)
                .expect("reference");
            store.evict_expired(now + Duration::from_secs(2));
            assert_eq!(store.len(), 0);
            assert_eq!(store.fifo_metadata_len(), 0);
        }
    }

    #[test]
    fn aggregate_byte_budget_evicts_oldest_values() {
        let now = Instant::now();
        let limits = RefStoreLimits::new(8, 20, Duration::from_secs(10), 20, 20);
        let mut store = RefStore::new(limits).expect("limits");
        let first = store.put(serde_json::json!("123456"), now).expect("ref");
        let second = store.put(serde_json::json!("abcdef"), now).expect("ref");
        let third = store.put(serde_json::json!("ghijkl"), now).expect("ref");
        assert!(store.bytes() <= limits.max_bytes);
        assert_eq!(store.get(&first, now), Err(RefStoreError::NotFound));
        assert_eq!(store.get(&second, now), Ok(serde_json::json!("abcdef")));
        assert_eq!(store.get(&third, now), Ok(serde_json::json!("ghijkl")));
    }

    #[test]
    fn value_and_read_sizes_are_bounded() {
        let now = Instant::now();
        let mut store = RefStore::new(limits()).expect("limits");
        assert!(matches!(
            store.put(serde_json::json!("x".repeat(100)), now),
            Err(RefStoreError::ValueTooLarge { .. })
        ));
        let id = store
            .put(serde_json::json!("a".repeat(20)), now)
            .expect("ref");
        assert!(matches!(
            store.read(&id, 1, now),
            Err(RefStoreError::ReadTooLarge { .. })
        ));
        assert!(matches!(
            store.read(&id, 33, now),
            Err(RefStoreError::InvalidReadLimit { limit: 32 })
        ));
        assert_eq!(
            store.read(&id, 32, now),
            Ok(serde_json::json!("a".repeat(20)))
        );
    }

    #[test]
    fn configured_limits_have_hard_bounds() {
        for invalid in [
            RefStoreLimits::new(0, 1, Duration::from_secs(1), 1, 1),
            RefStoreLimits::new(MAX_REF_ENTRIES + 1, 1, Duration::from_secs(1), 1, 1),
            RefStoreLimits::new(1, MAX_REF_BYTES + 1, Duration::from_secs(1), 1, 1),
            RefStoreLimits::new(1, 1, Duration::ZERO, 1, 1),
            RefStoreLimits::new(1, 1, Duration::from_secs(1), 2, 1),
            RefStoreLimits::new(1, 1, Duration::from_secs(1), 1, 2),
        ] {
            assert!(matches!(
                RefStore::new(invalid),
                Err(RefStoreError::InvalidLimits { .. })
            ));
        }
    }
}
