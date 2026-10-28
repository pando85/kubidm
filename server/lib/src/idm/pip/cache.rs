//! PIP Attribute Cache with TTL support
//!
//! This module provides caching for PIP retrieved attributes with configurable
//! time-to-live (TTL) to balance freshness with performance.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use super::{PipAttributeSet, PipId, PipSubject};

/// A cached attribute entry with timestamp
#[derive(Debug, Clone)]
struct CachedEntry {
    attributes: PipAttributeSet,
    cached_at: Instant,
    ttl: Duration,
}

impl CachedEntry {
    fn new(attributes: PipAttributeSet, ttl: Duration) -> Self {
        CachedEntry {
            attributes,
            cached_at: Instant::now(),
            ttl,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now().duration_since(self.cached_at) > self.ttl
    }

    #[cfg(test)]
    fn remaining_ttl(&self) -> Option<Duration> {
        let elapsed = Instant::now().duration_since(self.cached_at);
        if elapsed > self.ttl {
            None
        } else {
            Some(self.ttl - elapsed)
        }
    }
}

/// Cache key combining the PIP ID with every subject field that can influence
/// the query (UUID, username, email and context).
///
/// The context is a `BTreeMap`, so its ordering (and therefore the key) is
/// deterministic regardless of insertion order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CacheKey {
    pip_id: PipId,
    subject_uuid: uuid::Uuid,
    username: Option<String>,
    email: Option<String>,
    context: BTreeMap<String, String>,
}

impl CacheKey {
    fn new(pip_id: PipId, subject: &PipSubject) -> Self {
        CacheKey {
            pip_id,
            subject_uuid: subject.uuid,
            username: subject.username.clone(),
            email: subject.email.clone(),
            context: subject.context.clone(),
        }
    }
}

/// Cache statistics for monitoring
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub total_entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub expired_evictions: u64,
}

impl CacheStats {
    pub fn hit_rate(&self) -> f64 {
        if self.hits + self.misses == 0 {
            0.0
        } else {
            self.hits as f64 / (self.hits + self.misses) as f64
        }
    }
}

/// The PIP attribute cache with TTL support
#[derive(Debug)]
pub struct PipAttributeCache {
    entries: BTreeMap<CacheKey, CachedEntry>,
    default_ttl: Duration,
    stats: CacheStats,
    max_entries: usize,
}

impl PipAttributeCache {
    /// Create a new cache with default TTL
    pub fn new(default_ttl: Duration) -> Self {
        PipAttributeCache {
            entries: BTreeMap::new(),
            default_ttl,
            stats: CacheStats::default(),
            max_entries: 10000,
        }
    }

    /// Create a new cache with custom settings
    pub fn with_settings(default_ttl: Duration, max_entries: usize) -> Self {
        PipAttributeCache {
            entries: BTreeMap::new(),
            default_ttl,
            stats: CacheStats::default(),
            max_entries,
        }
    }

    /// Get cached attributes for a subject from a specific PIP
    ///
    /// Returns None if not cached or if entry is expired
    pub fn get(&mut self, pip_id: &PipId, subject: &PipSubject) -> Option<PipAttributeSet> {
        let key = CacheKey::new(pip_id.clone(), subject);

        if let Some(entry) = self.entries.get(&key) {
            if entry.is_expired() {
                self.stats.misses += 1;
                self.stats.expired_evictions += 1;
                self.entries.remove(&key);
                None
            } else {
                self.stats.hits += 1;
                Some(entry.attributes.clone())
            }
        } else {
            self.stats.misses += 1;
            None
        }
    }

    /// Store attributes in the cache
    ///
    /// If the cache is full, oldest entries are evicted
    pub fn put(&mut self, pip_id: &PipId, subject: &PipSubject, attributes: PipAttributeSet) {
        self.put_with_ttl(pip_id, subject, attributes, self.default_ttl);
    }

    /// Store attributes with a specific TTL
    pub fn put_with_ttl(
        &mut self,
        pip_id: &PipId,
        subject: &PipSubject,
        attributes: PipAttributeSet,
        ttl: Duration,
    ) {
        let key = CacheKey::new(pip_id.clone(), subject);

        if self.entries.len() >= self.max_entries {
            self.evict_oldest();
        }

        self.entries.insert(key, CachedEntry::new(attributes, ttl));
    }

    /// Remove all cached entries of a PIP for the subject's UUID, whatever
    /// username, email or context they were cached with.
    pub fn remove(&mut self, pip_id: &PipId, subject: &PipSubject) {
        let before = self.entries.len();
        self.entries
            .retain(|key, _| !(key.pip_id == *pip_id && key.subject_uuid == subject.uuid));
        let removed = before.saturating_sub(self.entries.len());
        self.stats.evictions += removed as u64;
    }

    /// Clear all cached entries
    pub fn clear(&mut self) {
        let count = self.entries.len();
        self.entries.clear();
        self.stats.evictions += count as u64;
    }

    /// Remove all expired entries
    pub fn purge_expired(&mut self) -> usize {
        let expired_keys: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.is_expired())
            .map(|(key, _)| key.clone())
            .collect();

        let count = expired_keys.len();
        for key in expired_keys {
            self.entries.remove(&key);
        }
        self.stats.expired_evictions += count as u64;
        count
    }

    /// Get cache statistics
    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }

    /// Get number of entries in cache
    pub fn size(&self) -> usize {
        self.entries.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Evict oldest entries to make room for new ones
    fn evict_oldest(&mut self) {
        if self.entries.is_empty() {
            return;
        }

        let oldest_key = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.cached_at)
            .map(|(key, _)| key.clone());

        if let Some(key) = oldest_key {
            self.entries.remove(&key);
            self.stats.evictions += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_cache_put_get() {
        let mut cache = PipAttributeCache::new(Duration::from_secs(60));
        let pip_id = PipId::new("test_pip");
        let subject = PipSubject::from_uuid(Uuid::new_v4());

        let mut attrs = PipAttributeSet::new();
        attrs.insert(
            super::super::PipAttributeName::new(&pip_id, "test_attr"),
            super::super::PipAttributeValue::String("test_value".to_string()),
        );

        cache.put(&pip_id, &subject, attrs.clone());

        let retrieved = cache.get(&pip_id, &subject);
        assert!(retrieved.is_some());
        assert_eq!(cache.stats().hits, 1);
    }

    #[test]
    fn test_cache_miss() {
        let mut cache = PipAttributeCache::new(Duration::from_secs(60));
        let pip_id = PipId::new("test_pip");
        let subject = PipSubject::from_uuid(Uuid::new_v4());

        let retrieved = cache.get(&pip_id, &subject);
        assert!(retrieved.is_none());
        assert_eq!(cache.stats().misses, 1);
    }

    #[allow(clippy::disallowed_methods)]
    #[test]
    fn test_cache_expiration() {
        let mut cache = PipAttributeCache::new(Duration::from_millis(10));
        let pip_id = PipId::new("test_pip");
        let subject = PipSubject::from_uuid(Uuid::new_v4());

        let attrs = PipAttributeSet::new();
        cache.put(&pip_id, &subject, attrs);

        std::thread::sleep(Duration::from_millis(20));

        let retrieved = cache.get(&pip_id, &subject);
        assert!(retrieved.is_none());
        assert_eq!(cache.stats().expired_evictions, 1);
    }

    #[test]
    fn test_cache_clear() {
        let mut cache = PipAttributeCache::new(Duration::from_secs(60));
        let pip_id = PipId::new("test_pip");
        let subject = PipSubject::from_uuid(Uuid::new_v4());

        cache.put(&pip_id, &subject, PipAttributeSet::new());
        assert_eq!(cache.size(), 1);

        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.stats().evictions, 1);
    }

    #[test]
    fn test_max_entries_eviction() {
        let mut cache = PipAttributeCache::with_settings(Duration::from_secs(60), 3);
        let pip_id = PipId::new("test_pip");

        for _ in 0..5 {
            let subject = PipSubject::from_uuid(Uuid::new_v4());
            cache.put(&pip_id, &subject, PipAttributeSet::new());
        }

        assert_eq!(cache.size(), 3);
        assert!(cache.stats().evictions >= 2);
    }

    #[test]
    fn test_cache_put_with_custom_ttl() {
        let mut cache = PipAttributeCache::new(Duration::from_secs(60));
        let pip_id = PipId::new("test_pip");
        let subject = PipSubject::from_uuid(Uuid::new_v4());

        cache.put_with_ttl(
            &pip_id,
            &subject,
            PipAttributeSet::new(),
            Duration::from_secs(120),
        );

        assert_eq!(cache.size(), 1);
    }

    #[test]
    fn test_cache_remove() {
        let mut cache = PipAttributeCache::new(Duration::from_secs(60));
        let pip_id = PipId::new("test_pip");
        let subject = PipSubject::from_uuid(Uuid::new_v4());

        cache.put(&pip_id, &subject, PipAttributeSet::new());
        assert_eq!(cache.size(), 1);

        cache.remove(&pip_id, &subject);
        assert!(cache.is_empty());
        assert_eq!(cache.stats().evictions, 1);
    }

    #[test]
    fn test_cache_remove_nonexistent() {
        let mut cache = PipAttributeCache::new(Duration::from_secs(60));
        let pip_id = PipId::new("test_pip");
        let subject = PipSubject::from_uuid(Uuid::new_v4());

        cache.remove(&pip_id, &subject);
        assert!(cache.is_empty());
        assert_eq!(cache.stats().evictions, 0);
    }

    #[test]
    fn test_cache_purge_expired() {
        let mut cache = PipAttributeCache::new(Duration::from_millis(50));
        let pip_id = PipId::new("test_pip");

        cache.put(
            &pip_id,
            &PipSubject::from_uuid(Uuid::new_v4()),
            PipAttributeSet::new(),
        );
        cache.put(
            &pip_id,
            &PipSubject::from_uuid(Uuid::new_v4()),
            PipAttributeSet::new(),
        );

        assert_eq!(cache.size(), 2);
        assert_eq!(cache.purge_expired(), 0);
    }

    #[test]
    fn test_cache_stats() {
        let mut cache = PipAttributeCache::new(Duration::from_secs(60));
        let pip_id = PipId::new("test_pip");
        let subject = PipSubject::from_uuid(Uuid::new_v4());

        cache.put(&pip_id, &subject, PipAttributeSet::new());

        cache.get(&pip_id, &subject);
        cache.get(&pip_id, &PipSubject::from_uuid(Uuid::new_v4()));

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(cache.size(), 1);
    }

    #[test]
    fn test_cache_hit_rate() {
        let stats = CacheStats {
            total_entries: 10,
            hits: 8,
            misses: 2,
            evictions: 0,
            expired_evictions: 0,
        };
        assert_eq!(stats.hit_rate(), 0.8);

        let empty_stats = CacheStats::default();
        assert_eq!(empty_stats.hit_rate(), 0.0);
    }

    #[test]
    fn test_cache_multiple_pips_same_subject() {
        let mut cache = PipAttributeCache::new(Duration::from_secs(60));
        let pip_id1 = PipId::new("pip1");
        let pip_id2 = PipId::new("pip2");
        let subject = PipSubject::from_uuid(Uuid::new_v4());

        cache.put(&pip_id1, &subject, PipAttributeSet::new());
        cache.put(&pip_id2, &subject, PipAttributeSet::new());

        assert_eq!(cache.size(), 2);
        assert!(cache.get(&pip_id1, &subject).is_some());
        assert!(cache.get(&pip_id2, &subject).is_some());
    }

    #[test]
    fn test_cache_same_pip_different_subjects() {
        let mut cache = PipAttributeCache::new(Duration::from_secs(60));
        let pip_id = PipId::new("test_pip");

        let subject1 = PipSubject::from_uuid(Uuid::new_v4());
        let subject2 = PipSubject::from_uuid(Uuid::new_v4());

        cache.put(&pip_id, &subject1, PipAttributeSet::new());
        cache.put(&pip_id, &subject2, PipAttributeSet::new());

        assert_eq!(cache.size(), 2);
        assert!(cache.get(&pip_id, &subject1).is_some());
        assert!(cache.get(&pip_id, &subject2).is_some());
    }

    #[test]
    fn test_cache_zero_ttl() {
        let mut cache = PipAttributeCache::new(Duration::from_secs(0));
        let pip_id = PipId::new("test_pip");
        let subject = PipSubject::from_uuid(Uuid::new_v4());

        cache.put(&pip_id, &subject, PipAttributeSet::new());
        assert_eq!(cache.size(), 1);
    }

    #[test]
    fn test_cache_eviction_order() {
        let mut cache = PipAttributeCache::with_settings(Duration::from_secs(60), 2);
        let pip_id = PipId::new("test_pip");

        let subject1 = PipSubject::from_uuid(Uuid::new_v4());
        let subject2 = PipSubject::from_uuid(Uuid::new_v4());
        let subject3 = PipSubject::from_uuid(Uuid::new_v4());

        cache.put(&pip_id, &subject1, PipAttributeSet::new());
        cache.put(&pip_id, &subject2, PipAttributeSet::new());
        cache.put(&pip_id, &subject3, PipAttributeSet::new());

        assert_eq!(cache.size(), 2);
        assert_eq!(cache.stats().evictions, 1);
    }

    #[test]
    fn test_cache_repeated_hits() {
        let mut cache = PipAttributeCache::new(Duration::from_secs(60));
        let pip_id = PipId::new("test_pip");
        let subject = PipSubject::from_uuid(Uuid::new_v4());

        cache.put(&pip_id, &subject, PipAttributeSet::new());

        for _ in 0..10 {
            cache.get(&pip_id, &subject);
        }

        assert_eq!(cache.stats().hits, 10);
    }

    #[test]
    fn test_cache_attributes_preserved() {
        let mut cache = PipAttributeCache::new(Duration::from_secs(60));
        let pip_id = PipId::new("test_pip");
        let subject = PipSubject::from_uuid(Uuid::new_v4());

        let mut attrs = PipAttributeSet::new();
        attrs.insert(
            super::super::PipAttributeName::new(&pip_id, "key1"),
            super::super::PipAttributeValue::String("value1".to_string()),
        );
        attrs.insert(
            super::super::PipAttributeName::new(&pip_id, "key2"),
            super::super::PipAttributeValue::Integer(42),
        );

        cache.put(&pip_id, &subject, attrs.clone());

        let retrieved = cache.get(&pip_id, &subject).unwrap();
        assert_eq!(retrieved.len(), 2);
    }

    #[test]
    fn test_cached_entry_remaining_ttl() {
        let entry = CachedEntry::new(PipAttributeSet::new(), Duration::from_secs(60));
        assert!(entry.remaining_ttl().is_some());
        assert!(entry.remaining_ttl().unwrap() <= Duration::from_secs(60));
    }

    #[test]
    fn test_cached_entry_is_expired() {
        let entry = CachedEntry::new(PipAttributeSet::new(), Duration::from_secs(60));
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_cache_key_creation() {
        let pip_id = PipId::new("test_pip");
        let uuid = Uuid::new_v4();
        let subject = PipSubject::from_uuid(uuid);

        let key = CacheKey::new(pip_id.clone(), &subject);
        assert_eq!(key.pip_id, pip_id);
        assert_eq!(key.subject_uuid, uuid);
    }

    #[test]
    fn test_cache_key_ordering() {
        let pip_id1 = PipId::new("pip1");
        let pip_id2 = PipId::new("pip2");
        let uuid = Uuid::new_v4();
        let subject = PipSubject::from_uuid(uuid);

        let key1 = CacheKey::new(pip_id1, &subject);
        let key2 = CacheKey::new(pip_id2, &subject);

        assert!(key1 < key2);
    }

    #[test]
    fn test_cache_key_includes_context_username_email() {
        let mut cache = PipAttributeCache::new(Duration::from_secs(60));
        let pip_id = PipId::new("test_pip");
        let uuid = Uuid::new_v4();

        let office = PipSubject::from_uuid(uuid)
            .with_username("alice")
            .with_context("location", "office");
        let home = PipSubject::from_uuid(uuid)
            .with_username("alice")
            .with_context("location", "home");

        let mut attrs = PipAttributeSet::new();
        attrs.insert(
            super::super::PipAttributeName::new(&pip_id, "risk"),
            super::super::PipAttributeValue::String("low".to_string()),
        );
        cache.put(&pip_id, &office, attrs);

        // Same UUID but a different context must not hit the office entry.
        assert!(cache.get(&pip_id, &home).is_none());
        assert!(cache
            .get(
                &pip_id,
                &PipSubject::from_uuid(uuid).with_context("location", "office")
            )
            .is_none());
        assert!(cache
            .get(&pip_id, &office.clone().with_email("alice@example.com"))
            .is_none());
        assert!(cache.get(&pip_id, &office).is_some());
    }

    #[test]
    fn test_cache_key_context_order_is_deterministic() {
        let pip_id = PipId::new("test_pip");
        let uuid = Uuid::new_v4();
        let a = PipSubject::from_uuid(uuid)
            .with_context("x", "1")
            .with_context("y", "2");
        let b = PipSubject::from_uuid(uuid)
            .with_context("y", "2")
            .with_context("x", "1");
        assert_eq!(CacheKey::new(pip_id.clone(), &a), CacheKey::new(pip_id, &b));
    }

    #[test]
    fn test_cache_remove_clears_all_contexts_for_subject() {
        let mut cache = PipAttributeCache::new(Duration::from_secs(60));
        let pip_id = PipId::new("test_pip");
        let other_pip = PipId::new("other_pip");
        let uuid = Uuid::new_v4();
        let a = PipSubject::from_uuid(uuid).with_context("location", "office");
        let b = PipSubject::from_uuid(uuid).with_context("location", "home");

        cache.put(&pip_id, &a, PipAttributeSet::new());
        cache.put(&pip_id, &b, PipAttributeSet::new());
        cache.put(&other_pip, &a, PipAttributeSet::new());
        assert_eq!(cache.size(), 3);

        cache.remove(&pip_id, &PipSubject::from_uuid(uuid));
        assert_eq!(cache.size(), 1);
        assert_eq!(cache.stats().evictions, 2);
        assert!(cache.get(&other_pip, &a).is_some());
    }

    #[test]
    fn test_cache_with_settings() {
        let cache = PipAttributeCache::with_settings(Duration::from_secs(300), 500);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_size_tracking() {
        let mut cache = PipAttributeCache::new(Duration::from_secs(60));
        let pip_id = PipId::new("test_pip");

        for i in 0..10 {
            let subject = PipSubject::from_uuid(Uuid::new_v4());
            cache.put(&pip_id, &subject, PipAttributeSet::new());
            assert_eq!(cache.size(), i + 1);
        }
    }
}
