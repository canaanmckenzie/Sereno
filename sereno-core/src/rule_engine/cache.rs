use crate::types::EvalResult;
use parking_lot::RwLock;
use std::collections::HashMap;

/// LRU-style cache for rule evaluation decisions
pub struct DecisionCache {
    cache: RwLock<HashMap<String, CacheEntry>>,
    max_size: usize,
}

struct CacheEntry {
    result: EvalResult,
    #[allow(dead_code)]
    last_access: std::time::Instant,
}

impl DecisionCache {
    /// Create a new cache with the given maximum size
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: RwLock::new(HashMap::with_capacity(max_size)),
            max_size,
        }
    }

    /// Get a cached decision
    pub fn get(&self, key: &str) -> Option<EvalResult> {
        let cache = self.cache.read();
        cache.get(key).map(|e| e.result.clone())
    }

    /// Insert a decision into the cache
    pub fn insert(&self, key: String, result: EvalResult) {
        let mut cache = self.cache.write();

        // Simple eviction: clear half the cache when full
        if cache.len() >= self.max_size {
            let keys_to_remove: Vec<_> = cache
                .keys()
                .take(self.max_size / 2)
                .cloned()
                .collect();
            for k in keys_to_remove {
                cache.remove(&k);
            }
        }

        cache.insert(
            key,
            CacheEntry {
                result,
                last_access: std::time::Instant::now(),
            },
        );
    }

    /// Clear all cached decisions
    pub fn clear(&self) {
        self.cache.write().clear();
    }

    /// Get the number of cached entries
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.cache.read().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_insert_and_get() {
        let cache = DecisionCache::new(100);

        cache.insert(
            "test_key".to_string(),
            EvalResult::Allow { rule_id: "rule1".to_string() },
        );

        let result = cache.get("test_key");
        assert!(result.is_some());
        match result.unwrap() {
            EvalResult::Allow { rule_id } => assert_eq!(rule_id, "rule1"),
            _ => panic!("Wrong result type"),
        }
    }

    #[test]
    fn test_cache_miss() {
        let cache = DecisionCache::new(100);
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn test_cache_clear() {
        let cache = DecisionCache::new(100);

        cache.insert("key1".to_string(), EvalResult::Ask);
        cache.insert("key2".to_string(), EvalResult::Ask);

        assert_eq!(cache.len(), 2);

        cache.clear();

        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_eviction() {
        let cache = DecisionCache::new(10);

        // Fill the cache
        for i in 0..15 {
            cache.insert(format!("key_{}", i), EvalResult::Ask);
        }

        // Cache should have evicted some entries
        assert!(cache.len() <= 10);
    }
}
