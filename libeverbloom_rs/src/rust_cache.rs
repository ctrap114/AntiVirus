use crate::rust_feature_extractor::FeatureVector;
use lru::LruCache;
use parking_lot::Mutex;
use pyo3::prelude::*;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct CacheEntry {
    value: String,
    expires_at: Option<Instant>,
}

#[pyclass]
pub struct ShardedLruCache {
    shards: Vec<Mutex<LruCache<u64, CacheEntry>>>,
    ttl: Option<Duration>,
}

#[pymethods]
impl ShardedLruCache {
    #[new]
    pub fn new(
        capacity_per_shard: Option<usize>,
        shard_count: Option<usize>,
        ttl_seconds: Option<u64>,
    ) -> Self {
        let shards = shard_count.unwrap_or(4).max(1);
        let capacity = capacity_per_shard.unwrap_or(256).max(1);
        ShardedLruCache {
            shards: (0..shards)
                .map(|_| Mutex::new(LruCache::new(NonZeroUsize::new(capacity).unwrap())))
                .collect(),
            ttl: ttl_seconds.map(Duration::from_secs),
        }
    }

    pub fn put(&self, key: String, value: String) {
        let hashed = self.hash_key(&key);
        let shard = &self.shards[hashed as usize % self.shards.len()];
        let mut guard = shard.lock();
        guard.put(
            hashed,
            CacheEntry {
                value,
                expires_at: self.ttl.map(|ttl| Instant::now() + ttl),
            },
        );
    }

    pub fn get(&self, key: String) -> Option<String> {
        let hashed = self.hash_key(&key);
        let shard = &self.shards[hashed as usize % self.shards.len()];
        let mut guard = shard.lock();
        if let Some(entry) = guard.get(&hashed) {
            if let Some(expires_at) = entry.expires_at {
                if Instant::now() > expires_at {
                    guard.pop(&hashed);
                    return None;
                }
            }
            return Some(entry.value.clone());
        }
        None
    }

    pub fn len(&self) -> usize {
        self.shards.iter().map(|shard| shard.lock().len()).sum()
    }

    pub fn clear(&self) {
        for shard in &self.shards {
            shard.lock().clear();
        }
    }
}

impl ShardedLruCache {
    pub fn put_feature_vector(&self, key: String, value: FeatureVector) {
        let serialized = serde_json::to_string(&value).unwrap_or_default();
        self.put(key, serialized);
    }

    pub fn get_feature_vector(&self, key: String) -> Option<FeatureVector> {
        self.get(key)
            .and_then(|value| serde_json::from_str(&value).ok())
    }
}

impl ShardedLruCache {
    fn hash_key<K: Hash>(&self, key: K) -> u64 {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_round_trips_feature_vectors() {
        let cache = ShardedLruCache::new(Some(8), Some(2), None);
        let feature = FeatureVector {
            sha256: "abc".into(),
            entropy: 7.3,
            printable_ratio: 0.77,
            string_count: 10,
            size: 512,
            section_count: 3,
            section_entropy: vec![5.0, 6.0, 7.0],
            section_entropy_histogram: vec![1, 0, 2],
            suspicious_import_count: 1,
            suspicious_resource_count: 1,
            packed: false,
            import_names: vec!["VirtualAlloc".into()],
            resource_names: vec!["ICON".into()],
        };
        cache.put_feature_vector("demo".into(), feature.clone());
        let round_trip = cache.get_feature_vector("demo".into()).unwrap();
        assert_eq!(round_trip.sha256, feature.sha256);
        assert_eq!(round_trip.section_count, feature.section_count);
    }
}
