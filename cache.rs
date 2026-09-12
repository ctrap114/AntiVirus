use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::SystemTime;
use std::{
    fs::File,
    io::{self, Read},
};

use sha2::{Digest, Sha256};

/// Layer switches that affect the meaning of cached evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScanContext {
    pub yara_enabled: bool,
    pub heuristic_enabled: bool,
    pub ai_enabled: bool,
    pub sandbox_enabled: bool,
    pub ai_threshold_bits: u32,
    pub sandbox_timeout_ms: u64,
    /// Versions of every evidence-producing layer. These are deliberately
    /// part of the context equality check so a hot-reloaded ruleset or model
    /// cannot reuse an old verdict/evidence record.
    pub rules_version: u64,
    pub yara_version: u64,
    pub ai_model_version: u64,
    pub sandbox_policy_version: u64,
}

/// Reusable per-file scan evidence stored in the cache.
///
/// Unlike a final verdict, these layer outputs remain valid when only the AI
/// ensemble weight or fusion policy changes. The scanner can reconstruct the
/// result and recompute the decision without reading the file again.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub path: PathBuf,
    pub malicious: bool,
    pub summary: String,
    pub context: ScanContext,
    pub heuristic_score: Option<f32>,
    pub ai_score: Option<f32>,
    pub ai_components: Vec<(String, f32, f32)>,
    /// Bounded, display-ready evidence retained for cache hits. Keeping rule
    /// names rather than YARA engine objects makes the cache independent of
    /// the rule compiler lifetime.
    pub yara_matches: Vec<String>,
    pub behavior_score: Option<f32>,
    pub sequence_matches: Option<Vec<String>>,
}

type CacheEntryKey = (SystemTime, u64);

/// File metadata used to decide whether a cached result is still valid.
///
/// A path alone is not a stable cache key: an executable can be replaced while
/// retaining the same name. The scanner therefore compares both size and the
/// filesystem modification time before reusing a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFingerprint {
    pub modified: Option<SystemTime>,
    pub size: u64,
    pub content_hash: Option<[u8; 32]>,
}

impl FileFingerprint {
    pub fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            modified: metadata.modified().ok(),
            size: metadata.len(),
            content_hash: None,
        }
    }

    /// Build a content-aware fingerprint and reject files that change while
    /// their digest is being calculated.
    pub fn from_path<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path = path.as_ref();
        let before = std::fs::metadata(path)?;
        let mut file = File::open(path)?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 1024 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        let after = std::fs::metadata(path)?;
        if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
            return Err(io::Error::other(
                "file changed while its cache fingerprint was calculated",
            ));
        }
        Ok(Self {
            modified: after.modified().ok(),
            size: after.len(),
            content_hash: Some(digest.finalize().into()),
        })
    }

    pub fn same_metadata(&self, other: Self) -> bool {
        self.modified == other.modified && self.size == other.size
    }
}

type CacheValue = (ScanResult, Option<FileFingerprint>, u64, u64, u64);

#[derive(Debug, Default)]
struct CacheState {
    entries: BTreeMap<CacheEntryKey, CacheValue>,
    by_path: HashMap<PathBuf, CacheEntryKey>,
}

/// LRU cache for scan results.
///
/// This cache keeps a path index for O(1)-average lookup and a BTreeMap for
/// oldest-first eviction. A counter breaks ties when writes share a timestamp.
#[derive(Clone, Debug)]
pub struct ScanCache {
    inner: Arc<Mutex<CacheState>>,
    max_size: usize,
    counter: Arc<Mutex<u64>>,
    generation: Arc<AtomicU64>,
    decision_generation: Arc<AtomicU64>,
}

impl ScanCache {
    /// Create a new cache capable of holding at most `max_size` entries.
    pub fn new(max_size: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CacheState::default())),
            max_size: max_size.max(1),
            counter: Arc::new(Mutex::new(0)),
            generation: Arc::new(AtomicU64::new(0)),
            decision_generation: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Return the number of entries currently stored in the cache.
    pub fn len(&self) -> usize {
        let guard = self.inner.lock().expect("cache mutex poisoned");
        guard.entries.len()
    }

    /// Return whether the cache currently contains no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Retrieve a cached scan result by path.
    ///
    /// If the result exists, it is promoted to the most-recently-used position.
    pub fn get<P: AsRef<Path>>(&self, path: P) -> Option<ScanResult> {
        let mut guard = self.inner.lock().expect("cache mutex poisoned");
        if let Some(key) = guard.by_path.remove(path.as_ref()) {
            if let Some((entry, fingerprint, generation, policy_epoch, decision_generation)) =
                guard.entries.remove(&key)
            {
                if generation != self.generation.load(Ordering::Acquire)
                    || decision_generation != self.decision_generation.load(Ordering::Acquire)
                {
                    return None;
                }
                let promoted_key = self.next_key();
                let result = entry.clone();
                guard.by_path.insert(entry.path.clone(), promoted_key);
                guard.entries.insert(
                    promoted_key,
                    (
                        entry,
                        fingerprint,
                        generation,
                        policy_epoch,
                        decision_generation,
                    ),
                );
                return Some(result);
            }
        }
        None
    }

    /// Retrieve a result only when it was produced for the same file
    /// fingerprint. This is the API used by the scanner for security-sensitive
    /// reuse; the path-only `get` method is retained for compatibility.
    pub fn get_fresh<P: AsRef<Path>>(
        &self,
        path: P,
        fingerprint: FileFingerprint,
    ) -> Option<ScanResult> {
        self.get_fresh_for_policy(path, fingerprint, 0)
    }

    /// Retrieve a result only when both the file and the protection policy
    /// are unchanged since the result was produced.
    pub fn get_fresh_for_policy<P: AsRef<Path>>(
        &self,
        path: P,
        fingerprint: FileFingerprint,
        policy_epoch: u64,
    ) -> Option<ScanResult> {
        self.get_matching_for_policy(path, fingerprint, policy_epoch, true, None)
    }

    pub fn get_fresh_for_policy_with_context<P: AsRef<Path>>(
        &self,
        path: P,
        fingerprint: FileFingerprint,
        policy_epoch: u64,
        context: ScanContext,
    ) -> Option<ScanResult> {
        self.get_matching_for_policy(path, fingerprint, policy_epoch, true, Some(context))
    }

    /// Retrieve reusable layer evidence even after the final decision
    /// generation has changed. The file fingerprint and kernel policy epoch
    /// are still mandatory, so this cannot resurrect evidence for a replaced
    /// file or a newly changed kernel rule.
    pub fn get_evidence_for_policy<P: AsRef<Path>>(
        &self,
        path: P,
        fingerprint: FileFingerprint,
        policy_epoch: u64,
    ) -> Option<ScanResult> {
        self.get_matching_for_policy(path, fingerprint, policy_epoch, false, None)
    }

    pub fn get_evidence_for_policy_with_context<P: AsRef<Path>>(
        &self,
        path: P,
        fingerprint: FileFingerprint,
        policy_epoch: u64,
        context: ScanContext,
    ) -> Option<ScanResult> {
        self.get_matching_for_policy(path, fingerprint, policy_epoch, false, Some(context))
    }

    fn get_matching_for_policy<P: AsRef<Path>>(
        &self,
        path: P,
        fingerprint: FileFingerprint,
        policy_epoch: u64,
        require_current_decision: bool,
        expected_context: Option<ScanContext>,
    ) -> Option<ScanResult> {
        let mut guard = self.inner.lock().expect("cache mutex poisoned");
        if let Some(key) = guard.by_path.remove(path.as_ref()) {
            if let Some((
                entry,
                stored_fingerprint,
                generation,
                stored_policy_epoch,
                decision_generation,
            )) = guard.entries.remove(&key)
            {
                let context_matches =
                    expected_context.is_none_or(|expected| entry.context == expected);
                let file_matches = generation == self.generation.load(Ordering::Acquire)
                    && stored_policy_epoch == policy_epoch
                    && stored_fingerprint == Some(fingerprint)
                    && context_matches;
                let decision_matches =
                    decision_generation == self.decision_generation.load(Ordering::Acquire);
                if file_matches && (!require_current_decision || decision_matches) {
                    let result = entry.clone();
                    let promoted_key = self.next_key();
                    guard.by_path.insert(entry.path.clone(), promoted_key);
                    guard.entries.insert(
                        promoted_key,
                        (
                            entry,
                            stored_fingerprint,
                            generation,
                            stored_policy_epoch,
                            decision_generation,
                        ),
                    );
                    return Some(result);
                }
                if file_matches && !decision_matches {
                    // Preserve reusable evidence while discarding only the
                    // old final decision. A future scan can recompute the
                    // decision under the current AI/fusion configuration.
                    let promoted_key = self.next_key();
                    guard.by_path.insert(entry.path.clone(), promoted_key);
                    guard.entries.insert(
                        promoted_key,
                        (
                            entry,
                            stored_fingerprint,
                            generation,
                            stored_policy_epoch,
                            decision_generation,
                        ),
                    );
                }
                // Otherwise the path, file, or kernel policy changed; drop
                // the stale entry instead of reusing it.
            }
        }
        None
    }

    /// Return whether a path has a current-generation entry with matching
    /// size/mtime. The caller must still calculate and verify the content hash
    /// before reusing the result; this method only avoids hashing files that
    /// have no plausible cache candidate.
    pub fn has_metadata_candidate<P: AsRef<Path>>(
        &self,
        path: P,
        fingerprint: FileFingerprint,
    ) -> bool {
        let guard = self.inner.lock().expect("cache mutex poisoned");
        guard
            .by_path
            .get(path.as_ref())
            .and_then(|key| guard.entries.get(key))
            .is_some_and(
                |(_, stored_fingerprint, generation, _policy_epoch, _decision_generation)| {
                    *generation == self.generation.load(Ordering::Acquire)
                        && stored_fingerprint
                            .is_some_and(|stored| stored.same_metadata(fingerprint))
                },
            )
    }

    /// Insert or replace a scan result in the cache.
    ///
    /// When the cache exceeds `max_size`, the oldest entry is evicted.
    pub fn put(&self, result: ScanResult) {
        self.put_with_fingerprint(result, None);
    }

    /// Insert a result together with the metadata fingerprint observed during
    /// the scan.
    pub fn put_fresh(&self, result: ScanResult, fingerprint: FileFingerprint) {
        self.put_fresh_for_policy(result, fingerprint, 0);
    }

    pub fn put_fresh_for_policy(
        &self,
        result: ScanResult,
        fingerprint: FileFingerprint,
        policy_epoch: u64,
    ) {
        self.put_with_fingerprint_and_policy(result, Some(fingerprint), policy_epoch);
    }

    pub fn put_fresh_for_policy_with_context(
        &self,
        result: ScanResult,
        fingerprint: FileFingerprint,
        policy_epoch: u64,
        context: ScanContext,
    ) {
        let mut result = result;
        result.context = context;
        self.put_with_fingerprint_and_policy(result, Some(fingerprint), policy_epoch);
    }

    fn put_with_fingerprint(&self, result: ScanResult, fingerprint: Option<FileFingerprint>) {
        self.put_with_fingerprint_and_policy(result, fingerprint, 0);
    }

    fn put_with_fingerprint_and_policy(
        &self,
        result: ScanResult,
        fingerprint: Option<FileFingerprint>,
        policy_epoch: u64,
    ) {
        let mut guard = self.inner.lock().expect("cache mutex poisoned");
        if let Some(existing_key) = guard.by_path.remove(&result.path) {
            guard.entries.remove(&existing_key);
        }

        let key = self.next_key();
        guard.by_path.insert(result.path.clone(), key);
        guard.entries.insert(
            key,
            (
                result,
                fingerprint,
                self.generation.load(Ordering::Acquire),
                policy_epoch,
                self.decision_generation.load(Ordering::Acquire),
            ),
        );
        self.evict_if_needed(&mut guard);
    }

    /// Remove a cached entry by its file path.
    pub fn invalidate_path<P: AsRef<Path>>(&self, path: P) {
        let mut guard = self.inner.lock().expect("cache mutex poisoned");
        if let Some(key) = guard.by_path.remove(path.as_ref()) {
            guard.entries.remove(&key);
        }
    }

    /// Clear all cached scan results.
    pub fn clear(&self) {
        let mut guard = self.inner.lock().expect("cache mutex poisoned");
        guard.entries.clear();
        guard.by_path.clear();
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.decision_generation.fetch_add(1, Ordering::AcqRel);
    }

    /// Invalidate only final decisions while preserving content evidence.
    ///
    /// This is used for AI blend/ensemble/fusion changes. The next scan can
    /// reuse the file's hash/YARA/heuristic/AI evidence and recompute its
    /// decision under the new context.
    pub fn invalidate_decisions(&self) {
        self.decision_generation.fetch_add(1, Ordering::AcqRel);
    }

    /// Invalidate entries from the previous engine/rule/model context,
    /// including reusable evidence.
    pub fn invalidate_context(&self) {
        let mut guard = self.inner.lock().expect("cache mutex poisoned");
        guard.entries.clear();
        guard.by_path.clear();
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.decision_generation.fetch_add(1, Ordering::AcqRel);
    }

    fn next_key(&self) -> CacheEntryKey {
        let mut counter_guard = self.counter.lock().expect("counter mutex poisoned");
        let value = *counter_guard;
        *counter_guard = value.wrapping_add(1);
        (SystemTime::now(), value)
    }

    fn evict_if_needed(&self, guard: &mut CacheState) {
        while guard.entries.len() > self.max_size {
            let oldest_key = guard.entries.keys().next().cloned();
            if let Some(key) = oldest_key {
                if let Some((entry, _, _, _, _)) = guard.entries.remove(&key) {
                    guard.by_path.remove(&entry.path);
                }
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn make_scan_result(path: &str, malicious: bool) -> ScanResult {
        ScanResult {
            path: PathBuf::from(path),
            malicious,
            summary: format!("result for {}", path),
            context: ScanContext::default(),
            heuristic_score: None,
            ai_score: None,
            ai_components: Vec::new(),
            yara_matches: Vec::new(),
            behavior_score: None,
            sequence_matches: None,
        }
    }

    #[test]
    fn test_cache_eviction_oldest_removed() {
        let cache = ScanCache::new(2);

        cache.put(make_scan_result("/tmp/file1", false));
        cache.put(make_scan_result("/tmp/file2", false));
        cache.put(make_scan_result("/tmp/file3", true));

        assert_eq!(cache.len(), 2);
        assert!(cache.get("/tmp/file1").is_none());
        assert!(cache.get("/tmp/file2").is_some());
        assert!(cache.get("/tmp/file3").is_some());
    }

    #[test]
    fn test_cache_get_promotes_entry() {
        let cache = ScanCache::new(2);

        cache.put(make_scan_result("/tmp/file1", false));
        cache.put(make_scan_result("/tmp/file2", false));

        assert!(cache.get("/tmp/file1").is_some());
        cache.put(make_scan_result("/tmp/file3", true));

        assert_eq!(cache.len(), 2);
        assert!(cache.get("/tmp/file2").is_none());
        assert!(cache.get("/tmp/file1").is_some());
        assert!(cache.get("/tmp/file3").is_some());
    }

    #[test]
    fn test_cache_invalidate_and_clear() {
        let cache = ScanCache::new(3);
        cache.put(make_scan_result("/tmp/file1", false));
        cache.put(make_scan_result("/tmp/file2", true));

        assert_eq!(cache.len(), 2);
        cache.invalidate_path("/tmp/file1");
        assert_eq!(cache.len(), 1);
        assert!(cache.get("/tmp/file1").is_none());
        cache.clear();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_fingerprint_prevents_reusing_replaced_file() {
        let cache = ScanCache::new(2);
        let first = FileFingerprint {
            modified: Some(SystemTime::UNIX_EPOCH),
            size: 10,
            content_hash: None,
        };
        let replaced = FileFingerprint {
            modified: Some(SystemTime::UNIX_EPOCH),
            size: 11,
            content_hash: None,
        };
        cache.put_fresh(make_scan_result("/tmp/file", true), first);

        assert!(cache.get_fresh("/tmp/file", replaced).is_none());
        assert!(cache.get_fresh("/tmp/file", first).is_none());
    }

    #[test]
    fn test_context_invalidation_rejects_old_entries() {
        let cache = ScanCache::new(2);
        let fingerprint = FileFingerprint {
            modified: Some(SystemTime::UNIX_EPOCH),
            size: 10,
            content_hash: Some([7; 32]),
        };
        cache.put_fresh(make_scan_result("/tmp/file", false), fingerprint);
        assert!(cache.get_fresh("/tmp/file", fingerprint).is_some());
        cache.invalidate_context();
        assert!(cache.get_fresh("/tmp/file", fingerprint).is_none());
    }

    #[test]
    fn policy_epoch_prevents_reusing_clean_verdict_after_policy_update() {
        let cache = ScanCache::new(4);
        let fingerprint = FileFingerprint {
            modified: Some(SystemTime::UNIX_EPOCH),
            size: 4,
            content_hash: Some([7; 32]),
        };
        cache.put_fresh_for_policy(make_scan_result("/tmp/policy-file", false), fingerprint, 11);
        assert!(cache
            .get_fresh_for_policy("/tmp/policy-file", fingerprint, 11)
            .is_some());
        cache.put_fresh_for_policy(make_scan_result("/tmp/policy-file", false), fingerprint, 11);
        assert!(cache
            .get_fresh_for_policy("/tmp/policy-file", fingerprint, 12)
            .is_none());
    }

    #[test]
    fn decision_invalidation_preserves_reusable_evidence() {
        let cache = ScanCache::new(4);
        let fingerprint = FileFingerprint {
            modified: Some(SystemTime::UNIX_EPOCH),
            size: 12,
            content_hash: Some([9; 32]),
        };
        let mut result = make_scan_result("/tmp/recompute", false);
        result.heuristic_score = Some(0.31);
        result.ai_score = Some(0.22);
        cache.put_fresh_for_policy(result, fingerprint, 3);

        assert!(cache
            .get_fresh_for_policy("/tmp/recompute", fingerprint, 3)
            .is_some());
        let mut result = make_scan_result("/tmp/recompute", false);
        result.heuristic_score = Some(0.31);
        result.ai_score = Some(0.22);
        cache.put_fresh_for_policy(result, fingerprint, 3);

        cache.invalidate_decisions();
        assert!(cache
            .get_fresh_for_policy("/tmp/recompute", fingerprint, 3)
            .is_none());
        let evidence = cache
            .get_evidence_for_policy("/tmp/recompute", fingerprint, 3)
            .expect("evidence survives decision invalidation");
        assert_eq!(evidence.heuristic_score, Some(0.31));
        assert_eq!(evidence.ai_score, Some(0.22));
    }

    #[test]
    fn layer_context_mismatch_does_not_reuse_evidence() {
        let cache = ScanCache::new(2);
        let fingerprint = FileFingerprint {
            modified: Some(SystemTime::UNIX_EPOCH),
            size: 5,
            content_hash: Some([3; 32]),
        };
        let context = ScanContext {
            ai_enabled: true,
            ..ScanContext::default()
        };
        let mut result = make_scan_result("/tmp/context", false);
        result.context = context;
        cache.put_fresh_for_policy_with_context(result, fingerprint, 0, context);

        let different_context = ScanContext {
            heuristic_enabled: true,
            ..ScanContext::default()
        };
        assert!(
            cache
                .get_evidence_for_policy_with_context(
                    "/tmp/context",
                    fingerprint,
                    0,
                    different_context,
                )
                .is_none()
        );
    }

    #[test]
    fn evidence_is_bound_to_all_engine_layer_versions() {
        let cache = ScanCache::new(2);
        let fingerprint = FileFingerprint {
            modified: Some(SystemTime::UNIX_EPOCH),
            size: 5,
            content_hash: Some([8; 32]),
        };
        let context = ScanContext {
            rules_version: 10,
            yara_version: 20,
            ai_model_version: 30,
            sandbox_policy_version: 40,
            ..ScanContext::default()
        };
        let mut result = make_scan_result("/tmp/versioned", false);
        result.context = context;
        cache.put_fresh_for_policy_with_context(result, fingerprint, 0, context);

        for changed in [
            ScanContext {
                rules_version: 11,
                ..context
            },
            ScanContext {
                yara_version: 21,
                ..context
            },
            ScanContext {
                ai_model_version: 31,
                ..context
            },
            ScanContext {
                sandbox_policy_version: 41,
                ..context
            },
        ] {
            assert!(cache
                .get_evidence_for_policy_with_context("/tmp/versioned", fingerprint, 0, changed,)
                .is_none());
            let mut replacement = make_scan_result("/tmp/versioned", false);
            replacement.context = context;
            cache.put_fresh_for_policy_with_context(replacement, fingerprint, 0, context);
        }
    }

    #[test]
    fn test_concurrent_access() {
        let cache = Arc::new(ScanCache::new(10));
        let mut handles = Vec::new();

        for i in 0..5 {
            let cache = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                for j in 0..20 {
                    let path = format!("/tmp/thread-{}/file-{}", i, j);
                    cache.put(make_scan_result(&path, j % 2 == 0));
                    let _ = cache.get(&path);
                }
            }));
        }

        for handle in handles {
            handle.join().expect("thread should join");
        }

        assert!(cache.len() <= 10);
    }
}
