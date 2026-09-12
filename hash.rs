use arc_swap::ArcSwap;
use csv::ReaderBuilder;
use dashmap::DashMap;
use hex::encode as hex_encode;
use log::{debug, error, info, warn};
use md5::Md5;
use rayon::prelude::*;
use rusqlite::types::ValueRef;
use rusqlite::Connection;
use serde_json::Value;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use thiserror::Error;

// Standard ssdeep/spamsum constants. The generated signature is the normal
// `blocksize:hash1:hash2` format, so it can be exchanged with libfuzzy/ssdeep.
const FUZZY_MIN_BLOCK_SIZE: usize = 3;
const FUZZY_PRIMARY_LIMIT: usize = 64;
const FUZZY_SECONDARY_LIMIT: usize = 64;
const FUZZY_MATCH_THRESHOLD: u8 = 85;
const FUZZY_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const FUZZY_HASH_INIT: u32 = 0x2802_1967;
const FUZZY_HASH_PRIME: u32 = 0x0100_0193;
const FUZZY_ROLLING_WINDOW: usize = 7;

/// Outcome categories returned by the hash matching batch pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashBatchResult {
    pub clean: Vec<PathBuf>,
    pub malicious: Vec<PathBuf>,
    pub unknown: Vec<PathBuf>,
}

/// Errors returned by the `HashMatcher` layer.
#[derive(Debug, Error)]
pub enum HashError {
    /// I/O error reading a file.
    #[error("I/O error while processing {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// CSV parsing or loading error.
    #[error("CSV parse error for {path}: {source}")]
    Csv {
        path: PathBuf,
        #[source]
        source: csv::Error,
    },

    /// JSON/JSONL parsing or loading error.
    #[error("JSON parse error for {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    /// SQLite database loading error.
    #[error("SQLite error reading {path}: {source}")]
    Sqlite {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },

    /// Hash string is not a supported exact hash.
    #[error("invalid hash format for {value}")]
    InvalidHashFormat { value: String },

    /// A fuzzy signature is not in standard ssdeep or legacy ssdeep-lite format.
    #[error("invalid fuzzy hash format for {value}")]
    InvalidFuzzyHash { value: String },

    /// Required field missing from the CSV header.
    #[error("CSV missing required header: {field}")]
    MissingHeader { field: String },

    /// A replacement database must contain at least one valid hash.
    #[error("hash database contains no valid entries")]
    EmptyDatabase,
}

/// A lightweight match result returned for a single file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashMatch {
    pub label: String,
    pub hash: String,
    pub algorithm: String,
    pub similarity: u8,
    /// Distinct source identifiers that contributed this normalized hash.
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FuzzyEntry {
    signature: String,
    is_malicious: bool,
    label: String,
    algorithm: String,
    sources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExactEntry {
    is_malicious: bool,
    sources: Vec<String>,
}

/// Thread-safe hash matcher using a concurrent DashMap.
///
/// It supports parallel SHA-256 computation and fast lookup against
/// a preloaded hash database of malicious indicators.
pub struct HashMatcher {
    hashes: ArcSwap<DashMap<String, ExactEntry>>,
    fuzzy_hashes: ArcSwap<Vec<FuzzyEntry>>,
    label: String,
}

impl HashMatcher {
    /// Create a new `HashMatcher` with optional initial hash entries.
    pub fn new(initial_hashes: Option<Vec<(String, bool)>>) -> Self {
        Self::new_with_label(initial_hashes, "hash".to_string())
    }

    /// Create a new `HashMatcher` with a custom label used for reporting.
    pub fn new_with_label(initial_hashes: Option<Vec<(String, bool)>>, label: String) -> Self {
        let map = DashMap::new();
        let mut fuzzy_hashes = Vec::new();
        if let Some(entries) = initial_hashes {
            for (hash, is_malicious) in entries {
                if let Ok(normalized) = normalize_hash(&hash) {
                    let mut existing = map.entry(normalized).or_insert(ExactEntry {
                        is_malicious: false,
                        sources: Vec::new(),
                    });
                    existing.is_malicious |= is_malicious;
                    merge_sources(&mut existing.sources, &label);
                } else if let Ok(normalized) = normalize_fuzzy_hash(&hash) {
                    merge_fuzzy_entry(
                        &mut fuzzy_hashes,
                        FuzzyEntry {
                            algorithm: fuzzy_algorithm_name(&normalized),
                            signature: normalized,
                            is_malicious,
                            label: label.clone(),
                            sources: vec![label.clone()],
                        },
                    );
                }
            }
        }
        Self {
            hashes: ArcSwap::from_pointee(map),
            fuzzy_hashes: ArcSwap::from_pointee(fuzzy_hashes),
            label,
        }
    }

    /// Load hash entries into the matcher.
    ///
    /// MD5, SHA-1, SHA-256, standard ssdeep, and legacy ssdeep-lite
    /// signatures are accepted and normalized.
    pub fn load_hashes(&self, entries: Vec<(String, bool)>) {
        let records = entries
            .into_iter()
            .map(|(hash, is_malicious)| HashDbEntry {
                hash,
                algorithm: "exact".to_string(),
                is_malicious,
                source: self.label.clone(),
            })
            .collect();
        self.load_records(records);
    }

    /// Load a hash database by extension and, for unknown extensions, by its
    /// content. Supported formats are SQLite/DB, CSV, plain text, JSON and
    /// JSONL/NDJSON. Exact hashes include MD5, SHA-1, SHA-256 and SHA-512;
    /// standard ssdeep and the legacy `ssdeep-lite` form are also accepted.
    pub fn load_from_file<P: AsRef<Path>>(&self, path: P) -> Result<usize, HashError> {
        let path = path.as_ref();
        let records = with_default_source(read_hash_entries_from_file(path)?, path);
        Ok(self.load_records(records))
    }

    /// Replace the current database atomically after parsing a supported file.
    pub fn replace_from_file<P: AsRef<Path>>(&self, path: P) -> Result<usize, HashError> {
        let path = path.as_ref();
        let records = with_default_source(read_hash_entries_from_file(path)?, path);
        self.replace_records(records, path)
    }

    fn load_records(&self, entries: Vec<HashDbEntry>) -> usize {
        let hashes = self.hashes.load();
        let fuzzy_hashes = self.fuzzy_hashes.load_full();
        let mut fuzzy_replacement = (*fuzzy_hashes).clone();
        let mut loaded = 0;
        for entry in entries {
            if is_fuzzy_algorithm(&entry.algorithm) {
                if let Ok(normalized) = normalize_fuzzy_hash(&entry.hash) {
                    merge_fuzzy_entry(
                        &mut fuzzy_replacement,
                        FuzzyEntry {
                            algorithm: fuzzy_algorithm_name(&normalized),
                            signature: normalized,
                            is_malicious: entry.is_malicious,
                            label: self.label.clone(),
                            sources: vec![entry.source],
                        },
                    );
                    loaded += 1;
                } else {
                    warn!("Skipping invalid fuzzy hash entry: {}", entry.hash);
                }
            } else if let Ok(hash) = normalize_hash(&entry.hash) {
                let mut existing = hashes.entry(hash).or_insert(ExactEntry {
                    is_malicious: false,
                    sources: Vec::new(),
                });
                existing.is_malicious |= entry.is_malicious;
                merge_sources(&mut existing.sources, &entry.source);
                loaded += 1;
            } else {
                warn!("Skipping invalid hash entry: {}", entry.hash);
            }
        }
        self.fuzzy_hashes.store(Arc::new(fuzzy_replacement));
        info!(
            "Hash matcher now stores {} exact and {} fuzzy entries",
            hashes.len(),
            self.fuzzy_hashes.load().len()
        );
        loaded
    }

    /// Load malicious fuzzy signatures. Fuzzy matches are only allowed to
    /// classify as malicious; they never create a clean verdict.
    pub fn load_fuzzy_hashes(&self, entries: Vec<(String, bool)>) -> usize {
        let fuzzy_hashes = self.fuzzy_hashes.load_full();
        let mut loaded = 0;
        let mut replacement = (*fuzzy_hashes).clone();
        for (signature, is_malicious) in entries {
            match normalize_fuzzy_hash(&signature) {
                Ok(signature) => {
                    merge_fuzzy_entry(
                        &mut replacement,
                        FuzzyEntry {
                            algorithm: fuzzy_algorithm_name(&signature),
                            signature,
                            is_malicious,
                            label: self.label.clone(),
                            sources: vec![self.label.clone()],
                        },
                    );
                    loaded += 1;
                }
                Err(error) => warn!("Skipping invalid fuzzy hash entry: {}", error),
            }
        }
        self.fuzzy_hashes.store(Arc::new(replacement));
        info!(
            "Hash matcher now stores {} fuzzy entries",
            self.fuzzy_hashes.load().len()
        );
        loaded
    }

    /// Load a CSV file containing hash entries. Both the native
    /// `hash,algorithm,is_malicious` schema and feeds with columns such as
    /// `md5_hash`, `sha256_hash`, `sha512_hash` and `ssdeep` are accepted.
    pub fn load_hashes_from_csv<P: AsRef<Path>>(&self, csv_path: P) -> Result<usize, HashError> {
        let path = csv_path.as_ref().to_path_buf();
        let entries = with_default_source(read_hashes_from_csv(&path)?, &path);
        let loaded = self.load_records(entries);
        info!("Loaded {} hash entries from CSV {}", loaded, path.display());
        Ok(loaded)
    }

    /// Load a JSON or JSON array database. Objects may use a generic `hash`
    /// field or separate `md5_hash`/`sha256_hash`/`ssdeep` fields.
    pub fn load_hashes_from_json<P: AsRef<Path>>(&self, json_path: P) -> Result<usize, HashError> {
        let path = json_path.as_ref().to_path_buf();
        let entries = with_default_source(read_hashes_from_json(&path)?, &path);
        Ok(self.load_records(entries))
    }

    /// Load one hash per line, optionally followed by an algorithm and a
    /// malicious flag. Comments beginning with `#` or `//` are ignored.
    pub fn load_hashes_from_text<P: AsRef<Path>>(&self, text_path: P) -> Result<usize, HashError> {
        let path = text_path.as_ref().to_path_buf();
        let entries = with_default_source(read_hashes_from_text(&path)?, &path);
        Ok(self.load_records(entries))
    }

    /// Load a SQLite database created by the local hash builder.
    ///
    /// Supports both the current `hashes(hash, algorithm, ...)` schema and the
    /// legacy `HashDB(hash, name)` schema.
    pub fn load_hashes_from_sqlite_db<P: AsRef<Path>>(
        &self,
        db_path: P,
    ) -> Result<usize, HashError> {
        let path = db_path.as_ref().to_path_buf();
        let entries = with_default_source(read_hashes_from_sqlite_db(&path)?, &path);
        let loaded = self.load_records(entries);
        info!(
            "Loaded {} hash entries from SQLite DB {}",
            loaded,
            path.display()
        );
        Ok(loaded)
    }

    /// Replace all in-memory entries only after the new database has been
    /// completely parsed, so concurrent scans never observe a partial update.
    pub fn replace_hashes_from_sqlite_db<P: AsRef<Path>>(
        &self,
        db_path: P,
    ) -> Result<usize, HashError> {
        let path = db_path.as_ref().to_path_buf();
        let entries = with_default_source(read_hashes_from_sqlite_db(&path)?, &path);
        if entries.is_empty() {
            return Err(HashError::EmptyDatabase);
        }
        self.replace_records(entries, &path)
    }

    fn replace_records(
        &self,
        entries: Vec<HashDbEntry>,
        source: &Path,
    ) -> Result<usize, HashError> {
        let replacement = DashMap::new();
        let mut fuzzy_replacement = Vec::new();
        let mut valid_entries = 0;
        for entry in entries {
            if is_fuzzy_algorithm(&entry.algorithm) {
                if let Ok(signature) = normalize_fuzzy_hash(&entry.hash) {
                    merge_fuzzy_entry(
                        &mut fuzzy_replacement,
                        FuzzyEntry {
                            algorithm: fuzzy_algorithm_name(&signature),
                            signature,
                            is_malicious: entry.is_malicious,
                            label: self.label.clone(),
                            sources: vec![entry.source],
                        },
                    );
                    valid_entries += 1;
                } else {
                    warn!("Skipping invalid fuzzy hash from SQLite DB: {}", entry.hash);
                }
            } else if let Ok(hash) = normalize_hash(&entry.hash) {
                let mut existing = replacement.entry(hash).or_insert(ExactEntry {
                    is_malicious: false,
                    sources: Vec::new(),
                });
                existing.is_malicious |= entry.is_malicious;
                merge_sources(&mut existing.sources, &entry.source);
                valid_entries += 1;
            } else {
                warn!("Skipping invalid hash from SQLite DB: {}", entry.hash);
            }
        }
        if valid_entries == 0 {
            return Err(HashError::EmptyDatabase);
        }
        self.hashes.store(Arc::new(replacement));
        self.fuzzy_hashes.store(Arc::new(fuzzy_replacement));
        info!(
            "Replaced hash database with {} entries from {}",
            valid_entries,
            source.display()
        );
        Ok(valid_entries)
    }

    /// Match a single file against the loaded hash set.
    pub fn match_file<P: AsRef<Path>>(&self, path: P) -> Result<Option<HashMatch>, HashError> {
        let path = path.as_ref();
        let mut file_hashes = compute_exact_hashes(path)?;
        let hashes = self.hashes.load();
        for file_hash in file_hashes.values() {
            if let Some(entry) = hashes.get(file_hash) {
                if entry.value().is_malicious {
                    return Ok(Some(HashMatch {
                        label: self.label.clone(),
                        hash: file_hash.to_string(),
                        algorithm: "exact".to_string(),
                        similarity: 100,
                        sources: entry.value().sources.clone(),
                    }));
                }
            }
        }

        let fuzzy_hashes = self.fuzzy_hashes.load();
        if fuzzy_hashes.is_empty() {
            return Ok(None);
        }
        file_hashes.fuzzy = ssdeep_hash_file(path)?;
        let mut best_match: Option<(&FuzzyEntry, u8)> = None;
        for entry in fuzzy_hashes.iter().filter(|entry| entry.is_malicious) {
            let similarity = fuzzy_similarity(&file_hashes.fuzzy, &entry.signature);
            if similarity >= FUZZY_MATCH_THRESHOLD
                && best_match
                    .as_ref()
                    .map(|(_, best_similarity)| similarity > *best_similarity)
                    .unwrap_or(true)
            {
                best_match = Some((entry, similarity));
            }
        }
        if let Some((entry, similarity)) = best_match {
            return Ok(Some(HashMatch {
                label: entry.label.clone(),
                hash: file_hashes.fuzzy,
                algorithm: entry.algorithm.clone(),
                similarity,
                sources: entry.sources.clone(),
            }));
        }

        Ok(None)
    }

    /// Return the number of loaded hash entries.
    pub fn entry_count(&self) -> usize {
        self.hashes.load().len() + self.fuzzy_hashes.load().len()
    }

    /// Match a batch of file paths in parallel.
    ///
    /// Returns three categories: clean, malicious, and unknown.
    pub fn match_batch(&self, paths: Vec<PathBuf>) -> HashBatchResult {
        let hashes = self.hashes.load_full();
        let fuzzy_hashes = self.fuzzy_hashes.load_full();
        let results: Vec<_> = paths
            .into_par_iter()
            .map(|path| {
                let path_buf = path.clone();
                debug!("Hash matching path {}", path_buf.display());
                match compute_exact_hashes(&path_buf) {
                    Ok(file_hashes) => {
                        let mut known_clean = false;
                        for file_hash in file_hashes.values() {
                            if let Some(entry) = hashes.get(file_hash) {
                                if entry.value().is_malicious {
                                    return (None, Some(path_buf), None);
                                }
                                known_clean = true;
                            }
                        }
                        if !fuzzy_hashes.is_empty() {
                            let fuzzy = match ssdeep_hash_file(&path_buf) {
                                Ok(value) => value,
                                Err(err) => {
                                    error!(
                                        "Failed to compute fuzzy hash for {}: {}",
                                        path_buf.display(),
                                        err
                                    );
                                    return (None, None, Some(path_buf));
                                }
                            };
                            if fuzzy_hashes.iter().any(|entry| {
                                entry.is_malicious
                                    && fuzzy_similarity(&fuzzy, &entry.signature)
                                        >= FUZZY_MATCH_THRESHOLD
                            }) {
                                return (None, Some(path_buf), None);
                            }
                        }
                        if known_clean {
                            (Some(path_buf), None, None)
                        } else {
                            (None, None, Some(path_buf))
                        }
                    }
                    Err(err) => {
                        error!(
                            "Failed to compute hashes for {}: {}",
                            path_buf.display(),
                            err
                        );
                        (None, None, Some(path_buf))
                    }
                }
            })
            .collect();

        let mut clean = Vec::new();
        let mut malicious = Vec::new();
        let mut unknown = Vec::new();
        for (maybe_clean, maybe_bad, maybe_unknown) in results {
            if let Some(path) = maybe_clean {
                clean.push(path);
            } else if let Some(path) = maybe_bad {
                malicious.push(path);
            } else if let Some(path) = maybe_unknown {
                unknown.push(path);
            }
        }

        HashBatchResult {
            clean,
            malicious,
            unknown,
        }
    }
}

/// Calculate the bounded local fuzzy signature used by `HashMatcher`.
pub fn calculate_fuzzy_hash<P: AsRef<Path>>(path: P) -> Result<String, HashError> {
    Ok(compute_file_hashes(path.as_ref())?.fuzzy)
}

#[derive(Debug, Clone)]
struct HashDbEntry {
    hash: String,
    algorithm: String,
    is_malicious: bool,
    source: String,
}

fn source_identifier(path: &Path) -> String {
    path.display().to_string()
}

fn with_default_source(mut entries: Vec<HashDbEntry>, path: &Path) -> Vec<HashDbEntry> {
    let source = source_identifier(path);
    for entry in &mut entries {
        if entry.source.trim().is_empty() {
            entry.source = source.clone();
        }
    }
    entries
}

fn merge_sources(sources: &mut Vec<String>, source: &str) {
    let source = source.trim();
    if !source.is_empty() && !sources.iter().any(|item| item == source) {
        sources.push(source.to_string());
    }
}

fn merge_fuzzy_entry(entries: &mut Vec<FuzzyEntry>, incoming: FuzzyEntry) {
    if let Some(existing) = entries.iter_mut().find(|entry| {
        entry.algorithm == incoming.algorithm && entry.signature == incoming.signature
    }) {
        existing.is_malicious |= incoming.is_malicious;
        for source in incoming.sources {
            merge_sources(&mut existing.sources, &source);
        }
        return;
    }
    entries.push(incoming);
}

fn read_hashes_from_sqlite_db(path: &Path) -> Result<Vec<HashDbEntry>, HashError> {
    let conn = Connection::open(path).map_err(|source| HashError::Sqlite {
        path: path.to_path_buf(),
        source,
    })?;

    let table = if conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND lower(name)='hashes')",
            [],
            |row| row.get(0),
        )
        .map_err(|source| HashError::Sqlite {
            path: path.to_path_buf(),
            source,
        })? {
        "hashes"
    } else {
        let has_legacy_schema: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND lower(name)='hashdb')",
                [],
                |row| row.get(0),
            )
            .map_err(|source| HashError::Sqlite {
                path: path.to_path_buf(),
                source,
            })?;
        if has_legacy_schema {
            "HashDB"
        } else {
            return Err(HashError::MissingHeader {
                field: "hashes or HashDB table".to_string(),
            });
        }
    };
    read_hashes_from_sqlite_table(&conn, table, path)
}

fn read_hashes_from_sqlite_table(
    conn: &Connection,
    table: &str,
    path: &Path,
) -> Result<Vec<HashDbEntry>, HashError> {
    let escaped_table = table.replace('"', "\"\"");
    let query = format!("SELECT * FROM \"{escaped_table}\"");
    let mut stmt = conn.prepare(&query).map_err(|source| HashError::Sqlite {
        path: path.to_path_buf(),
        source,
    })?;
    let columns = stmt
        .column_names()
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let hash_columns = columns
        .iter()
        .enumerate()
        .filter_map(|(index, name)| hash_column_algorithm(name).map(|algorithm| (index, algorithm)))
        .collect::<Vec<_>>();
    if hash_columns.is_empty() {
        return Err(HashError::MissingHeader {
            field: "hash column".to_string(),
        });
    }
    let algorithm_index = columns
        .iter()
        .position(|name| normalize_column_name(name) == "algorithm");
    let malicious_index = columns.iter().position(|name| {
        matches!(
            normalize_column_name(name).as_str(),
            "is_malicious" | "malicious" | "detected" | "verdict" | "status" | "threat"
        )
    });
    let source_index = columns.iter().position(|name| is_source_column(name));
    let rows = stmt
        .query_map([], move |row| {
            let row_malicious = malicious_index
                .and_then(|index| row.get_ref(index).ok())
                .and_then(sqlite_value_to_bool)
                .unwrap_or(true);
            let row_algorithm = algorithm_index
                .and_then(|index| row.get_ref(index).ok())
                .and_then(sqlite_value_to_string)
                .unwrap_or_else(|| "exact".to_string());
            let row_source = source_index
                .and_then(|index| row.get_ref(index).ok())
                .and_then(sqlite_value_to_string)
                .unwrap_or_default();
            let mut entries = Vec::new();
            for (index, fixed_algorithm) in &hash_columns {
                let Some(value) = row.get_ref(*index).ok().and_then(sqlite_value_to_string) else {
                    continue;
                };
                if value.trim().is_empty() {
                    continue;
                }
                entries.push(HashDbEntry {
                    hash: value,
                    algorithm: if fixed_algorithm.is_empty() {
                        row_algorithm.clone()
                    } else {
                        (*fixed_algorithm).to_string()
                    },
                    is_malicious: row_malicious,
                    source: row_source.clone(),
                });
            }
            Ok(entries)
        })
        .map_err(|source| HashError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?;

    let mut entries = Vec::new();
    for row in rows {
        let row_entries = row.map_err(|source| HashError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?;
        entries.extend(row_entries);
    }
    Ok(entries)
}

fn sqlite_value_to_string(value: ValueRef<'_>) -> Option<String> {
    match value {
        ValueRef::Text(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
        ValueRef::Integer(value) => Some(value.to_string()),
        ValueRef::Real(value) => Some(value.to_string()),
        ValueRef::Blob(_) | ValueRef::Null => None,
    }
}

fn sqlite_value_to_bool(value: ValueRef<'_>) -> Option<bool> {
    match value {
        ValueRef::Integer(value) => Some(value != 0),
        ValueRef::Real(value) => Some(value != 0.0),
        ValueRef::Text(bytes) => parse_malicious_value(&String::from_utf8_lossy(bytes), true),
        ValueRef::Blob(_) | ValueRef::Null => None,
    }
}

fn read_hash_entries_from_file(path: &Path) -> Result<Vec<HashDbEntry>, HashError> {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match extension.as_str() {
        "sqlite" | "sqlite3" | "db" => read_hashes_from_sqlite_db(path),
        "csv" | "tsv" => read_hashes_from_csv(path),
        "json" => read_hashes_from_json(path),
        "jsonl" | "ndjson" => read_hashes_from_jsonl(path),
        "txt" | "list" | "hashes" => read_hashes_from_text(path),
        "dat" => read_hashes_from_dat(path),
        _ => {
            let sample = read_file_text(path)?;
            let trimmed = sample.trim_start_matches('\u{feff}').trim_start();
            if trimmed.starts_with('{') || trimmed.starts_with('[') {
                read_hashes_from_json(path)
            } else if trimmed
                .lines()
                .next()
                .is_some_and(looks_like_hash_csv_header)
            {
                read_hashes_from_csv(path)
            } else {
                read_hashes_from_text(path)
            }
        }
    }
}

fn read_file_text(path: &Path) -> Result<String, HashError> {
    std::fs::read_to_string(path).map_err(|source| HashError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn read_hashes_from_csv(path: &Path) -> Result<Vec<HashDbEntry>, HashError> {
    let file = File::open(path).map_err(|source| HashError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let delimiter = path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("tsv"));
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .delimiter(if delimiter { b'\t' } else { b',' })
        .trim(csv::Trim::All)
        .from_reader(BufReader::new(file));
    let headers = reader
        .headers()
        .map_err(|source| HashError::Csv {
            path: path.to_path_buf(),
            source,
        })?
        .iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let hash_columns = headers
        .iter()
        .enumerate()
        .filter_map(|(index, name)| hash_column_algorithm(name).map(|algorithm| (index, algorithm)))
        .collect::<Vec<_>>();
    if hash_columns.is_empty() {
        return Err(HashError::MissingHeader {
            field: "hash column".to_string(),
        });
    }
    let algorithm_index = headers
        .iter()
        .position(|name| normalize_column_name(name) == "algorithm");
    let malicious_index = headers.iter().position(|name| {
        matches!(
            normalize_column_name(name).as_str(),
            "is_malicious" | "malicious" | "detected" | "verdict" | "status" | "threat"
        )
    });
    let source_index = headers.iter().position(|name| is_source_column(name));
    let mut entries = Vec::new();
    for record in reader.records() {
        let record = record.map_err(|source| HashError::Csv {
            path: path.to_path_buf(),
            source,
        })?;
        let row_malicious = malicious_index
            .and_then(|index| record.get(index))
            .and_then(|value| parse_malicious_value(value, true))
            .unwrap_or(true);
        let row_algorithm = algorithm_index
            .and_then(|index| record.get(index))
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("exact");
        let row_source = source_index
            .and_then(|index| record.get(index))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or_default();
        for (index, fixed_algorithm) in &hash_columns {
            let Some(value) = record.get(*index).map(str::trim) else {
                continue;
            };
            if value.is_empty() {
                continue;
            }
            entries.push(HashDbEntry {
                hash: value.to_string(),
                algorithm: if fixed_algorithm.is_empty() {
                    row_algorithm.to_string()
                } else {
                    (*fixed_algorithm).to_string()
                },
                is_malicious: row_malicious,
                source: row_source.to_string(),
            });
        }
    }
    Ok(entries)
}

fn read_hashes_from_text(path: &Path) -> Result<Vec<HashDbEntry>, HashError> {
    let file = File::open(path).map_err(|source| HashError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|source| HashError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if let Some(entry) = parse_text_hash_line(&line) {
            entries.push(entry);
        }
    }
    Ok(entries)
}

/// DAT files are commonly distributed as line-oriented hash lists, but their
/// delimiters vary between vendors. Reuse the conservative text parser and
/// additionally accept ClamAV-style `hash:size:name` records. Binary DAT/CVD
/// containers are intentionally not interpreted as hash lists.
fn read_hashes_from_dat(path: &Path) -> Result<Vec<HashDbEntry>, HashError> {
    let bytes = std::fs::read(path).map_err(|source| HashError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if bytes.contains(&0) {
        return Err(HashError::MissingHeader {
            field: "text-based DAT hash list".to_string(),
        });
    }
    let text = String::from_utf8_lossy(&bytes);
    let mut entries = Vec::new();
    for line in text.lines() {
        if let Some(entry) = parse_clamav_hash_line(line).or_else(|| parse_text_hash_line(line)) {
            entries.push(entry);
        }
    }
    Ok(entries)
}

fn parse_clamav_hash_line(line: &str) -> Option<HashDbEntry> {
    let mut parts = line.trim().splitn(3, ':');
    let candidate = parts.next()?.trim().trim_matches('"');
    if normalize_hash(candidate).is_err() {
        return None;
    }
    Some(HashDbEntry {
        hash: candidate.to_string(),
        algorithm: infer_algorithm(candidate).unwrap_or("exact").to_string(),
        is_malicious: true,
        source: String::new(),
    })
}

fn parse_text_hash_line(line: &str) -> Option<HashDbEntry> {
    let line = line.trim().trim_start_matches('\u{feff}');
    if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
        return None;
    }
    let line = line
        .split_once(" #")
        .map_or(line, |(value, _)| value)
        .trim();
    let tokens = line
        .split(|character: char| {
            character == ','
                || character == ';'
                || character == '|'
                || character == '\t'
                || character.is_ascii_whitespace()
        })
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    let mut explicit_algorithm = None;
    let mut malicious = true;
    for token in &tokens {
        if let Some(algorithm) = canonical_algorithm(token) {
            explicit_algorithm = Some(algorithm);
        } else if let Some(value) = parse_malicious_value(token, true) {
            malicious = value;
        }
    }
    for token in &tokens {
        let raw_candidate = token
            .split_once('=')
            .map_or(*token, |(_, value)| value)
            .trim_matches('"');
        if let Ok(normalized) = normalize_fuzzy_hash(raw_candidate) {
            return Some(HashDbEntry {
                hash: normalized.clone(),
                algorithm: fuzzy_algorithm_name(&normalized),
                is_malicious: malicious,
                source: String::new(),
            });
        }
        let (prefixed_algorithm, candidate) = raw_candidate
            .split_once(':')
            .filter(|(prefix, _)| canonical_algorithm(prefix).is_some())
            .map_or((None, raw_candidate), |(prefix, value)| {
                (canonical_algorithm(prefix), value)
            });
        if let Ok(normalized) = normalize_fuzzy_hash(candidate) {
            return Some(HashDbEntry {
                hash: normalized,
                algorithm: prefixed_algorithm
                    .or(explicit_algorithm)
                    .unwrap_or("ssdeep")
                    .to_string(),
                is_malicious: malicious,
                source: String::new(),
            });
        }
        if normalize_hash(candidate).is_ok() {
            return Some(HashDbEntry {
                hash: candidate.trim_matches('"').to_string(),
                algorithm: prefixed_algorithm
                    .or(explicit_algorithm)
                    .unwrap_or("exact")
                    .to_string(),
                is_malicious: malicious,
                source: String::new(),
            });
        }
    }
    None
}

fn read_hashes_from_json(path: &Path) -> Result<Vec<HashDbEntry>, HashError> {
    let text = read_file_text(path)?;
    let value =
        serde_json::from_str::<Value>(text.trim_start_matches('\u{feff}')).map_err(|source| {
            HashError::Json {
                path: path.to_path_buf(),
                source,
            }
        })?;
    let mut entries = Vec::new();
    collect_json_hashes(&value, true, &mut entries);
    Ok(entries)
}

fn read_hashes_from_jsonl(path: &Path) -> Result<Vec<HashDbEntry>, HashError> {
    let file = File::open(path).map_err(|source| HashError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for (line_number, line) in reader.lines().enumerate() {
        let line = line.map_err(|source| HashError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let line = line.trim().trim_start_matches('\u{feff}');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let value = serde_json::from_str::<Value>(line).map_err(|source| HashError::Json {
            path: path.to_path_buf(),
            source,
        })?;
        collect_json_hashes(&value, true, &mut entries);
        debug!(
            "parsed hash JSONL record {} from {}",
            line_number + 1,
            path.display()
        );
    }
    Ok(entries)
}

fn collect_json_hashes(value: &Value, default_malicious: bool, output: &mut Vec<HashDbEntry>) {
    match value {
        Value::String(value) => {
            if let Some(entry) = make_hash_entry(value, None, default_malicious) {
                output.push(entry);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_json_hashes(value, default_malicious, output);
            }
        }
        Value::Object(object) => {
            let row_malicious = object
                .iter()
                .find(|(key, _)| is_malicious_column(key))
                .and_then(|(_, value)| json_value_to_bool(value))
                .unwrap_or(default_malicious);
            let row_algorithm = object
                .get("algorithm")
                .and_then(Value::as_str)
                .unwrap_or("exact");
            let row_source = object
                .iter()
                .find(|(key, _)| is_source_column(key))
                .and_then(|(_, value)| value.as_str())
                .unwrap_or_default();
            let mut found_hash = false;
            for (key, value) in object {
                let Some(value) = value.as_str() else {
                    continue;
                };
                let Some(fixed_algorithm) = hash_column_algorithm(key) else {
                    continue;
                };
                let algorithm = if fixed_algorithm.is_empty() {
                    row_algorithm
                } else {
                    fixed_algorithm
                };
                if let Some(mut entry) = make_hash_entry(value, Some(algorithm), row_malicious) {
                    if !row_source.is_empty() {
                        entry.source = row_source.to_string();
                    }
                    output.push(entry);
                    found_hash = true;
                }
            }
            if !found_hash {
                for (key, value) in object {
                    if matches!(
                        normalize_column_name(key).as_str(),
                        "data" | "items" | "hashes" | "results" | "indicators" | "records"
                    ) {
                        collect_json_hashes(value, row_malicious, output);
                    }
                }
                for (key, value) in object {
                    if infer_algorithm(key).is_some() {
                        let malicious = json_value_to_bool(value).unwrap_or(row_malicious);
                        if let Some(mut entry) = make_hash_entry(key, None, malicious) {
                            if !row_source.is_empty() {
                                entry.source = row_source.to_string();
                            }
                            output.push(entry);
                        }
                    }
                }
            }
        }
        Value::Bool(_) | Value::Number(_) | Value::Null => {}
    }
}

fn make_hash_entry(
    value: &str,
    algorithm: Option<&str>,
    is_malicious: bool,
) -> Option<HashDbEntry> {
    let value = value.trim().trim_matches('"');
    if value.is_empty() {
        return None;
    }
    let algorithm = algorithm
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| infer_algorithm(value).unwrap_or("exact"));
    if is_fuzzy_algorithm(algorithm) {
        normalize_fuzzy_hash(value).ok().map(|hash| HashDbEntry {
            hash,
            algorithm: algorithm.to_string(),
            is_malicious,
            source: String::new(),
        })
    } else {
        normalize_hash(value).ok().map(|hash| HashDbEntry {
            hash,
            algorithm: algorithm.to_string(),
            is_malicious,
            source: String::new(),
        })
    }
}

fn json_value_to_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::Number(value) => value.as_i64().map(|value| value != 0),
        Value::String(value) => parse_malicious_value(value, true),
        Value::Array(_) | Value::Object(_) | Value::Null => None,
    }
}

fn normalize_column_name(value: &str) -> String {
    value
        .trim()
        .trim_start_matches('\u{feff}')
        .to_ascii_lowercase()
        .replace(['-', ' '], "_")
}

/// Returns an empty algorithm for a generic hash column so a row-level
/// `algorithm` field can decide whether it is MD5/SHA/ssdeep.
fn hash_column_algorithm(value: &str) -> Option<&'static str> {
    match normalize_column_name(value).as_str() {
        "hash" | "hashes" | "value" | "indicator" | "hash_value" => Some(""),
        "md5" | "md5_hash" => Some("md5"),
        "sha1" | "sha_1" | "sha1_hash" | "sha_1_hash" => Some("sha1"),
        "sha256" | "sha_256" | "sha256_hash" | "sha_256_hash" => Some("sha256"),
        "sha512" | "sha_512" | "sha512_hash" | "sha_512_hash" => Some("sha512"),
        "ssdeep" | "ssdeep_hash" | "fuzzy" | "fuzzy_hash" | "spamsum" => Some("ssdeep"),
        _ => None,
    }
}

fn is_malicious_column(value: &str) -> bool {
    matches!(
        normalize_column_name(value).as_str(),
        "is_malicious" | "malicious" | "detected" | "verdict" | "status" | "threat"
    )
}

fn is_source_column(value: &str) -> bool {
    matches!(
        normalize_column_name(value).as_str(),
        "source" | "provider" | "feed" | "dataset" | "origin"
    )
}

fn canonical_algorithm(value: &str) -> Option<&'static str> {
    match normalize_column_name(value).as_str() {
        "exact" | "hash" => Some("exact"),
        "md5" => Some("md5"),
        "sha1" | "sha_1" => Some("sha1"),
        "sha256" | "sha_256" => Some("sha256"),
        "sha512" | "sha_512" => Some("sha512"),
        "fuzzy" | "ssdeep" | "ssdeep_lite" | "spamsum" => Some("ssdeep"),
        _ => None,
    }
}

fn parse_malicious_value(value: &str, default: bool) -> Option<bool> {
    match value.trim().trim_matches('"').to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "y" | "malicious" | "infected" | "detected" | "online" => Some(true),
        "0" | "false" | "no" | "n" | "clean" | "benign" | "allow" | "allowed" | "undetected"
        | "whitelisted" => Some(false),
        "" => Some(default),
        _ => None,
    }
}

fn infer_algorithm(value: &str) -> Option<&'static str> {
    if normalize_fuzzy_hash(value).is_ok() {
        return Some("ssdeep");
    }
    match normalize_hash(value).ok()?.len() {
        32 => Some("md5"),
        40 => Some("sha1"),
        64 => Some("sha256"),
        128 => Some("sha512"),
        _ => None,
    }
}

fn looks_like_hash_csv_header(line: &str) -> bool {
    line.split([',', '\t', ';'])
        .map(str::trim)
        .any(|column| hash_column_algorithm(column).is_some())
}

fn normalize_hash(hash: &str) -> Result<String, HashError> {
    let normalized = hash.trim().to_lowercase();
    if !matches!(normalized.len(), 32 | 40 | 64 | 128)
        || !normalized.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(HashError::InvalidHashFormat {
            value: hash.to_string(),
        });
    }
    Ok(normalized)
}

fn is_fuzzy_algorithm(algorithm: &str) -> bool {
    matches!(
        algorithm.trim().to_ascii_lowercase().as_str(),
        "fuzzy" | "ssdeep" | "ssdeep-lite"
    )
}

fn normalize_fuzzy_hash(value: &str) -> Result<String, HashError> {
    parse_fuzzy_signature(value).map(|_| value.trim().to_string())
}

fn fuzzy_algorithm_name(signature: &str) -> String {
    if signature.trim_start().starts_with("ssdeep-lite:") {
        "ssdeep-lite".to_string()
    } else {
        "ssdeep".to_string()
    }
}

#[derive(Debug, Clone, Copy)]
struct ParsedFuzzy<'a> {
    block_size: usize,
    primary: &'a str,
    secondary: &'a str,
    legacy: bool,
}

fn parse_fuzzy_signature(value: &str) -> Result<ParsedFuzzy<'_>, HashError> {
    let normalized = value.trim();
    let parts: Vec<&str> = normalized.split(':').collect();
    let (block_size, primary, secondary, legacy) = match parts.as_slice() {
        [prefix, block_size, primary, secondary] if *prefix == "ssdeep-lite" => {
            (*block_size, *primary, *secondary, true)
        }
        [block_size, primary, secondary] => (*block_size, *primary, *secondary, false),
        _ => {
            return Err(HashError::InvalidFuzzyHash {
                value: value.to_string(),
            })
        }
    };

    let Ok(block_size) = block_size.parse::<usize>() else {
        return Err(HashError::InvalidFuzzyHash {
            value: value.to_string(),
        });
    };
    let valid_block_size = if legacy {
        (FUZZY_MIN_BLOCK_SIZE..=1 << 20).contains(&block_size)
    } else {
        is_standard_ssdeep_block_size(block_size)
    };
    let valid_signature = |signature: &str, max_len: usize| {
        !signature.is_empty()
            && signature.len() <= max_len
            && signature.bytes().all(|byte| FUZZY_ALPHABET.contains(&byte))
    };
    let valid_lengths = if legacy {
        valid_signature(primary, 64) && valid_signature(secondary, 64)
    } else {
        valid_signature(primary, FUZZY_PRIMARY_LIMIT - 1)
            && valid_signature(secondary, FUZZY_SECONDARY_LIMIT - 1)
    };
    if !valid_block_size || !valid_lengths {
        return Err(HashError::InvalidFuzzyHash {
            value: value.to_string(),
        });
    }
    Ok(ParsedFuzzy {
        block_size,
        primary,
        secondary,
        legacy,
    })
}

fn is_standard_ssdeep_block_size(block_size: usize) -> bool {
    if !(FUZZY_MIN_BLOCK_SIZE..=1 << 20).contains(&block_size)
        || !block_size.is_multiple_of(FUZZY_MIN_BLOCK_SIZE)
    {
        return false;
    }
    let mut quotient = block_size / FUZZY_MIN_BLOCK_SIZE;
    while quotient > 1 {
        if !quotient.is_multiple_of(2) {
            return false;
        }
        quotient /= 2;
    }
    true
}

#[derive(Clone, Copy)]
struct RollingHash {
    window: [u8; FUZZY_ROLLING_WINDOW],
    h1: u32,
    h2: u32,
    h3: u32,
    index: usize,
}

impl RollingHash {
    fn new() -> Self {
        Self {
            window: [0; FUZZY_ROLLING_WINDOW],
            h1: 0,
            h2: 0,
            h3: 0,
            index: 0,
        }
    }

    fn update(&mut self, byte: u8) {
        self.h2 = self.h2.wrapping_sub(self.h1);
        self.h2 = self
            .h2
            .wrapping_add((FUZZY_ROLLING_WINDOW as u32).wrapping_mul(byte as u32));
        self.h1 = self
            .h1
            .wrapping_add(byte as u32)
            .wrapping_sub(self.window[self.index] as u32);
        self.window[self.index] = byte;
        self.index = (self.index + 1) % FUZZY_ROLLING_WINDOW;
        self.h3 = (self.h3 << 5) ^ byte as u32;
    }

    fn sum(&self) -> u32 {
        self.h1.wrapping_add(self.h2).wrapping_add(self.h3)
    }
}

#[cfg(test)]
fn ssdeep_hash_bytes(data: &[u8]) -> String {
    let mut reader = data;
    let mut block_size = ssdeep_block_size(data.len());
    loop {
        let (primary, secondary) =
            piecewise_hash_reader(&mut reader, block_size).expect("slice reads cannot fail");
        if block_size == FUZZY_MIN_BLOCK_SIZE || primary.len() >= 32 {
            return format!("{block_size}:{primary}:{secondary}");
        }
        block_size /= 2;
        reader = data;
    }
}

fn ssdeep_block_size(file_size: usize) -> usize {
    let mut block_size = FUZZY_MIN_BLOCK_SIZE;
    while block_size.saturating_mul(64) < file_size {
        block_size = block_size.saturating_mul(2);
    }
    block_size
}

fn piecewise_hash_reader<R: Read>(
    mut reader: R,
    block_size: usize,
) -> std::io::Result<(String, String)> {
    let mut primary = String::new();
    let mut secondary = String::new();
    let mut primary_hash = FUZZY_HASH_INIT;
    let mut secondary_hash = FUZZY_HASH_INIT;
    let mut primary_rolling = RollingHash::new();
    let mut secondary_rolling = RollingHash::new();
    let mut buffer = [0u8; 8192];
    let block_size_u32 = block_size as u32;
    let secondary_block_size = block_size.saturating_mul(2);
    let secondary_block_size_u32 = secondary_block_size as u32;

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        for &byte in &buffer[..bytes_read] {
            primary_hash = primary_hash.wrapping_mul(FUZZY_HASH_PRIME) ^ byte as u32;
            secondary_hash = secondary_hash.wrapping_mul(FUZZY_HASH_PRIME) ^ byte as u32;
            primary_rolling.update(byte);
            secondary_rolling.update(byte);

            if primary.len() < FUZZY_PRIMARY_LIMIT - 1
                && primary_rolling.sum() % block_size_u32 == block_size_u32 - 1
            {
                primary.push(FUZZY_ALPHABET[(primary_hash & 0x3f) as usize] as char);
                primary_hash = FUZZY_HASH_INIT;
            }
            if secondary.len() < FUZZY_SECONDARY_LIMIT - 1
                && secondary_rolling.sum() % secondary_block_size_u32
                    == secondary_block_size_u32 - 1
            {
                secondary.push(FUZZY_ALPHABET[(secondary_hash & 0x3f) as usize] as char);
                secondary_hash = FUZZY_HASH_INIT;
            }
        }
    }

    if primary.len() < FUZZY_PRIMARY_LIMIT - 1 {
        primary.push(FUZZY_ALPHABET[(primary_hash & 0x3f) as usize] as char);
    }
    if secondary.len() < FUZZY_SECONDARY_LIMIT - 1 {
        secondary.push(FUZZY_ALPHABET[(secondary_hash & 0x3f) as usize] as char);
    }
    Ok((primary, secondary))
}

fn ssdeep_hash_file(path: &Path) -> Result<String, HashError> {
    let file_size = File::open(path)
        .and_then(|file| file.metadata())
        .map_err(|source| HashError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .len()
        .min(usize::MAX as u64) as usize;
    let mut block_size = ssdeep_block_size(file_size);
    loop {
        let file = File::open(path).map_err(|source| HashError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let (primary, secondary) =
            piecewise_hash_reader(file, block_size).map_err(|source| HashError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        if block_size == FUZZY_MIN_BLOCK_SIZE || primary.len() >= 32 {
            return Ok(format!("{block_size}:{primary}:{secondary}"));
        }
        block_size /= 2;
    }
}

fn fuzzy_similarity(left: &str, right: &str) -> u8 {
    let Ok(left) = parse_fuzzy_signature(left) else {
        return 0;
    };
    let Ok(right) = parse_fuzzy_signature(right) else {
        return 0;
    };
    if left.legacy || right.legacy {
        return legacy_similarity(left, right);
    }
    standard_similarity(left, right)
}

fn standard_similarity(left: ParsedFuzzy<'_>, right: ParsedFuzzy<'_>) -> u8 {
    if left.block_size == right.block_size {
        score_strings(left.primary, right.primary, left.block_size).max(score_strings(
            left.secondary,
            right.secondary,
            left.block_size.saturating_mul(2),
        ))
    } else if left.block_size == right.block_size.saturating_mul(2) {
        score_strings(left.primary, right.secondary, left.block_size)
    } else if right.block_size == left.block_size.saturating_mul(2) {
        score_strings(right.primary, left.secondary, right.block_size)
    } else {
        0
    }
}

fn legacy_similarity(left: ParsedFuzzy<'_>, right: ParsedFuzzy<'_>) -> u8 {
    if left.block_size != right.block_size
        && left.block_size != right.block_size.saturating_mul(2)
        && right.block_size != left.block_size.saturating_mul(2)
    {
        return 0;
    }
    let direct =
        weighted_signature_similarity(left.primary, left.secondary, right.primary, right.secondary);
    let cross = if left.block_size == right.block_size.saturating_mul(2)
        || right.block_size == left.block_size.saturating_mul(2)
    {
        weighted_signature_similarity(left.secondary, left.primary, right.primary, right.secondary)
    } else {
        0
    };
    direct.max(cross)
}

fn score_strings(left: &str, right: &str, block_size: usize) -> u8 {
    if left == right {
        return 100;
    }
    let left = trim_repeated(left.as_bytes());
    let right = trim_repeated(right.as_bytes());
    if left.len() < 7 || right.len() < 7 || !has_common_substring_7(&left, &right) {
        return 0;
    }
    let distance = levenshtein(&left, &right) as usize;
    let total_len = left.len() + right.len();
    let mut score = 100usize.saturating_sub(distance.saturating_mul(100) / total_len.max(1));
    let cap = block_size
        .saturating_div(3)
        .saturating_mul(left.len().min(right.len()));
    if block_size < 45 {
        score = score.min(cap);
    }
    score.min(100) as u8
}

fn trim_repeated(value: &[u8]) -> Vec<u8> {
    let mut trimmed = Vec::with_capacity(value.len());
    for &byte in value {
        if trimmed.len() < 3
            || trimmed[trimmed.len() - 3..]
                .iter()
                .any(|item| *item != byte)
        {
            trimmed.push(byte);
        }
    }
    trimmed
}

fn has_common_substring_7(left: &[u8], right: &[u8]) -> bool {
    left.windows(7)
        .any(|window| right.windows(7).any(|candidate| candidate == window))
}

fn levenshtein(left: &[u8], right: &[u8]) -> u32 {
    if left.len() < right.len() {
        return levenshtein(right, left);
    }
    let mut previous: Vec<u32> = (0..=right.len() as u32).collect();
    for (left_index, left_byte) in left.iter().enumerate() {
        let mut current = vec![left_index as u32 + 1; right.len() + 1];
        for (right_index, right_byte) in right.iter().enumerate() {
            current[right_index + 1] = if left_byte == right_byte {
                previous[right_index]
            } else {
                1 + previous[right_index]
                    .min(previous[right_index + 1])
                    .min(current[right_index])
            };
        }
        previous = current;
    }
    previous[right.len()]
}

fn weighted_signature_similarity(
    left_primary: &str,
    left_secondary: &str,
    right_primary: &str,
    right_secondary: &str,
) -> u8 {
    let primary = lcs_similarity(left_primary.as_bytes(), right_primary.as_bytes());
    let secondary = lcs_similarity(left_secondary.as_bytes(), right_secondary.as_bytes());
    ((primary as u16 * 70 + secondary as u16 * 30) / 100) as u8
}

fn lcs_similarity(left: &[u8], right: &[u8]) -> u8 {
    if left.is_empty() && right.is_empty() {
        return 100;
    }
    let mut previous = vec![0u16; right.len() + 1];
    for left_byte in left {
        let mut current = vec![0u16; right.len() + 1];
        for (index, right_byte) in right.iter().enumerate() {
            current[index + 1] = if left_byte == right_byte {
                previous[index] + 1
            } else {
                current[index].max(previous[index + 1])
            };
        }
        previous = current;
    }
    let denominator = (left.len() + right.len()) as u16;
    ((previous[right.len()] * 200) / denominator).min(100) as u8
}

struct FileHashes {
    md5: String,
    sha1: String,
    sha256: String,
    sha512: String,
    fuzzy: String,
}

impl FileHashes {
    fn values(&self) -> [&str; 4] {
        [&self.sha512, &self.sha256, &self.sha1, &self.md5]
    }
}

fn compute_file_hashes(path: &Path) -> Result<FileHashes, HashError> {
    let mut hashes = compute_exact_hashes(path)?;
    hashes.fuzzy = ssdeep_hash_file(path)?;
    Ok(hashes)
}

fn compute_exact_hashes(path: &Path) -> Result<FileHashes, HashError> {
    let file = File::open(path).map_err(|source| HashError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    let mut reader = BufReader::new(file);
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut sha512 = Sha512::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = reader.read(&mut buffer).map_err(|source| HashError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if bytes_read == 0 {
            break;
        }
        md5.update(&buffer[..bytes_read]);
        sha1.update(&buffer[..bytes_read]);
        sha256.update(&buffer[..bytes_read]);
        sha512.update(&buffer[..bytes_read]);
    }

    Ok(FileHashes {
        md5: hex_encode(md5.finalize()),
        sha1: hex_encode(sha1.finalize()),
        sha256: hex_encode(sha256.finalize()),
        sha512: hex_encode(sha512.finalize()),
        fuzzy: String::new(),
    })
}

#[cfg(test)]
fn compute_sha256(path: &Path) -> Result<String, HashError> {
    Ok(compute_file_hashes(path)?.sha256)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_load_hashes_from_sqlite_db() {
        let dir = tempdir().expect("create temp dir");
        let db_path = dir.path().join("hashes.sqlite");
        let conn = Connection::open(&db_path).expect("open sqlite db");
        conn.execute(
            "CREATE TABLE hashes (hash TEXT PRIMARY KEY, algorithm TEXT, source TEXT, first_seen TEXT, meta TEXT)",
            [],
        )
        .expect("create hashes table");

        let sha256_hash = "0".repeat(64);
        conn.execute(
            "INSERT INTO hashes (hash, algorithm, source, first_seen, meta) VALUES (?1, ?2, 'test', NULL, '{}')",
            rusqlite::params![sha256_hash, "sha256"],
        )
        .expect("insert sha256 hash");

        let matcher = HashMatcher::new(None);
        let loaded = matcher
            .load_hashes_from_sqlite_db(&db_path)
            .expect("load sqlite db");
        assert_eq!(loaded, 1);
        assert_eq!(matcher.entry_count(), 1);
    }

    #[test]
    fn test_match_file_returns_match_for_loaded_sqlite_hash() {
        let dir = tempdir().expect("create temp dir");
        let db_path = dir.path().join("hashes.sqlite");
        let file_path = dir.path().join("sample.bin");
        let mut file = File::create(&file_path).expect("create sample file");
        file.write_all(b"sample-content")
            .expect("write sample content");
        file.flush().expect("flush sample file");

        let conn = Connection::open(&db_path).expect("open sqlite db");
        conn.execute(
            "CREATE TABLE hashes (hash TEXT PRIMARY KEY, algorithm TEXT, source TEXT, first_seen TEXT, meta TEXT)",
            [],
        )
        .expect("create hashes table");

        let sample_hash = compute_sha256(&file_path).expect("compute sample hash");
        conn.execute(
            "INSERT INTO hashes (hash, algorithm, source, first_seen, meta) VALUES (?1, ?2, 'test', NULL, '{}')",
            rusqlite::params![sample_hash, "sha256"],
        )
        .expect("insert sample hash");

        let matcher = HashMatcher::new_with_label(None, "local_db".to_string());
        matcher
            .load_hashes_from_sqlite_db(&db_path)
            .expect("load sqlite db");
        let matched = matcher.match_file(&file_path).expect("match file");
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().label, "local_db");
    }

    #[test]
    fn test_load_fuzzy_hash_from_sqlite_algorithm_column() {
        let dir = tempdir().expect("create temp dir");
        let db_path = dir.path().join("fuzzy.sqlite");
        let file_path = dir.path().join("fuzzy-sample.bin");
        let original: Vec<u8> = (0..20_000).map(|index| (index % 251) as u8).collect();
        let signature = ssdeep_hash_bytes(&original);
        let mut edited = original;
        edited[12_345] ^= 0x5a;
        std::fs::write(&file_path, edited).expect("write sample");

        let conn = Connection::open(&db_path).expect("open sqlite db");
        conn.execute(
            "CREATE TABLE hashes (hash TEXT PRIMARY KEY, algorithm TEXT, source TEXT, first_seen TEXT, meta TEXT)",
            [],
        )
        .expect("create hashes table");
        conn.execute(
            "INSERT INTO hashes (hash, algorithm, source, first_seen, meta) VALUES (?1, 'fuzzy', 'test', NULL, '{}')",
            rusqlite::params![signature],
        )
        .expect("insert fuzzy hash");

        let matcher = HashMatcher::new_with_label(None, "fuzzy_sqlite".to_string());
        assert_eq!(
            matcher
                .load_hashes_from_sqlite_db(&db_path)
                .expect("load sqlite"),
            1
        );
        let matched = matcher
            .match_file(&file_path)
            .expect("match file")
            .expect("expected fuzzy match");
        assert_eq!(matched.algorithm, "ssdeep");
    }

    #[test]
    fn test_load_and_match_legacy_md5_database() {
        let dir = tempdir().expect("create temp dir");
        let db_path = dir.path().join("HashDB.db");
        let file_path = dir.path().join("legacy-sample.bin");
        std::fs::write(&file_path, b"legacy sample").expect("write sample");

        let sample_hash = hex_encode(Md5::digest(b"legacy sample"));
        let conn = Connection::open(&db_path).expect("open sqlite db");
        conn.execute(
            "CREATE TABLE HashDB (hash TEXT NOT NULL, name TEXT NOT NULL)",
            [],
        )
        .expect("create legacy table");
        conn.execute(
            "INSERT INTO HashDB (hash, name) VALUES (?1, ?2)",
            rusqlite::params![sample_hash, "legacy-malware"],
        )
        .expect("insert hash");
        drop(conn);

        let matcher = HashMatcher::new_with_label(None, "legacy_db".to_string());
        assert_eq!(
            matcher
                .load_hashes_from_sqlite_db(&db_path)
                .expect("load legacy db"),
            1
        );
        let matched = matcher.match_file(&file_path).expect("match file");
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().hash.len(), 32);

        let invalid_path = dir.path().join("invalid.sqlite");
        Connection::open(&invalid_path).expect("create invalid database");
        assert!(matcher
            .replace_hashes_from_sqlite_db(&invalid_path)
            .is_err());
        assert_eq!(matcher.entry_count(), 1);
    }

    #[test]
    fn test_load_hashes_from_csv() {
        let dir = tempdir().expect("create temp dir");
        let csv_path = dir.path().join("hashes.csv");
        let mut file = File::create(&csv_path).expect("create csv");
        writeln!(file, "hash,is_malicious").expect("write header");
        writeln!(file, "{},false", "0".repeat(64)).expect("write hash line");
        writeln!(file, "{},true", "1".repeat(64)).expect("write hash line");
        file.flush().expect("flush csv");

        let matcher = HashMatcher::new(None);
        let loaded = matcher.load_hashes_from_csv(&csv_path).expect("load csv");
        assert_eq!(loaded, 2);
        assert_eq!(matcher.entry_count(), 2);
    }

    #[test]
    fn test_loads_json_and_sha512_hashes() {
        let dir = tempdir().expect("create temp dir");
        let file_path = dir.path().join("json-sample.bin");
        let data = b"json-format-sample";
        std::fs::write(&file_path, data).expect("write sample");
        let md5_hash = hex_encode(Md5::digest(data));
        let sha512_hash = hex_encode(Sha512::digest(data));
        let json_path = dir.path().join("hashes.json");
        std::fs::write(
            &json_path,
            serde_json::json!([{"md5_hash": md5_hash}, {"sha512_hash": sha512_hash}]).to_string(),
        )
        .expect("write json");

        let matcher = HashMatcher::new_with_label(None, "json_db".to_string());
        assert_eq!(matcher.load_from_file(&json_path).expect("load json"), 2);
        let matched = matcher
            .match_file(&file_path)
            .expect("match json sample")
            .expect("expected sha512 match");
        assert_eq!(matched.hash, sha512_hash);
    }

    #[test]
    fn test_loads_multicolumn_csv_and_plain_text() {
        let dir = tempdir().expect("create temp dir");
        let data = b"multi-format-sample";
        let file_path = dir.path().join("multi-format.bin");
        std::fs::write(&file_path, data).expect("write sample");
        let sha256_hash = hex_encode(Sha256::digest(data));
        let sha512_hash = hex_encode(Sha512::digest(data));

        let csv_path = dir.path().join("feed.csv");
        std::fs::write(
            &csv_path,
            format!("sha256_hash,sha512_hash,status\n{sha256_hash},{sha512_hash},malicious\n"),
        )
        .expect("write feed");
        let csv_matcher = HashMatcher::new(None);
        assert_eq!(csv_matcher.load_from_file(&csv_path).expect("load feed"), 2);
        assert!(csv_matcher
            .match_file(&file_path)
            .expect("match feed")
            .is_some());

        let text_path = dir.path().join("hashes.list");
        std::fs::write(
            &text_path,
            format!("# comments are ignored\nsha512 {sha512_hash} true\n"),
        )
        .expect("write text list");
        let text_matcher = HashMatcher::new(None);
        assert_eq!(
            text_matcher.load_from_file(&text_path).expect("load text"),
            1
        );
        assert!(text_matcher
            .match_file(&file_path)
            .expect("match text list")
            .is_some());
    }

    #[test]
    fn test_loads_jsonl_and_sqlite_hash_columns() {
        let dir = tempdir().expect("create temp dir");
        let data = b"jsonl-and-sqlite-sample";
        let file_path = dir.path().join("sample.bin");
        std::fs::write(&file_path, data).expect("write sample");
        let sha1_hash = hex_encode(Sha1::digest(data));

        let jsonl_path = dir.path().join("hashes.jsonl");
        std::fs::write(
            &jsonl_path,
            format!("{{\"sha1_hash\":\"{sha1_hash}\",\"malicious\":true}}\n"),
        )
        .expect("write jsonl");
        let jsonl_matcher = HashMatcher::new(None);
        assert_eq!(
            jsonl_matcher
                .load_from_file(&jsonl_path)
                .expect("load jsonl"),
            1
        );
        assert!(jsonl_matcher
            .match_file(&file_path)
            .expect("match jsonl")
            .is_some());

        let db_path = dir.path().join("columns.sqlite");
        let conn = Connection::open(&db_path).expect("open sqlite db");
        conn.execute(
            "CREATE TABLE hashes (md5_hash TEXT, sha1_hash TEXT, malicious INTEGER)",
            [],
        )
        .expect("create multi-column schema");
        conn.execute(
            "INSERT INTO hashes (md5_hash, sha1_hash, malicious) VALUES (NULL, ?1, 1)",
            rusqlite::params![sha1_hash],
        )
        .expect("insert multi-column hash");
        let sqlite_matcher = HashMatcher::new(None);
        assert_eq!(
            sqlite_matcher
                .load_from_file(&db_path)
                .expect("load sqlite columns"),
            1
        );
        assert!(sqlite_matcher
            .match_file(&file_path)
            .expect("match sqlite columns")
            .is_some());
    }

    #[test]
    fn test_dat_support_and_cross_source_merge() {
        let dir = tempdir().expect("create temp dir");
        let data = b"dat-merge-sample";
        let file_path = dir.path().join("sample.bin");
        std::fs::write(&file_path, data).expect("write sample");
        let sha256_hash = hex_encode(Sha256::digest(data));

        let dat_path = dir.path().join("vendor-a.dat");
        std::fs::write(
            &dat_path,
            format!("# clamav-style DAT\n{sha256_hash}:0:Test.Detected\n"),
        )
        .expect("write dat");
        let csv_path = dir.path().join("vendor-b.csv");
        std::fs::write(
            &csv_path,
            format!("hash,is_malicious\n{sha256_hash},false\n"),
        )
        .expect("write second source");

        let matcher = HashMatcher::new_with_label(None, "merged".to_string());
        assert_eq!(matcher.load_from_file(&dat_path).expect("load dat"), 1);
        assert_eq!(matcher.load_from_file(&csv_path).expect("load csv"), 1);
        assert_eq!(matcher.entry_count(), 1);

        let matched = matcher
            .match_file(&file_path)
            .expect("match merged hash")
            .expect("expected merged match");
        assert_eq!(matched.sources.len(), 2);
        assert!(matched.sources.contains(&dat_path.display().to_string()));
        assert!(matched.sources.contains(&csv_path.display().to_string()));
    }

    #[test]
    fn test_match_batch_classification() {
        let dir = tempdir().expect("create temp dir");
        let clean_path = dir.path().join("clean.bin");
        let malicious_path = dir.path().join("bad.bin");
        let unknown_path = dir.path().join("unknown.bin");

        let mut clean_file = File::create(&clean_path).expect("create clean");
        clean_file.write_all(b"clean-content").expect("write clean");

        let mut malicious_file = File::create(&malicious_path).expect("create bad");
        malicious_file.write_all(b"bad-content").expect("write bad");

        let matcher = HashMatcher::new(None);
        let bad_hash = compute_sha256(&malicious_path).expect("compute bad hash");
        matcher.load_hashes(vec![(bad_hash, true)]);

        let result = matcher.match_batch(vec![
            clean_path.clone(),
            malicious_path.clone(),
            unknown_path.clone(),
        ]);
        assert_eq!(result.malicious, vec![malicious_path]);
        assert_eq!(result.clean.len(), 0);
        assert_eq!(result.unknown.len(), 2);
    }

    #[test]
    fn test_normalize_hash_failure() {
        let err = normalize_hash("not-a-valid-hash").unwrap_err();
        assert!(matches!(err, HashError::InvalidHashFormat { .. }));
    }

    #[test]
    fn test_fuzzy_match_survives_local_edit() {
        let dir = tempdir().expect("create temp dir");
        let file_path = dir.path().join("edited.bin");
        let original: Vec<u8> = (0..20_000).map(|index| (index % 251) as u8).collect();
        let signature = ssdeep_hash_bytes(&original);
        let mut edited = original;
        edited[12_345] ^= 0x5a;
        std::fs::write(&file_path, edited).expect("write edited sample");

        let matcher = HashMatcher::new_with_label(None, "fuzzy_db".to_string());
        assert_eq!(matcher.load_fuzzy_hashes(vec![(signature, true)]), 1);
        let matched = matcher
            .match_file(&file_path)
            .expect("fuzzy match file")
            .expect("expected fuzzy match");
        assert_eq!(matched.algorithm, "ssdeep");
        assert!(matched.similarity >= FUZZY_MATCH_THRESHOLD);
    }

    #[test]
    fn test_clean_fuzzy_signature_does_not_classify() {
        let dir = tempdir().expect("create temp dir");
        let file_path = dir.path().join("clean-like.bin");
        let data: Vec<u8> = (0..20_000).map(|index| (index % 251) as u8).collect();
        let signature = ssdeep_hash_bytes(&data);
        std::fs::write(&file_path, data).expect("write clean-like sample");

        let matcher = HashMatcher::new(None);
        assert_eq!(matcher.load_fuzzy_hashes(vec![(signature, false)]), 1);
        assert!(matcher
            .match_file(&file_path)
            .expect("match file")
            .is_none());
    }

    #[test]
    fn test_ssdeep_matches_known_interoperability_vector() {
        assert_eq!(ssdeep_hash_bytes(b"Hello there!"), "3:aNRn:aNRn");
        assert_eq!(fuzzy_similarity("3:aNRn:aNRn", "3:aNRn:aNRn"), 100);
    }

    #[test]
    fn test_legacy_ssdeep_lite_signature_remains_readable() {
        let legacy = "ssdeep-lite:3:ABCDEFG:ABCDEFG";
        assert_eq!(
            normalize_fuzzy_hash(legacy).expect("legacy signature"),
            legacy
        );
        assert_eq!(fuzzy_algorithm_name(legacy), "ssdeep-lite");
    }
}
