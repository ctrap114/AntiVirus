use arc_swap::ArcSwap;
use rusqlite::Connection;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const DEFAULT_MIN_CONFIDENCE: u8 = 70;

#[derive(Debug, Error)]
pub enum ThreatIntelError {
    #[error("SQLite error reading {path}: {source}")]
    Sqlite {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatIntelRecord {
    pub value: String,
    pub ioc_type: String,
    pub source: String,
    pub confidence: u8,
    pub malware: Option<String>,
    pub tags: Option<String>,
    pub reference: Option<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatIntelMatch {
    pub observed: String,
    pub record: ThreatIntelRecord,
}

impl ThreatIntelMatch {
    pub fn description(&self) -> String {
        let mut description = format!(
            "{}={} source={} confidence={}",
            self.record.ioc_type, self.record.value, self.record.source, self.record.confidence
        );
        if let Some(malware) = &self.record.malware {
            if !malware.is_empty() {
                description.push_str(&format!(" malware={malware}"));
            }
        }
        description
    }
}

#[derive(Debug, Default, Clone)]
struct ThreatIntelSnapshot {
    by_key: HashMap<String, Vec<ThreatIntelRecord>>,
    networks: Vec<ThreatIntelNetwork>,
}

#[derive(Debug, Clone)]
struct ThreatIntelNetwork {
    address: IpAddr,
    prefix: u8,
    record: ThreatIntelRecord,
}

/// Read-only, atomically replaceable network IOC matcher.
///
/// The matcher deliberately does not block traffic or query the network. It
/// only scores endpoints observed by the sandbox and ignores expired or
/// low-confidence database rows.
pub struct ThreatIntelMatcher {
    snapshot: ArcSwap<ThreatIntelSnapshot>,
    min_confidence: u8,
}

impl ThreatIntelMatcher {
    pub fn new(min_confidence: u8) -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(ThreatIntelSnapshot::default()),
            min_confidence: min_confidence.max(1),
        }
    }

    pub fn with_default_confidence() -> Self {
        Self::new(DEFAULT_MIN_CONFIDENCE)
    }

    pub fn load_from_sqlite_db<P: AsRef<Path>>(
        &self,
        db_path: P,
    ) -> Result<usize, ThreatIntelError> {
        let entries = read_iocs_from_sqlite_db(db_path.as_ref(), self.min_confidence)?;
        let current = self.snapshot.load_full();
        let mut replacement = (*current).clone();
        let mut loaded = 0;
        for record in entries {
            add_record(&mut replacement, record);
            loaded += 1;
        }
        self.snapshot.store(Arc::new(replacement));
        Ok(loaded)
    }

    pub fn replace_from_sqlite_db<P: AsRef<Path>>(
        &self,
        db_path: P,
    ) -> Result<usize, ThreatIntelError> {
        let entries = read_iocs_from_sqlite_db(db_path.as_ref(), self.min_confidence)?;
        let loaded = entries.len();
        let mut replacement = ThreatIntelSnapshot::default();
        for record in entries {
            add_record(&mut replacement, record);
        }
        self.snapshot.store(Arc::new(replacement));
        Ok(loaded)
    }

    pub fn entry_count(&self) -> usize {
        let snapshot = self.snapshot.load();
        let exact = snapshot
            .by_key
            .values()
            .flatten()
            .filter(|record| !record_is_expired(record))
            .count();
        let networks = snapshot
            .networks
            .iter()
            .filter(|network| !record_is_expired(&network.record))
            .count();
        exact + networks
    }

    pub fn match_observation(&self, observation: &str) -> Vec<ThreatIntelMatch> {
        let snapshot = self.snapshot.load();
        let mut matches = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for key in observation_keys(observation) {
            if let Some(records) = snapshot.by_key.get(&key) {
                for record in records {
                    if record_is_expired(record) {
                        continue;
                    }
                    let identity =
                        format!("{}:{}:{}", record.source, record.ioc_type, record.value);
                    if seen.insert(identity) {
                        matches.push(ThreatIntelMatch {
                            observed: observation.to_string(),
                            record: record.clone(),
                        });
                    }
                }
            }
        }
        for address in observation_keys(observation)
            .into_iter()
            .filter_map(|value| value.parse::<IpAddr>().ok())
        {
            for network in &snapshot.networks {
                if record_is_expired(&network.record)
                    || !ip_in_network(address, network.address, network.prefix)
                {
                    continue;
                }
                let identity = format!(
                    "{}:{}:{}",
                    network.record.source, network.record.ioc_type, network.record.value
                );
                if seen.insert(identity) {
                    matches.push(ThreatIntelMatch {
                        observed: observation.to_string(),
                        record: network.record.clone(),
                    });
                }
            }
        }
        matches
    }

    pub fn match_observations<'a, I>(&self, observations: I) -> Vec<ThreatIntelMatch>
    where
        I: IntoIterator<Item = &'a str>,
    {
        observations
            .into_iter()
            .flat_map(|observation| self.match_observation(observation))
            .collect()
    }
}

fn read_iocs_from_sqlite_db(
    path: &Path,
    min_confidence: u8,
) -> Result<Vec<ThreatIntelRecord>, ThreatIntelError> {
    let connection = Connection::open(path).map_err(|source| ThreatIntelError::Sqlite {
        path: path.to_path_buf(),
        source,
    })?;
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='iocs')",
            [],
            |row| row.get(0),
        )
        .map_err(|source| ThreatIntelError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?;
    if !exists {
        return Ok(Vec::new());
    }

    let mut statement = connection
        .prepare(
            "SELECT value, ioc_type, source, COALESCE(confidence, 0), first_seen,
                    last_seen, expires_at, malware, tags, reference
             FROM iocs",
        )
        .map_err(|source| ThreatIntelError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<String>>(9)?,
            ))
        })
        .map_err(|source| ThreatIntelError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?;

    let now = unix_now();
    let mut entries = Vec::new();
    for row in rows {
        let (
            value,
            ioc_type,
            source,
            confidence,
            first_seen,
            last_seen,
            expires_at,
            malware,
            tags,
            reference,
        ) = row.map_err(|source| ThreatIntelError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?;
        let confidence = confidence.clamp(0, 100) as u8;
        if confidence < min_confidence
            || expires_at
                .as_deref()
                .and_then(parse_rfc3339_epoch)
                .is_some_and(|expires| expires <= now)
        {
            continue;
        }
        let Some((value, ioc_type)) = normalize_indicator(&value, &ioc_type) else {
            continue;
        };
        entries.push(ThreatIntelRecord {
            value,
            ioc_type,
            source,
            confidence,
            malware,
            tags,
            reference,
            first_seen,
            last_seen,
            expires_at,
        });
    }
    Ok(entries)
}

fn normalize_indicator(value: &str, ioc_type: &str) -> Option<(String, String)> {
    let value = value
        .trim()
        .to_ascii_lowercase()
        .trim_end_matches('.')
        .to_string();
    match ioc_type.trim().to_ascii_lowercase().as_str() {
        "ip" | "ipv4" | "ipv6" => value.parse::<IpAddr>().ok().map(|address| {
            (
                address.to_string(),
                if address.is_ipv4() { "ipv4" } else { "ipv6" }.to_string(),
            )
        }),
        "domain" => normalize_domain(&value).map(|domain| (domain, "domain".to_string())),
        "url" if value.starts_with("http://") || value.starts_with("https://") => {
            Some((value, "url".to_string()))
        }
        "cidr" | "network" => parse_cidr(&value)
            .map(|(address, prefix)| (format!("{address}/{prefix}"), "cidr".to_string())),
        _ => None,
    }
}

fn add_record(snapshot: &mut ThreatIntelSnapshot, record: ThreatIntelRecord) {
    if record.ioc_type == "cidr" {
        if let Some((address, prefix)) = parse_cidr(&record.value) {
            snapshot.networks.push(ThreatIntelNetwork {
                address,
                prefix,
                record,
            });
        }
        return;
    }
    for key in indicator_keys(&record.value, &record.ioc_type) {
        snapshot.by_key.entry(key).or_default().push(record.clone());
    }
}

fn record_is_expired(record: &ThreatIntelRecord) -> bool {
    record
        .expires_at
        .as_deref()
        .and_then(parse_rfc3339_epoch)
        .is_some_and(|expires| expires <= unix_now())
}

fn parse_cidr(value: &str) -> Option<(IpAddr, u8)> {
    let (address, prefix) = value.trim().split_once('/')?;
    let address = address.parse::<IpAddr>().ok()?;
    let prefix = prefix.parse::<u8>().ok()?;
    let bits: u32 = if address.is_ipv4() { 32 } else { 128 };
    if u32::from(prefix) > bits {
        return None;
    }
    let masked = match address {
        IpAddr::V4(address) => {
            let raw = u32::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (bits - u32::from(prefix))
            };
            IpAddr::V4(std::net::Ipv4Addr::from(raw & mask))
        }
        IpAddr::V6(address) => {
            let raw = u128::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (bits - u32::from(prefix))
            };
            IpAddr::V6(std::net::Ipv6Addr::from(raw & mask))
        }
    };
    Some((masked, prefix))
}

fn ip_in_network(address: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (address, network) {
        (IpAddr::V4(address), IpAddr::V4(network)) => {
            if prefix > 32 {
                return false;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            (u32::from(address) & mask) == (u32::from(network) & mask)
        }
        (IpAddr::V6(address), IpAddr::V6(network)) => {
            if prefix > 128 {
                return false;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            (u128::from(address) & mask) == (u128::from(network) & mask)
        }
        _ => false,
    }
}
fn indicator_keys(value: &str, ioc_type: &str) -> Vec<String> {
    let Some((value, ioc_type)) = normalize_indicator(value, ioc_type) else {
        return Vec::new();
    };
    if ioc_type == "url" {
        let mut keys = vec![value.clone()];
        if let Some(host) = endpoint_host(&value) {
            keys.push(host);
        }
        keys
    } else {
        vec![value]
    }
}

fn observation_keys(observation: &str) -> Vec<String> {
    let mut keys = Vec::new();
    for token in observation.split(|character: char| {
        character.is_whitespace() || matches!(character, ',' | ';' | '(' | ')' | '"' | '\'')
    }) {
        let token =
            token.trim_matches(|character: char| matches!(character, '[' | ']' | '{' | '}'));
        if token.is_empty() {
            continue;
        }
        if let Some((value, _kind)) = normalize_indicator(token, "url") {
            keys.push(value.clone());
            if let Some(host) = endpoint_host(&value) {
                keys.push(host);
            }
        }
        if let Ok(address) = token
            .trim_matches(|character: char| matches!(character, '[' | ']'))
            .parse::<IpAddr>()
        {
            keys.push(address.to_string());
        }
        if let Some(host) = endpoint_host(token) {
            keys.push(host);
        }
    }
    keys.sort();
    keys.dedup();
    keys
}

fn endpoint_host(value: &str) -> Option<String> {
    let mut candidate = value.trim();
    if let Some((_, rest)) = candidate.split_once("://") {
        candidate = rest;
    }
    candidate = candidate.split(['/', '?', '#']).next().unwrap_or(candidate);
    candidate = candidate.rsplit('@').next().unwrap_or(candidate);
    if candidate.starts_with('[') {
        return candidate
            .strip_prefix('[')
            .and_then(|value| value.split(']').next())
            .and_then(|value| value.parse::<IpAddr>().ok())
            .map(|value| value.to_string());
    }
    if let Ok(address) = candidate.parse::<IpAddr>() {
        return Some(address.to_string());
    }
    if let Some((host, port)) = candidate.rsplit_once(':') {
        if port.parse::<u16>().is_ok() {
            candidate = host;
        }
    }
    normalize_domain(candidate)
}

fn normalize_domain(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty() || value.len() > 253 || !value.contains('.') {
        return None;
    }
    let valid = value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    });
    valid.then_some(value)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn parse_rfc3339_epoch(value: &str) -> Option<i64> {
    let (date, time) = value.trim().split_once('T')?;
    let mut date_parts = date.split('-');
    let year = date_parts.next()?.parse::<i64>().ok()?;
    let month = date_parts.next()?.parse::<i64>().ok()?;
    let day = date_parts.next()?.parse::<i64>().ok()?;
    let time = time.trim_end_matches('Z');
    let time = time.split(['+', '-']).next().unwrap_or(time);
    let mut time_parts = time.split(':');
    let hour = time_parts.next()?.parse::<i64>().ok()?;
    let minute = time_parts.next()?.parse::<i64>().ok()?;
    let second = time_parts.next()?.split('.').next()?.parse::<i64>().ok()?;
    let days = days_from_civil(year, month, day)?;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_adjusted = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_adjusted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    use tempfile::tempdir;

    #[test]
    fn matches_endpoint_with_port_and_url() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("iocs.sqlite");
        let connection = Connection::open(&db_path).unwrap();
        connection
            .execute(
                "CREATE TABLE iocs (value TEXT, ioc_type TEXT, source TEXT, confidence INTEGER, first_seen TEXT, last_seen TEXT, expires_at TEXT, malware TEXT, tags TEXT, reference TEXT, meta TEXT, PRIMARY KEY(value, ioc_type, source))",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO iocs VALUES (?1, 'domain', 'urlhaus', 85, NULL, NULL, '2099-01-01T00:00:00Z', 'test', NULL, NULL, '{}')",
                params!["bad.example"],
            )
            .unwrap();
        let matcher = ThreatIntelMatcher::with_default_confidence();
        assert_eq!(matcher.load_from_sqlite_db(&db_path).unwrap(), 1);
        let matches = matcher.match_observation("tcp://bad.example:443");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].record.source, "urlhaus");
    }

    #[test]
    fn matches_ip_inside_cidr_network() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("iocs.sqlite");
        let connection = Connection::open(&db_path).unwrap();
        connection
            .execute(
                "CREATE TABLE iocs (value TEXT, ioc_type TEXT, source TEXT, confidence INTEGER, first_seen TEXT, last_seen TEXT, expires_at TEXT, malware TEXT, tags TEXT, reference TEXT, meta TEXT, PRIMARY KEY(value, ioc_type, source))",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO iocs VALUES ('192.0.2.0/24', 'cidr', 'spamhaus_drop_v4', 96, NULL, NULL, '2099-01-01T00:00:00Z', NULL, NULL, 'test', '{}')",
                [],
            )
            .unwrap();

        let matcher = ThreatIntelMatcher::with_default_confidence();
        assert_eq!(matcher.load_from_sqlite_db(&db_path).unwrap(), 1);
        assert_eq!(
            matcher.match_observation("tcp://192.0.2.42:443")[0]
                .record
                .ioc_type,
            "cidr"
        );
        assert!(matcher
            .match_observation("tcp://198.51.100.42:443")
            .is_empty());
    }

    #[test]
    fn ignores_expired_and_low_confidence_entries() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("iocs.sqlite");
        let connection = Connection::open(&db_path).unwrap();
        connection
            .execute(
                "CREATE TABLE iocs (value TEXT, ioc_type TEXT, source TEXT, confidence INTEGER, first_seen TEXT, last_seen TEXT, expires_at TEXT, malware TEXT, tags TEXT, reference TEXT, meta TEXT, PRIMARY KEY(value, ioc_type, source))",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO iocs VALUES ('expired.example', 'domain', 'test', 90, NULL, NULL, '2000-01-01T00:00:00Z', NULL, NULL, NULL, '{}'), ('weak.example', 'domain', 'test', 20, NULL, NULL, '2099-01-01T00:00:00Z', NULL, NULL, NULL, '{}')",
                [],
            )
            .unwrap();
        let matcher = ThreatIntelMatcher::with_default_confidence();
        assert_eq!(matcher.load_from_sqlite_db(&db_path).unwrap(), 0);
        assert!(matcher.match_observation("expired.example").is_empty());
    }
}
