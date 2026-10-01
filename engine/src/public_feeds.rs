use crate::layers::threat_intel::ThreatIntelMatcher;
use rusqlite::{params, Connection};
use serde_json::Value;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_FEED_BYTES: usize = 16 * 1024 * 1024;
const CURL_CONNECT_TIMEOUT: &str = "5";
const CURL_MAX_TIME: &str = "20";

#[derive(Debug, Clone, Copy)]
enum FeedFormat {
    FeodoJson,
    SpamhausDropJson,
    OpenPhishText,
    IpsumText,
}

#[derive(Debug, Clone, Copy)]
struct Feed {
    source: &'static str,
    url: &'static str,
    format: FeedFormat,
    confidence: u8,
    ttl: Duration,
}

const FEEDS: &[Feed] = &[
    Feed {
        source: "feodo_tracker",
        url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
        format: FeedFormat::FeodoJson,
        confidence: 96,
        ttl: Duration::from_secs(30 * 60),
    },
    Feed {
        source: "spamhaus_drop_v4",
        url: "https://www.spamhaus.org/drop/drop_v4.json",
        format: FeedFormat::SpamhausDropJson,
        confidence: 96,
        ttl: Duration::from_secs(36 * 60 * 60),
    },
    Feed {
        source: "spamhaus_drop_v6",
        url: "https://www.spamhaus.org/drop/drop_v6.json",
        format: FeedFormat::SpamhausDropJson,
        confidence: 96,
        ttl: Duration::from_secs(36 * 60 * 60),
    },
    Feed {
        source: "openphish",
        url: "https://openphish.com/feed.txt",
        format: FeedFormat::OpenPhishText,
        confidence: 90,
        ttl: Duration::from_secs(36 * 60 * 60),
    },
    Feed {
        source: "ipsum",
        url: "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
        format: FeedFormat::IpsumText,
        confidence: 70,
        ttl: Duration::from_secs(36 * 60 * 60),
    },
];

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FeedUpdateSummary {
    pub attempted: usize,
    pub succeeded: usize,
    pub records: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
struct FeedRecord {
    value: String,
    ioc_type: String,
    confidence: u8,
    malware: Option<String>,
    tags: Option<String>,
    first_seen: Option<String>,
    last_seen: Option<String>,
    expires_at: String,
    reference: String,
}

pub fn default_cache_path() -> PathBuf {
    std::env::var_os("EVERBLOOM_PUBLIC_THREAT_INTEL_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("data/public_threat_intel.sqlite"))
}

pub fn public_feeds_enabled() -> bool {
    std::env::var("EVERBLOOM_THREAT_INTEL_PUBLIC_FEEDS")
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(true)
}

pub fn update_interval() -> Duration {
    let seconds = std::env::var("EVERBLOOM_THREAT_INTEL_INTERVAL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1800)
        .clamp(300, 86_400);
    Duration::from_secs(seconds)
}

pub fn load_cached(matcher: &ThreatIntelMatcher, path: &Path) -> Result<usize, String> {
    if !path.is_file() {
        return Ok(0);
    }
    matcher
        .load_from_sqlite_db(path)
        .map_err(|error| error.to_string())
}

pub fn spawn_updater(
    matcher: Arc<ThreatIntelMatcher>,
    database_path: PathBuf,
    interval: Duration,
) -> std::io::Result<()> {
    thread::Builder::new()
        .name("everbloom-public-threat-intel".to_string())
        .spawn(move || loop {
            let summary = update_once(&matcher, &database_path);
            if summary.succeeded > 0 {
                log::info!(
                    "public threat feeds updated: succeeded={}/{} records={} errors={}",
                    summary.succeeded,
                    summary.attempted,
                    summary.records,
                    summary.errors.len()
                );
            }
            for error in summary.errors {
                log::warn!("public threat feed unavailable: {error}");
            }
            thread::sleep(interval);
        })
        .map(|_| ())
}

pub fn update_once(matcher: &ThreatIntelMatcher, database_path: &Path) -> FeedUpdateSummary {
    let mut summary = FeedUpdateSummary::default();
    if let Some(parent) = database_path.parent() {
        if let Err(error) = std::fs::create_dir_all(parent) {
            summary.errors.push(format!(
                "unable to create public threat-intel directory {}: {}",
                parent.display(),
                error
            ));
            return summary;
        }
    }

    for feed in FEEDS {
        summary.attempted += 1;
        match download(feed)
            .and_then(|body| parse(feed, &body, unix_now()))
            .and_then(|records| {
                replace_source_records(database_path, feed.source, &records).map(|_| records.len())
            }) {
            Ok(record_count) => match matcher.replace_from_sqlite_db(database_path) {
                Ok(_) => {
                    summary.succeeded += 1;
                    summary.records += record_count;
                }
                Err(error) => summary
                    .errors
                    .push(format!("{} matcher reload failed: {}", feed.source, error)),
            },
            Err(error) => summary.errors.push(format!("{}: {}", feed.source, error)),
        }
    }
    summary
}

fn download(feed: &Feed) -> Result<Vec<u8>, String> {
    let executable = if cfg!(windows) { "curl.exe" } else { "curl" };
    let mut command = Command::new(executable);
    command.args([
        "--fail",
        "--silent",
        "--show-error",
        "--location",
        "--connect-timeout",
        CURL_CONNECT_TIMEOUT,
        "--max-time",
        CURL_MAX_TIME,
        "--max-filesize",
        &MAX_FEED_BYTES.to_string(),
        "--user-agent",
        "EverbloomSecurity-ThreatIntel/1.0",
        feed.url,
    ]);
    #[cfg(windows)]
    {
        // Suppress the curl console window that would otherwise pop up on every
        // feed refresh (see ndjson.rs for the same CREATE_NO_WINDOW pattern).
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let output = command
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if detail.is_empty() {
            format!("curl exited with {}", output.status)
        } else {
            detail
        });
    }
    if output.stdout.len() > MAX_FEED_BYTES {
        return Err(format!(
            "feed exceeds {} MiB safety limit",
            MAX_FEED_BYTES / 1024 / 1024
        ));
    }
    Ok(output.stdout)
}

fn parse(feed: &Feed, body: &[u8], now: i64) -> Result<Vec<FeedRecord>, String> {
    match feed.format {
        FeedFormat::FeodoJson => parse_feodo(feed, body, now),
        FeedFormat::SpamhausDropJson => parse_spamhaus_drop(feed, body, now),
        FeedFormat::OpenPhishText => parse_openphish(feed, body, now),
        FeedFormat::IpsumText => parse_ipsum(feed, body, now),
    }
}

fn parse_feodo(feed: &Feed, body: &[u8], now: i64) -> Result<Vec<FeedRecord>, String> {
    let values: Vec<Value> = serde_json::from_slice(body).map_err(|error| error.to_string())?;
    Ok(values
        .into_iter()
        .filter_map(|value| {
            let object = value.as_object()?;
            let address = object.get("ip_address")?.as_str()?.parse::<IpAddr>().ok()?;
            let status = object
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let confidence = if status.eq_ignore_ascii_case("online") {
                feed.confidence
            } else {
                feed.confidence.saturating_sub(10)
            };
            Some(FeedRecord {
                value: address.to_string(),
                ioc_type: if address.is_ipv4() { "ipv4" } else { "ipv6" }.to_string(),
                confidence,
                malware: object
                    .get("malware")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                tags: Some(format!("botnet_c2,status={status}")),
                first_seen: object
                    .get("first_seen")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                last_seen: object
                    .get("last_online")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                expires_at: expiry(now, feed.ttl),
                reference: feed.url.to_string(),
            })
        })
        .collect())
}

fn parse_spamhaus_drop(feed: &Feed, body: &[u8], now: i64) -> Result<Vec<FeedRecord>, String> {
    let root: Value = serde_json::from_slice(body).map_err(|error| error.to_string())?;
    let values = root
        .as_array()
        .cloned()
        .or_else(|| root.get("data").and_then(Value::as_array).cloned())
        .unwrap_or_default();
    Ok(values
        .into_iter()
        .filter_map(|value| {
            let object = value.as_object()?;
            let cidr = ["cidr", "netblock", "network"]
                .iter()
                .find_map(|key| object.get(*key).and_then(Value::as_str))?;
            if !valid_cidr(cidr) {
                return None;
            }
            Some(FeedRecord {
                value: cidr.to_string(),
                ioc_type: "cidr".to_string(),
                confidence: feed.confidence,
                malware: None,
                tags: Some("high_confidence_malicious_netblock".to_string()),
                first_seen: None,
                last_seen: None,
                expires_at: expiry(now, feed.ttl),
                reference: feed.url.to_string(),
            })
        })
        .collect())
}

fn parse_openphish(feed: &Feed, body: &[u8], now: i64) -> Result<Vec<FeedRecord>, String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with('#')
                && (line.starts_with("http://") || line.starts_with("https://"))
                && line.len() <= 2048
        })
        .map(|url| FeedRecord {
            value: url.to_ascii_lowercase(),
            ioc_type: "url".to_string(),
            confidence: feed.confidence,
            malware: Some("phishing".to_string()),
            tags: Some("phishing_url".to_string()),
            first_seen: None,
            last_seen: None,
            expires_at: expiry(now, feed.ttl),
            reference: feed.url.to_string(),
        })
        .collect())
}

fn parse_ipsum(feed: &Feed, body: &[u8], now: i64) -> Result<Vec<FeedRecord>, String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    Ok(text
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let value = fields.next()?;
            if value.starts_with('#') {
                return None;
            }
            let address = value.parse::<IpAddr>().ok()?;
            let hits = fields
                .next()
                .and_then(|field| field.parse::<u8>().ok())
                .unwrap_or(1);
            Some(FeedRecord {
                value: address.to_string(),
                ioc_type: if address.is_ipv4() { "ipv4" } else { "ipv6" }.to_string(),
                confidence: feed
                    .confidence
                    .saturating_add(hits.saturating_sub(1).min(20)),
                malware: None,
                tags: Some(format!("aggregated_blacklist_hits={hits}")),
                first_seen: None,
                last_seen: None,
                expires_at: expiry(now, feed.ttl),
                reference: feed.url.to_string(),
            })
        })
        .collect())
}

fn replace_source_records(
    database_path: &Path,
    source: &str,
    records: &[FeedRecord],
) -> Result<(), String> {
    let connection = Connection::open(database_path).map_err(|error| error.to_string())?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS iocs (
                value TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                source TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                first_seen TEXT,
                last_seen TEXT,
                expires_at TEXT,
                malware TEXT,
                tags TEXT,
                reference TEXT,
                meta TEXT,
                PRIMARY KEY(value, ioc_type, source)
            );",
        )
        .map_err(|error| error.to_string())?;
    let transaction = connection
        .unchecked_transaction()
        .map_err(|error| error.to_string())?;
    transaction
        .execute("DELETE FROM iocs WHERE source = ?1", params![source])
        .map_err(|error| error.to_string())?;
    for record in records {
        transaction
            .execute(
                "INSERT OR REPLACE INTO iocs
                 (value, ioc_type, source, confidence, first_seen, last_seen, expires_at, malware, tags, reference, meta)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    record.value,
                    record.ioc_type,
                    source,
                    record.confidence,
                    record.first_seen,
                    record.last_seen,
                    record.expires_at,
                    record.malware,
                    record.tags,
                    record.reference,
                    "{}"
                ],
            )
            .map_err(|error| error.to_string())?;
    }
    transaction.commit().map_err(|error| error.to_string())
}

fn valid_cidr(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    prefix <= if address.is_ipv4() { 32 } else { 128 }
}

fn expiry(now: i64, ttl: Duration) -> String {
    unix_to_rfc3339(now.saturating_add(ttl.as_secs() as i64))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn unix_to_rfc3339(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let seconds = epoch.rem_euclid(86_400);
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }).div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096).div_euclid(365);
    let year = yoe + era * 400;
    let day_of_year = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month_part = (5 * day_of_year + 2).div_euclid(153);
    let day = day_of_year - (153 * month_part + 2).div_euclid(5) + 1;
    let month = month_part + if month_part < 10 { 3 } else { -9 };
    let year = year + i64::from(month <= 2);
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_feed_expiry_is_rfc3339() {
        assert!(expiry(1_700_000_000, Duration::from_secs(3600)).ends_with('Z'));
    }

    #[test]
    fn cidr_validation_rejects_invalid_prefix() {
        assert!(valid_cidr("192.0.2.0/24"));
        assert!(!valid_cidr("192.0.2.0/33"));
        assert!(!valid_cidr("not-an-ip/24"));
    }
}
