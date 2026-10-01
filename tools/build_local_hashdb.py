"""Build a local hash and network IOC database from public threat feeds.

The updater stores hashes in ``hashes`` and network indicators in ``iocs``.
Network indicators always carry source, confidence, timestamps, a reference,
and an optional expiry so the scanner never treats a stale feed item as a
permanent block rule.

Examples:
    python tools/build_local_hashdb.py --out data/local_hashes.sqlite \
        --malwarebazaar --mb-limit 500 --urlhaus-recent --urlhaus-limit 500
    python tools/build_local_hashdb.py --out data/local_hashes.sqlite \
        --threatfox --threatfox-api-key "$env:THREATFOX_AUTH_KEY"

MalwareBazaar and ThreatFox may require an API key depending on provider
policy. URLhaus' recent CSV feed is public and can be collected without a
credential. The updater does not submit any samples or indicators.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import io
import json
import os
import re
import sqlite3
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional
from urllib.error import URLError


MB_API_URL = "https://mb-api.abuse.ch/api/v1/"
MB_PUBLIC_SHA256_EXPORT = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
URLHAUS_RECENT_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
_HASH_RE = re.compile(r"\b([A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})\b")


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_feed_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


class LocalHashDB:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.conn = sqlite3.connect(str(self.path))
        self._init_db()

    def _init_db(self) -> None:
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS hashes (
                hash TEXT PRIMARY KEY,
                algorithm TEXT,
                source TEXT,
                first_seen TEXT,
                meta TEXT
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_source ON hashes(source)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS iocs (
                value TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                source TEXT NOT NULL,
                confidence INTEGER,
                first_seen TEXT,
                last_seen TEXT,
                expires_at TEXT,
                malware TEXT,
                tags TEXT,
                reference TEXT,
                meta TEXT,
                PRIMARY KEY(value, ioc_type, source)
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_iocs_expiry ON iocs(expires_at)")
        self.conn.commit()

    def add(
        self,
        h: str,
        algorithm: str,
        source: str,
        first_seen: Optional[str] = None,
        meta: Optional[dict] = None,
    ) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO hashes (hash, algorithm, source, first_seen, meta) VALUES (?, ?, ?, ?, ?)",
            (h.lower(), algorithm, source, first_seen or iso_z(utc_now()), json.dumps(meta or {}, sort_keys=True)),
        )

    def add_ioc(
        self,
        value: str,
        ioc_type: str,
        source: str,
        *,
        confidence: Optional[int] = None,
        first_seen: Optional[str] = None,
        last_seen: Optional[str] = None,
        expires_at: Optional[str] = None,
        malware: Optional[str] = None,
        tags: Optional[str] = None,
        reference: Optional[str] = None,
        meta: Optional[dict] = None,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO iocs
                (value, ioc_type, source, confidence, first_seen, last_seen,
                 expires_at, malware, tags, reference, meta)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(value, ioc_type, source) DO UPDATE SET
                confidence=excluded.confidence,
                first_seen=excluded.first_seen,
                last_seen=excluded.last_seen,
                expires_at=excluded.expires_at,
                malware=excluded.malware,
                tags=excluded.tags,
                reference=excluded.reference,
                meta=excluded.meta
            """,
            (
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
                json.dumps(meta or {}, sort_keys=True),
            ),
        )

    def commit(self) -> None:
        self.conn.commit()

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()


def fetch_malwarebazaar_recent(limit: int = 100, api_key: Optional[str] = None) -> Iterable[dict]:
    payload_data = {"query": "get_recent", "selector": str(min(max(limit, 1), 100))}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if api_key:
        headers["Auth-Key"] = api_key.strip()
    request = urllib.request.Request(
        MB_API_URL,
        data=urllib.parse.urlencode(payload_data).encode("ascii"),
        method="POST",
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = json.loads(response.read().decode("utf-8", errors="ignore"))
    except Exception as exc:
        raise RuntimeError(f"failed to query MalwareBazaar: {exc}") from exc
    if body.get("query_status") not in (None, "ok"):
        raise RuntimeError(f"MalwareBazaar API returned status: {body.get('query_status')} - {body.get('message')}")
    fetched = 0
    for item in body.get("data") or []:
        if fetched >= limit:
            break
        if not item.get("sha256_hash") and not item.get("sha256"):
            continue
        fetched += 1
        yield item


def fetch_urlhaus_recent(limit: int = 500) -> Iterable[dict]:
    request = urllib.request.Request(URLHAUS_RECENT_CSV, headers={"User-Agent": "EverbloomSecurity-threat-intel-updater"})
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except Exception as exc:
        raise RuntimeError(f"failed to fetch URLhaus recent feed: {exc}") from exc

    lines = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            header = stripped.lstrip("#").strip()
            if header.lower().startswith("id,"):
                lines.append(header)
            continue
        lines.append(line)
    for row in list(csv.DictReader(io.StringIO("\n".join(lines))))[:limit]:
        if row.get("url_status", "").strip().lower() != "online":
            continue
        if row.get("threat", "").strip().lower() not in ("", "malware_download"):
            continue
        yield row


def fetch_threatfox_iocs(api_key: str, days: int = 7, limit: int = 500) -> Iterable[dict]:
    if not api_key.strip():
        raise RuntimeError("ThreatFox requires an Auth-Key")
    payload = json.dumps({"query": "get_iocs", "days": max(1, min(days, 30))}).encode("utf-8")
    request = urllib.request.Request(
        THREATFOX_API_URL,
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json", "Auth-Key": api_key.strip()},
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            body = json.loads(response.read().decode("utf-8", errors="ignore"))
    except Exception as exc:
        raise RuntimeError(f"failed to query ThreatFox: {exc}") from exc
    if body.get("query_status") not in (None, "ok"):
        raise RuntimeError(f"ThreatFox API returned status: {body.get('query_status')} - {body.get('message')}")
    yielded = 0
    for item in body.get("data") or []:
        if yielded >= limit:
            break
        if item.get("ioc_type") in {"domain", "ip", "ipv4", "ipv6", "url"} and item.get("ioc"):
            yielded += 1
            yield item


def is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def normalize_domain(value: str) -> Optional[str]:
    value = value.strip().lower().rstrip(".")
    if not value or len(value) > 253 or ":" in value or "/" in value or " " in value or "." not in value:
        return None
    labels = value.split(".")
    if any(not label or len(label) > 63 or label[0] == "-" or label[-1] == "-" for label in labels):
        return None
    if any(not re.fullmatch(r"[a-z0-9-]+", label) for label in labels):
        return None
    return value


def extract_url_iocs(url: str) -> list[tuple[str, str]]:
    parsed = urllib.parse.urlparse(url.strip())
    host = parsed.hostname
    if not host:
        return []
    host = host.lower().rstrip(".")
    if is_public_ip(host):
        return [(host, "ipv6" if ":" in host else "ipv4")]
    domain = normalize_domain(host)
    return [(domain, "domain")] if domain else []


def scan_clamav_signatures(dir_path: Path) -> Iterable[dict]:
    for root, _dirs, files in os.walk(dir_path):
        for name in files:
            path = Path(root) / name
            try:
                content = path.read_text(errors="ignore")
            except Exception:
                continue
            for match in _HASH_RE.finditer(content):
                value = match.group(1)
                yield {
                    "hash": value,
                    "algorithm": {32: "md5", 40: "sha1", 64: "sha256"}[len(value)],
                    "source_file": str(path),
                }


def fetch_from_url_extract_hashes(url: str, limit: int = 0) -> Iterable[dict]:
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            text = response.read().decode("utf-8", errors="ignore")
    except URLError as exc:
        raise RuntimeError(f"failed to fetch {url}: {exc}") from exc
    found = 0
    for match in _HASH_RE.finditer(text):
        value = match.group(1)
        yield {"hash": value, "meta": {"source_url": url}}
        found += 1
        if limit and found >= limit:
            return


def fetch_github_repo_hashes(
    repo: str, branch: str = "main", path_prefixes: Optional[list[str]] = None, limit: int = 0
) -> Iterable[dict]:
    repo = repo.strip().strip("/")
    if "/" not in repo:
        raise ValueError("repository should be in owner/name format")
    prefixes = [p.strip("/").strip() for p in (path_prefixes or []) if p and p.strip()]

    def should_scan(path_name: str) -> bool:
        return not prefixes or any(
            path_name.strip("/") == prefix or path_name.strip("/").startswith(prefix + "/") for prefix in prefixes
        )

    def walk(path: str = "") -> Iterable[dict]:
        url = f"https://api.github.com/repos/{repo}/contents/{path}?ref={branch}"
        request = urllib.request.Request(url, headers={"User-Agent": "EverbloomSecurity-threat-intel-updater"})
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8", errors="ignore"))
        payload = payload if isinstance(payload, list) else [payload]
        for item in payload:
            path_name = item.get("path", "")
            if item.get("type") == "dir" and should_scan(path_name):
                yield from walk(path_name)
            elif item.get("type") == "file" and should_scan(path_name) and item.get("download_url"):
                with urllib.request.urlopen(item["download_url"], timeout=30) as response:
                    text = response.read().decode("utf-8", errors="ignore")
                found = 0
                for match in _HASH_RE.finditer(text):
                    yield {"hash": match.group(1), "meta": {"source_url": item["download_url"], "repo": repo, "path": path_name}}
                    found += 1
                    if limit and found >= limit:
                        break

    yield from walk()


def add_hash(db: Optional[LocalHashDB], value: str, source: str, first_seen: Optional[str], meta: Optional[dict]) -> None:
    algorithm = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(value))
    if algorithm and re.fullmatch(r"[a-fA-F0-9]+", value):
        if db:
            db.add(value, algorithm, source, first_seen, meta)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a local hash and threat-intelligence DB")
    parser.add_argument("--out", type=Path, required=True, help="output SQLite DB path")
    parser.add_argument("--malwarebazaar", action="store_true")
    parser.add_argument("--mb-limit", type=int, default=500)
    parser.add_argument("--mb-api-key", type=str)
    parser.add_argument("--urlhaus-recent", action="store_true", help="collect online entries from URLhaus recent CSV")
    parser.add_argument("--urlhaus-limit", type=int, default=500)
    parser.add_argument("--threatfox", action="store_true", help="collect recent ThreatFox domain/IP IOCs")
    parser.add_argument("--threatfox-days", type=int, default=7)
    parser.add_argument("--threatfox-limit", type=int, default=500)
    parser.add_argument("--threatfox-api-key", type=str)
    parser.add_argument("--clamav-sigs", type=Path)
    parser.add_argument("--fetch-url", action="append")
    parser.add_argument("--fetch-github-repo", action="append")
    parser.add_argument("--github-path", action="append")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    db = None if args.dry_run else LocalHashDB(args.out)
    hash_count = 0
    ioc_count = 0
    collected = utc_now()
    try:
        if args.malwarebazaar:
            key = args.mb_api_key or os.environ.get("MALWAREBAZAAR_API_KEY")
            try:
                malware_items = list(fetch_malwarebazaar_recent(args.mb_limit, key))
            except RuntimeError as exc:
                print(f"Warning: MalwareBazaar API unavailable ({exc}); using its public SHA-256 export")
                malware_items = [
                    {"sha256_hash": item["hash"], "meta": item.get("meta")}
                    for item in fetch_from_url_extract_hashes(MB_PUBLIC_SHA256_EXPORT, limit=args.mb_limit)
                ]
            for item in malware_items:
                for field in ("md5_hash", "sha1_hash", "sha256_hash", "md5", "sha1", "sha256"):
                    value = item.get(field)
                    if value:
                        add_hash(db, value, "malwarebazaar", item.get("first_seen"), item)
                        hash_count += 1

        if args.clamav_sigs:
            for item in scan_clamav_signatures(args.clamav_sigs):
                add_hash(db, item["hash"], f"clamav_sigs:{item['source_file']}", None, item)
                hash_count += 1

        for url in args.fetch_url or []:
            for item in fetch_from_url_extract_hashes(url, limit=args.mb_limit):
                add_hash(db, item["hash"], f"url:{url}", None, item.get("meta"))
                hash_count += 1

        for repo in args.fetch_github_repo or []:
            for item in fetch_github_repo_hashes(repo, path_prefixes=args.github_path, limit=args.mb_limit):
                add_hash(db, item["hash"], f"github_repo:{repo}", None, item.get("meta"))
                hash_count += 1

        if args.urlhaus_recent:
            expires = iso_z(collected + timedelta(days=7))
            for item in fetch_urlhaus_recent(args.urlhaus_limit):
                url = item.get("url", "").strip()
                for value, ioc_type in extract_url_iocs(url):
                    if db:
                        db.add_ioc(
                            value,
                            ioc_type,
                            "urlhaus",
                            confidence=85,
                            first_seen=item.get("dateadded"),
                            last_seen=item.get("dateadded"),
                            expires_at=expires,
                            tags=item.get("tags"),
                            reference=item.get("urlhaus_link"),
                            meta={"url": url, "threat": item.get("threat"), "collected_at": iso_z(collected)},
                        )
                    ioc_count += 1

        if args.threatfox:
            key = args.threatfox_api_key or os.environ.get("THREATFOX_AUTH_KEY")
            for item in fetch_threatfox_iocs(key or "", args.threatfox_days, args.threatfox_limit):
                raw_type = item.get("ioc_type", "").lower()
                value = item.get("ioc", "").strip().lower().rstrip(".")
                if raw_type == "ip":
                    raw_type = "ipv6" if ":" in value else "ipv4"
                if raw_type in {"ipv4", "ipv6"} and not is_public_ip(value):
                    continue
                if raw_type == "domain":
                    value = normalize_domain(value) or ""
                if not value or raw_type not in {"domain", "ipv4", "ipv6", "url"}:
                    continue
                last_seen = item.get("last_seen")
                expiry_base = parse_feed_time(last_seen) or collected
                expires = iso_z(expiry_base + timedelta(days=180))
                if db:
                    db.add_ioc(
                        value,
                        raw_type,
                        "threatfox",
                        confidence=int(item.get("confidence_level") or 0),
                        first_seen=item.get("first_seen"),
                        last_seen=last_seen,
                        expires_at=expires,
                        malware=item.get("malware_printable") or item.get("malware"),
                        tags=item.get("tags"),
                        reference=item.get("reference"),
                        meta=item,
                    )
                ioc_count += 1

        if db:
            db.commit()
        mode = "Dry-run" if args.dry_run else "Completed"
        print(f"{mode}: {hash_count} hash occurrences, {ioc_count} IOC occurrences; DB={args.out}")
    finally:
        if db:
            db.close()


if __name__ == "__main__":
    main()
