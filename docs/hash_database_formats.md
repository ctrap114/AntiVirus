# Hash database formats

The engine accepts one or more hash databases through `EVERBLOOM_HASH_DB`
(use the platform path-list separator) or the built-in `data/local_hashes.*`
discovery paths. The loader selects the format from the extension and falls
back to content detection for unknown extensions.

Supported formats:

- SQLite/DB: `hashes` or legacy `HashDB` tables. A generic `hash` column or
  dedicated `md5_hash`, `sha1_hash`, `sha256_hash`, `sha512_hash`, and `ssdeep`
  columns are supported.
- CSV/TSV: the native `hash,algorithm,is_malicious` schema and multi-column
  threat-feed exports are supported. Missing verdict fields default to
  malicious because these files are treated as threat feeds.
- JSON: an array of strings, an array of objects, wrapper fields such as
  `data`/`results`/`hashes`, and objects containing dedicated hash fields.
- JSONL/NDJSON: one JSON value per line.
- Plain text: one hash per line, with optional algorithm and verdict, for
  example `sha256 <hash> true`. Lines beginning with `#` or `//` are ignored.
- DAT: line-oriented vendor lists, including `hash:size:name` records and
  common `hash|name`, `hash=name`, and whitespace-separated variants. Binary
  CVD/container files are rejected rather than treated as text lists.

Exact matching supports MD5, SHA-1, SHA-256, and SHA-512. Fuzzy matching
supports standard `ssdeep` signatures and the historical
`ssdeep-lite:<block>:<primary>:<secondary>` form. Invalid or unsupported
values are skipped and never become matches.

Examples:

```text
# hashes.txt
sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef true
```

```csv
sha256_hash,md5_hash,is_malicious
<sha256>,<md5>,true
```

The database is parsed completely before replacement, so a malformed or empty
replacement cannot remove the currently active database.

When several files are discovered or supplied through the startup list, all
valid sources are loaded. Identical normalized hashes are merged into one
entry, their source paths are deduplicated, and a malicious verdict is kept if
any source marks the hash as malicious. `HashMatch.sources` exposes the merged
source paths to callers.
