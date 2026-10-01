//! Persistent file quarantine support.
//!
//! Quarantined files are moved out of their original location into a fixed
//! quarantine root, encoded with a small non-executable container format, and
//! paired with durable JSON metadata.  The original file is removed only after
//! the encoded copy has been successfully submitted.
//!
//! The quarantine container uses a portable byte-level encoding (XOR 0xA5) so
//! that payloads can be safely moved across users and systems without relying
//! on Windows DPAPI secrets.  A backup format (`EVERBLOOM-QUARANTINE-BACKUP-v1`)
//! allows the store to be exported (`export_quarantine`) and replayed
//! (`import_quarantine`) on any machine.
//!
//! Optional metadata encryption (via `EVERBLOOM_ENCRYPT_QUARANTINE`) uses the
//! custom EverbloomSecurity stream cipher (`engine/src/crypto.rs`) to produce a
//! `.json.enc` file; the plaintext `.json` remains for recovery and debug.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const ENCRYPTION_KEY_ENV: &str = "EVERBLOOM_QUARANTINE_ENCRYPTION_KEY";
