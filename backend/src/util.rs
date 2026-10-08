use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::model::PasswordEntry;

pub fn data_dir() -> PathBuf {
    env::var_os("DBX_PLUGIN_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::temp_dir().join("dbx-plugin-data").join("io.dbx.password"))
}

pub fn vault_path() -> PathBuf {
    data_dir().join("vault.json")
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn entry_matches(entry: &PasswordEntry, needle: &str) -> bool {
    [
        entry.title.as_str(),
        entry.username.as_str(),
        entry.url.as_str(),
        entry.notes.as_str(),
    ]
    .iter()
    .any(|field| field.to_lowercase().contains(needle))
}

pub fn log_stderr(message: impl AsRef<str>) {
    let _ = writeln!(io::stderr(), "[io.dbx.password] {}", message.as_ref());
}
