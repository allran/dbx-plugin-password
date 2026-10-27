use serde::{Deserialize, Serialize};

use crate::crypto::{ARGON2_ITERATIONS, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM};

pub const DEFAULT_GROUP_ID: &str = "default";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub id: String,
    pub name: String,
    /// Empty string = root-level group. Missing in old vaults → default via serde.
    #[serde(default)]
    pub parent_id: String,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordEntry {
    pub id: String,
    pub group_id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VaultData {
    pub groups: Vec<Group>,
    pub entries: Vec<PasswordEntry>,
}

/// On-disk encrypted envelope (always encrypted; never plaintext passwords).
///
/// - `protection = "open"`: key lives in sibling `vault.key` (auto-unlock)
/// - `protection = "password"`: Argon2id(master password, salt) → AES key
///
/// Version history:
/// - 2: AES-GCM without AAD; kdf name only
/// - 3: AES-GCM with AAD over metadata; Argon2 m/t/p stored for password mode
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedVaultFile {
    pub format: String,
    pub version: u32,
    pub encrypted: bool,
    /// `"open"` | `"password"`
    #[serde(default = "default_protection_password")]
    pub protection: String,
    #[serde(default)]
    pub kdf: String,
    /// Argon2 memory cost in KiB (password mode, v3+).
    #[serde(default)]
    pub kdf_memory_kib: Option<u32>,
    #[serde(default)]
    pub kdf_iterations: Option<u32>,
    #[serde(default)]
    pub kdf_parallelism: Option<u32>,
    #[serde(default)]
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

fn default_protection_password() -> String {
    // Legacy encrypted vaults (v0.3.0 early) had no protection field → password mode.
    EncryptedVaultFile::PROTECTION_PASSWORD.to_string()
}

impl EncryptedVaultFile {
    pub const FORMAT: &'static str = "dbx-password-vault";
    /// Current write version (AAD + KDF params).
    pub const VERSION: u32 = 3;
    pub const MIN_SUPPORTED_VERSION: u32 = 2;
    pub const KDF: &'static str = "argon2id";
    pub const PROTECTION_OPEN: &'static str = "open";
    pub const PROTECTION_PASSWORD: &'static str = "password";

    pub fn argon2_params(&self) -> (u32, u32, u32) {
        (
            self.kdf_memory_kib.unwrap_or(ARGON2_MEMORY_KIB),
            self.kdf_iterations.unwrap_or(ARGON2_ITERATIONS),
            self.kdf_parallelism.unwrap_or(ARGON2_PARALLELISM),
        )
    }
}

impl VaultData {
    pub fn ensure_default_group(&mut self, now: u64) {
        if let Some(group) = self.groups.iter_mut().find(|g| g.id == DEFAULT_GROUP_ID) {
            group.parent_id.clear();
            return;
        }
        self.groups.insert(
            0,
            Group {
                id: DEFAULT_GROUP_ID.to_string(),
                name: "Default".to_string(),
                parent_id: String::new(),
                created_at: now,
                updated_at: now,
            },
        );
    }

    /// List/search responses omit secrets; use `get_entry` for the full password.
    pub fn redacted(&self) -> Self {
        Self {
            groups: self.groups.clone(),
            entries: self
                .entries
                .iter()
                .map(|e| PasswordEntry {
                    password: String::new(),
                    ..e.clone()
                })
                .collect(),
        }
    }
}
