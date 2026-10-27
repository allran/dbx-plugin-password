use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use dbx_plugin_sdk::PluginError;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{
    b64_decode, b64_encode, decrypt, derive_key, derive_key_default, encrypt, envelope_aad,
    keys_eq, random_key, random_salt, ARGON2_ITERATIONS, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM,
    KEY_LEN,
};
use crate::fsutil::{chmod_owner_only, ensure_parent, write_private_file};
use crate::model::{
    EncryptedVaultFile, Group, PasswordEntry, VaultData, DEFAULT_GROUP_ID,
};
use crate::util::{entry_matches, now_ms};

pub struct VaultStore {
    data: VaultData,
    path: PathBuf,
    unlocked: bool,
    has_password: bool,
    /// True when the in-memory vault is usable but the on-disk file is still
    /// plaintext / missing encrypted envelope (migrate or create write failed).
    encryption_pending: bool,
    master_key: Option<Zeroizing<[u8; KEY_LEN]>>,
    salt: Option<Vec<u8>>,
    /// Argon2 m/t/p from the unlocked envelope (password mode).
    kdf_memory_kib: u32,
    kdf_iterations: u32,
    kdf_parallelism: u32,
}

impl VaultStore {
    fn open_key_path(vault_path: &PathBuf) -> PathBuf {
        vault_path.with_file_name("vault.key")
    }

    fn prepare_data(mut data: VaultData) -> VaultData {
        data.ensure_default_group(now_ms());
        Self::sanitize_parents(&mut data);
        Self::sanitize_entries(&mut data);
        data
    }

    fn read_open_key(path: &PathBuf) -> Result<Zeroizing<[u8; KEY_LEN]>, PluginError> {
        let raw = fs::read_to_string(path)
            .map_err(|_| PluginError::new(-32000, "Missing vault open key"))?;
        let bytes = b64_decode(raw.trim())?;
        if bytes.len() != KEY_LEN {
            return Err(PluginError::new(-32000, "Invalid vault open key"));
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&bytes);
        Ok(Zeroizing::new(key))
    }

    fn write_open_key(path: &PathBuf, key: &[u8; KEY_LEN]) -> Result<(), PluginError> {
        write_private_file(path, b64_encode(key).as_bytes(), "key.tmp")
    }

    fn open_key_matches(path: &PathBuf, key: &[u8; KEY_LEN]) -> bool {
        Self::read_open_key(path)
            .map(|existing| keys_eq(&*existing, key))
            .unwrap_or(false)
    }

    fn remove_open_key(path: &PathBuf) {
        let _ = fs::remove_file(path);
    }

    /// Idempotent fix for legacy `vault.key` files created as 0644 (0.3.0).
    fn ensure_open_key_permissions(path: &PathBuf) -> Result<(), PluginError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(path).map_err(|err| {
                PluginError::new(-32000, format!("Failed to stat vault key: {err}"))
            })?;
            let mode = meta.permissions().mode() & 0o777;
            if mode != 0o600 {
                chmod_owner_only(path)?;
            }
        }
        #[cfg(windows)]
        {
            chmod_owner_only(path)?;
        }
        let _ = path;
        Ok(())
    }

    fn replace_envelope(&self, raw: &str) -> Result<(), PluginError> {
        write_private_file(&self.path, raw.as_bytes(), "json.tmp")
    }

    fn validate_envelope(envelope: &EncryptedVaultFile) -> Result<(), PluginError> {
        if envelope.format != EncryptedVaultFile::FORMAT {
            return Err(PluginError::new(-32602, "Unsupported vault format"));
        }
        if !envelope.encrypted {
            return Err(PluginError::new(-32602, "Vault is not encrypted"));
        }
        if envelope.version < EncryptedVaultFile::MIN_SUPPORTED_VERSION
            || envelope.version > EncryptedVaultFile::VERSION
        {
            return Err(PluginError::new(
                -32602,
                format!("Unsupported vault version: {}", envelope.version),
            ));
        }
        if envelope.protection != EncryptedVaultFile::PROTECTION_OPEN
            && envelope.protection != EncryptedVaultFile::PROTECTION_PASSWORD
        {
            return Err(PluginError::new(
                -32602,
                format!("Unsupported vault protection: {}", envelope.protection),
            ));
        }
        if envelope.protection == EncryptedVaultFile::PROTECTION_PASSWORD {
            if envelope.kdf != EncryptedVaultFile::KDF {
                return Err(PluginError::new(
                    -32602,
                    format!("Unsupported vault KDF: {}", envelope.kdf),
                ));
            }
            if envelope.salt.trim().is_empty() {
                return Err(PluginError::new(-32602, "Missing vault salt"));
            }
        }
        if envelope.nonce.trim().is_empty() || envelope.ciphertext.trim().is_empty() {
            return Err(PluginError::new(-32602, "Invalid encrypted vault"));
        }
        Ok(())
    }

    fn envelope_aad_bytes(envelope: &EncryptedVaultFile) -> Vec<u8> {
        // v2 envelopes were sealed without AAD; v3+ bind metadata.
        if envelope.version >= 3 {
            envelope_aad(
                envelope.version,
                &envelope.protection,
                &envelope.kdf,
                &envelope.salt,
            )
        } else {
            Vec::new()
        }
    }

    fn decrypt_envelope(
        envelope: &EncryptedVaultFile,
        key: &[u8; KEY_LEN],
    ) -> Result<VaultData, PluginError> {
        Self::validate_envelope(envelope)?;
        let nonce = b64_decode(&envelope.nonce)?;
        let ciphertext = b64_decode(&envelope.ciphertext)?;
        let aad = Self::envelope_aad_bytes(envelope);
        let plaintext = decrypt(key, &nonce, &ciphertext, &aad)?;
        let data: VaultData = serde_json::from_slice(plaintext.as_ref())
            .map_err(|_| PluginError::new(-32602, "Invalid vault payload"))?;
        Ok(Self::prepare_data(data))
    }

    /// Create a new open-mode encrypted vault (or migrate plaintext → encrypted).
    /// On disk failure, returns Err without leaving a keyless encrypted envelope.
    fn bootstrap_open(path: PathBuf, data: VaultData) -> Result<Self, PluginError> {
        let data = Self::prepare_data(data);
        let key = random_key();
        let mut store = Self {
            data,
            path,
            unlocked: true,
            has_password: false,
            encryption_pending: true,
            master_key: Some(key),
            salt: None,
            kdf_memory_kib: ARGON2_MEMORY_KIB,
            kdf_iterations: ARGON2_ITERATIONS,
            kdf_parallelism: ARGON2_PARALLELISM,
        };
        store.persist()?;
        Ok(store)
    }

    fn bootstrap_open_or_warn(path: PathBuf, data: VaultData, context: &str) -> Self {
        match Self::bootstrap_open(path.clone(), data.clone()) {
            Ok(store) => store,
            Err(err) => {
                eprintln!(
                    "[io.dbx.password] {context}: {err:?}; keeping prior on-disk data and retrying on next save"
                );
                // Serve unlocked in memory so the user is not locked out; next persist()
                // will retry key-first encryption. Disk is unchanged (still empty/plaintext).
                Self {
                    data: Self::prepare_data(data),
                    path,
                    unlocked: true,
                    has_password: false,
                    encryption_pending: true,
                    master_key: Some(random_key()),
                    salt: None,
                    kdf_memory_kib: ARGON2_MEMORY_KIB,
                    kdf_iterations: ARGON2_ITERATIONS,
                    kdf_parallelism: ARGON2_PARALLELISM,
                }
            }
        }
    }

    fn locked_empty(path: PathBuf, has_password: bool, salt: Option<Vec<u8>>) -> Self {
        Self {
            data: VaultData::default(),
            path,
            unlocked: false,
            has_password,
            encryption_pending: false,
            master_key: None,
            salt,
            kdf_memory_kib: ARGON2_MEMORY_KIB,
            kdf_iterations: ARGON2_ITERATIONS,
            kdf_parallelism: ARGON2_PARALLELISM,
        }
    }

    pub fn load(path: PathBuf) -> Self {
        let raw = fs::read_to_string(&path).unwrap_or_default();
        if raw.trim().is_empty() {
            return Self::bootstrap_open_or_warn(
                path,
                VaultData::default(),
                "failed to create encrypted vault",
            );
        }

        if let Ok(envelope) = serde_json::from_str::<EncryptedVaultFile>(&raw) {
            if envelope.encrypted && envelope.format == EncryptedVaultFile::FORMAT {
                if envelope.protection == EncryptedVaultFile::PROTECTION_OPEN {
                    // Open mode: auto-unlock with sibling vault.key
                    let key_path = Self::open_key_path(&path);
                    if let Ok(key) = Self::read_open_key(&key_path) {
                        if let Ok(data) = Self::decrypt_envelope(&envelope, &key) {
                            // N2: fix legacy 0644 keys from 0.3.0 without rewriting contents.
                            let _ = Self::ensure_open_key_permissions(&key_path);
                            return Self {
                                data,
                                path,
                                unlocked: true,
                                has_password: false,
                                encryption_pending: false,
                                master_key: Some(key),
                                salt: None,
                                kdf_memory_kib: ARGON2_MEMORY_KIB,
                                kdf_iterations: ARGON2_ITERATIONS,
                                kdf_parallelism: ARGON2_PARALLELISM,
                            };
                        }
                    }
                    // Keep ciphertext on disk if vault.key is missing/corrupt; do not wipe.
                    return Self::locked_empty(path, false, None);
                }

                // Password-protected (including legacy envelopes without protection field).
                let salt = b64_decode(&envelope.salt).unwrap_or_default();
                return Self::locked_empty(path, true, Some(salt));
            }
        }

        // Corrupt encrypted envelope (partial write / bad JSON shape) — never wipe.
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) {
            let looks_encrypted = value.get("format").and_then(|v| v.as_str())
                == Some(EncryptedVaultFile::FORMAT)
                || (value.get("encrypted").and_then(|v| v.as_bool()) == Some(true)
                    && value.get("ciphertext").is_some());
            if looks_encrypted {
                let open = value.get("protection").and_then(|v| v.as_str())
                    == Some(EncryptedVaultFile::PROTECTION_OPEN);
                return Self::locked_empty(path, !open, None);
            }

            // Legacy plaintext vault.json → migrate to open encryption.
            if value.get("groups").map(|g| g.is_array()).unwrap_or(false) {
                if let Ok(data) = serde_json::from_value::<VaultData>(value) {
                    return Self::bootstrap_open_or_warn(
                        path,
                        data,
                        "failed to migrate plaintext vault to encryption",
                    );
                }
            }
        }

        // Unrecognized non-empty file — keep on disk, do not bootstrap over it.
        Self::locked_empty(path, false, None)
    }

    fn sanitize_entries(data: &mut VaultData) {
        for entry in &mut data.entries {
            if entry.group_id.is_empty()
                || !data.groups.iter().any(|g| g.id == entry.group_id)
            {
                entry.group_id = DEFAULT_GROUP_ID.to_string();
            }
        }
    }

    fn sanitize_parents(data: &mut VaultData) {
        let ids: HashSet<String> = data.groups.iter().map(|g| g.id.clone()).collect();
        for group in &mut data.groups {
            if group.id == DEFAULT_GROUP_ID {
                group.parent_id.clear();
                continue;
            }
            let parent = group.parent_id.trim();
            if parent.is_empty() || parent == group.id || !ids.contains(parent) {
                group.parent_id.clear();
            } else {
                group.parent_id = parent.to_string();
            }
        }
        let snapshot: Vec<(String, String)> = data
            .groups
            .iter()
            .map(|g| (g.id.clone(), g.parent_id.clone()))
            .collect();
        let parent_of: std::collections::HashMap<&str, &str> = snapshot
            .iter()
            .map(|(id, parent)| (id.as_str(), parent.as_str()))
            .collect();
        let mut cyclic: HashSet<String> = HashSet::new();
        for (id, _) in &snapshot {
            let mut seen = HashSet::new();
            let mut cur = id.as_str();
            loop {
                if !seen.insert(cur) {
                    cyclic.insert(id.clone());
                    break;
                }
                let Some(parent) = parent_of.get(cur).copied().filter(|p| !p.is_empty()) else {
                    break;
                };
                cur = parent;
            }
        }
        for group in &mut data.groups {
            if cyclic.contains(&group.id) {
                group.parent_id.clear();
            }
        }
    }

    pub fn status(&self) -> (bool, bool, bool) {
        (self.has_password, self.unlocked, self.encryption_pending)
    }

    fn require_unlocked(&self) -> Result<(), PluginError> {
        if self.unlocked {
            Ok(())
        } else {
            Err(PluginError::new(-32602, "Vault is locked"))
        }
    }

    fn persist(&mut self) -> Result<(), PluginError> {
        ensure_parent(&self.path)?;

        let key = self
            .master_key
            .as_ref()
            .ok_or_else(|| PluginError::new(-32602, "Vault is locked"))?;
        let mut plaintext = serde_json::to_vec(&self.data).map_err(|err| {
            PluginError::new(-32000, format!("Failed to serialize vault: {err}"))
        })?;

        let (protection, kdf, salt_b64, kdf_memory_kib, kdf_iterations, kdf_parallelism) =
            if self.has_password {
                let salt = self
                    .salt
                    .as_ref()
                    .ok_or_else(|| PluginError::new(-32000, "Missing vault salt"))?;
                (
                    EncryptedVaultFile::PROTECTION_PASSWORD.to_string(),
                    EncryptedVaultFile::KDF.to_string(),
                    b64_encode(salt),
                    Some(ARGON2_MEMORY_KIB),
                    Some(ARGON2_ITERATIONS),
                    Some(ARGON2_PARALLELISM),
                )
            } else {
                (
                    EncryptedVaultFile::PROTECTION_OPEN.to_string(),
                    String::new(),
                    String::new(),
                    None,
                    None,
                    None,
                )
            };

        let aad = envelope_aad(
            EncryptedVaultFile::VERSION,
            &protection,
            &kdf,
            &salt_b64,
        );
        let (ciphertext, nonce) = encrypt(&**key, &plaintext, &aad)?;
        plaintext.zeroize();

        let envelope = EncryptedVaultFile {
            format: EncryptedVaultFile::FORMAT.to_string(),
            version: EncryptedVaultFile::VERSION,
            encrypted: true,
            protection,
            kdf,
            kdf_memory_kib,
            kdf_iterations,
            kdf_parallelism,
            salt: salt_b64,
            nonce: b64_encode(&nonce),
            ciphertext: b64_encode(&ciphertext),
        };

        let raw = serde_json::to_string_pretty(&envelope).map_err(|err| {
            PluginError::new(-32000, format!("Failed to serialize vault: {err}"))
        })?;

        if self.has_password {
            // Password mode: envelope first, then drop any leftover open key.
            self.replace_envelope(&raw)?;
            Self::remove_open_key(&Self::open_key_path(&self.path));
        } else {
            // Open mode (P1): write/rotate vault.key BEFORE replacing the envelope so a
            // crash cannot leave ciphertext that no key can open. Skip rewrite when the
            // on-disk key already matches (P2: avoid non-atomic rewrite every save).
            let key_path = Self::open_key_path(&self.path);
            let key_existed = key_path.exists();
            let key_matched = Self::open_key_matches(&key_path, &**key);
            if !key_matched {
                Self::write_open_key(&key_path, &**key)?;
            } else {
                // N2: content match still fixes legacy 0644 permissions.
                Self::ensure_open_key_permissions(&key_path)?;
            }
            if let Err(err) = self.replace_envelope(&raw) {
                // Drop orphan key created in this attempt when no prior key existed.
                if !key_matched && !key_existed {
                    Self::remove_open_key(&key_path);
                }
                return Err(err);
            }
        }
        self.encryption_pending = false;
        Ok(())
    }

    fn verify_current_password(&self, password: &str) -> Result<(), PluginError> {
        let salt = self
            .salt
            .as_ref()
            .ok_or_else(|| PluginError::new(-32000, "Missing vault salt"))?;
        let key = self
            .master_key
            .as_ref()
            .ok_or_else(|| PluginError::new(-32602, "Vault is locked"))?;
        let check = derive_key(
            password,
            salt,
            self.kdf_memory_kib,
            self.kdf_iterations,
            self.kdf_parallelism,
        )?;
        if !keys_eq(&*check, &**key) {
            return Err(PluginError::new(-32602, "Wrong master password"));
        }
        Ok(())
    }

    pub fn unlock(&mut self, password: &str) -> Result<(), PluginError> {
        if self.unlocked {
            if self.has_password {
                let password = password.trim();
                if password.is_empty() {
                    return Err(PluginError::new(-32602, "Master password is required"));
                }
                self.verify_current_password(password)?;
            }
            return Ok(());
        }
        if !self.has_password {
            // Open mode should already be unlocked on load.
            let key_path = Self::open_key_path(&self.path);
            let key = Self::read_open_key(&key_path)?;
            let raw = fs::read_to_string(&self.path)
                .map_err(|err| PluginError::new(-32000, format!("Failed to read vault: {err}")))?;
            let envelope: EncryptedVaultFile = serde_json::from_str(&raw)
                .map_err(|_| PluginError::new(-32602, "Invalid encrypted vault"))?;
            self.data = Self::decrypt_envelope(&envelope, &*key).map_err(|err| {
                let msg = format!("{err:?}");
                if msg.contains("decrypt") || msg.contains("Decryption") {
                    PluginError::new(-32602, "Vault decryption failed")
                } else {
                    err
                }
            })?;
            self.master_key = Some(key);
            self.unlocked = true;
            return Ok(());
        }
        let password = password.trim();
        if password.is_empty() {
            return Err(PluginError::new(-32602, "Master password is required"));
        }

        let raw = fs::read_to_string(&self.path)
            .map_err(|err| PluginError::new(-32000, format!("Failed to read vault: {err}")))?;
        let envelope: EncryptedVaultFile = serde_json::from_str(&raw)
            .map_err(|_| PluginError::new(-32602, "Invalid encrypted vault"))?;
        Self::validate_envelope(&envelope)?;
        let salt = b64_decode(&envelope.salt)?;
        let (m, t, p) = envelope.argon2_params();
        let key = derive_key(password, &salt, m, t, p)?;
        match Self::decrypt_envelope(&envelope, &*key) {
            Ok(data) => {
                self.data = data;
                self.master_key = Some(key);
                self.salt = Some(salt);
                self.kdf_memory_kib = m;
                self.kdf_iterations = t;
                self.kdf_parallelism = p;
                self.unlocked = true;
                Ok(())
            }
            Err(err) => {
                let msg = format!("{err:?}");
                if msg.contains("decrypt")
                    || msg.contains("Decryption")
                    || msg.contains("Invalid vault payload")
                {
                    Err(PluginError::new(-32602, "Wrong master password"))
                } else {
                    Err(err)
                }
            }
        }
    }

    pub fn lock(&mut self) -> Result<(), PluginError> {
        if !self.has_password {
            return Ok(());
        }
        // Best-effort flush; locking must clear secrets from memory even if disk write fails.
        if self.unlocked {
            if let Err(err) = self.persist() {
                eprintln!("[io.dbx.password] persist before lock failed: {err:?}");
            }
        }
        self.data = VaultData::default();
        self.master_key = None; // Zeroizing drops and zeroes
        self.unlocked = false;
        Ok(())
    }

    pub fn set_master_password(
        &mut self,
        password: &str,
        current_password: Option<&str>,
    ) -> Result<(), PluginError> {
        self.require_unlocked()?;
        let password = password.trim();
        if password.is_empty() {
            return Err(PluginError::new(-32602, "Master password is required"));
        }
        if password.chars().count() < 8 {
            return Err(PluginError::new(
                -32602,
                "Master password must be at least 8 characters",
            ));
        }

        if self.has_password {
            let current = current_password.map(str::trim).unwrap_or("");
            if current.is_empty() {
                return Err(PluginError::new(
                    -32602,
                    "Current master password is required",
                ));
            }
            self.verify_current_password(current)?;
        }

        let salt = random_salt();
        let key = derive_key_default(password, &salt)?;
        let prev_has_password = self.has_password;
        let prev_key = self.master_key.take();
        let prev_salt = self.salt.clone();
        let prev_kdf = (
            self.kdf_memory_kib,
            self.kdf_iterations,
            self.kdf_parallelism,
        );
        self.has_password = true;
        self.master_key = Some(key);
        self.salt = Some(salt.to_vec());
        self.kdf_memory_kib = ARGON2_MEMORY_KIB;
        self.kdf_iterations = ARGON2_ITERATIONS;
        self.kdf_parallelism = ARGON2_PARALLELISM;
        self.unlocked = true;
        if let Err(err) = self.persist() {
            self.has_password = prev_has_password;
            self.master_key = prev_key;
            self.salt = prev_salt;
            self.kdf_memory_kib = prev_kdf.0;
            self.kdf_iterations = prev_kdf.1;
            self.kdf_parallelism = prev_kdf.2;
            return Err(err);
        }
        Ok(())
    }

    pub fn clear_master_password(&mut self, current_password: &str) -> Result<(), PluginError> {
        self.require_unlocked()?;
        if !self.has_password {
            return Ok(());
        }
        let current = current_password.trim();
        if current.is_empty() {
            return Err(PluginError::new(
                -32602,
                "Current master password is required",
            ));
        }
        self.verify_current_password(current)?;

        // Switch back to open mode: new local key file, still encrypted on disk.
        let key = random_key();
        let prev_key = self.master_key.take();
        let prev_salt = self.salt.clone();
        self.has_password = false;
        self.master_key = Some(key);
        self.salt = None;
        self.unlocked = true;
        if let Err(err) = self.persist() {
            self.has_password = true;
            self.master_key = prev_key;
            self.salt = prev_salt;
            return Err(err);
        }
        Ok(())
    }

    pub fn snapshot(&self) -> Result<VaultData, PluginError> {
        self.require_unlocked()?;
        Ok(self.data.clone())
    }

    /// List/search without secrets; use `get_entry` for the password field.
    pub fn list(&self, query: Option<&str>) -> Result<VaultData, PluginError> {
        let data = self.snapshot()?;
        let filtered = match query.map(str::trim).filter(|q| !q.is_empty()) {
            None => data,
            Some(query) => {
                let needle = query.to_lowercase();
                let entries: Vec<PasswordEntry> = data
                    .entries
                    .iter()
                    .filter(|entry| entry_matches(entry, &needle))
                    .cloned()
                    .collect();
                VaultData {
                    groups: data.groups,
                    entries,
                }
            }
        };
        Ok(filtered.redacted())
    }

    fn require_group_mut(&mut self, id: &str) -> Result<&mut Group, PluginError> {
        self.require_unlocked()?;
        self.data
            .groups
            .iter_mut()
            .find(|g| g.id == id)
            .ok_or_else(|| PluginError::new(-32602, "Group not found"))
    }

    fn require_entry_mut(&mut self, id: &str) -> Result<&mut PasswordEntry, PluginError> {
        self.require_unlocked()?;
        self.data
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| PluginError::new(-32602, "Password entry not found"))
    }

    fn group_exists(&self, id: &str) -> bool {
        self.data.groups.iter().any(|g| g.id == id)
    }

    fn resolve_parent_id(&self, parent_id: Option<&str>) -> Result<String, PluginError> {
        let parent_id = parent_id
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .unwrap_or("");
        if parent_id.is_empty() {
            return Ok(String::new());
        }
        if !self.group_exists(parent_id) {
            return Err(PluginError::new(-32602, "Parent group not found"));
        }
        Ok(parent_id.to_string())
    }

    fn sibling_name_taken(&self, parent_id: &str, name: &str, except_id: Option<&str>) -> bool {
        self.data.groups.iter().any(|g| {
            if g.parent_id != parent_id || !g.name.eq_ignore_ascii_case(name) {
                return false;
            }
            match except_id {
                Some(id) => g.id != id,
                None => true,
            }
        })
    }

    pub fn create_group(
        &mut self,
        name: &str,
        parent_id: Option<&str>,
    ) -> Result<Group, PluginError> {
        self.require_unlocked()?;
        let name = name.trim();
        if name.is_empty() {
            return Err(PluginError::new(-32602, "Group name is required"));
        }
        let parent_id = self.resolve_parent_id(parent_id)?;
        if self.sibling_name_taken(&parent_id, name, None) {
            return Err(PluginError::new(-32602, "Group name already exists"));
        }
        let now = now_ms();
        let group = Group {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            parent_id,
            created_at: now,
            updated_at: now,
        };
        self.data.groups.push(group.clone());
        self.persist()?;
        Ok(group)
    }

    pub fn rename_group(&mut self, id: &str, name: &str) -> Result<Group, PluginError> {
        self.require_unlocked()?;
        if id == DEFAULT_GROUP_ID {
            return Err(PluginError::new(-32602, "Cannot rename the default group"));
        }
        let name = name.trim();
        if name.is_empty() {
            return Err(PluginError::new(-32602, "Group name is required"));
        }
        let parent_id = self
            .data
            .groups
            .iter()
            .find(|g| g.id == id)
            .map(|g| g.parent_id.clone())
            .ok_or_else(|| PluginError::new(-32602, "Group not found"))?;
        if self.sibling_name_taken(&parent_id, name, Some(id)) {
            return Err(PluginError::new(-32602, "Group name already exists"));
        }
        let now = now_ms();
        {
            let group = self.require_group_mut(id)?;
            group.name = name.to_string();
            group.updated_at = now;
        }
        let group = self
            .data
            .groups
            .iter()
            .find(|g| g.id == id)
            .cloned()
            .ok_or_else(|| PluginError::new(-32602, "Group not found"))?;
        self.persist()?;
        Ok(group)
    }

    pub fn delete_group(&mut self, id: &str) -> Result<(), PluginError> {
        self.require_unlocked()?;
        if id == DEFAULT_GROUP_ID {
            return Err(PluginError::new(-32602, "Cannot delete the default group"));
        }
        let parent_id = self
            .data
            .groups
            .iter()
            .find(|g| g.id == id)
            .map(|g| g.parent_id.clone())
            .ok_or_else(|| PluginError::new(-32602, "Group not found"))?;

        let fallback = if parent_id.is_empty() || !self.group_exists(&parent_id) {
            DEFAULT_GROUP_ID.to_string()
        } else {
            parent_id.clone()
        };

        let now = now_ms();
        for group in &mut self.data.groups {
            if group.parent_id == id {
                group.parent_id = parent_id.clone();
                group.updated_at = now;
            }
        }
        for entry in &mut self.data.entries {
            if entry.group_id == id {
                entry.group_id = fallback.clone();
                entry.updated_at = now;
            }
        }
        self.data.groups.retain(|g| g.id != id);
        self.persist()?;
        Ok(())
    }

    pub fn create_entry(
        &mut self,
        group_id: Option<&str>,
        title: &str,
        username: &str,
        password: &str,
        url: &str,
        notes: &str,
    ) -> Result<PasswordEntry, PluginError> {
        self.require_unlocked()?;
        let title = title.trim();
        if title.is_empty() {
            return Err(PluginError::new(-32602, "Title is required"));
        }
        let group_id = group_id
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .unwrap_or(DEFAULT_GROUP_ID);
        if !self.group_exists(group_id) {
            return Err(PluginError::new(-32602, "Group not found"));
        }
        let now = now_ms();
        let entry = PasswordEntry {
            id: Uuid::new_v4().to_string(),
            group_id: group_id.to_string(),
            title: title.to_string(),
            username: username.trim().to_string(),
            password: password.to_string(),
            url: url.trim().to_string(),
            notes: notes.to_string(),
            created_at: now,
            updated_at: now,
        };
        self.data.entries.insert(0, entry.clone());
        self.persist()?;
        Ok(entry)
    }

    pub fn update_entry(
        &mut self,
        id: &str,
        group_id: Option<&str>,
        title: &str,
        username: &str,
        password: &str,
        url: &str,
        notes: &str,
    ) -> Result<PasswordEntry, PluginError> {
        self.require_unlocked()?;
        let title = title.trim();
        if title.is_empty() {
            return Err(PluginError::new(-32602, "Title is required"));
        }
        if let Some(group_id) = group_id.map(str::trim).filter(|id| !id.is_empty()) {
            if !self.group_exists(group_id) {
                return Err(PluginError::new(-32602, "Group not found"));
            }
        }
        let now = now_ms();
        {
            let entry = self.require_entry_mut(id)?;
            if let Some(group_id) = group_id.map(str::trim).filter(|id| !id.is_empty()) {
                entry.group_id = group_id.to_string();
            }
            entry.title = title.to_string();
            entry.username = username.trim().to_string();
            entry.password = password.to_string();
            entry.url = url.trim().to_string();
            entry.notes = notes.to_string();
            entry.updated_at = now;
        }
        let entry = self
            .data
            .entries
            .iter()
            .find(|e| e.id == id)
            .cloned()
            .ok_or_else(|| PluginError::new(-32602, "Password entry not found"))?;
        self.persist()?;
        Ok(entry)
    }

    pub fn delete_entry(&mut self, id: &str) -> Result<bool, PluginError> {
        self.require_unlocked()?;
        let before = self.data.entries.len();
        self.data.entries.retain(|e| e.id != id);
        let deleted = self.data.entries.len() != before;
        if deleted {
            self.persist()?;
        }
        Ok(deleted)
    }

    pub fn get_entry(&self, id: &str) -> Result<Option<&PasswordEntry>, PluginError> {
        self.require_unlocked()?;
        Ok(self.data.entries.iter().find(|e| e.id == id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PasswordEntry;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_vault_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "dbx-pw-vault-test-{}-{}-{}",
            std::process::id(),
            nanos,
            seq
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn empty_path_bootstraps_encrypted_open_vault() {
        let dir = tmp_vault_dir();
        let path = dir.join("vault.json");

        let store = VaultStore::load(path.clone());
        assert!(store.unlocked);
        assert!(!store.has_password);

        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("\"entries\""));
        let envelope: EncryptedVaultFile = serde_json::from_str(&raw).unwrap();
        assert!(envelope.encrypted);
        assert_eq!(envelope.protection, EncryptedVaultFile::PROTECTION_OPEN);
        assert!(dir.join("vault.key").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn migrates_legacy_plaintext_vault() {
        let dir = tmp_vault_dir();
        let path = dir.join("vault.json");

        let legacy = VaultData {
            groups: vec![Group {
                id: DEFAULT_GROUP_ID.to_string(),
                name: "Default".into(),
                parent_id: String::new(),
                created_at: 1,
                updated_at: 1,
            }],
            entries: vec![PasswordEntry {
                id: "e1".into(),
                group_id: DEFAULT_GROUP_ID.to_string(),
                title: "Legacy".into(),
                username: "u".into(),
                password: "secret-plain".into(),
                url: String::new(),
                notes: String::new(),
                created_at: 1,
                updated_at: 1,
            }],
        };
        fs::write(&path, serde_json::to_string_pretty(&legacy).unwrap()).unwrap();

        let store = VaultStore::load(path.clone());
        assert!(store.unlocked);
        assert!(!store.has_password);
        assert_eq!(store.data.entries.len(), 1);
        assert_eq!(store.data.entries[0].password, "secret-plain");

        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("secret-plain"));
        let envelope: EncryptedVaultFile = serde_json::from_str(&raw).unwrap();
        assert_eq!(envelope.protection, EncryptedVaultFile::PROTECTION_OPEN);
        assert!(dir.join("vault.key").exists());

        // Reload from migrated files
        let store2 = VaultStore::load(path.clone());
        assert!(store2.unlocked);
        assert_eq!(store2.data.entries[0].password, "secret-plain");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_encrypted_file_is_not_wiped() {
        let dir = tmp_vault_dir();
        let path = dir.join("vault.json");
        // Looks like our envelope but incomplete / invalid for full parse path.
        fs::write(
            &path,
            r#"{"format":"dbx-password-vault","encrypted":true,"ciphertext":"%%%"}"#,
        )
        .unwrap();
        let before = fs::read_to_string(&path).unwrap();

        let store = VaultStore::load(path.clone());
        assert!(!store.unlocked);
        let after = fs::read_to_string(&path).unwrap();
        assert_eq!(before, after, "corrupt vault must not be overwritten");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_master_password_stays_encrypted() {
        let dir = tmp_vault_dir();
        let path = dir.join("vault.json");

        let mut store = VaultStore::load(path.clone());
        store
            .create_entry(None, "T", "u", "p", "", "")
            .unwrap();
        store.set_master_password("test-pass", None).unwrap();
        assert!(store.has_password);
        assert!(!dir.join("vault.key").exists());

        store.clear_master_password("test-pass").unwrap();
        assert!(!store.has_password);
        assert!(dir.join("vault.key").exists());

        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("\"password\":\"p\""));
        let envelope: EncryptedVaultFile = serde_json::from_str(&raw).unwrap();
        assert_eq!(envelope.protection, EncryptedVaultFile::PROTECTION_OPEN);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_mode_persist_does_not_rewrite_key() {
        let dir = tmp_vault_dir();
        let path = dir.join("vault.json");
        let key_path = dir.join("vault.key");

        let mut store = VaultStore::load(path.clone());
        let key_before = fs::read(&key_path).unwrap();
        #[cfg(unix)]
        let mtime_before = fs::metadata(&key_path).unwrap().modified().unwrap();

        store
            .create_entry(None, "A", "u", "p", "", "")
            .unwrap();
        store
            .create_entry(None, "B", "u", "p", "", "")
            .unwrap();

        let key_after = fs::read(&key_path).unwrap();
        assert_eq!(key_before, key_after, "vault.key must not be rewritten on every save");
        #[cfg(unix)]
        {
            let mtime_after = fs::metadata(&key_path).unwrap().modified().unwrap();
            assert_eq!(mtime_before, mtime_after);
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn lock_clears_memory_even_when_persist_fails() {
        let dir = tmp_vault_dir();
        let path = dir.join("vault.json");

        let mut store = VaultStore::load(path.clone());
        store
            .create_entry(None, "Secret", "u", "hunter2", "", "")
            .unwrap();
        store.set_master_password("test-pass", None).unwrap();
        assert!(store.unlocked);
        assert!(store.master_key.is_some());

        // Make the vault directory read-only so persist before lock fails.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&dir).unwrap().permissions();
            perms.set_mode(0o555);
            fs::set_permissions(&dir, perms).unwrap();
        }

        store.lock().unwrap();
        assert!(!store.unlocked);
        assert!(store.master_key.is_none());
        assert!(store.data.entries.is_empty());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&dir).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&dir, perms).unwrap();
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn matching_key_still_fixes_legacy_permissions() {
        let dir = tmp_vault_dir();
        let path = dir.join("vault.json");
        let key_path = dir.join("vault.key");

        let mut store = VaultStore::load(path.clone());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&key_path).unwrap().permissions();
            perms.set_mode(0o644);
            fs::set_permissions(&key_path, perms).unwrap();
            assert_eq!(
                fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
                0o644
            );
        }

        store
            .create_entry(None, "A", "u", "p", "", "")
            .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn encryption_pending_clears_after_successful_persist() {
        let dir = tmp_vault_dir();
        let path = dir.join("vault.json");
        // Simulate migrate failure: plaintext on disk, in-memory open with pending flag.
        let legacy = VaultData {
            groups: vec![Group {
                id: DEFAULT_GROUP_ID.to_string(),
                name: "Default".into(),
                parent_id: String::new(),
                created_at: 1,
                updated_at: 1,
            }],
            entries: vec![],
        };
        fs::write(&path, serde_json::to_string_pretty(&legacy).unwrap()).unwrap();
        // Make dir read-only so first bootstrap fails.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&dir).unwrap().permissions();
            perms.set_mode(0o555);
            fs::set_permissions(&dir, perms).unwrap();
        }

        let mut store = VaultStore::load(path.clone());
        #[cfg(unix)]
        {
            let (_, _, pending) = store.status();
            assert!(pending, "readonly migrate should set encryptionPending");
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&dir).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&dir, perms).unwrap();
        }

        store
            .create_entry(None, "Recovered", "u", "p", "", "")
            .unwrap();
        let (_, _, pending) = store.status();
        assert!(!pending);
        let raw = fs::read_to_string(&path).unwrap();
        let envelope: EncryptedVaultFile = serde_json::from_str(&raw).unwrap();
        assert_eq!(envelope.protection, EncryptedVaultFile::PROTECTION_OPEN);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_redacts_passwords_get_returns_secret() {
        let dir = tmp_vault_dir();
        let path = dir.join("vault.json");
        let mut store = VaultStore::load(path);
        store
            .create_entry(None, "T", "u", "secret-pw", "", "")
            .unwrap();
        let listed = store.list(None).unwrap();
        assert_eq!(listed.entries.len(), 1);
        assert_eq!(listed.entries[0].password, "");
        let full = store.get_entry(&listed.entries[0].id).unwrap().unwrap();
        assert_eq!(full.password, "secret-pw");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn password_mode_roundtrip_v3_with_aad() {
        let dir = tmp_vault_dir();
        let path = dir.join("vault.json");
        let mut store = VaultStore::load(path.clone());
        store
            .create_entry(None, "T", "u", "secret-pw", "", "")
            .unwrap();
        store.set_master_password("test-pass-ok", None).unwrap();
        store.lock().unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        let envelope: EncryptedVaultFile = serde_json::from_str(&raw).unwrap();
        assert_eq!(envelope.version, EncryptedVaultFile::VERSION);
        assert_eq!(envelope.kdf_memory_kib, Some(ARGON2_MEMORY_KIB));
        assert!(!raw.contains("secret-pw"));

        let mut store2 = VaultStore::load(path);
        store2.unlock("test-pass-ok").unwrap();
        assert_eq!(store2.get_entry(&store2.list(None).unwrap().entries[0].id).unwrap().unwrap().password, "secret-pw");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_master_password_writes_key_before_envelope() {
        let dir = tmp_vault_dir();
        let path = dir.join("vault.json");
        let key_path = dir.join("vault.key");

        let mut store = VaultStore::load(path.clone());
        store
            .create_entry(None, "T", "u", "p", "", "")
            .unwrap();
        store.set_master_password("test-pass", None).unwrap();

        // Occupy vault.key as a directory so key write fails (maintainer repro).
        fs::create_dir_all(&key_path).unwrap();
        let before = fs::read_to_string(&path).unwrap();
        let err = store.clear_master_password("test-pass").unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("vault.key")
                || msg.contains("vault key")
                || msg.contains("Is a directory")
                || msg.contains("directory"),
            "unexpected error: {msg}"
        );
        // Envelope must remain password-protected — not replaced with an open envelope.
        let after = fs::read_to_string(&path).unwrap();
        assert_eq!(before, after);
        let envelope: EncryptedVaultFile = serde_json::from_str(&after).unwrap();
        assert_eq!(
            envelope.protection,
            EncryptedVaultFile::PROTECTION_PASSWORD
        );
        assert!(store.has_password, "in-memory mode must roll back");

        let _ = fs::remove_dir_all(&dir);
    }
}
