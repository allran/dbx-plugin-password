use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use dbx_plugin_sdk::PluginError;
use uuid::Uuid;

use crate::crypto::{
    b64_decode, b64_encode, decrypt, derive_key, encrypt, random_key, random_salt,
};
use crate::model::{
    EncryptedVaultFile, Group, PasswordEntry, VaultData, DEFAULT_GROUP_ID,
};
use crate::util::{entry_matches, now_ms};

pub struct VaultStore {
    data: VaultData,
    path: PathBuf,
    unlocked: bool,
    has_password: bool,
    master_key: Option<[u8; 32]>,
    salt: Option<Vec<u8>>,
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

    fn read_open_key(path: &PathBuf) -> Result<[u8; 32], PluginError> {
        let raw = fs::read_to_string(path)
            .map_err(|_| PluginError::new(-32000, "Missing vault open key"))?;
        let bytes = b64_decode(raw.trim())?;
        if bytes.len() != 32 {
            return Err(PluginError::new(-32000, "Invalid vault open key"));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(key)
    }

    fn write_open_key(path: &PathBuf, key: &[u8; 32]) -> Result<(), PluginError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                PluginError::new(-32000, format!("Failed to create data dir: {err}"))
            })?;
        }
        fs::write(path, b64_encode(key))
            .map_err(|err| PluginError::new(-32000, format!("Failed to write vault key: {err}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    fn remove_open_key(path: &PathBuf) {
        let _ = fs::remove_file(path);
    }

    fn decrypt_envelope(
        envelope: &EncryptedVaultFile,
        key: &[u8; 32],
    ) -> Result<VaultData, PluginError> {
        let nonce = b64_decode(&envelope.nonce)?;
        let ciphertext = b64_decode(&envelope.ciphertext)?;
        let plaintext = decrypt(key, &nonce, &ciphertext)?;
        let data: VaultData = serde_json::from_slice(&plaintext)
            .map_err(|_| PluginError::new(-32602, "Invalid vault payload"))?;
        Ok(Self::prepare_data(data))
    }

    /// Create a new open-mode encrypted vault (or migrate plaintext → encrypted).
    fn bootstrap_open(path: PathBuf, data: VaultData) -> Self {
        let data = Self::prepare_data(data);
        let key = random_key();
        let store = Self {
            data,
            path,
            unlocked: true,
            has_password: false,
            master_key: Some(key),
            salt: None,
        };
        // Best-effort persist; load still returns usable in-memory vault if write fails.
        let _ = store.persist();
        store
    }

    fn locked_empty(path: PathBuf, has_password: bool, salt: Option<Vec<u8>>) -> Self {
        Self {
            data: VaultData::default(),
            path,
            unlocked: false,
            has_password,
            master_key: None,
            salt,
        }
    }

    pub fn load(path: PathBuf) -> Self {
        let raw = fs::read_to_string(&path).unwrap_or_default();
        if raw.trim().is_empty() {
            return Self::bootstrap_open(path, VaultData::default());
        }

        if let Ok(envelope) = serde_json::from_str::<EncryptedVaultFile>(&raw) {
            if envelope.encrypted && envelope.format == EncryptedVaultFile::FORMAT {
                if envelope.protection == EncryptedVaultFile::PROTECTION_OPEN {
                    // Open mode: auto-unlock with sibling vault.key
                    let key_path = Self::open_key_path(&path);
                    if let Ok(key) = Self::read_open_key(&key_path) {
                        if let Ok(data) = Self::decrypt_envelope(&envelope, &key) {
                            return Self {
                                data,
                                path,
                                unlocked: true,
                                has_password: false,
                                master_key: Some(key),
                                salt: None,
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
                    return Self::bootstrap_open(path, data);
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

    pub fn status(&self) -> (bool, bool) {
        (self.has_password, self.unlocked)
    }

    fn require_unlocked(&self) -> Result<(), PluginError> {
        if self.unlocked {
            Ok(())
        } else {
            Err(PluginError::new(-32602, "Vault is locked"))
        }
    }

    fn persist(&self) -> Result<(), PluginError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                PluginError::new(-32000, format!("Failed to create data dir: {err}"))
            })?;
        }

        let key = self
            .master_key
            .as_ref()
            .ok_or_else(|| PluginError::new(-32602, "Vault is locked"))?;
        let plaintext = serde_json::to_vec(&self.data).map_err(|err| {
            PluginError::new(-32000, format!("Failed to serialize vault: {err}"))
        })?;
        let (ciphertext, nonce) = encrypt(key, &plaintext)?;

        let envelope = if self.has_password {
            let salt = self
                .salt
                .as_ref()
                .ok_or_else(|| PluginError::new(-32000, "Missing vault salt"))?;
            EncryptedVaultFile {
                format: EncryptedVaultFile::FORMAT.to_string(),
                version: EncryptedVaultFile::VERSION,
                encrypted: true,
                protection: EncryptedVaultFile::PROTECTION_PASSWORD.to_string(),
                kdf: EncryptedVaultFile::KDF.to_string(),
                salt: b64_encode(salt),
                nonce: b64_encode(&nonce),
                ciphertext: b64_encode(&ciphertext),
            }
        } else {
            EncryptedVaultFile {
                format: EncryptedVaultFile::FORMAT.to_string(),
                version: EncryptedVaultFile::VERSION,
                encrypted: true,
                protection: EncryptedVaultFile::PROTECTION_OPEN.to_string(),
                kdf: String::new(),
                salt: String::new(),
                nonce: b64_encode(&nonce),
                ciphertext: b64_encode(&ciphertext),
            }
        };

        let raw = serde_json::to_string_pretty(&envelope).map_err(|err| {
            PluginError::new(-32000, format!("Failed to serialize vault: {err}"))
        })?;
        // Atomic replace: write temp then rename so a crash cannot truncate vault.json.
        let tmp = self.path.with_extension("json.tmp");
        fs::write(&tmp, &raw)
            .map_err(|err| PluginError::new(-32000, format!("Failed to write vault: {err}")))?;
        #[cfg(windows)]
        {
            let _ = fs::remove_file(&self.path);
        }
        fs::rename(&tmp, &self.path).map_err(|err| {
            let _ = fs::remove_file(&tmp);
            PluginError::new(-32000, format!("Failed to replace vault: {err}"))
        })?;

        if self.has_password {
            Self::remove_open_key(&Self::open_key_path(&self.path));
        } else {
            // Write open key only after the envelope is safely on disk.
            Self::write_open_key(&Self::open_key_path(&self.path), key)?;
        }
        Ok(())
    }

    pub fn unlock(&mut self, password: &str) -> Result<(), PluginError> {
        if self.unlocked {
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
            self.data = Self::decrypt_envelope(&envelope, &key)?;
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
        let salt = b64_decode(&envelope.salt)?;
        let key = derive_key(password, &salt)?;
        self.data = Self::decrypt_envelope(&envelope, &key)?;
        self.master_key = Some(key);
        self.salt = Some(salt);
        self.unlocked = true;
        Ok(())
    }

    pub fn lock(&mut self) -> Result<(), PluginError> {
        if !self.has_password {
            return Ok(());
        }
        if self.unlocked {
            self.persist()?;
        }
        self.data = VaultData::default();
        self.master_key = None;
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
        if password.chars().count() < 4 {
            return Err(PluginError::new(
                -32602,
                "Master password must be at least 4 characters",
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
            let salt = self
                .salt
                .as_ref()
                .ok_or_else(|| PluginError::new(-32000, "Missing vault salt"))?;
            let check = derive_key(current, salt)?;
            if Some(check) != self.master_key {
                return Err(PluginError::new(-32602, "Wrong master password"));
            }
        }

        let salt = random_salt();
        let key = derive_key(password, &salt)?;
        let prev_has_password = self.has_password;
        let prev_key = self.master_key;
        let prev_salt = self.salt.clone();
        self.has_password = true;
        self.master_key = Some(key);
        self.salt = Some(salt.to_vec());
        self.unlocked = true;
        if let Err(err) = self.persist() {
            self.has_password = prev_has_password;
            self.master_key = prev_key;
            self.salt = prev_salt;
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
        let salt = self
            .salt
            .as_ref()
            .ok_or_else(|| PluginError::new(-32000, "Missing vault salt"))?;
        let check = derive_key(current, salt)?;
        if Some(check) != self.master_key {
            return Err(PluginError::new(-32602, "Wrong master password"));
        }

        // Switch back to open mode: new local key file, still encrypted on disk.
        let key = random_key();
        let prev_key = self.master_key;
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

    pub fn list(&self, query: Option<&str>) -> Result<VaultData, PluginError> {
        let data = self.snapshot()?;
        let Some(query) = query.map(str::trim).filter(|q| !q.is_empty()) else {
            return Ok(data);
        };
        let needle = query.to_lowercase();
        let entries: Vec<PasswordEntry> = data
            .entries
            .iter()
            .filter(|entry| entry_matches(entry, &needle))
            .cloned()
            .collect();
        Ok(VaultData {
            groups: data.groups,
            entries,
        })
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
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("dbx-pw-vault-test-{nanos}"));
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
}
