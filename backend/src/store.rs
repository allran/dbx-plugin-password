use std::fs;
use std::path::PathBuf;

use dbx_plugin_sdk::PluginError;
use uuid::Uuid;

use crate::model::{Group, PasswordEntry, VaultData, DEFAULT_GROUP_ID};
use crate::util::{entry_matches, now_ms};

pub struct VaultStore {
    data: VaultData,
    path: PathBuf,
}

impl VaultStore {
    pub fn load(path: PathBuf) -> Self {
        let mut data = fs::read_to_string(&path)
            .ok()
            .and_then(|raw| serde_json::from_str::<VaultData>(&raw).ok())
            .unwrap_or_default();
        data.ensure_default_group(now_ms());
        for entry in &mut data.entries {
            if entry.group_id.is_empty()
                || !data.groups.iter().any(|g| g.id == entry.group_id)
            {
                entry.group_id = DEFAULT_GROUP_ID.to_string();
            }
        }
        Self { data, path }
    }

    fn persist(&self) -> Result<(), PluginError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                PluginError::new(-32000, format!("Failed to create data dir: {err}"))
            })?;
        }
        let raw = serde_json::to_string_pretty(&self.data).map_err(|err| {
            PluginError::new(-32000, format!("Failed to serialize vault: {err}"))
        })?;
        fs::write(&self.path, raw)
            .map_err(|err| PluginError::new(-32000, format!("Failed to write vault: {err}")))?;
        Ok(())
    }

    pub fn snapshot(&self) -> VaultData {
        self.data.clone()
    }

    pub fn list(&self, query: Option<&str>) -> VaultData {
        let Some(query) = query.map(str::trim).filter(|q| !q.is_empty()) else {
            return self.snapshot();
        };
        let needle = query.to_lowercase();
        let entries: Vec<PasswordEntry> = self
            .data
            .entries
            .iter()
            .filter(|entry| entry_matches(entry, &needle))
            .cloned()
            .collect();
        VaultData {
            groups: self.data.groups.clone(),
            entries,
        }
    }

    fn require_group_mut(&mut self, id: &str) -> Result<&mut Group, PluginError> {
        self.data
            .groups
            .iter_mut()
            .find(|g| g.id == id)
            .ok_or_else(|| PluginError::new(-32602, "Group not found"))
    }

    fn require_entry_mut(&mut self, id: &str) -> Result<&mut PasswordEntry, PluginError> {
        self.data
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| PluginError::new(-32602, "Password entry not found"))
    }

    fn group_exists(&self, id: &str) -> bool {
        self.data.groups.iter().any(|g| g.id == id)
    }

    pub fn create_group(&mut self, name: &str) -> Result<Group, PluginError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(PluginError::new(-32602, "Group name is required"));
        }
        if self
            .data
            .groups
            .iter()
            .any(|g| g.name.eq_ignore_ascii_case(name))
        {
            return Err(PluginError::new(-32602, "Group name already exists"));
        }
        let now = now_ms();
        let group = Group {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            created_at: now,
            updated_at: now,
        };
        self.data.groups.push(group.clone());
        self.persist()?;
        Ok(group)
    }

    pub fn rename_group(&mut self, id: &str, name: &str) -> Result<Group, PluginError> {
        if id == DEFAULT_GROUP_ID {
            return Err(PluginError::new(-32602, "Cannot rename the default group"));
        }
        let name = name.trim();
        if name.is_empty() {
            return Err(PluginError::new(-32602, "Group name is required"));
        }
        if self
            .data
            .groups
            .iter()
            .any(|g| g.id != id && g.name.eq_ignore_ascii_case(name))
        {
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
        if id == DEFAULT_GROUP_ID {
            return Err(PluginError::new(-32602, "Cannot delete the default group"));
        }
        if !self.group_exists(id) {
            return Err(PluginError::new(-32602, "Group not found"));
        }
        self.data.groups.retain(|g| g.id != id);
        for entry in &mut self.data.entries {
            if entry.group_id == id {
                entry.group_id = DEFAULT_GROUP_ID.to_string();
                entry.updated_at = now_ms();
            }
        }
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
        let before = self.data.entries.len();
        self.data.entries.retain(|e| e.id != id);
        let deleted = self.data.entries.len() != before;
        if deleted {
            self.persist()?;
        }
        Ok(deleted)
    }

    pub fn get_entry(&self, id: &str) -> Option<&PasswordEntry> {
        self.data.entries.iter().find(|e| e.id == id)
    }
}
