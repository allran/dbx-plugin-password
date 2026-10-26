use std::sync::{Arc, Mutex};

use dbx_plugin_sdk::{PluginEmitter, PluginError, PluginHandler, RequestContext};
use serde_json::{json, Value};

use crate::store::VaultStore;

pub struct Plugin {
    store: Arc<Mutex<VaultStore>>,
}

impl Plugin {
    pub fn new(store: Arc<Mutex<VaultStore>>) -> Self {
        Self { store }
    }

    fn with_store<R>(
        &self,
        f: impl FnOnce(&mut VaultStore) -> Result<R, PluginError>,
    ) -> Result<R, PluginError> {
        let mut store = self
            .store
            .lock()
            .map_err(|_| PluginError::new(-32000, "Vault store is poisoned"))?;
        f(&mut store)
    }
}

fn require_str<'a>(params: &'a Value, key: &str) -> Result<&'a str, PluginError> {
    params
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| PluginError::new(-32602, format!("Missing {key}")))
}

fn optional_str<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params.get(key).and_then(Value::as_str)
}

fn field_or_empty<'a>(params: &'a Value, key: &str) -> &'a str {
    optional_str(params, key).unwrap_or("")
}

impl PluginHandler for Plugin {
    fn handle(
        &self,
        _context: RequestContext,
        method: &str,
        params: Value,
        _emitter: &PluginEmitter,
    ) -> Result<Value, PluginError> {
        match method {
            "vault/status" => self.with_store(|store| {
                let (has_password, unlocked) = store.status();
                Ok(json!({
                    "hasPassword": has_password,
                    "unlocked": unlocked,
                    "locked": has_password && !unlocked,
                }))
            }),
            "vault/unlock" => {
                let password = field_or_empty(&params, "password");
                self.with_store(|store| {
                    store.unlock(password)?;
                    let (has_password, unlocked) = store.status();
                    Ok(json!({
                        "success": true,
                        "hasPassword": has_password,
                        "unlocked": unlocked,
                    }))
                })
            }
            "vault/lock" => self.with_store(|store| {
                store.lock()?;
                let (has_password, unlocked) = store.status();
                Ok(json!({
                    "success": true,
                    "hasPassword": has_password,
                    "unlocked": unlocked,
                }))
            }),
            "vault/setMasterPassword" => {
                let password = require_str(&params, "password")?;
                let current = optional_str(&params, "currentPassword");
                self.with_store(|store| {
                    store.set_master_password(password, current)?;
                    Ok(json!({ "success": true, "hasPassword": true, "unlocked": true }))
                })
            }
            "vault/clearMasterPassword" => {
                let current = require_str(&params, "currentPassword")?;
                self.with_store(|store| {
                    store.clear_master_password(current)?;
                    Ok(json!({ "success": true, "hasPassword": false, "unlocked": true }))
                })
            }
            "password/list" => {
                let query = optional_str(&params, "query");
                self.with_store(|store| {
                    let vault = store.list(query)?;
                    Ok(json!({
                        "groups": vault.groups,
                        "entries": vault.entries,
                    }))
                })
            }
            "password/get" => {
                let id = require_str(&params, "id")?;
                self.with_store(|store| {
                    let entry = store
                        .get_entry(id)?
                        .cloned()
                        .ok_or_else(|| PluginError::new(-32602, "Password entry not found"))?;
                    Ok(json!({ "entry": entry }))
                })
            }
            "password/create" => {
                let title = require_str(&params, "title")?;
                let group_id = optional_str(&params, "groupId");
                let username = field_or_empty(&params, "username");
                let password = field_or_empty(&params, "password");
                let url = field_or_empty(&params, "url");
                let notes = field_or_empty(&params, "notes");
                self.with_store(|store| {
                    let entry =
                        store.create_entry(group_id, title, username, password, url, notes)?;
                    Ok(json!({ "entry": entry }))
                })
            }
            "password/update" => {
                let id = require_str(&params, "id")?;
                let title = require_str(&params, "title")?;
                let group_id = optional_str(&params, "groupId");
                let username = field_or_empty(&params, "username");
                let password = field_or_empty(&params, "password");
                let url = field_or_empty(&params, "url");
                let notes = field_or_empty(&params, "notes");
                self.with_store(|store| {
                    let entry = store.update_entry(
                        id, group_id, title, username, password, url, notes,
                    )?;
                    Ok(json!({ "entry": entry }))
                })
            }
            "password/delete" => {
                let id = require_str(&params, "id")?;
                self.with_store(|store| {
                    let deleted = store.delete_entry(id)?;
                    Ok(json!({ "success": deleted }))
                })
            }
            "group/create" => {
                let name = require_str(&params, "name")?;
                let parent_id = optional_str(&params, "parentId");
                self.with_store(|store| {
                    let group = store.create_group(name, parent_id)?;
                    Ok(json!({ "group": group }))
                })
            }
            "group/rename" => {
                let id = require_str(&params, "id")?;
                let name = require_str(&params, "name")?;
                self.with_store(|store| {
                    let group = store.rename_group(id, name)?;
                    Ok(json!({ "group": group }))
                })
            }
            "group/delete" => {
                let id = require_str(&params, "id")?;
                self.with_store(|store| {
                    store.delete_group(id)?;
                    Ok(json!({ "success": true }))
                })
            }
            _ => Err(PluginError::method_not_found(method)),
        }
    }
}
