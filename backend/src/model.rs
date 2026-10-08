use serde::{Deserialize, Serialize};

pub const DEFAULT_GROUP_ID: &str = "default";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub id: String,
    pub name: String,
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

impl VaultData {
    pub fn ensure_default_group(&mut self, now: u64) {
        if self.groups.iter().any(|g| g.id == DEFAULT_GROUP_ID) {
            return;
        }
        self.groups.insert(
            0,
            Group {
                id: DEFAULT_GROUP_ID.to_string(),
                name: "Default".to_string(),
                created_at: now,
                updated_at: now,
            },
        );
    }
}
