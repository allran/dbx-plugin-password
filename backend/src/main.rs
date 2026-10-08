mod model;
mod plugin;
mod store;
mod util;

use std::sync::{Arc, Mutex};

use dbx_plugin_sdk::{PluginMetadata, PluginServer};

use plugin::Plugin;
use store::VaultStore;
use util::{log_stderr, vault_path};

fn main() -> std::io::Result<()> {
    let path = vault_path();
    log_stderr(format!("vault path: {}", path.display()));
    let store = Arc::new(Mutex::new(VaultStore::load(path)));

    let metadata = PluginMetadata::new("io.dbx.password", env!("CARGO_PKG_VERSION"));
    let plugin = Plugin::new(store);
    PluginServer::new(metadata, plugin).serve()
}
