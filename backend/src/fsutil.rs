use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use dbx_plugin_sdk::PluginError;

/// Atomically replace `dest` with contents of `tmp` (tmp is consumed on success).
///
/// Unix: `rename` overwrites atomically.
/// Windows: `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)` — never deletes
/// the live file before the replacement succeeds.
pub fn atomic_replace(tmp: &Path, dest: &Path) -> Result<(), PluginError> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::GetLastError;
        use windows_sys::Win32::Storage::FileSystem::{
            MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        };

        fn wide(path: &Path) -> Vec<u16> {
            path.as_os_str().encode_wide().chain(Some(0)).collect()
        }

        let from = wide(tmp);
        let to = wide(dest);
        // SAFETY: NUL-terminated wide paths live for the duration of the call.
        let ok = unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            let err = std::io::Error::from_raw_os_error(code as i32);
            let _ = fs::remove_file(tmp);
            return Err(PluginError::new(
                -32000,
                format!("Failed to replace {}: {err}", dest.display()),
            ));
        }
        return Ok(());
    }

    #[cfg(not(windows))]
    {
        fs::rename(tmp, dest).map_err(|err| {
            let _ = fs::remove_file(tmp);
            PluginError::new(
                -32000,
                format!("Failed to replace {}: {err}", dest.display()),
            )
        })
    }
}

pub fn ensure_parent(path: &Path) -> Result<(), PluginError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            PluginError::new(-32000, format!("Failed to create data dir: {err}"))
        })?;
    }
    Ok(())
}

pub fn chmod_owner_only(path: &Path) -> Result<(), PluginError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|err| {
            PluginError::new(
                -32000,
                format!("Failed to set permissions on {}: {err}", path.display()),
            )
        })?;
    }
    #[cfg(windows)]
    {
        // Best-effort owner-only ACL via System32\icacls.exe (documented sidecar side effect).
        if let Err(err) = restrict_current_user_acl(path) {
            eprintln!(
                "[io.dbx.password] best-effort ACL tighten failed for {}: {err}",
                path.display()
            );
        }
    }
    let _ = path;
    Ok(())
}

/// Write `payload` to `dest` via temp file + fsync + atomic replace.
pub fn write_private_file(dest: &Path, payload: &[u8], tmp_ext: &str) -> Result<(), PluginError> {
    ensure_parent(dest)?;
    let tmp: PathBuf = dest.with_extension(tmp_ext);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|err| {
                PluginError::new(-32000, format!("Failed to write {}: {err}", dest.display()))
            })?;
        file.write_all(payload).map_err(|err| {
            let _ = fs::remove_file(&tmp);
            PluginError::new(-32000, format!("Failed to write {}: {err}", dest.display()))
        })?;
        file.sync_all().map_err(|err| {
            let _ = fs::remove_file(&tmp);
            PluginError::new(-32000, format!("Failed to sync {}: {err}", dest.display()))
        })?;
    }

    #[cfg(not(unix))]
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|err| {
                PluginError::new(-32000, format!("Failed to write {}: {err}", dest.display()))
            })?;
        file.write_all(payload).map_err(|err| {
            let _ = fs::remove_file(&tmp);
            PluginError::new(-32000, format!("Failed to write {}: {err}", dest.display()))
        })?;
        file.sync_all().map_err(|err| {
            let _ = fs::remove_file(&tmp);
            PluginError::new(-32000, format!("Failed to sync {}: {err}", dest.display()))
        })?;
    }

    atomic_replace(&tmp, dest)?;
    chmod_owner_only(dest)?;
    Ok(())
}

/// Best-effort: disable inheritance and grant the current user full control.
#[cfg(windows)]
fn restrict_current_user_acl(path: &Path) -> std::io::Result<()> {
    let path_str = path.to_string_lossy();
    let icacls = {
        let root = std::env::var_os("SystemRoot")
            .or_else(|| std::env::var_os("WINDIR"))
            .unwrap_or_else(|| std::ffi::OsString::from(r"C:\Windows"));
        PathBuf::from(root).join("System32").join("icacls.exe")
    };
    // Remove inheritance, then grant current user (F).
    let disable = std::process::Command::new(&icacls)
        .args([&*path_str, "/inheritance:r"])
        .output()?;
    if !disable.status.success() {
        return Ok(());
    }
    let user = std::env::var("USERNAME").unwrap_or_default();
    if user.is_empty() {
        return Ok(());
    }
    let grant = format!("{user}:(F)");
    let _ = std::process::Command::new(&icacls)
        .args([&*path_str, "/grant:r", &grant])
        .output()?;
    Ok(())
}
