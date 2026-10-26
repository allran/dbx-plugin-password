use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use dbx_plugin_sdk::PluginError;
use rand::rngs::OsRng;
use rand::TryRngCore;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// OWASP-ish desktop defaults: ~19 MiB, 2 iterations, 1 lane.
fn argon2() -> Result<Argon2<'static>, PluginError> {
    let params = Params::new(19_456, 2, 1, Some(KEY_LEN))
        .map_err(|err| PluginError::new(-32000, format!("Invalid Argon2 params: {err}")))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn fill_random(buf: &mut [u8]) -> Result<(), PluginError> {
    OsRng
        .try_fill_bytes(buf)
        .map_err(|err| PluginError::new(-32000, format!("RNG failed: {err}")))
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    fill_random(&mut salt).expect("OS RNG failed");
    salt
}

pub fn random_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    fill_random(&mut key).expect("OS RNG failed");
    key
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce).expect("OS RNG failed");
    nonce
}

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], PluginError> {
    let mut key = [0u8; KEY_LEN];
    argon2()?
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|err| PluginError::new(-32000, format!("Key derivation failed: {err}")))?;
    Ok(key)
}

pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_LEN]), PluginError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|err| PluginError::new(-32000, format!("Invalid cipher key: {err}")))?;
    let nonce = random_nonce();
    let ciphertext = cipher
        .encrypt(&Nonce::from(nonce), plaintext)
        .map_err(|_| PluginError::new(-32000, "Encryption failed"))?;
    Ok((ciphertext, nonce))
}

pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, PluginError> {
    let nonce: [u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| PluginError::new(-32602, "Invalid vault nonce"))?;
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|err| PluginError::new(-32000, format!("Invalid cipher key: {err}")))?;
    cipher
        .decrypt(&Nonce::from(nonce), ciphertext)
        .map_err(|_| PluginError::new(-32602, "Wrong master password"))
}

pub fn b64_encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub fn b64_decode(value: &str) -> Result<Vec<u8>, PluginError> {
    B64.decode(value)
        .map_err(|_| PluginError::new(-32602, "Invalid vault encoding"))
}
