use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use dbx_plugin_sdk::PluginError;
use rand::rngs::OsRng;
use rand::TryRngCore;
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

/// OWASP-ish desktop defaults: ~19 MiB, 2 iterations, 1 lane.
pub const ARGON2_MEMORY_KIB: u32 = 19_456;
pub const ARGON2_ITERATIONS: u32 = 2;
pub const ARGON2_PARALLELISM: u32 = 1;

fn argon2_with(
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Argon2<'static>, PluginError> {
    let params = Params::new(memory_kib, iterations, parallelism, Some(KEY_LEN))
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

pub fn random_key() -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    fill_random(&mut key).expect("OS RNG failed");
    Zeroizing::new(key)
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce).expect("OS RNG failed");
    nonce
}

pub fn derive_key(
    password: &str,
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>, PluginError> {
    let mut key = [0u8; KEY_LEN];
    argon2_with(memory_kib, iterations, parallelism)?
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|err| PluginError::new(-32000, format!("Key derivation failed: {err}")))?;
    Ok(Zeroizing::new(key))
}

pub fn derive_key_default(
    password: &str,
    salt: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, PluginError> {
    derive_key(
        password,
        salt,
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
    )
}

/// Constant-time equality for 32-byte keys.
pub fn keys_eq(a: &[u8; KEY_LEN], b: &[u8; KEY_LEN]) -> bool {
    let mut diff = 0u8;
    for i in 0..KEY_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Canonical AAD binding envelope metadata to the ciphertext (v3+).
pub fn envelope_aad(version: u32, protection: &str, kdf: &str, salt_b64: &str) -> Vec<u8> {
    format!("dbx-password-vault|{version}|{protection}|{kdf}|{salt_b64}").into_bytes()
}

pub fn encrypt(
    key: &[u8; KEY_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; NONCE_LEN]), PluginError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|err| PluginError::new(-32000, format!("Invalid cipher key: {err}")))?;
    let nonce = random_nonce();
    let ciphertext = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| PluginError::new(-32000, "Encryption failed"))?;
    Ok((ciphertext, nonce))
}

pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PluginError> {
    let nonce: [u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| PluginError::new(-32602, "Invalid vault nonce"))?;
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|err| PluginError::new(-32000, format!("Invalid cipher key: {err}")))?;
    let plaintext = cipher
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| PluginError::new(-32602, "Vault decryption failed"))?;
    Ok(Zeroizing::new(plaintext))
}

pub fn b64_encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub fn b64_decode(value: &str) -> Result<Vec<u8>, PluginError> {
    B64.decode(value)
        .map_err(|_| PluginError::new(-32602, "Invalid vault encoding"))
}
