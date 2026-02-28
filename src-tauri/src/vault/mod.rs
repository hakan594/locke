use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use thiserror::Error;
use zeroize::ZeroizeOnDrop;

use crate::crypto::{self, Argon2Params, DerivedKey, HMAC_LEN, SALT_LEN};
use crate::models::VaultData;

pub const MAGIC: &[u8; 4] = b"KPRS";
pub const FILE_VERSION: u32 = 2;

const V2_SALT_OFFSET:    usize = 8;
const V2_M_COST_OFFSET:  usize = 24;
const V2_T_COST_OFFSET:  usize = 28;
const V2_P_COST_OFFSET:  usize = 32;
const V2_PAYLOAD_OFFSET: usize = 36;
const V2_MIN_LEN:        usize = V2_PAYLOAD_OFFSET + HMAC_LEN + 1;

const V1_SALT_OFFSET:    usize = 8;
const V1_PAYLOAD_OFFSET: usize = 24;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault is locked")]
    Locked,
    #[error("vault already exists at the given path")]
    AlreadyExists,
    #[error("invalid vault file format")]
    InvalidFormat,
    #[error("unsupported vault version {0}")]
    UnsupportedVersion(u32),
    #[error("crypto error: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

#[derive(Default)]
pub struct VaultState(pub Arc<Mutex<InnerState>>);

pub struct InnerState {
    pub path:        Option<PathBuf>,
    pub data:        Option<VaultData>,
    pub key:         Option<LockedKey>,

    pub argon2_params: Option<Argon2Params>,

    pub vault_lock:  Option<std::fs::File>,
}

impl Default for InnerState {
    fn default() -> Self {
        Self {
            path:           None,
            data:           None,
            key:            None,
            argon2_params:  None,
            vault_lock:     None,
        }
    }
}

impl InnerState {
    pub fn is_unlocked(&self) -> bool {
        self.key.is_some() && self.data.is_some()
    }
}

#[derive(ZeroizeOnDrop)]
pub struct LockedKey(pub DerivedKey);

fn build_v2_file(
    salt: &[u8; 16],
    params: Argon2Params,
    ciphertext: &[u8],
    key: &DerivedKey,
) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(V2_PAYLOAD_OFFSET + ciphertext.len() + HMAC_LEN);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&FILE_VERSION.to_le_bytes());
    bytes.extend_from_slice(salt);
    bytes.extend_from_slice(&params.m_cost.to_le_bytes());
    bytes.extend_from_slice(&params.t_cost.to_le_bytes());
    bytes.extend_from_slice(&params.p_cost.to_le_bytes());
    bytes.extend_from_slice(ciphertext);

    let hmac = crypto::compute_hmac(key, &bytes);
    bytes.extend_from_slice(&hmac);
    bytes
}

pub fn create_vault(path: &PathBuf, master_password: &str) -> Result<(), VaultError> {
    if path.exists() {
        return Err(VaultError::AlreadyExists);
    }

    let params = Argon2Params::STRONG;
    let salt = crypto::generate_salt();
    let key  = crypto::derive_key(master_password, &salt, params)?;

    let data = VaultData { version: FILE_VERSION, entries: vec![], wallets: vec![] };
    let json = serde_json::to_vec(&data)?;
    let ciphertext = crypto::encrypt(&key, &json)?;

    let file_bytes = build_v2_file(&salt, params, &ciphertext, &key);
    std::fs::write(path, &file_bytes)?;
    Ok(())
}

pub fn open_vault(
    path: &PathBuf,
    master_password: &str,
) -> Result<(DerivedKey, VaultData, Argon2Params), VaultError> {
    let raw = std::fs::read(path)?;

    if raw.len() < 8 {
        return Err(VaultError::InvalidFormat);
    }

    let magic_ok = raw[0..4]
        .iter()
        .zip(MAGIC.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
    if !magic_ok {
        return Err(VaultError::InvalidFormat);
    }

    let version = u32::from_le_bytes(raw[4..8].try_into().unwrap());

    match version {
        1 => open_vault_v1(master_password, &raw),
        2 => open_vault_v2(master_password, &raw),
        v => Err(VaultError::UnsupportedVersion(v)),
    }
}

fn open_vault_v1(
    master_password: &str,
    raw: &[u8],
) -> Result<(DerivedKey, VaultData, Argon2Params), VaultError> {
    if raw.len() < V1_PAYLOAD_OFFSET + 1 {
        return Err(VaultError::InvalidFormat);
    }
    let salt       = &raw[V1_SALT_OFFSET..V1_PAYLOAD_OFFSET];
    let ciphertext = &raw[V1_PAYLOAD_OFFSET..];
    let params     = Argon2Params::LEGACY;
    let key        = crypto::derive_key(master_password, salt, params)?;

    let raw_key = key.raw_bytes_for_legacy_v1_only();
    let plaintext = crypto::decrypt_legacy(&raw_key, ciphertext)?;
    let data: VaultData = serde_json::from_slice(&plaintext)?;
    Ok((key, data, params))
}

fn open_vault_v2(
    master_password: &str,
    raw: &[u8],
) -> Result<(DerivedKey, VaultData, Argon2Params), VaultError> {
    if raw.len() < V2_MIN_LEN {
        return Err(VaultError::InvalidFormat);
    }
    let salt   = &raw[V2_SALT_OFFSET..V2_SALT_OFFSET + SALT_LEN];
    let m_cost = u32::from_le_bytes(raw[V2_M_COST_OFFSET..V2_T_COST_OFFSET].try_into().unwrap());
    let t_cost = u32::from_le_bytes(raw[V2_T_COST_OFFSET..V2_P_COST_OFFSET].try_into().unwrap());
    let p_cost = u32::from_le_bytes(raw[V2_P_COST_OFFSET..V2_PAYLOAD_OFFSET].try_into().unwrap());
    let params = Argon2Params { m_cost, t_cost, p_cost };

    let file_len  = raw.len();
    let body      = &raw[..file_len - HMAC_LEN];
    let stored_mac = &raw[file_len - HMAC_LEN..];
    let ciphertext = &raw[V2_PAYLOAD_OFFSET..file_len - HMAC_LEN];

    let key = crypto::derive_key(master_password, salt, params)?;

    crypto::verify_hmac(&key, body, stored_mac)?;

    let plaintext = crypto::decrypt(&key, ciphertext)?;
    let data: VaultData = serde_json::from_slice(&plaintext)?;
    Ok((key, data, params))
}

pub fn save_vault(state: &InnerState) -> Result<(), VaultError> {
    let path   = state.path.as_ref().ok_or(VaultError::Locked)?;
    let key    = state.key .as_ref().ok_or(VaultError::Locked)?;
    let data   = state.data.as_ref().ok_or(VaultError::Locked)?;
    let params = state.argon2_params.unwrap_or(Argon2Params::STRONG);

    let existing = std::fs::read(path)?;
    if existing.len() < 8 {
        return Err(VaultError::InvalidFormat);
    }
    let version = u32::from_le_bytes(existing[4..8].try_into().unwrap());
    let salt: [u8; 16] = match version {
        1 => existing[V1_SALT_OFFSET..V1_SALT_OFFSET + 16].try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        2 => existing[V2_SALT_OFFSET..V2_SALT_OFFSET + 16].try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        v => return Err(VaultError::UnsupportedVersion(v)),
    };

    let json       = serde_json::to_vec(data)?;
    let ciphertext = crypto::encrypt(&key.0, &json)?;
    let file_bytes = build_v2_file(&salt, params, &ciphertext, &key.0);
    std::fs::write(path, &file_bytes)?;
    Ok(())
}

