use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AeadOsRng},
    Aes256Gcm, Key as AesKey, Nonce as AesNonce,
};
use chacha20poly1305::{
    ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce,
};
use argon2::{Argon2, ParamsBuilder, Version};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

type HmacSha256 = Hmac<Sha256>;

const AES_NONCE_LEN: usize = 12;

const CHACHA_NONCE_LEN: usize = 12;

pub const KEY_LEN: usize = 32;

pub const SALT_LEN: usize = 16;

pub const HMAC_LEN: usize = 32;

const DOMAIN_AES:    &[u8] = b"locke-vault-aes-key-v2";
const DOMAIN_CHACHA: &[u8] = b"locke-vault-chacha-key-v2";
const DOMAIN_HMAC:   &[u8] = b"locke-vault-integrity-v2";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed — wrong master password or corrupted data")]
    DecryptionFailed,
    #[error("integrity check failed — vault file may have been tampered with")]
    IntegrityFailed,
    #[error("key derivation failed: {0}")]
    KdfFailed(String),
    #[error("invalid ciphertext format")]
    InvalidFormat,
}

#[derive(ZeroizeOnDrop)]
pub struct DerivedKey([u8; KEY_LEN]);

impl DerivedKey {

    fn sub_key(&self, domain: &[u8]) -> [u8; KEY_LEN] {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&self.0)
            .expect("HMAC accepts any key length");
        mac.update(domain);
        mac.finalize().into_bytes().into()
    }

    pub fn aes_key(&self) -> [u8; KEY_LEN] { self.sub_key(DOMAIN_AES) }

    pub fn chacha_key(&self) -> [u8; KEY_LEN] { self.sub_key(DOMAIN_CHACHA) }

    pub fn integrity_key(&self) -> [u8; KEY_LEN] { self.sub_key(DOMAIN_HMAC) }

    pub fn raw_bytes_for_legacy_v1_only(&self) -> [u8; KEY_LEN] { self.0 }
}

#[derive(Debug, Clone, Copy)]
pub struct Argon2Params {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Argon2Params {

    pub const STRONG: Self = Self { m_cost: 131_072, t_cost: 4, p_cost: 4 };

    pub const LEGACY: Self = Self { m_cost: 65_536, t_cost: 3, p_cost: 4 };
}

fn build_argon2(p: Argon2Params) -> Argon2<'static> {
    let params = ParamsBuilder::new()
        .m_cost(p.m_cost)
        .t_cost(p.t_cost)
        .p_cost(p.p_cost)
        .build()
        .expect("valid argon2 params");
    Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params)
}

pub fn derive_key(password: &str, salt: &[u8], params: Argon2Params) -> Result<DerivedKey, CryptoError> {
    let argon2 = build_argon2(params);
    let mut output = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|e| CryptoError::KdfFailed(e.to_string()))?;
    Ok(DerivedKey(output))
}

pub fn generate_salt() -> [u8; SALT_LEN] {
    rand::thread_rng().gen()
}

pub fn encrypt(key: &DerivedKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {

    let aes_key_bytes = key.aes_key();
    let aes_cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(&aes_key_bytes));
    let aes_nonce = Aes256Gcm::generate_nonce(&mut AeadOsRng);
    let mut aes_ct = aes_cipher
        .encrypt(&aes_nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut aes_blob: Vec<u8> = aes_nonce.to_vec();
    aes_blob.append(&mut aes_ct);

    let chacha_key_bytes = key.chacha_key();
    let chacha_cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(&chacha_key_bytes));
    let chacha_nonce_raw: [u8; CHACHA_NONCE_LEN] = rand::thread_rng().gen();
    let chacha_nonce = ChaChaNonce::from_slice(&chacha_nonce_raw);
    let mut chacha_ct = chacha_cipher
        .encrypt(chacha_nonce, aes_blob.as_slice())
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut output: Vec<u8> = chacha_nonce_raw.to_vec();
    output.append(&mut chacha_ct);
    Ok(output)
}

pub fn decrypt(key: &DerivedKey, data: &[u8]) -> Result<Vec<u8>, CryptoError> {

    if data.len() < CHACHA_NONCE_LEN {
        return Err(CryptoError::InvalidFormat);
    }
    let (chacha_nonce_raw, chacha_ct) = data.split_at(CHACHA_NONCE_LEN);
    let chacha_nonce = ChaChaNonce::from_slice(chacha_nonce_raw);
    let chacha_key_bytes = key.chacha_key();
    let chacha_cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(&chacha_key_bytes));
    let aes_blob = chacha_cipher
        .decrypt(chacha_nonce, chacha_ct)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    if aes_blob.len() < AES_NONCE_LEN {
        return Err(CryptoError::InvalidFormat);
    }
    let (aes_nonce_bytes, aes_ct) = aes_blob.split_at(AES_NONCE_LEN);
    let aes_nonce = AesNonce::from_slice(aes_nonce_bytes);
    let aes_key_bytes = key.aes_key();
    let aes_cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(&aes_key_bytes));
    aes_cipher
        .decrypt(aes_nonce, aes_ct)
        .map_err(|_| CryptoError::DecryptionFailed)
}

pub fn decrypt_legacy(raw_key: &[u8; KEY_LEN], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < AES_NONCE_LEN {
        return Err(CryptoError::InvalidFormat);
    }
    let (nonce_bytes, ciphertext) = data.split_at(AES_NONCE_LEN);
    let nonce = AesNonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(raw_key));
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

pub fn compute_hmac(key: &DerivedKey, data: &[u8]) -> [u8; HMAC_LEN] {
    let ikey = key.integrity_key();
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&ikey)
        .expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn verify_hmac(key: &DerivedKey, data: &[u8], expected: &[u8]) -> Result<(), CryptoError> {
    if expected.len() != HMAC_LEN {
        return Err(CryptoError::IntegrityFailed);
    }
    let computed = compute_hmac(key, data);
    let mismatch = computed
        .iter()
        .zip(expected.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if mismatch == 0 { Ok(()) } else { Err(CryptoError::IntegrityFailed) }
}

pub fn generate_password(length: usize, use_symbols: bool) -> String {
    const LOWER:   &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const UPPER:   &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGITS:  &[u8] = b"0123456789";
    const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}|;:,.<>?";

    let mut charset: Vec<u8> = Vec::new();
    charset.extend_from_slice(LOWER);
    charset.extend_from_slice(UPPER);
    charset.extend_from_slice(DIGITS);
    if use_symbols { charset.extend_from_slice(SYMBOLS); }

    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| charset[rng.gen_range(0..charset.len())] as char)
        .collect()
}

