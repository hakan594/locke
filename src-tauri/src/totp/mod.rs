use thiserror::Error;
use totp_rs::{Algorithm, Secret, TOTP};

#[derive(Debug, Error)]
pub enum TotpError {
    #[error("invalid TOTP secret: {0}")]
    InvalidSecret(String),
    #[error("TOTP generation failed: {0}")]
    GenerateFailed(String),
}

fn build_totp(base32_secret: &str) -> Result<TOTP, TotpError> {
    let secret = Secret::Encoded(base32_secret.to_uppercase())
        .to_bytes()
        .map_err(|e| TotpError::InvalidSecret(e.to_string()))?;

    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret,
        None,
        "Locke".to_string(),
    )
    .map_err(|e| TotpError::InvalidSecret(e.to_string()))
}

pub fn current_code(base32_secret: &str) -> Result<String, TotpError> {
    let totp = build_totp(base32_secret)?;
    totp.generate_current()
        .map_err(|e| TotpError::GenerateFailed(e.to_string()))
}

pub fn qr_base64(issuer: &str, account: &str, base32_secret: &str) -> Result<String, TotpError> {
    let secret = Secret::Encoded(base32_secret.to_uppercase())
        .to_bytes()
        .map_err(|e| TotpError::InvalidSecret(e.to_string()))?;

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret,
        Some(issuer.to_string()),
        account.to_string(),
    )
    .map_err(|e| TotpError::InvalidSecret(e.to_string()))?;

    totp.get_qr_base64()
        .map_err(|e| TotpError::GenerateFailed(e.to_string()))
}

