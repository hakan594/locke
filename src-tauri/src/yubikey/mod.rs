

use pcsc::{Card, Context, Protocols, Scope, ShareMode};
use thiserror::Error;

const INS_HMAC: u8 = 0x01;
const P1_SLOT2: u8 = 0x38;
const RESP_LEN: usize = 20;
const YUBIKEY_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01];

#[derive(Debug, Error)]
pub enum YubiKeyError {
    #[error("no YubiKey detected")]
    NotFound,
    #[error("PC/SC error: {0}")]
    PcscError(#[from] pcsc::Error),
    #[error("YubiKey APDU error: SW={0:#06X}")]
    ApduError(u16),
    #[error("unexpected response length: {0}")]
    BadResponseLen(usize),
}

pub fn is_connected() -> bool {
    open_yubikey_card().is_ok()
}

pub fn hmac_challenge(challenge: &[u8]) -> Result<Vec<u8>, YubiKeyError> {
    let card = open_yubikey_card()?;
    select_applet(&card)?;

    let lc = challenge.len() as u8;
    let mut apdu = vec![0x00, INS_HMAC, P1_SLOT2, 0x00, lc];
    apdu.extend_from_slice(challenge);
    apdu.push(0x00);

    let mut resp_buf = [0u8; 22];
    let resp = card.transmit(&apdu, &mut resp_buf)?;
    let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
    if sw != 0x9000 {
        return Err(YubiKeyError::ApduError(sw));
    }
    let data = &resp[..resp.len() - 2];
    if data.len() != RESP_LEN {
        return Err(YubiKeyError::BadResponseLen(data.len()));
    }
    Ok(data.to_vec())
}

fn open_yubikey_card() -> Result<Card, YubiKeyError> {
    let ctx = Context::establish(Scope::User)?;
    let readers_buf = &mut [0u8; 4096];
    let mut readers = ctx.list_readers(readers_buf)?;
    let reader = readers
        .find(|r| r.to_string_lossy().to_lowercase().contains("yubikey"))
        .ok_or(YubiKeyError::NotFound)?;
    let card = ctx.connect(reader, ShareMode::Shared, Protocols::T1)?;
    Ok(card)
}

fn select_applet(card: &Card) -> Result<(), YubiKeyError> {
    let mut select = vec![0x00, 0xA4, 0x04, 0x00, YUBIKEY_AID.len() as u8];
    select.extend_from_slice(YUBIKEY_AID);
    select.push(0x00);
    let mut buf = [0u8; 32];
    let resp = card.transmit(&select, &mut buf)?;
    let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
    if sw != 0x9000 {
        return Err(YubiKeyError::ApduError(sw));
    }
    Ok(())
}

