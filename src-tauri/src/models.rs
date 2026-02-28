use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: Uuid,
    pub title: String,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_secret: Option<String>,
    pub category: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub favourite: bool,
}

impl Default for Entry {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            title: String::new(),
            username: String::new(),
            password: None,
            url: None,
            notes: None,
            totp_secret: None,
            category: "General".into(),
            created_at: now,
            updated_at: now,
            favourite: false,
        }
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        if let Some(ref mut p) = self.password {
            p.zeroize();
        }
        if let Some(ref mut t) = self.totp_secret {
            t.zeroize();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomChain {
    pub name: String,
    pub symbol: String,
    pub address: String,
    pub rpc_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub name: String,
    pub symbol: String,
    pub contract_address: String,
    pub decimals: u8,
    pub chain_id: u64,
    pub rpc_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAccount {
    pub id: Uuid,
    pub name: String,

    pub mnemonic: String,

    pub btc_address: String,
    pub eth_address: String,
    pub sol_address: String,
    #[serde(default)]
    pub ltc_address: String,
    #[serde(default)]
    pub doge_address: String,
    #[serde(default)]
    pub trx_address: String,
    #[serde(default)]
    pub ton_address: String,

    #[serde(default)]
    pub custom_chains: Vec<CustomChain>,

    #[serde(default)]
    pub tokens: Vec<Token>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct WalletSummary {
    pub id: Uuid,
    pub name: String,
    pub btc_address: String,
    pub eth_address: String,
    pub sol_address: String,
    pub ltc_address: String,
    pub doge_address: String,
    pub trx_address: String,
    pub ton_address: String,
    pub custom_chains: Vec<CustomChain>,
    pub tokens: Vec<Token>,
    pub created_at: DateTime<Utc>,
}

impl From<&WalletAccount> for WalletSummary {
    fn from(w: &WalletAccount) -> Self {
        Self {
            id: w.id,
            name: w.name.clone(),
            btc_address:  w.btc_address.clone(),
            eth_address:  w.eth_address.clone(),
            sol_address:  w.sol_address.clone(),
            ltc_address:  w.ltc_address.clone(),
            doge_address: w.doge_address.clone(),
            trx_address:  w.trx_address.clone(),
            ton_address:  w.ton_address.clone(),
            custom_chains: w.custom_chains.clone(),
            tokens: w.tokens.clone(),
            created_at: w.created_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultData {
    pub version: u32,
    pub entries: Vec<Entry>,
    #[serde(default)]
    pub wallets: Vec<WalletAccount>,
}

#[derive(Debug, Deserialize)]
pub struct EntryInput {
    pub title: String,
    pub username: String,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub category: Option<String>,
    pub favourite: Option<bool>,
}

