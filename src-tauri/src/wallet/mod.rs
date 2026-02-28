use bip32::{DerivationPath, XPrv};
use bip39::Mnemonic;
use bech32::{self, ToBase32, Variant};
use bs58;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use hmac::{Hmac, Mac};
use k256::{
    ecdsa::SigningKey,
};
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256, Sha512};
use sha3::Keccak256;

type HmacSha512 = Hmac<Sha512>;
const SLIP10_HARDENED: u32 = 0x8000_0000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivedAddresses {
    pub btc: String,
    pub eth: String,
    pub sol: String,
    pub ltc: String,
    pub doge: String,
    pub trx: String,
    pub ton: String,
}

#[derive(Debug, Serialize)]
pub struct SwapQuote {
    pub from_symbol: String,
    pub to_symbol: String,
    pub from_amount: f64,
    pub to_amount: f64,
    pub rate: f64,   
    pub from_usd: f64,
    pub to_usd: f64,
}

pub fn generate_mnemonic(word_count: usize) -> Result<String, String> {

    use rand::RngCore as _;
    let entropy_len: usize = if word_count == 24 { 32 } else { 16 };
    let mut entropy = vec![0u8; entropy_len];
    rand::thread_rng().fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy).map_err(|e| e.to_string())?;
    Ok(mnemonic.to_string())
}

pub fn validate_mnemonic(phrase: &str) -> bool {
    phrase.parse::<Mnemonic>().is_ok()
}

fn mnemonic_to_seed(phrase: &str) -> Result<[u8; 64], String> {
    let m: Mnemonic = phrase.parse().map_err(|e: bip39::Error| e.to_string())?;
    Ok(m.to_seed(""))
}

fn derive_btc_address(seed: &[u8; 64]) -> Result<String, String> {
    let path: DerivationPath = "m/84'/0'/0'/0/0".parse().map_err(|e: bip32::Error| e.to_string())?;
    let xprv = XPrv::derive_from_path(seed.as_slice(), &path).map_err(|e| e.to_string())?;

    let verifying = xprv.private_key().verifying_key();
    let compressed = verifying.to_encoded_point(true);
    let pubkey_bytes = compressed.as_bytes();

    let sha = Sha256::digest(pubkey_bytes);
    let hash160 = Ripemd160::digest(sha);

    let mut data = vec![bech32::u5::try_from_u8(0).map_err(|e| e.to_string())?];
    data.extend_from_slice(&hash160.to_base32());
    bech32::encode("bc", data, Variant::Bech32).map_err(|e| e.to_string())
}

fn derive_eth_address(seed: &[u8; 64]) -> Result<String, String> {
    let path: DerivationPath = "m/44'/60'/0'/0/0".parse().map_err(|e: bip32::Error| e.to_string())?;
    let xprv = XPrv::derive_from_path(seed.as_slice(), &path).map_err(|e| e.to_string())?;

    let verifying = xprv.private_key().verifying_key();
    let uncompressed = verifying.to_encoded_point(false);
    let pubkey_xy = &uncompressed.as_bytes()[1..];

    let hash = Keccak256::digest(pubkey_xy);
    let addr_bytes = &hash[12..];
    Ok(eip55_checksum(addr_bytes))
}

fn eip55_checksum(bytes: &[u8]) -> String {
    let lower_hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let hash = Keccak256::digest(lower_hex.as_bytes());

    let mut result = String::with_capacity(42);
    result.push_str("0x");
    for (i, c) in lower_hex.chars().enumerate() {
        let nibble_byte = hash[i / 2];
        let nibble = if i % 2 == 0 { nibble_byte >> 4 } else { nibble_byte & 0xf };
        if c.is_ascii_alphabetic() && nibble >= 8 {
            result.push(c.to_ascii_uppercase());
        } else {
            result.push(c);
        }
    }
    result
}

fn base58check(version: u8, payload: &[u8]) -> String {
    let mut full = Vec::with_capacity(1 + payload.len() + 4);
    full.push(version);
    full.extend_from_slice(payload);
    let checksum = Sha256::digest(Sha256::digest(&full));
    full.extend_from_slice(&checksum[..4]);
    bs58::encode(full).into_string()
}

fn derive_ltc_address(seed: &[u8; 64]) -> Result<String, String> {
    let path: DerivationPath = "m/44'/2'/0'/0/0".parse().map_err(|e: bip32::Error| e.to_string())?;
    let xprv = XPrv::derive_from_path(seed.as_slice(), &path).map_err(|e| e.to_string())?;
    let verifying = xprv.private_key().verifying_key();
    let compressed = verifying.to_encoded_point(true);
    let sha = Sha256::digest(compressed.as_bytes());
    let hash160 = Ripemd160::digest(sha);
    Ok(base58check(0x30, &hash160))
}

fn derive_doge_address(seed: &[u8; 64]) -> Result<String, String> {
    let path: DerivationPath = "m/44'/3'/0'/0/0".parse().map_err(|e: bip32::Error| e.to_string())?;
    let xprv = XPrv::derive_from_path(seed.as_slice(), &path).map_err(|e| e.to_string())?;
    let verifying = xprv.private_key().verifying_key();
    let compressed = verifying.to_encoded_point(true);
    let sha = Sha256::digest(compressed.as_bytes());
    let hash160 = Ripemd160::digest(sha);
    Ok(base58check(0x1e, &hash160))
}

fn derive_trx_address(seed: &[u8; 64]) -> Result<String, String> {
    let path: DerivationPath = "m/44'/195'/0'/0/0".parse().map_err(|e: bip32::Error| e.to_string())?;
    let xprv = XPrv::derive_from_path(seed.as_slice(), &path).map_err(|e| e.to_string())?;
    let verifying = xprv.private_key().verifying_key();
    let uncompressed = verifying.to_encoded_point(false);
    let pubkey_xy = &uncompressed.as_bytes()[1..];       
    let hash = Keccak256::digest(pubkey_xy);
    let addr_bytes = &hash[12..];
    Ok(base58check(0x41, addr_bytes))
}

fn derive_ton_address(seed: &[u8; 64]) -> Result<String, String> {
    let path: [u32; 4] = [
        44  | SLIP10_HARDENED,
        607 | SLIP10_HARDENED,
        0   | SLIP10_HARDENED,
        0   | SLIP10_HARDENED,
    ];
    let (private, _chain) = slip10_ed25519_derive(seed, &path);
    let signing = Ed25519SigningKey::from_bytes(&private);
    let verifying = signing.verifying_key();
    let hex: String = verifying.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
    Ok(format!("0:{}", hex))
}

fn derive_sol_address(seed: &[u8; 64]) -> Result<String, String> {

    let path: [u32; 4] = [
        44  | SLIP10_HARDENED,
        501 | SLIP10_HARDENED,
        0   | SLIP10_HARDENED,
        0   | SLIP10_HARDENED,
    ];
    let (private, _chain) = slip10_ed25519_derive(seed, &path);

    let signing = Ed25519SigningKey::from_bytes(&private);
    let verifying = signing.verifying_key();
    Ok(bs58::encode(verifying.as_bytes()).into_string())
}

fn slip10_ed25519_derive(seed: &[u8], path: &[u32]) -> ([u8; 32], [u8; 32]) {

    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed").unwrap();
    mac.update(seed);
    let result = mac.finalize().into_bytes();
    let (mut key, mut chain) = ([0u8; 32], [0u8; 32]);
    key.copy_from_slice(&result[..32]);
    chain.copy_from_slice(&result[32..]);

    for &index in path {
        let mut mac = HmacSha512::new_from_slice(&chain).unwrap();
        mac.update(&[0x00]);
        mac.update(&key);
        mac.update(&index.to_be_bytes());
        let r = mac.finalize().into_bytes();
        key.copy_from_slice(&r[..32]);
        chain.copy_from_slice(&r[32..]);
    }
    (key, chain)
}

pub fn derive_addresses(mnemonic: &str) -> Result<DerivedAddresses, String> {
    let seed = mnemonic_to_seed(mnemonic)?;
    Ok(DerivedAddresses {
        btc:  derive_btc_address(&seed)?,
        eth:  derive_eth_address(&seed)?,
        sol:  derive_sol_address(&seed)?,
        ltc:  derive_ltc_address(&seed)?,
        doge: derive_doge_address(&seed)?,
        trx:  derive_trx_address(&seed)?,
        ton:  derive_ton_address(&seed)?,
    })
}

pub fn eth_signing_key(mnemonic: &str) -> Result<SigningKey, String> {
    let seed = mnemonic_to_seed(mnemonic)?;
    let path: DerivationPath = "m/44'/60'/0'/0/0".parse().map_err(|e: bip32::Error| e.to_string())?;
    let xprv = XPrv::derive_from_path(seed.as_slice(), &path).map_err(|e| e.to_string())?;
    Ok(xprv.private_key().clone())
}

pub async fn get_evm_balance(address: &str, rpc_url: &str) -> Result<String, String> {
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "eth_getBalance",
        "params": [address, "latest"]
    });
    let resp: serde_json::Value = client
        .post(rpc_url)
        .json(&body)
        .send().await.map_err(|e| e.to_string())?
        .json().await.map_err(|e| e.to_string())?;

    let hex = resp["result"].as_str().unwrap_or("0x0");
    let wei = u128::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap_or(0);
    let eth = wei as f64 / 1e18;
    Ok(format!("{:.6}", eth))
}

pub async fn get_btc_balance(address: &str) -> Result<String, String> {
    let url = format!("https://blockstream.info/api/address/{}", address);
    let client = reqwest::Client::new();
    let resp: serde_json::Value = client.get(&url).send().await
        .map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;

    let funded: u64 = resp["chain_stats"]["funded_txo_sum"].as_u64().unwrap_or(0)
        + resp["mempool_stats"]["funded_txo_sum"].as_u64().unwrap_or(0);
    let spent: u64 = resp["chain_stats"]["spent_txo_sum"].as_u64().unwrap_or(0)
        + resp["mempool_stats"]["spent_txo_sum"].as_u64().unwrap_or(0);
    let sat = funded.saturating_sub(spent);
    Ok(format!("{:.8}", sat as f64 / 1e8))
}

pub async fn get_sol_balance(address: &str) -> Result<String, String> {
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "getBalance",
        "params": [address]
    });
    let resp: serde_json::Value = client
        .post("https://api.mainnet-beta.solana.com")
        .json(&body)
        .send().await.map_err(|e| e.to_string())?
        .json().await.map_err(|e| e.to_string())?;

    let lamports = resp["result"]["value"].as_u64().unwrap_or(0);
    Ok(format!("{:.9}", lamports as f64 / 1e9))
}

pub async fn get_ltc_balance(address: &str) -> Result<String, String> {
    let url = format!("https://api.blockcypher.com/v1/ltc/main/addrs/{}/balance", address);
    let client = reqwest::Client::new();
    let resp: serde_json::Value = client.get(&url).send().await
        .map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    if let Some(err) = resp["error"].as_str() { return Err(err.to_string()); }
    let satoshi = resp["balance"].as_u64().unwrap_or(0);
    Ok(format!("{:.8}", satoshi as f64 / 1e8))
}

pub async fn get_doge_balance(address: &str) -> Result<String, String> {
    let url = format!("https://api.blockcypher.com/v1/doge/main/addrs/{}/balance", address);
    let client = reqwest::Client::new();
    let resp: serde_json::Value = client.get(&url).send().await
        .map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    if let Some(err) = resp["error"].as_str() { return Err(err.to_string()); }
    let satoshi = resp["balance"].as_u64().unwrap_or(0);
    Ok(format!("{:.8}", satoshi as f64 / 1e8))
}

pub async fn get_trx_balance(address: &str) -> Result<String, String> {
    let url = format!("https://api.trongrid.io/v1/accounts/{}", address);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build().map_err(|e| e.to_string())?;
    let resp: serde_json::Value = client.get(&url)
        .header("Accept", "application/json")
        .send().await.map_err(|e| e.to_string())?
        .json().await.map_err(|e| e.to_string())?;
    let sun = resp["data"][0]["balance"].as_u64().unwrap_or(0);
    Ok(format!("{:.6}", sun as f64 / 1_000_000.0))
}

pub async fn get_ton_balance(address: &str) -> Result<String, String> {
    let url = format!("https://tonapi.io/v2/accounts/{}", address);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build().map_err(|e| e.to_string())?;
    let resp: serde_json::Value = client.get(&url)
        .header("Accept", "application/json")
        .send().await.map_err(|e| e.to_string())?
        .json().await.map_err(|e| e.to_string())?;
    let nanoton = resp["balance"].as_u64().unwrap_or(0);
    Ok(format!("{:.9}", nanoton as f64 / 1_000_000_000.0))
}

pub async fn get_swap_quote(
    from_cg_id: &str,
    to_cg_id: &str,
    from_symbol: &str,
    to_symbol: &str,
    from_amount: f64,
) -> Result<SwapQuote, String> {
    let ids = format!("{},{}", from_cg_id, to_cg_id);
    let url = format!(
        "https://api.coingecko.com/api/v3/simple/price?ids={}&vs_currencies=usd",
        ids
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("Mozilla/5.0")
        .build().map_err(|e| e.to_string())?;

    let response = client.get(&url).send().await.map_err(|e| e.to_string())?;
    let status = response.status();
    if status.as_u16() == 429 {
        return Err("429: API rate limited — попробуйте через минуту".to_string());
    }
    if !status.is_success() {
        return Err(format!("Ошибка API CoinGecko: HTTP {}", status.as_u16()));
    }

    let resp: serde_json::Value = response.json().await.map_err(|e| e.to_string())?;

    let from_usd = resp[from_cg_id]["usd"].as_f64()
        .ok_or_else(|| format!("Цена не найдена для {} ({}). Попробуйте позже.", from_symbol, from_cg_id))?;
    let to_usd_price = resp[to_cg_id]["usd"].as_f64()
        .ok_or_else(|| format!("Цена не найдена для {} ({}). Попробуйте позже.", to_symbol, to_cg_id))?;

    if from_usd <= 0.0 || to_usd_price <= 0.0 {
        return Err("Получены некорректные цены от API.".to_string());
    }

    let rate = from_usd / to_usd_price;
    let to_amount = from_amount * rate;
    Ok(SwapQuote {
        from_symbol: from_symbol.to_string(),
        to_symbol: to_symbol.to_string(),
        from_amount,
        to_amount,
        rate,
        from_usd: from_amount * from_usd,
        to_usd: to_amount * to_usd_price,
    })
}

pub struct EthTxParams {
    pub to: String,
    pub amount_eth: f64,
    pub chain_id: u64,    
    pub rpc_url: String,
}

pub struct EthTxPreview {
    pub from: String,
    pub to: String,
    pub value_eth: f64,
    pub gas_price_gwei: f64,
    pub fee_eth: f64,
    pub chain_id: u64,
}

async fn eth_rpc<T: for<'de> Deserialize<'de>>(
    rpc: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<T, String> {
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": method, "params": params
    });
    let resp: serde_json::Value = client.post(rpc).json(&body).send().await
        .map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;

    if let Some(err) = resp.get("error") {
        return Err(err.to_string());
    }
    serde_json::from_value(resp["result"].clone()).map_err(|e| e.to_string())
}

async fn eth_get_nonce(rpc: &str, from: &str) -> Result<u64, String> {
    let hex: String = eth_rpc(rpc, "eth_getTransactionCount",
        serde_json::json!([from, "latest"])).await?;
    u64::from_str_radix(hex.trim_start_matches("0x"), 16).map_err(|e| e.to_string())
}

async fn eth_get_gas_price(rpc: &str) -> Result<u64, String> {
    let hex: String = eth_rpc(rpc, "eth_gasPrice", serde_json::json!([])).await?;
    u64::from_str_radix(hex.trim_start_matches("0x"), 16).map_err(|e| e.to_string())
}

pub async fn eth_preview(mnemonic: &str, params: &EthTxParams) -> Result<EthTxPreview, String> {
    let signing_key = eth_signing_key(mnemonic)?;
    let seed = mnemonic_to_seed(mnemonic)?;
    let from = derive_eth_address(&seed)?;
    let gas_price_wei = eth_get_gas_price(&params.rpc_url).await?;
    let gas_limit: u64 = 21_000;
    let fee_wei = gas_price_wei as u128 * gas_limit as u128;
    drop(signing_key);
    Ok(EthTxPreview {
        from,
        to: params.to.clone(),
        value_eth: params.amount_eth,
        gas_price_gwei: gas_price_wei as f64 / 1e9,
        fee_eth: fee_wei as f64 / 1e18,
        chain_id: params.chain_id,
    })
}

pub async fn eth_send(mnemonic: &str, params: &EthTxParams) -> Result<String, String> {
    let signing_key = eth_signing_key(mnemonic)?;
    let seed = mnemonic_to_seed(mnemonic)?;
    let from = derive_eth_address(&seed)?;

    let nonce     = eth_get_nonce(&params.rpc_url, &from).await?;
    let gas_price = eth_get_gas_price(&params.rpc_url).await?;
    let gas_limit: u64 = 21_000;
    let value_wei: u128 = (params.amount_eth * 1e18) as u128;
    let to_bytes  = hex::decode(params.to.trim_start_matches("0x"))
        .map_err(|_| "invalid to address".to_string())?;

    let unsigned = rlp_list(&[
        rlp_uint(nonce as u128),
        rlp_uint(gas_price as u128),
        rlp_uint(gas_limit as u128),
        rlp_bytes(&to_bytes),
        rlp_uint(value_wei),
        rlp_bytes(&[]),             
        rlp_uint(params.chain_id as u128),
        rlp_bytes(&[]),             
        rlp_bytes(&[]),             
    ]);

    let hash = keccak256(&unsigned);
    let (signature, recid) = signing_key
        .sign_prehash_recoverable(&hash)
        .map_err(|e| e.to_string())?;

    let sig_bytes = signature.to_bytes();
    let r = &sig_bytes[..32];
    let s = &sig_bytes[32..];
    let v: u64 = recid.is_y_odd() as u64 + params.chain_id * 2 + 35;

    let signed = rlp_list(&[
        rlp_uint(nonce as u128),
        rlp_uint(gas_price as u128),
        rlp_uint(gas_limit as u128),
        rlp_bytes(&to_bytes),
        rlp_uint(value_wei),
        rlp_bytes(&[]),
        rlp_uint(v as u128),
        rlp_bytes(r),
        rlp_bytes(s),
    ]);

    let raw_hex = format!("0x{}", hex::encode(&signed));
    let tx_hash: String = eth_rpc(&params.rpc_url, "eth_sendRawTransaction",
        serde_json::json!([raw_hex])).await?;
    Ok(tx_hash)
}

fn keccak256(data: &[u8]) -> Vec<u8> {
    Keccak256::digest(data).to_vec()
}

fn rlp_uint(n: u128) -> Vec<u8> {
    if n == 0 {
        return rlp_bytes(&[]);
    }
    let bytes = n.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(15);
    rlp_bytes(&bytes[start..])
}

fn rlp_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        return data.to_vec();
    }
    let mut out = rlp_length_prefix(data.len(), 0x80);
    out.extend_from_slice(data);
    out
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.iter().flat_map(|i| i.iter().copied()).collect();
    let mut out = rlp_length_prefix(payload.len(), 0xC0);
    out.extend_from_slice(&payload);
    out
}

fn rlp_length_prefix(len: usize, offset: u8) -> Vec<u8> {
    if len < 56 {
        vec![offset + len as u8]
    } else {
        let len_bytes = (len as u64).to_be_bytes();
        let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let be = &len_bytes[start..];
        let mut v = vec![offset + 55 + be.len() as u8];
        v.extend_from_slice(be);
        v
    }
}

pub async fn get_token_balance(
    address: &str,
    contract: &str,
    rpc_url: &str,
    decimals: u8,
) -> Result<String, String> {

    let addr_bytes = hex::decode(address.trim_start_matches("0x"))
        .map_err(|_| "invalid address".to_string())?;
    let mut calldata = vec![0x70u8, 0xa0, 0x82, 0x31];
    calldata.extend_from_slice(&[0u8; 12]);            
    calldata.extend_from_slice(&addr_bytes);            

    let result: String = eth_rpc(rpc_url, "eth_call", serde_json::json!([
        { "to": contract, "data": format!("0x{}", hex::encode(&calldata)) },
        "latest"
    ])).await?;

    let raw = result.trim_start_matches("0x");
    if raw.len() < 64 {
        return Ok("0".to_string());
    }

    let hi = u128::from_str_radix(&raw[..32], 16).unwrap_or(0);
    let lo = u128::from_str_radix(&raw[32..64], 16).unwrap_or(0);

    if hi > 0 {
        return Ok(">3.4e38".to_string());
    }
    let divisor = 10u128.pow(decimals as u32) as f64;
    Ok(format!("{:.6}", lo as f64 / divisor))
}

pub struct EthTokenTxParams {
    pub contract_address: String,
    pub to: String,
    pub amount: f64,      
    pub decimals: u8,
    pub chain_id: u64,
    pub rpc_url: String,
}

pub struct EthTokenTxPreview {
    pub from: String,
    pub to: String,
    pub amount: f64,
    pub gas_price_gwei: f64,
    pub fee_eth: f64,
    pub chain_id: u64,
}

fn erc20_transfer_data(to: &str, amount_raw: u128) -> Result<Vec<u8>, String> {

    let to_bytes = hex::decode(to.trim_start_matches("0x"))
        .map_err(|_| "invalid to address".to_string())?;
    let mut data = vec![0xa9u8, 0x05, 0x9c, 0xbb];
    data.extend_from_slice(&[0u8; 12]);  
    data.extend_from_slice(&to_bytes);    

    let mut amount_bytes = [0u8; 32];
    let raw = amount_raw.to_be_bytes();
    amount_bytes[16..].copy_from_slice(&raw);
    data.extend_from_slice(&amount_bytes);
    Ok(data)
}

pub async fn eth_token_preview(
    mnemonic: &str,
    params: &EthTokenTxParams,
) -> Result<EthTokenTxPreview, String> {
    let seed = mnemonic_to_seed(mnemonic)?;
    let from = derive_eth_address(&seed)?;
    let gas_price_wei = eth_get_gas_price(&params.rpc_url).await?;
    let gas_limit: u64 = 65_000;
    let fee_wei = gas_price_wei as u128 * gas_limit as u128;
    Ok(EthTokenTxPreview {
        from,
        to: params.to.clone(),
        amount: params.amount,
        gas_price_gwei: gas_price_wei as f64 / 1e9,
        fee_eth: fee_wei as f64 / 1e18,
        chain_id: params.chain_id,
    })
}

pub async fn eth_token_send(
    mnemonic: &str,
    params: &EthTokenTxParams,
) -> Result<String, String> {
    let signing_key = eth_signing_key(mnemonic)?;
    let seed = mnemonic_to_seed(mnemonic)?;
    let from = derive_eth_address(&seed)?;

    let nonce     = eth_get_nonce(&params.rpc_url, &from).await?;
    let gas_price = eth_get_gas_price(&params.rpc_url).await?;
    let gas_limit: u64 = 65_000;

    let divisor  = 10u128.pow(params.decimals as u32);
    let amount_raw = (params.amount * divisor as f64) as u128;
    let calldata = erc20_transfer_data(&params.to, amount_raw)?;

    let contract_bytes = hex::decode(params.contract_address.trim_start_matches("0x"))
        .map_err(|_| "invalid contract address".to_string())?;

    let unsigned = rlp_list(&[
        rlp_uint(nonce as u128),
        rlp_uint(gas_price as u128),
        rlp_uint(gas_limit as u128),
        rlp_bytes(&contract_bytes), 
        rlp_uint(0),                 
        rlp_bytes(&calldata),        
        rlp_uint(params.chain_id as u128),
        rlp_bytes(&[]),
        rlp_bytes(&[]),
    ]);

    let hash = keccak256(&unsigned);
    let (signature, recid) = signing_key
        .sign_prehash_recoverable(&hash)
        .map_err(|e| e.to_string())?;

    let sig_bytes = signature.to_bytes();
    let r = &sig_bytes[..32];
    let s = &sig_bytes[32..];
    let v: u64 = recid.is_y_odd() as u64 + params.chain_id * 2 + 35;

    let signed = rlp_list(&[
        rlp_uint(nonce as u128),
        rlp_uint(gas_price as u128),
        rlp_uint(gas_limit as u128),
        rlp_bytes(&contract_bytes),
        rlp_uint(0),
        rlp_bytes(&calldata),
        rlp_uint(v as u128),
        rlp_bytes(r),
        rlp_bytes(s),
    ]);

    let raw_hex = format!("0x{}", hex::encode(&signed));
    let tx_hash: String = eth_rpc(&params.rpc_url, "eth_sendRawTransaction",
        serde_json::json!([raw_hex])).await?;
    Ok(tx_hash)
}

