use std::path::PathBuf;

use serde::Serialize;
use tauri::State;
use uuid::Uuid;

use crate::{
    crypto,
    models::{Entry, EntryInput, WalletAccount, WalletSummary},
    security,
    totp,
    vault::{self, LockedKey, VaultState},
    wallet,
    yubikey,
};

#[cfg(target_os = "windows")]
fn acquire_vault_lock(path: &std::path::PathBuf) -> Option<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .write(false)
        .share_mode(1)
        .open(path)
        .ok()
}

#[cfg(not(target_os = "windows"))]
fn acquire_vault_lock(_path: &std::path::PathBuf) -> Option<std::fs::File> {
    None
}

#[derive(Debug, Serialize)]
pub struct CommandError(String);

impl<E: std::fmt::Display> From<E> for CommandError {
    fn from(e: E) -> Self {
        CommandError(e.to_string())
    }
}

type CmdResult<T> = Result<T, CommandError>;

#[tauri::command]
pub fn create_vault(
    path: String,
    master_password: String,
    state: State<VaultState>,
) -> CmdResult<()> {
    let path = PathBuf::from(&path);
    vault::create_vault(&path, &master_password)?;

    let (key, data, params) = vault::open_vault(&path, &master_password)?;
    let mut inner = state.0.lock().unwrap();
    inner.vault_lock    = acquire_vault_lock(&path);
    inner.path          = Some(path);
    inner.data          = Some(data);
    inner.key           = Some(LockedKey(key));
    inner.argon2_params = Some(params);
    Ok(())
}

#[tauri::command]
pub fn unlock_vault(
    path: String,
    master_password: String,
    state: State<VaultState>,
) -> CmdResult<()> {
    let path = PathBuf::from(&path);
    match vault::open_vault(&path, &master_password) {
        Ok((key, data, params)) => {
            log_access("Vault unlocked", true);
            let mut inner = state.0.lock().unwrap();
            inner.vault_lock    = acquire_vault_lock(&path);
            inner.path          = Some(path);
            inner.data          = Some(data);
            inner.key           = Some(LockedKey(key));
            inner.argon2_params = Some(params);
            Ok(())
        }
        Err(e) => {
            log_access("Failed unlock attempt", false);
            Err(CommandError(e.to_string()))
        }
    }
}

#[tauri::command]
pub fn lock_vault(state: State<VaultState>) -> CmdResult<()> {
    log_access("Vault locked", true);
    let mut inner = state.0.lock().unwrap();
    inner.vault_lock    = None;

    inner.key           = None;
    inner.data          = None;
    inner.path          = None;
    inner.argon2_params = None;
    Ok(())
}

#[tauri::command]
pub fn is_vault_unlocked(state: State<VaultState>) -> bool {
    state.0.lock().unwrap().is_unlocked()
}

#[tauri::command]
pub fn list_entries(state: State<VaultState>) -> CmdResult<Vec<Entry>> {
    let inner = state.0.lock().unwrap();
    if !inner.is_unlocked() {
        return Err(CommandError("Vault is locked".into()));
    }
    Ok(inner.data.as_ref().unwrap().entries.clone())
}

#[tauri::command]
pub fn get_entry(id: String, state: State<VaultState>) -> CmdResult<Entry> {
    let uid = Uuid::parse_str(&id).map_err(|e| CommandError(e.to_string()))?;
    let inner = state.0.lock().unwrap();
    let data = inner.data.as_ref().ok_or(CommandError("Vault is locked".into()))?;
    data.entries
        .iter()
        .find(|e| e.id == uid)
        .cloned()
        .ok_or(CommandError(format!("Entry {id} not found")))
}

#[tauri::command]
pub fn create_entry(input: EntryInput, state: State<VaultState>) -> CmdResult<Entry> {
    let mut inner = state.0.lock().unwrap();
    if !inner.is_unlocked() {
        return Err(CommandError("Vault is locked".into()));
    }
    let mut entry = Entry::default();
    apply_input(&mut entry, input);
    let entry_clone = entry.clone();
    inner.data.as_mut().unwrap().entries.push(entry);
    vault::save_vault(&inner)?;
    Ok(entry_clone)
}

#[tauri::command]
pub fn update_entry(
    id: String,
    input: EntryInput,
    state: State<VaultState>,
) -> CmdResult<Entry> {
    let uid = Uuid::parse_str(&id).map_err(|e| CommandError(e.to_string()))?;
    let mut inner = state.0.lock().unwrap();
    if !inner.is_unlocked() {
        return Err(CommandError("Vault is locked".into()));
    }
    let data = inner.data.as_mut().ok_or(CommandError("Vault is locked".into()))?;
    let entry = data
        .entries
        .iter_mut()
        .find(|e| e.id == uid)
        .ok_or(CommandError(format!("Entry {id} not found")))?;

    apply_input(entry, input);
    entry.updated_at = chrono::Utc::now();
    let entry_clone = entry.clone();
    vault::save_vault(&inner)?;
    Ok(entry_clone)
}

#[tauri::command]
pub fn delete_entry(id: String, state: State<VaultState>) -> CmdResult<()> {
    let uid = Uuid::parse_str(&id).map_err(|e| CommandError(e.to_string()))?;
    let mut inner = state.0.lock().unwrap();
    if !inner.is_unlocked() {
        return Err(CommandError("Vault is locked".into()));
    }
    let data = inner.data.as_mut().ok_or(CommandError("Vault is locked".into()))?;
    let before = data.entries.len();
    data.entries.retain(|e| e.id != uid);
    if data.entries.len() == before {
        return Err(CommandError(format!("Entry {id} not found")));
    }
    vault::save_vault(&inner)?;
    Ok(())
}

#[tauri::command]
pub fn generate_password(length: usize, use_symbols: bool) -> String {
    crypto::generate_password(length, use_symbols)
}

#[derive(Serialize)]
pub struct TotpResponse {
    pub code: String,
    pub qr_base64: Option<String>,
}

#[tauri::command]
pub fn get_totp_code(entry_id: String, state: State<VaultState>) -> CmdResult<TotpResponse> {
    let uid =
        Uuid::parse_str(&entry_id).map_err(|e| CommandError(e.to_string()))?;
    let inner = state.0.lock().unwrap();
    let data = inner.data.as_ref().ok_or(CommandError("Vault is locked".into()))?;
    let entry = data
        .entries
        .iter()
        .find(|e| e.id == uid)
        .ok_or(CommandError(format!("Entry {entry_id} not found")))?;
    let secret = entry
        .totp_secret
        .as_deref()
        .ok_or(CommandError("No TOTP secret for this entry".into()))?;
    let code = totp::current_code(secret)?;
    Ok(TotpResponse { code, qr_base64: None })
}

#[tauri::command]
pub fn add_totp_to_entry(
    entry_id: String,
    base32_secret: String,
    state: State<VaultState>,
) -> CmdResult<String> {
    let uid =
        Uuid::parse_str(&entry_id).map_err(|e| CommandError(e.to_string()))?;

    let code = totp::current_code(&base32_secret)?;

    let mut inner = state.0.lock().unwrap();
    let data = inner.data.as_mut().ok_or(CommandError("Vault is locked".into()))?;
    let entry = data
        .entries
        .iter_mut()
        .find(|e| e.id == uid)
        .ok_or(CommandError(format!("Entry {entry_id} not found")))?;
    entry.totp_secret = Some(base32_secret.to_uppercase());
    entry.updated_at = chrono::Utc::now();
    vault::save_vault(&inner)?;
    Ok(code)
}

#[tauri::command]
pub fn has_yubikey() -> bool {
    yubikey::is_connected()
}

#[tauri::command]
pub fn yubikey_challenge(challenge_hex: String) -> CmdResult<String> {
    let challenge = hex::decode(&challenge_hex)
        .map_err(|e| CommandError(format!("Invalid hex challenge: {e}")))?;
    let response = yubikey::hmac_challenge(&challenge)?;
    Ok(hex::encode(response))
}

fn apply_input(entry: &mut Entry, input: EntryInput) {
    entry.title = input.title;
    entry.username = input.username;
    entry.password = input.password;
    entry.url = input.url;
    entry.notes = input.notes;
    if let Some(cat) = input.category {
        entry.category = cat;
    }
    if let Some(fav) = input.favourite {
        entry.favourite = fav;
    }
}

#[tauri::command]
pub fn backup_vault(dest_path: String, state: State<VaultState>) -> CmdResult<()> {
    let inner = state.0.lock().unwrap();
    let src = inner.path.as_ref().ok_or(CommandError("Vault not open".into()))?;
    std::fs::copy(src, &dest_path)?;
    Ok(())
}

#[tauri::command]
pub fn change_master_password(
    current_password: String,
    new_password: String,
    state: State<VaultState>,
) -> CmdResult<()> {
    let mut inner = state.0.lock().unwrap();
    let path = inner.path.clone().ok_or(CommandError("Vault not open".into()))?;

    let (_old_key, data, _old_params) = vault::open_vault(&path, &current_password)
        .map_err(|_| CommandError("Current password is incorrect".into()))?;

    let new_params = crate::crypto::Argon2Params::STRONG;
    let new_salt   = crypto::generate_salt();
    let new_key    = crypto::derive_key(&new_password, &new_salt, new_params)
        .map_err(|e| CommandError(e.to_string()))?;

    let json       = serde_json::to_vec(&data).map_err(|e| CommandError(e.to_string()))?;
    let ciphertext = crypto::encrypt(&new_key, &json).map_err(|e| CommandError(e.to_string()))?;

    let mut file_bytes: Vec<u8> = Vec::new();
    file_bytes.extend_from_slice(vault::MAGIC);
    file_bytes.extend_from_slice(&vault::FILE_VERSION.to_le_bytes());
    file_bytes.extend_from_slice(&new_salt);
    file_bytes.extend_from_slice(&new_params.m_cost.to_le_bytes());
    file_bytes.extend_from_slice(&new_params.t_cost.to_le_bytes());
    file_bytes.extend_from_slice(&new_params.p_cost.to_le_bytes());
    file_bytes.extend_from_slice(&ciphertext);
    let hmac = crypto::compute_hmac(&new_key, &file_bytes);
    file_bytes.extend_from_slice(&hmac);
    std::fs::write(&path, &file_bytes)?;

    inner.key           = Some(vault::LockedKey(new_key));
    inner.argon2_params = Some(new_params);
    Ok(())
}

#[derive(Clone, serde::Serialize)]
pub struct AccessLogEntry {
    pub timestamp: String,
    pub event: String,
    pub success: bool,
}

static ACCESS_LOG: std::sync::OnceLock<std::sync::Mutex<Vec<AccessLogEntry>>> = std::sync::OnceLock::new();

fn access_log() -> &'static std::sync::Mutex<Vec<AccessLogEntry>> {
    ACCESS_LOG.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

pub fn log_access(event: &str, success: bool) {
    let entry = AccessLogEntry {
        timestamp: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        event: event.to_string(),
        success,
    };
    let mut log = access_log().lock().unwrap();
    log.push(entry);

    if log.len() > 200 {
        let drain_count = log.len() - 200;
        log.drain(0..drain_count);
    }
}

#[tauri::command]
pub fn get_access_log() -> Vec<AccessLogEntry> {
    access_log().lock().unwrap().clone()
}

#[tauri::command]
pub fn clear_access_log() {
    access_log().lock().unwrap().clear();
}

#[tauri::command]
pub fn set_window_title(title: String, window: tauri::Window) -> CmdResult<()> {
    window.set_title(&title).map_err(|e| CommandError(e.to_string()))?;
    Ok(())
}

#[tauri::command]
pub fn set_content_protection(enabled: bool, window: tauri::Window) -> CmdResult<()> {
    window.set_content_protected(enabled).map_err(|e| CommandError(e.to_string()))?;
    Ok(())
}

#[derive(Clone, Serialize)]
pub struct SecurityStatus {

    pub self_hash: Option<String>,

    pub hooked_functions: Vec<String>,

    pub keyboard_hook_detected: bool,

    pub clipboard_owner_pid: u32,

    pub mitigations_applied: bool,

    pub vault_canary_ok: bool,
}

#[tauri::command]
pub fn get_security_status() -> SecurityStatus {
    SecurityStatus {
        self_hash:               security::compute_self_hash(),
        hooked_functions:        security::find_hooked_functions()
                                     .into_iter().map(|s| s.to_string()).collect(),
        keyboard_hook_detected:  security::detect_keyboard_hooks(),
        clipboard_owner_pid:     security::clipboard_owner_pid(),
        mitigations_applied:     crate::MITIGATIONS_APPLIED.load(std::sync::atomic::Ordering::Relaxed),
        vault_canary_ok:         security::verify_vault_magic_canary(),
    }
}

#[tauri::command]
pub fn verify_integrity(expected_hash: String) -> bool {
    security::verify_self_integrity(&expected_hash)
}

#[tauri::command]
pub fn check_debugger() -> bool {
    #[cfg(target_os = "windows")]
    {
        use winapi::um::debugapi::IsDebuggerPresent;
        unsafe { IsDebuggerPresent() != 0 }
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

#[tauri::command]
pub fn scan_processes() -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        const SUSPICIOUS: &[&str] = &[

            "x64dbg.exe", "x32dbg.exe", "ollydbg.exe", "windbg.exe",
            "ida.exe", "ida64.exe", "idaq.exe", "idaq64.exe",
            "idaw.exe", "idaw64.exe", "idapro.exe",

            "processhacker.exe", "procmon.exe", "procmon64.exe",
            "processhacker2.exe", "systeminformer.exe",

            "wireshark.exe", "fiddler.exe", "charles.exe", "mitmproxy.exe",
            "burpsuite.exe", "javaw.exe", 

            "cheatengine.exe", "cheatengine-x86_64.exe", "cheatengine-x86_64-SSE4-AVX2.exe",

            "dnspy.exe", "de4dot.exe", "reflexil.exe", "ilspy.exe", "dotpeek.exe",

            "pe-bear.exe", "lordpe.exe", "peid.exe", "die.exe",
            "exeinfope.exe", "studype.exe",

            "hxd.exe", "winhex.exe", "010editor.exe",

            "apimonitor-x64.exe", "apimonitor-x86.exe", "apispy.exe",

            "procexp.exe", "procexp64.exe", "autoruns.exe", "autoruns64.exe",

            "scylla.exe", "scylla_x64.exe", "scylla_x86.exe",
        ];

        use winapi::um::tlhelp32::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
            PROCESSENTRY32W, TH32CS_SNAPPROCESS,
        };
        use winapi::um::handleapi::CloseHandle;
        use winapi::shared::minwindef::FALSE;

        let mut found = Vec::new();
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == winapi::um::handleapi::INVALID_HANDLE_VALUE {
                return found;
            }
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            if Process32FirstW(snap, &mut entry) != FALSE {
                loop {
                    let name_raw = &entry.szExeFile;
                    let len = name_raw.iter().position(|&c| c == 0).unwrap_or(name_raw.len());
                    let name = String::from_utf16_lossy(&name_raw[..len]).to_lowercase();
                    if SUSPICIOUS.iter().any(|s| name == *s) {
                        found.push(name);
                    }
                    if Process32NextW(snap, &mut entry) == FALSE {
                        break;
                    }
                }
            }
            CloseHandle(snap);
        }
        found
    }
    #[cfg(not(target_os = "windows"))]
    {
        vec![]
    }
}

#[tauri::command]
pub fn wallet_generate_mnemonic(word_count: usize) -> CmdResult<String> {
    wallet::generate_mnemonic(word_count).map_err(CommandError)
}

#[tauri::command]
pub fn wallet_validate_mnemonic(phrase: String) -> bool {
    wallet::validate_mnemonic(&phrase)
}

#[tauri::command]
pub fn wallet_create(
    name: String,
    mnemonic: String,
    state: State<VaultState>,
) -> CmdResult<WalletSummary> {
    let addrs = wallet::derive_addresses(&mnemonic).map_err(CommandError)?;
    let account = WalletAccount {
        id: uuid::Uuid::new_v4(),
        name,
        mnemonic,
        btc_address:   addrs.btc,
        eth_address:   addrs.eth,
        sol_address:   addrs.sol,
        ltc_address:   addrs.ltc,
        doge_address:  addrs.doge,
        trx_address:   addrs.trx,
        ton_address:   addrs.ton,
        custom_chains: vec![],
        tokens:        vec![],
        created_at:    chrono::Utc::now(),
    };
    let summary = WalletSummary::from(&account);
    let mut inner = state.0.lock().unwrap();
    let data = inner.data.as_mut().ok_or_else(|| CommandError("Vault is locked".into()))?;
    data.wallets.push(account);
    vault::save_vault(&inner).map_err(|e| CommandError(e.to_string()))?;
    Ok(summary)
}

#[tauri::command]
pub fn wallet_list(state: State<VaultState>) -> CmdResult<Vec<WalletSummary>> {
    let inner = state.0.lock().unwrap();
    let data = inner.data.as_ref().ok_or_else(|| CommandError("Vault is locked".into()))?;
    Ok(data.wallets.iter().map(WalletSummary::from).collect())
}

#[tauri::command]
pub fn wallet_delete(id: String, state: State<VaultState>) -> CmdResult<()> {
    let uid = uuid::Uuid::parse_str(&id).map_err(|e| CommandError(e.to_string()))?;
    let mut inner = state.0.lock().unwrap();
    let data = inner.data.as_mut().ok_or_else(|| CommandError("Vault is locked".into()))?;
    let before = data.wallets.len();
    data.wallets.retain(|w| w.id != uid);
    if data.wallets.len() == before {
        return Err(CommandError(format!("Wallet {id} not found")));
    }
    vault::save_vault(&inner).map_err(|e| CommandError(e.to_string()))?;
    Ok(())
}

#[tauri::command]
pub fn wallet_export_mnemonic(wallet_id: String, state: State<VaultState>) -> CmdResult<String> {
    let uid = uuid::Uuid::parse_str(&wallet_id).map_err(|e| CommandError(e.to_string()))?;
    let inner = state.0.lock().unwrap();
    let data = inner.data.as_ref().ok_or_else(|| CommandError("Vault is locked".into()))?;
    data.wallets
        .iter()
        .find(|w| w.id == uid)
        .map(|w| w.mnemonic.clone())
        .ok_or_else(|| CommandError(format!("Wallet {wallet_id} not found")))
}

#[tauri::command]
pub async fn wallet_get_balance(
    address: String,
    chain: String,
    rpc_url: Option<String>,
) -> CmdResult<String> {
    let result = match chain.as_str() {
        "btc"  => wallet::get_btc_balance(&address).await,
        "sol"  => wallet::get_sol_balance(&address).await,
        "ltc"  => wallet::get_ltc_balance(&address).await,
        "doge" => wallet::get_doge_balance(&address).await,
        "trx"  => wallet::get_trx_balance(&address).await,
        "ton"  => wallet::get_ton_balance(&address).await,

        _ => {
            let rpc = rpc_url.unwrap_or_else(|| "https://cloudflare-eth.com/".to_string());
            wallet::get_evm_balance(&address, &rpc).await
        }
    };
    result.map_err(CommandError)
}

#[tauri::command]
pub async fn wallet_get_token_balance(
    address: String,
    contract_address: String,
    decimals: u8,
    rpc_url: String,
) -> CmdResult<String> {
    wallet::get_token_balance(&address, &contract_address, &rpc_url, decimals)
        .await
        .map_err(CommandError)
}

#[derive(Serialize)]
pub struct EthTxPreviewDto {
    pub from: String,
    pub to: String,
    pub value_eth: f64,
    pub gas_price_gwei: f64,
    pub fee_eth: f64,
    pub chain_id: u64,
}

#[tauri::command]
pub async fn wallet_eth_preview(
    wallet_id: String,
    to: String,
    amount_eth: f64,
    chain_id: u64,
    rpc_url: String,
    state: State<'_, VaultState>,
) -> CmdResult<EthTxPreviewDto> {
    let uid = uuid::Uuid::parse_str(&wallet_id).map_err(|e| CommandError(e.to_string()))?;
    let mnemonic = {
        let inner = state.0.lock().unwrap();
        let data = inner.data.as_ref().ok_or_else(|| CommandError("Vault is locked".into()))?;
        data.wallets.iter().find(|w| w.id == uid)
            .map(|w| w.mnemonic.clone())
            .ok_or_else(|| CommandError(format!("Wallet {wallet_id} not found")))?
    };
    let params = wallet::EthTxParams { to, amount_eth, chain_id, rpc_url };
    let p = wallet::eth_preview(&mnemonic, &params).await.map_err(CommandError)?;
    Ok(EthTxPreviewDto {
        from: p.from, to: p.to, value_eth: p.value_eth,
        gas_price_gwei: p.gas_price_gwei, fee_eth: p.fee_eth, chain_id: p.chain_id,
    })
}

#[tauri::command]
pub async fn wallet_eth_send(
    wallet_id: String,
    to: String,
    amount_eth: f64,
    chain_id: u64,
    rpc_url: String,
    state: State<'_, VaultState>,
) -> CmdResult<String> {
    let uid = uuid::Uuid::parse_str(&wallet_id).map_err(|e| CommandError(e.to_string()))?;
    let mnemonic = {
        let inner = state.0.lock().unwrap();
        let data = inner.data.as_ref().ok_or_else(|| CommandError("Vault is locked".into()))?;
        data.wallets.iter().find(|w| w.id == uid)
            .map(|w| w.mnemonic.clone())
            .ok_or_else(|| CommandError(format!("Wallet {wallet_id} not found")))?
    };
    let params = wallet::EthTxParams { to, amount_eth, chain_id, rpc_url };
    wallet::eth_send(&mnemonic, &params).await.map_err(CommandError)
}

#[tauri::command]
pub async fn wallet_get_swap_quote(
    from_cg_id: String,
    to_cg_id: String,
    from_symbol: String,
    to_symbol: String,
    from_amount: f64,
) -> CmdResult<wallet::SwapQuote> {
    wallet::get_swap_quote(&from_cg_id, &to_cg_id, &from_symbol, &to_symbol, from_amount)
        .await
        .map_err(CommandError)
}

#[derive(Serialize)]
pub struct EthTokenTxPreviewDto {
    pub from: String,
    pub to: String,
    pub amount: f64,
    pub gas_price_gwei: f64,
    pub fee_eth: f64,
    pub chain_id: u64,
}

#[tauri::command]
pub async fn wallet_token_preview(
    wallet_id: String,
    contract_address: String,
    to: String,
    amount: f64,
    decimals: u8,
    chain_id: u64,
    rpc_url: String,
    state: State<'_, VaultState>,
) -> CmdResult<EthTokenTxPreviewDto> {
    let uid = uuid::Uuid::parse_str(&wallet_id).map_err(|e| CommandError(e.to_string()))?;
    let mnemonic = {
        let inner = state.0.lock().unwrap();
        let data = inner.data.as_ref().ok_or_else(|| CommandError("Vault is locked".into()))?;
        data.wallets.iter().find(|w| w.id == uid)
            .map(|w| w.mnemonic.clone())
            .ok_or_else(|| CommandError(format!("Wallet {wallet_id} not found")))?
    };
    let params = wallet::EthTokenTxParams {
        contract_address, to: to.clone(), amount, decimals, chain_id, rpc_url,
    };
    let p = wallet::eth_token_preview(&mnemonic, &params).await.map_err(CommandError)?;
    Ok(EthTokenTxPreviewDto {
        from: p.from, to: p.to, amount: p.amount,
        gas_price_gwei: p.gas_price_gwei, fee_eth: p.fee_eth, chain_id: p.chain_id,
    })
}

#[tauri::command]
pub async fn wallet_token_send(
    wallet_id: String,
    contract_address: String,
    to: String,
    amount: f64,
    decimals: u8,
    chain_id: u64,
    rpc_url: String,
    state: State<'_, VaultState>,
) -> CmdResult<String> {
    let uid = uuid::Uuid::parse_str(&wallet_id).map_err(|e| CommandError(e.to_string()))?;
    let mnemonic = {
        let inner = state.0.lock().unwrap();
        let data = inner.data.as_ref().ok_or_else(|| CommandError("Vault is locked".into()))?;
        data.wallets.iter().find(|w| w.id == uid)
            .map(|w| w.mnemonic.clone())
            .ok_or_else(|| CommandError(format!("Wallet {wallet_id} not found")))?
    };
    let params = wallet::EthTokenTxParams {
        contract_address, to, amount, decimals, chain_id, rpc_url,
    };
    wallet::eth_token_send(&mnemonic, &params).await.map_err(CommandError)
}
