pub mod commands;
pub mod crypto;
pub mod models;
pub mod security;
pub mod totp;
pub mod vault;
pub mod wallet;
pub mod yubikey;

use std::sync::atomic::{AtomicBool, Ordering};

pub static MITIGATIONS_APPLIED: AtomicBool = AtomicBool::new(false);

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {

    security::apply_process_mitigations();
    MITIGATIONS_APPLIED.store(true, Ordering::Relaxed);

    security::start_clipboard_monitor(std::sync::Arc::new(|| {
        crate::commands::log_access("CLIPBOARD THEFT DETECTED — foreign process read clipboard", false);
    }));

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(vault::VaultState::default())
        .invoke_handler(tauri::generate_handler![

            commands::create_vault,
            commands::unlock_vault,
            commands::lock_vault,
            commands::is_vault_unlocked,

            commands::list_entries,
            commands::get_entry,
            commands::create_entry,
            commands::update_entry,
            commands::delete_entry,

            commands::generate_password,

            commands::get_totp_code,
            commands::add_totp_to_entry,

            commands::yubikey_challenge,
            commands::has_yubikey,

            commands::backup_vault,
            commands::change_master_password,

            commands::get_access_log,
            commands::clear_access_log,

            commands::set_window_title,
            commands::set_content_protection,

            commands::get_security_status,
            commands::verify_integrity,
            commands::check_debugger,
            commands::scan_processes,

            commands::wallet_generate_mnemonic,
            commands::wallet_validate_mnemonic,
            commands::wallet_create,
            commands::wallet_list,
            commands::wallet_delete,
            commands::wallet_export_mnemonic,
            commands::wallet_get_balance,
            commands::wallet_get_token_balance,
            commands::wallet_eth_preview,
            commands::wallet_eth_send,
            commands::wallet_get_swap_quote,
            commands::wallet_token_preview,
            commands::wallet_token_send,
        ])
        .setup(|_app| {
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

