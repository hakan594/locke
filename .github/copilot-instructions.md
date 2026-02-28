# KeePass-RS — Copilot Instructions

## Project Overview
Desktop password manager built with **Rust + Tauri** on Windows.

## Architecture
- **Backend**: Rust (all cryptography, business logic, file I/O)
- **Frontend**: HTML/CSS/JS via Tauri WebView
- **Storage**: Local `.vault` file (AES-256-GCM encrypted JSON)

## Cryptography Stack
| Layer | Algorithm | Crate |
|-------|-----------|-------|
| KDF | Argon2id | `argon2` |
| Encryption | AES-256-GCM | `aes-gcm` |
| TOTP (2FA) | RFC 6238 TOTP | `totp-rs` |
| YubiKey | HMAC-SHA1 | `yubico` / `pcsc` |
| RNG | OS CSPRNG | `rand` |

## Key Conventions
- All crypto operations happen in Rust, never in JS
- Vault key is derived from master password via Argon2id, never stored
- Plaintext is zeroed from memory after use (zeroize)
- TOTP secret is stored encrypted inside the vault
- YubiKey challenge-response used as optional second factor

## Completed Steps
- [x] Project scaffolded
- [x] Rust crypto dependencies added
