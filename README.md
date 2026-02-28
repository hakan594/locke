# Locke

Десктопный менеджер паролей с военным уровнем шифрования, написанный на **Rust + Tauri**.

## Стек безопасности

| Слой | Алгоритм | Описание |
|------|----------|----------|
| KDF | **Argon2id** | Защита мастер-пароля (64 MiB, 3 iter, 4 threads) |
| Шифрование | **AES-256-GCM** | Authenticated encryption с уникальным 96-bit nonce |
| 2FA | **TOTP** (RFC 6238) | Совместим с Authy / Google Authenticator |
| Аппаратный ключ | **YubiKey** HMAC-SHA1 | Challenge-Response через PC/SC (slot 2) |
| RNG | OS CSPRNG | `rand::thread_rng()` → `/dev/urandom` / `CryptGenRandom` |
| Обнуление памяти | **zeroize** | Мастер-ключ и пароли зануляются при Drop |

## Формат файла хранилища (`.vault`)

```
[4 bytes] Magic: "KPRS"
[4 bytes] Version: u32 LE
[16 bytes] Argon2id salt
[N bytes] AES-256-GCM ciphertext
            └── [12 bytes nonce] [encrypted JSON + 16-byte GCM tag]
```

Расшифрованный JSON содержит `VaultData` — массив записей.

## Требования

- **Windows 10/11 x64**
- [Rust 1.75+](https://rustup.rs/)
- [Node.js 18+](https://nodejs.org/)
- [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
- WebView2 Runtime (встроен в Windows 11)

## Запуск в режиме разработки

```powershell
npm install
npm run dev
```

Артефакты сборки направляются в `C:\cargo-target\locke\` (обход ограничения Cargo на кириллические пути).

## Production сборка

```powershell
npm run build
```

Исполняемый файл появится в `src-tauri\target\release\`.

## YubiKey setup

1. Откройте **YubiKey Manager**
2. `Applications → OTP → Slot 2 → HMAC-SHA1 Challenge-Response`
3. Сгенерируйте секретный ключ и сохраните конфигурацию
4. При создании хранилища с включённым YubiKey приложение автоматически обнаружит устройство

## Структура проекта

```
KeePass/
├── src/                    # Frontend (HTML/CSS/JS)
│   ├── index.html
│   ├── styles.css
│   └── main.js
└── src-tauri/              # Backend (Rust)
    ├── src/
    │   ├── lib.rs           # Tauri setup + команды
    │   ├── main.rs          # Точка входа
    │   ├── commands.rs      # IPC bridge JS ↔ Rust
    │   ├── models.rs        # Entry, VaultData
    │   ├── crypto/mod.rs    # AES-256-GCM + Argon2id
    │   ├── vault/mod.rs     # Файловый I/O
    │   ├── totp/mod.rs      # RFC 6238 TOTP
    │   └── yubikey/mod.rs   # HMAC-SHA1 PC/SC
    ├── capabilities/        # Tauri 2 permissions
    ├── icons/
    └── tauri.conf.json
```

## Безопасность

- Мастер-пароль **никогда не хранится** — только производный ключ в RAM
- Ключ живёт в `Mutex<InnerState>` и обнуляется при блокировке через `zeroize`
- Весь криптографический код — **только в Rust**, никакого JS шифрования
- CSP заголовок запрещает inline-скрипты и внешние ресурсы
