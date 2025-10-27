# YKVC — YubiKey VeraCrypt CLI

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![codecov](https://codecov.io/gh/dzatona/ykvc/graph/badge.svg?token=OQ24W8WEDJ)](https://codecov.io/gh/dzatona/ykvc)
[![CI](https://github.com/dzatona/ykvc/actions/workflows/ci.yml/badge.svg)](https://github.com/dzatona/ykvc/actions/workflows/ci.yml)
[![Release](https://github.com/dzatona/ykvc/actions/workflows/release.yml/badge.svg)](https://github.com/dzatona/ykvc/actions/workflows/release.yml)
[![Security Audit](https://github.com/dzatona/ykvc/actions/workflows/audit.yml/badge.svg)](https://github.com/dzatona/ykvc/actions/workflows/audit.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A command-line utility for generating cryptographic keyfiles using YubiKey hardware tokens for use with VeraCrypt encrypted containers.

## Features

-  **Two-Factor Security**: Combines YubiKey hardware token with challenge phrase
-  **HMAC-SHA1 Challenge-Response**: Uses YubiKey slot 2 for deterministic key generation
-  **Secure Deletion**: 10-pass shred with final zero overwrite
-  **Cross-Platform**: Supports macOS and Ubuntu/Debian Linux
-  **Auto-Install**: Automatically installs all required dependencies
-  **Memory Safe**: Written in Rust with zero unsafe code

## Installation

Download the latest version with a single command:

```bash
curl -sSL https://raw.githubusercontent.com/dzatona/ykvc/main/install.sh | bash
```

This script will:
- Automatically detect your OS and architecture
- Download the latest release from GitHub
- Extract it to the current directory
- Clean up the archive file

**Supported platforms:**
- macOS (Apple Silicon & Intel)
- Ubuntu/Debian (x86_64)

## Quick Start

### 1. First-Time Setup

The utility will automatically install dependencies (Homebrew, YubiKey tools, coreutils) on first run.

### 2. Program YubiKey Slot 2

**IMPORTANT: Always use slot 2 for HMAC-SHA1 Challenge-Response!**

```bash
ykvc slot2 program
```

**Save the displayed secret!** You'll need it to restore access if you lose your YubiKey.

### 3. Generate Keyfile

```bash
ykvc generate
```

1. Enter your challenge phrase (password)
2. The keyfile will be created in the current directory
3. Use the keyfile with VeraCrypt to mount your container
4. Press Enter to securely delete the keyfile (10 passes + zero overwrite)

## Commands

### Info

Display YubiKey information:

```bash
ykvc info
```

### Slot 2 Management

**Check slot 2 status:**
```bash
ykvc slot2 check
```

**Program slot 2** (generates new random secret):
```bash
ykvc slot2 program
```

**Restore slot 2** from saved secret:
```bash
ykvc slot2 restore <secret-hex>
```

### Keyfile Generation

**Generate in current directory:**
```bash
ykvc generate
```

**Generate at specific path:**
```bash
ykvc generate -o /path/to/keyfile.key
```

### Testing

Test challenge-response without creating files:
```bash
ykvc test
```

## How It Works

### Security Model

YKVC implements two-factor authentication for VeraCrypt keyfiles:

1. **Something you know**: Challenge phrase (password)
2. **Something you have**: YubiKey with programmed secret

**Formula:**
```
Keyfile = HMAC-SHA1(SECRET_in_YubiKey, Challenge_Phrase)
```

- The **SECRET** is stored in YubiKey slot 2 and cannot be extracted
- Without the YubiKey, the correct keyfile cannot be generated
- Without the challenge phrase, the keyfile cannot be generated

### Workflow

```
┌─────────────┐     ┌──────────────┐
│  Challenge  │────▶│   YubiKey    │
│   Phrase    │     │   Slot 2     │
└─────────────┘     │  (SECRET)    │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │  HMAC-SHA1   │
                    │  Response    │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │   Keyfile    │
                    │  (20 bytes)  │
                    └──────────────┘
```

### Secure Deletion

- **macOS**: Uses `gshred` (GNU coreutils) with 10 random passes + zero overwrite
- **Linux**: Uses `shred` with 10 random passes + zero overwrite
- Files are verified to be deleted after shredding

## Requirements

### Runtime Dependencies

These are installed automatically on first run:

**macOS:**
- Homebrew (if not installed)
- ykpers
- yubikey-manager
- coreutils (for gshred)

**Ubuntu/Debian:**
- yubikey-manager
- yubikey-personalization
- coreutils (for shred)

### Hardware

- YubiKey with HMAC-SHA1 Challenge-Response support (most YubiKeys support this)

## Safety and Best Practices

###  Important Notes

1. **Always use slot 2** for HMAC-SHA1 Challenge-Response (slot 1 is typically used for OTP)
2. **Save your secret** when programming slot 2 - store it in a password manager or secure location
3. **Remember your challenge phrase** - write it down or store in a password manager
4. **Backup your VeraCrypt containers** - hardware can fail, have redundant backups

### Recovery Procedure

If you lose your YubiKey:

1. Buy a new YubiKey
2. Restore slot 2 with your saved secret:
   ```bash
   ykvc slot2 restore <your-saved-secret-hex>
   ```
3. Use the same challenge phrase to generate keyfiles

**Without the secret, your encrypted data is permanently inaccessible!**

## Development

### Build

```bash
cargo build --release
```

### Test

```bash
cargo test
cargo clippy
cargo fmt --check
```

### Project Structure

```
ykvc/
├── src/
│   ├── main.rs           # CLI interface
│   ├── yubikey.rs        # YubiKey operations
│   ├── keyfile.rs        # Keyfile generation & deletion
│   ├── error.rs          # Error types
│   └── platform/
│       ├── mod.rs        # Platform abstraction
│       ├── macos.rs      # macOS-specific code
│       └── linux.rs      # Linux-specific code
├── Cargo.toml
└── README.md
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- Built with [Rust](https://www.rust-lang.org/)
- Uses [YubiKey](https://www.yubico.com/) hardware tokens
- Designed for [VeraCrypt](https://veracrypt.jp/) encrypted containers
