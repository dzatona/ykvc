# ykvc

YubiKey VeraCrypt CLI utility for generating cryptographic keyfiles. Two-factor security combining YubiKey hardware (HMAC-SHA1) with challenge phrase.

## Install

```bash
curl -sSL https://raw.githubusercontent.com/dzatona/ykvc/main/install.sh | bash
```

## Usage

```bash
ykvc info                     # YubiKey information
ykvc slot2 check              # Check slot 2 status
ykvc slot2 program            # Program slot 2 (shows secret to save)
ykvc slot2 restore <secret>   # Restore slot 2 from saved secret
ykvc generate                 # Generate keyfile
ykvc test                     # Test challenge-response
```

## Build

```bash
git clone https://github.com/dzatona/ykvc
cd ykvc
cargo build --release
```

## License

MIT
