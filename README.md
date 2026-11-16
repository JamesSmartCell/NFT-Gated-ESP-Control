# NFT-Gated ESP32 Garage Door Controller

ESP32 firmware that controls a garage door, gated by NFT ownership verification using Ethereum signatures (secp256k1 & P-256 passkeys). Built with PlatformIO and the [Web3E library](https://github.com/AlphaWallet/Web3E).

## Overview

This firmware authenticates users via:
- **secp256k1** (MetaMask) signatures, or
- **P-256** (NIST P256/secp256r1) passkey signatures

The device verifies that the recovered Ethereum address holds a specific NFT before operating the garage door relay. It connects to the SmartLayerProxy service (https://github.com/JamesSmartCell/SmartLayerProxy) via the Web3E `TcpBridge`, which bridges requests from the wallet interface (https://wallet.percolate.one) to the device.

### Architecture

```
User (wallet.percolate.one)
  ↕
SmartLayerProxy
  ↕ TcpBridge (Web3E)
  ↕
ESP32 Device (this firmware)
  ↓
Garage Door Relay
```

### NFT Gating

- **Contract**: `0x3158e836ec0e85A46f7a7208d91EA9837A0C6ccC`
- **Chain**: Base Sepolia testnet (`BASE_SEPOLIA_ID`)
- **Check**: `balanceOf(address)` must return > 0

The device queries the contract via Web3E to verify NFT ownership before allowing garage door operation or OTA updates.

## Hardware

- **Board**: ESP-WROVER-KIT (`esp-wrover-kit` in platformio.ini)
- **Flash**: 4MB (default) or 16MB (see partition tables)
- **Relays**:
  - `RELAY_1` (GPIO 21): Main garage door control
  - `RELAY_2` (GPIO 22): Interior door control

## Build & Flash

### Prerequisites
- [PlatformIO](https://platformio.org/)
- ESP32 toolchain (automatically installed by PlatformIO)

### Build
```bash
pio run
```

### Flash
```bash
pio run --target upload
```

### Monitor
```bash
pio run --target monitor
# Serial: 115200 baud
```

## Partition Tables

Three partition table configurations are provided:

1. **`partitions.csv`** (ESP32-C6, 4MB):
   - Single OTA partition (3MB app)
   - Zigbee coordinator support
   - SPIFFS, coredump

2. **`wrover_ota.csv`** (ESP32 WROVER, 4MB):
   - Dual OTA partitions (1.25MB each)
   - SPIFFS, coredump
   - Default for `esp-wrover-kit`

3. **`wrover_ota_16mb.csv`** (ESP32 WROVER, 16MB):
   - Dual OTA partitions (6.25MB each)
   - Large SPIFFS (3.5MB)
   - Requires `board_build.flash_size = 16MB` in platformio.ini

The active partition table is selected via `board_build.partitions` in platformio.ini (default: `min_spiffs.csv`).

## Dependencies

- **Web3E**: EVM library for ESP32
  - Source: https://github.com/AlphaWallet/Web3E
  - Declared in platformio.ini as `lib_deps = Web3E`
  - Version: determined by PlatformIO registry (latest compatible)

## Configuration

### Required Secrets

**⚠️ Security Note**: The following values are currently hard-coded in `src/main.cpp` and **must be externalized** before production use:

- **Infura API Key** (`INFURA_KEY`, line 13)
- **WiFi credentials** (SSIDs/passwords, lines 28-32)
- **Admin addresses** (`adminAddrs[]`, line 90)

Move these to a secure configuration file (e.g., `secrets.h` excluded from version control) or use EEPROM/NVS storage.

### Build Flags

- **`WEB3E_RELEASE`** (defined in `src/web3e_flags.h`):
  - When defined: strips Web3E debug logging
  - Force-included into Web3E library via platformio.ini: `-include src/web3e_flags.h`

## OTA Firmware Updates

### Mechanism
OTA updates are handled by the `updateReady` API route, implemented in `src/main.cpp` (lines 336-396).

### Requirements
- **Authentication**: P-256 passkey signature required (`sig` parameter)
- **Authorization**: Recovered address must hold the garage door NFT (`DOOR_CONTRACT` on Base Sepolia)
- **Parameters**:
  - `url`: HTTPS URL of the new firmware binary
  - `version`: Version string (e.g., "1.1.1")
  - `sig`: P-256 signature over the current challenge
  - `hashType`: (optional) `"keccak"` (default), `"sha256"`, or `"webauthn"`

### Process
1. User calls `getVersion` to check current firmware (`FIRMWARE_VERSION`)
2. User calls `getChallenge` to receive a challenge token
3. User signs the challenge with their P-256 passkey
4. User calls `updateReady` with signature, URL, and version
5. Device verifies NFT ownership (same contract as garage door access)
6. If authorized, device downloads firmware via `HTTPUpdate` (ESP32 OTA library)
7. On success, device reboots into the new firmware

### Current Version
Defined in `src/main.cpp` as `FIRMWARE_VERSION` (currently `"1.1.0-toggle"`).

## API Commands

The device exposes the following API routes via SmartLayerProxy/TcpBridge:

| Route | Description | Auth |
|-------|-------------|------|
| `getChallenge` | Get a random challenge token for signature | None |
| `getVersion` | Get firmware version string | None |
| `checkGarageSig` | Operate garage door (secp256k1 sig, timed) | NFT + sig |
| `checkGarageSig2` | Operate garage door (secp256k1 sig, toggle) | NFT + sig |
| `checkGarageSigP256` | Operate garage door (P-256 sig, timed) | NFT + sig |
| `checkGarageSigP256_2` | Operate garage door (P-256 sig, toggle) | NFT + sig |
| `updateReady` | Trigger OTA firmware update | NFT + sig |

**Signature Parameters**:
- `sig`: Hex-encoded signature (130 chars: r + s + recid)
- `hashType`: (P-256 only) `"keccak"`, `"sha256"`, or `"webauthn"`
- `digest`: (P-256 webauthn only) Pre-computed hash digest

For P-256 passkey integration details, see [P256_PASSKEY_INTEGRATION.md](./P256_PASSKEY_INTEGRATION.md).

## Implementation Details

### P-256 Signature Verification
- **Library**: Trezor NIST P-256 implementation (via Web3E)
- **Address Derivation**: `keccak256(pubkey_x || pubkey_y)[12:32]` (same as Tempo, webauthn-p256)
- **Recovery ID Handling**: Tries all recids (0-3) when wallet provides incorrect value
- **Source**: `src/P256Crypto.cpp`, `src/P256Crypto.h`

### Relay Operation
- **Main Garage Door** (`RELAY_1`): 1.5-second pulse (open/close)
- **Interior Door** (`RELAY_2`): 10-second unlatch
- **Auto-sequence**: Interior door operates 15 seconds after garage door
- **Timed vs Toggle**: APIs ending in `2` toggle indefinitely; others accept `openTime` parameter

### Admin Override
Two hardcoded admin addresses bypass NFT checks (line 90 in `src/main.cpp`).

## License

MIT License - see [LICENSE](./LICENSE)

Copyright (c) 2026 James Brown

## References

- [Web3E Library](https://github.com/AlphaWallet/Web3E)
- [SmartLayerProxy](https://github.com/JamesSmartCell/SmartLayerProxy)
- [Wallet Interface](https://wallet.percolate.one)
- [P-256 Passkey Integration](./P256_PASSKEY_INTEGRATION.md)
