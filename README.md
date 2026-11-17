# NFT-Gated ESP32 Garage Door Controller

Production-ready ESP32 firmware that controls a garage door, gated by NFT ownership verification using Ethereum signatures (secp256k1 & P-256 passkeys). Built with PlatformIO and the [Web3E library](https://github.com/AlphaWallet/Web3E).

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

- **Contract**: Configured in `src/secrets.h` (default: `0x3158e836ec0e85A46f7a7208d91EA9837A0C6ccC`)
- **Chain**: Base Sepolia testnet (`BASE_SEPOLIA_ID`)
- **Check**: `balanceOf(address)` must return > 0

The device queries the contract via Web3E to verify NFT ownership before allowing garage door operation.

## Hardware

- **Board**: ESP-WROVER-KIT (`esp-wrover-kit` in platformio.ini)
- **Flash**: 4MB (default) or 16MB (see partition tables)
- **Relays**:
  - `RELAY_1` (GPIO 21): Main garage door control
  - `RELAY_2` (GPIO 22): Interior door control

## Setup & Provisioning

### 1. Initial Setup

```bash
git clone <this-repo>
cd NFT-Gated-ESP-Control
```

### 2. Configure Secrets

**IMPORTANT**: Before building, create your secrets file:

```bash
cp src/secrets.h.example src/secrets.h
# Edit src/secrets.h with your credentials
```

**Required configuration in `src/secrets.h`**:
- Wi-Fi SSIDs and passwords (fallback credentials)
- NFT contract address (`DOOR_CONTRACT_ADDRESS`)
- Admin Ethereum addresses

**Security**: `src/secrets.h` is gitignored and never committed.

### 3. Device Provisioning Workflow

There are two ways to provision Wi-Fi credentials on production devices:

#### Option A: Setup Firmware (Recommended for Production)

Use the separate [Web3E-Setup-Firmware](https://github.com/JamesSmartCell/Web3E-Setup-Firmware) to provision devices via captive portal:

1. Flash the setup firmware to the device
2. Device creates a captive portal Wi-Fi network
3. User connects and enters Wi-Fi credentials
4. Setup firmware writes credentials to EEPROM WifiStore (offset 33+)
5. Flash this production firmware
6. Device reads credentials from WifiStore and connects

#### Option B: Secrets Migration (Development/Initial Deployment)

For devices that have never been provisioned:

1. Configure fallback credentials in `src/secrets.h`
2. Flash this firmware
3. On first boot, if WifiStore is empty, firmware:
   - Uses fallback credentials from `secrets.h` to connect
   - Writes those credentials to EEPROM WifiStore
   - Future boots read from WifiStore

**Migration Safety**: Existing production devices with hardcoded credentials will automatically migrate to WifiStore on first boot with this firmware. Connectivity is never lost.

## Build & Flash

### Prerequisites
- [PlatformIO](https://platformio.org/)
- ESP32 toolchain (automatically installed by PlatformIO)
- Git (for version hash generation)

### Build

```bash
pio run
```

Build output (from production firmware):
```
RAM:   [==        ]  16.7% (used 54840 bytes from 327680 bytes)
Flash: [=======   ]  68.7% (used 1350239 bytes from 1966080 bytes)
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

## Firmware Version & Identity

Firmware version follows the format: `<PROJECT_ID>@<semver>+<shorthash>`

**Example**: `garagedoor@1.2.0+a4d316c`

**Components**:
- `PROJECT_ID`: Build flag (default: `"garagedoor"`)
- `semver`: From `FIRMWARE_SEMVER` in `src/main.cpp` (e.g., `"1.2.0"`)
- `shorthash`: 7-character git commit SHA, generated at build time by `git_version.py`
  - Appends `-dirty` if working tree has uncommitted changes
  - Ignores untracked files

**Configure**:
- Change `PROJECT_ID` in `platformio.ini` build flags
- Change `FIRMWARE_SEMVER` in `src/main.cpp`

**View current version**:
- Serial output at boot
- `getVersion` API command
- Reported to SmartLayerProxy in 0x09 firmware login

## OTA Firmware Updates

### New OTA Flow (Production)

Firmware binaries are stored in **Cloudflare R2** and coordinated by **SmartLayerProxy**.

#### Update Triggers

The device checks for updates:
1. **At boot** (after Wi-Fi connects)
2. **Every 24 hours** (automatic periodic check)
3. **On proxy push notification** (via `updateReady` API method, rate-limited to 60s)

#### Update Process

1. Device fetches metadata: `GET {PROXY_BASE_URL}/api/firmware/{PROJECT_ID}/latest`
2. Proxy returns JSON:
   ```json
   {
     "version": "garagedoor@1.2.0+abc1234",
     "url": "https://firmware.percolate.one/garagedoor/1.2.0/firmware.bin",
     "sha256": "f4a3b2c1d5e6...",
     "size": 1350239
   }
   ```
3. Device compares `version` with current `FW_VERSION`
4. If different, device streams binary from `url` via HTTPS
5. While downloading, device computes SHA-256 hash
6. Device verifies:
   - SHA-256 matches `sha256` field
   - Size matches `size` field
7. If verified, device commits update and reboots
8. If verification fails, device aborts and continues with current firmware

**Security**: Device only installs firmware from the configured `PROXY_BASE_URL` and only after SHA-256 verification. URL is never accepted from API callers.

#### Proxy Configuration

- Default proxy: `https://scriptproxy.percolate.one`
- Configure via `PROXY_BASE_URL` build flag in `platformio.ini`

### Legacy OTA Flow (Removed)

The old authenticated `updateReady` API method (which required NFT ownership and accepted arbitrary URLs) has been **removed** in this release. The new flow uses the proxy's firmware service for centralized, verified updates.

## Releasing a New Firmware Version

### 1. Prepare Release

```bash
# Update version in src/main.cpp
vim src/main.cpp  # Change FIRMWARE_SEMVER (e.g., "1.3.0")

# Commit changes
git add src/main.cpp
git commit -m "Bump firmware version to 1.3.0"
git push
```

### 2. Build Release Binary

```bash
# Clean build
pio run --target clean
pio run

# Collect artifacts
cp .pio/build/esp32dev/firmware.bin releases/garagedoor-1.3.0+<hash>.bin
```

### 3. Upload to Firmware Service

Use the SmartLayerProxy upload tool with **plain semver**:

```bash
cd /path/to/SmartLayerProxy

# Upload firmware with PLAIN SEMVER (matches FIRMWARE_SEMVER from main.cpp)
node tools/firmware/upload.js \
  --project garagedoor \
  --version "1.3.0" \
  --file /path/to/firmware.bin \
  --set-current

# Tool computes SHA-256 and size automatically
# Uploads to Cloudflare R2
# Registers metadata in firmware database
```

**IMPORTANT**: The `--version` argument should be **plain semver** (e.g., `"1.3.0"`), matching the `FIRMWARE_SEMVER` value in `src/main.cpp`. The device will parse this correctly whether the proxy stores it as:
- `"1.3.0"` (plain semver)
- `"garagedoor@1.3.0"` (with project prefix)
- `"garagedoor@1.3.0+abc1234"` (full format)

**Tool fields stored by proxy**:
- `version`: Semver string (e.g., `"1.3.0"` or with project/build metadata)
- `url`: R2 public URL (e.g., `https://firmware.percolate.one/...`)
- `sha256`: SHA-256 hex digest (64 chars, lowercase)
- `size`: File size in bytes

**Device version comparison**:
- Extracts MAJOR.MINOR.PATCH from both formats
- Compares using semver rules (only upgrades if newer)
- Blocks downgrades
- Validates project prefix if present (must match `PROJECT_ID`)
- Ignores build metadata (git hash) during comparison

### 4. Notify Devices (Optional)

The proxy can push an `updateReady` notification to trigger immediate checks:

```javascript
// Via SmartLayerProxy TCP bridge
await tcpService.notifyDevices({
  project: 'garagedoor',
  api: 'updateReady'
});
// Devices check within 60 seconds (rate limit)
```

Devices will also discover the update on their next periodic check (24h) or reboot.

### Version Comparison Logic

The device implements **strict semver comparison** with safety features:

**Parsing:**
- Handles formats: `"1.2.0"`, `"v1.2.0"`, `"1.2.0+hash"`, `"project@1.2.0+hash"`
- Extracts MAJOR.MINOR.PATCH (ignores build metadata)
- Validates project prefix if present (must match `PROJECT_ID`)

**Comparison:**
- Only installs if available version is **strictly newer** (MAJOR.MINOR.PATCH)
- **Blocks downgrades** (e.g., won't install 1.1.0 when running 1.2.0)
- Ignores build metadata differences (1.2.0+abc and 1.2.0+xyz are same version)

**Failure tracking:**
- If a version fails SHA-256 or size check, device won't retry it for 24 hours
- Prevents infinite OTA loops on corrupt metadata
- After 24h, device will retry in case issue was transient

**Rate limiting:**
- `updateReady` API limited to once per 60 seconds
- Prevents rapid OTA attempts

## Partition Tables

**Active**: `min_spiffs.csv` (ESP32, 4MB)
- Dual OTA partitions (1.28MB each)
- Minimal SPIFFS
- **Required for OTA**: Two app slots for safe updates

**Alternative configurations** (not currently used by esp32dev):
- **`wrover_ota.csv`** (4MB): Dual OTA + SPIFFS + coredump
- **`wrover_ota_16mb.csv`** (16MB): Dual OTA (6.25MB each) + large SPIFFS

**OTA Note**: The default `min_spiffs.csv` provides two OTA app slots as required by the ESP32 OTA mechanism. Binary size (1.35MB) fits comfortably in each 1.28MB partition.

## Dependencies

### Web3E (Pinned to GitHub)

- **Source**: https://github.com/AlphaWallet/Web3E
- **Commit**: `ef0ef692902ef7545b00c1f955179f5b4e12c126` (Nov 17, 2026)
- **Version**: 1.45.0+sha.ef0ef69

**Why pinned**: Web3E master now includes:
- `WifiStore`: EEPROM-based Wi-Fi credential storage
- `WiFiDiagnostics`: Connection quality metrics
- `TcpBridge` firmware version login (opcode 0x09)
- Startup watchdog for robust connection handling

**Declared in platformio.ini**:
```ini
lib_deps = 
    https://github.com/AlphaWallet/Web3E.git#ef0ef692902ef7545b00c1f955179f5b4e12c126
```

**No more hand-edited libdeps**: All Web3E code comes from the pinned GitHub commit.

### Other Libraries

- **ArduinoJson** 7.4.3: JSON parsing for firmware metadata
- **EEPROM**, **HTTPClient**, **Update**, **WiFi**, **NetworkClientSecure**: ESP32 framework libraries

## Configuration

### Required Secrets (src/secrets.h)

**⚠️ Security Note**: All secrets have been moved from `src/main.cpp` to the gitignored `src/secrets.h` file.

**Contents** (see `src/secrets.h.example`):
- Wi-Fi credentials (SSID/password pairs)
- NFT contract address (`DOOR_CONTRACT_ADDRESS`)
- Admin Ethereum addresses (`ADMIN_ADDRESS_1`, `ADMIN_ADDRESS_2`)

**Build behavior**:
- If `src/secrets.h` is missing: **Build fails** with `#error` (unless `-DNO_SECRETS_FALLBACK` is set)
- Production builds **must** have `secrets.h` configured

### Build Flags

Configured in `platformio.ini`:

- **`PROJECT_ID`**: Firmware project identifier (default: `"garagedoor"`)
- **`PROXY_BASE_URL`**: SmartLayerProxy base URL (default: `"https://scriptproxy.percolate.one"`)
- **`WEB3E_RELEASE`**: (via `web3e_flags.h`) Strips Web3E debug logging

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
| `updateReady` | Trigger OTA firmware check | **None** (rate-limited: 60s) |

**Signature Parameters**:
- `sig`: Hex-encoded signature (130 chars: r + s + recid)
- `hashType`: (P-256 only) `"keccak"`, `"sha256"`, or `"webauthn"`
- `digest`: (P-256 webauthn only) Pre-computed hash digest

For P-256 passkey integration details, see [P256_PASSKEY_INTEGRATION.md](./P256_PASSKEY_INTEGRATION.md).

### `updateReady` API (New)

**Purpose**: Trigger an immediate OTA update check (pushed by proxy when new firmware is available).

**Authentication**: **None required** (unauthenticated endpoint)

**Security**:
- Device only installs firmware from configured `PROXY_BASE_URL`
- Device verifies SHA-256 and size before accepting update
- Rate-limited to 1 request per 60 seconds
- Proxy push notification, not user-initiated

**Response**:
- `"checking"`: Update check initiated
- `"rate_limited"`: Too soon since last check

**Usage by SmartLayerProxy**:
```javascript
// After firmware upload, notify all devices
await notifyDevices({
  project: 'garagedoor',
  api: 'updateReady'
});
```

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
Admin addresses configured in `secrets.h` bypass NFT checks for all door operations.

### Wi-Fi Connection Management
- **Multi-network support**: WifiStore stores up to 8 networks
- **Watchdog**: Web3E `WiFiConnection` handles automatic reconnection
- **Diagnostics**: Connection quality metrics reported to proxy (opcode 0x0A)

### EEPROM Layout

- **Bytes 0-32**: KeyID (Web3E device identity key)
- **Bytes 33+**: WifiStore (magic, version, networks, CRC32)
- **Total**: 1024 bytes (`WEB3E_EEPROM_SIZE`)

**Critical**: All components use `WEB3E_EEPROM_SIZE=1024` when calling `EEPROM.begin()`. On arduino-esp32 3.x, a smaller size **truncates** the NVS blob.

## Troubleshooting

### Build Issues

**"secrets.h not found"**:
```bash
cp src/secrets.h.example src/secrets.h
# Edit with your credentials
```

**"Flash overflow"**:
- Current binary: 1.35MB (fits in 1.28MB partition with headroom)
- If overflow occurs, use `wrover_ota_16mb.csv` or reduce code size

### Runtime Issues

**Device won't connect**:
1. Check serial output for WifiStore validation
2. Verify `secrets.h` credentials match your network
3. Check if WifiStore was written (migration should happen automatically)

**OTA fails**:
- Check proxy is reachable: `curl https://scriptproxy.percolate.one/api/firmware/garagedoor/latest`
- Verify SHA-256 in proxy metadata matches uploaded binary
- Check serial logs for specific failure (network, size, hash)

**Door doesn't operate**:
- Verify NFT balance via Web3E logs
- Check challenge/signature in serial output
- Test admin addresses first (bypass NFT check)

## Development

### Project Structure

```
NFT-Gated-ESP-Control/
├── src/
│   ├── main.cpp              # Main firmware (Wi-Fi, OTA, door control)
│   ├── ActionHandler.{cpp,h} # Scheduled action queue
│   ├── P256Crypto.{cpp,h}    # P-256 signature recovery
│   ├── web3e_flags.h         # Web3E build flags
│   ├── secrets.h.example     # Template for secrets
│   └── secrets.h             # Actual secrets (gitignored)
├── platformio.ini            # PlatformIO config (board, libs, flags)
├── git_version.py            # Build script: inject git hash
├── min_spiffs.csv            # Partition table (4MB, dual OTA, minimal SPIFFS) - DEFAULT
├── wrover_ota.csv            # Partition table (4MB, dual OTA) - not used by esp32dev
├── wrover_ota_16mb.csv       # Partition table (16MB, dual OTA) - not used by esp32dev
└── README.md                 # This file
```

### Adding Features

1. **New API methods**: Add to `APIRoutes` enum and `Initialize()` in `main.cpp`
2. **Persistent config**: Use EEPROM offsets beyond WifiStore (offset 800+)
3. **Hardware I/O**: Define pins and configure in `setup()`

### Testing

1. **Build**: `pio run` (must succeed with zero errors)
2. **Flash**: `pio run --target upload`
3. **Monitor**: `pio run --target monitor`
4. **Verify**:
   - Wi-Fi connection
   - TcpBridge login (see 0x09 firmware version in logs)
   - Challenge generation
   - Door operation via test signature
   - OTA check (should run at boot)

## License

MIT License

Copyright (c) 2026 James Brown

## References

- [Web3E Library](https://github.com/AlphaWallet/Web3E)
- [SmartLayerProxy](https://github.com/JamesSmartCell/SmartLayerProxy)
- [Web3E Setup Firmware](https://github.com/JamesSmartCell/Web3E-Setup-Firmware)
- [Wallet Interface](https://wallet.percolate.one)
- [P-256 Passkey Integration](./P256_PASSKEY_INTEGRATION.md)
