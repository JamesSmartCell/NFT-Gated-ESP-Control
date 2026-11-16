# P256 Passkey Integration Guide

This document describes how to integrate a web app using passkeys (P256) with the garage door controller.

## Overview

The ESP32 now supports P256 (secp256r1 / nist256p1) signature verification alongside the existing secp256k1 (MetaMask) flow. The address is derived from the P256 public key using:

```
address = keccak256(pub_key_x || pub_key_y)[12:32]
```

This matches **Tempo**, **webauthn-p256**, and similar P256-to-address schemes.

> **Note on Coinbase Smart Wallet**: Coinbase uses a different approach—the address is a smart contract (CREATE2), not derived from the pubkey hash. For Coinbase Smart Wallet compatibility, you would need to add the factory's address derivation logic. The current implementation uses the simpler pubkey-hash derivation.

## API: checkGarageSigP256

**Route**: `checkGarageSigP256`

**Parameters**:
| Param | Required | Description |
|-------|----------|-------------|
| `sig` | Yes | Hex string: r (64 chars) + s (64 chars) + recid (2 chars) = 130 chars. May include `0x` prefix. |
| `hashType` | No | `"keccak"` (default) or `"sha256"`. See below. |

## Message Hash Formats

### 1. Keccak (default) – personal_sign format

Same as Ethereum `personal_sign`:
```
digest = keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)
```

Use when your app can sign arbitrary data and you want parity with the existing MetaMask flow.

### 2. SHA256 – passkey-friendly

```
digest = sha256(message)
```

Use when your passkey/WebAuthn signs a SHA256 hash. Pass `hashType: "sha256"` in the API params.

## Web App Flow

1. **Get challenge**: Call `getChallenge` → receive e.g. `"Apples-a1b2c3d4"`
2. **Sign with passkey**: 
   - For `hashType: "keccak"`: Create personal_sign digest, sign with P256
   - For `hashType: "sha256"`: Hash challenge with SHA256, sign with P256
3. **Format signature**: Concatenate r + s + recid as hex (130 chars)
4. **Call API**: `checkGarageSigP256` with `sig` and optionally `hashType`
5. **Result**: `"pass"` if the derived address holds the NFT, else `"fail"`

## Signature Format

- **r**: 32 bytes, big-endian → 64 hex chars
- **s**: 32 bytes, big-endian → 64 hex chars  
- **recid**: 1 byte (0–3 for P256). If your library uses v=27/28 (Ethereum style), the ESP32 will normalize it.

## Address Derivation

The NFT must be held at the address derived from the P256 public key. Ensure your passkey wallet uses this derivation:

```
keccak256(0x04 || x || y)[12:32]
```

Where (x, y) are the 32-byte coordinates of the uncompressed P256 public key.

## Example (JavaScript / Web Crypto)

```javascript
// After getting challenge from getChallenge
const challenge = "Apples-a1b2c3d4";

// Option A: SHA256 hash (hashType: "sha256")
const msgBuffer = new TextEncoder().encode(challenge);
const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
// Sign hashBuffer with your passkey credential...

// Option B: Keccak personal_sign (hashType: "keccak" or omit)
const prefix = "\x19Ethereum Signed Message:\n" + challenge.length;
const fullMsg = prefix + challenge;
// Hash with keccak256, sign with P256...

// Format sig: r (hex) + s (hex) + recid (hex, 2 chars)
const sigHex = rHex + sHex + recidHex.padStart(2, '0');
```

## Libraries

- **webauthn-p256** (npm): P256 signing for WebAuthn
- **@noble/curves**: P256 operations
- **viem** / **ethers**: Keccak256, hex utilities
