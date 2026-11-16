/**
 * P256 (secp256r1 / nist256p1) signature verification for passkey support.
 * 
 * Derives Ethereum address from P256 public key using:
 *   address = keccak256(pub_key_x || pub_key_y)[12:32]
 * 
 * This matches Tempo, webauthn-p256, and similar P256-to-address schemes.
 * For Coinbase Smart Wallet, the address is the smart contract address (CREATE2);
 * that derivation would require additional factory/salt logic.
 */

#ifndef P256_CRYPTO_H
#define P256_CRYPTO_H

#include <string>
#include <vector>

/**
 * Compute personal_sign digest for a message. Used when trying multiple recids.
 */
void P256PersonalMessageDigest(const std::string* message, uint8_t digest[32]);

/**
 * Recover Ethereum address from P256 signature over personal_sign format.
 * Same hash format as secp256k1: Keccak256("\x19Ethereum Signed Message:\n" + len + message)
 * 
 * @param signature Hex string: r (64 chars) + s (64 chars) + recid (2 chars) = 130 chars
 * @param message The challenge message (e.g. "Apples-1234abcd")
 * @return Recovered address as hex string (0x + 40 chars), or empty string on failure
 */
std::string ECRecoverFromPersonalMessageP256(const std::string* signature, const std::string* message);

/**
 * Recover Ethereum address from P256 signature over SHA256(message).
 * Use this when the passkey/WebAuthn signs SHA256 of the challenge (common for passkeys).
 * 
 * @param signature Hex string: r + s + recid (130 chars)
 * @param message The challenge message
 * @return Recovered address as hex string, or empty string on failure
 */
std::string ECRecoverFromMessageP256_SHA256(const std::string* signature, const std::string* message);

/**
 * Recover address from P256 signature when you have the digest directly.
 * 
 * @param signature Hex string: r + s + recid (130 chars)
 * @param digest 32-byte hash that was signed
 * @return Recovered address as hex string, or empty string on failure
 */
std::string ECRecoverFromHashP256(const std::string* signature, const uint8_t* digest);

/**
 * Recover with a specific recid. Try recids 0-3 when wallet sends wrong recid.
 * sigBytes is 65 bytes; recid byte will be overwritten.
 */
std::string ECRecoverFromHashP256WithRecid(uint8_t* sigBytes, const uint8_t* digest, int recid);

/**
 * Recover from WebAuthn format: digest is passed directly (SHA256 of authenticatorData||SHA256(clientDataJSON)).
 * digestHex is 64 hex chars (32 bytes).
 */
std::vector<std::string> ECRecoverFromDigestP256AllRecids(const std::string* signature, const std::string* digestHex);

/**
 * Try all recids 0-3; return all successfully recovered addresses.
 * Caller checks each for NFT balance.
 */
std::vector<std::string> ECRecoverFromPersonalMessageP256AllRecids(const std::string* signature, const std::string* message);

/**
 * Derive Ethereum address from P256 public key (uncompressed 65 bytes: 0x04 || x || y).
 * Formula: keccak256(pubkey[1:65])[12:32] - same as secp256k1 EOA derivation.
 */
std::string P256PublicKeyToAddress(const uint8_t* publicKey65);

#endif // P256_CRYPTO_H
