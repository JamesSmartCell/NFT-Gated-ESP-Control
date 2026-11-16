/**
 * P256 signature verification and address derivation for passkey support.
 */

#include "P256Crypto.h"
#include "Util.h"
#include "Web3.h"
#include "Crypto.h"
#include "Trezor/nist256p1.h"
#include "Trezor/ecdsa.h"
#include "Trezor/sha3.h"
#include "mbedtls/sha256.h"
#include <string.h>
#include <vector>

// Use PERSONAL_MESSAGE_PREFIX from Crypto.h (Ethereum personal_sign prefix)

/**
 * Compute the digest that was signed (personal_sign format).
 * Exposed so main can try multiple recids.
 */
void P256PersonalMessageDigest(const std::string* message, uint8_t digest[32])
{
    std::string challengeStr = PERSONAL_MESSAGE_PREFIX;
    challengeStr += Util::toString((int)message->length());
    challengeStr += *message;
    Crypto::Keccak256((uint8_t*)challengeStr.c_str(), challengeStr.length(), digest);
}

std::string ECRecoverFromPersonalMessageP256(const std::string* signature, const std::string* message)
{
    uint8_t digest[32];
    std::string challengeStr = PERSONAL_MESSAGE_PREFIX;
    challengeStr += Util::toString((int)message->length());
    challengeStr += *message;
    Crypto::Keccak256((uint8_t*)challengeStr.c_str(), challengeStr.length(), digest);
    return ECRecoverFromHashP256(signature, digest);
}

std::string ECRecoverFromMessageP256_SHA256(const std::string* signature, const std::string* message)
{
    uint8_t digest[32];
    mbedtls_sha256((const unsigned char*)message->c_str(), message->length(), digest, 0);
    return ECRecoverFromHashP256(signature, digest);
}

std::string ECRecoverFromHashP256(const std::string* signature, const uint8_t* digest)
{
    // Signature: 65 bytes = r (32) + s (32) + recid (1)
    // Hex: 130 chars, optionally with 0x prefix
    const size_t sigLen = 65;
    const size_t hexLen = 130;

    if (signature->length() < hexLen) {
        return "";
    }

    const char* sigStr = signature->c_str();
    if (sigStr[0] == '0' && (sigStr[1] == 'x' || sigStr[1] == 'X')) {
        sigStr += 2;
    }

    uint8_t sigBytes[sigLen];
    Util::ConvertHexToBytes(sigBytes, sigStr, sigLen);

    // recid: last byte. For P256, typically 0-3
    int recid = sigBytes[64];
    if (recid > 26) recid -= 27;  // Handle Ethereum-style v (27/28)

    return ECRecoverFromHashP256WithRecid(sigBytes, digest, recid);
}

/**
 * Try recovery with a specific recid. Caller can loop recid 0-3 when wallet
 * sends wrong recid (webauthn-p256 doesn't provide it; wallet guesses 0).
 * sigBytes must be 65 bytes (r,s,recid); the recid byte is overwritten.
 */
std::string ECRecoverFromHashP256WithRecid(uint8_t* sigBytes, const uint8_t* digest, int recid)
{
    sigBytes[64] = (uint8_t)recid;
    uint8_t pubkey[65];
    int result = ecdsa_recover_pub_from_sig(&nist256p1, pubkey, sigBytes, digest, recid);
    if (result != 0) {
        return "";
    }
    return P256PublicKeyToAddress(pubkey);
}

/**
 * Try all recids 0-3 and return addresses that successfully recover.
 * Wallet sends recid 0 but webauthn-p256 may need 1, 2, or 3.
 */
std::vector<std::string> ECRecoverFromPersonalMessageP256AllRecids(const std::string* signature, const std::string* message)
{
    std::vector<std::string> addresses;
    const size_t sigLen = 65;
    const size_t hexLen = 130;

    if (signature->length() < hexLen) {
        return addresses;
    }

    const char* sigStr = signature->c_str();
    if (sigStr[0] == '0' && (sigStr[1] == 'x' || sigStr[1] == 'X')) {
        sigStr += 2;
    }

    uint8_t sigBytes[sigLen];
    Util::ConvertHexToBytes(sigBytes, sigStr, sigLen);

    uint8_t digest[32];
    P256PersonalMessageDigest(message, digest);

    for (int recid = 0; recid <= 3; recid++) {
        std::string addr = ECRecoverFromHashP256WithRecid(sigBytes, digest, recid);
        if (!addr.empty()) {
            addresses.push_back(addr);
        }
    }
    return addresses;
}

/**
 * WebAuthn: digest is SHA256(authenticatorData || SHA256(clientDataJSON)).
 * digestHex is 64 hex chars (32 bytes). Wallet passes it directly.
 */
std::vector<std::string> ECRecoverFromDigestP256AllRecids(const std::string* signature, const std::string* digestHex)
{
    std::vector<std::string> addresses;
    const size_t sigLen = 65;
    const size_t sigHexLen = 130;
    const size_t digestHexLen = 64;

    if (signature->length() < sigHexLen || digestHex->length() < digestHexLen) {
        return addresses;
    }

    const char* sigStr = signature->c_str();
    if (sigStr[0] == '0' && (sigStr[1] == 'x' || sigStr[1] == 'X')) {
        sigStr += 2;
    }

    const char* digStr = digestHex->c_str();
    if (digStr[0] == '0' && (digStr[1] == 'x' || digStr[1] == 'X')) {
        digStr += 2;
    }

    uint8_t sigBytes[sigLen];
    Util::ConvertHexToBytes(sigBytes, sigStr, sigLen);

    uint8_t digest[32];
    Util::ConvertHexToBytes(digest, digStr, 32);

    for (int recid = 0; recid <= 3; recid++) {
        std::string addr = ECRecoverFromHashP256WithRecid(sigBytes, digest, recid);
        if (!addr.empty()) {
            addresses.push_back(addr);
        }
    }
    return addresses;
}

std::string P256PublicKeyToAddress(const uint8_t* publicKey65)
{
    if (publicKey65[0] != 0x04) {
        return "";
    }
    // keccak256(x || y) - 64 bytes
    uint8_t hashed[32];
    keccak_256(publicKey65 + 1, 64, hashed);
    // Address = last 20 bytes
    return Util::ConvertBytesToHex(hashed + 12, 20);
}
