#include "web3e_flags.h"
#include <Arduino.h>
#include <stdint.h>

#include <ActionHandler.h>
#include "EEPROM.h"
#include <APIReturn.h>
#include "P256Crypto.h"

#include "esp_system.h"

#include <Web3.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <WiFiClientSecure.h>
#include <Update.h>
#include <HTTPClient.h>
#include <TcpBridge.h>
#include <WiFiConnection.h>
#include <WifiStore.h>
#include <WiFiDiagnostics.h>
#include <ArduinoJson.h>

#include <functional>
#include <string>
#include <vector>
#include <map>
#include <SPI.h>

// Include secrets (gitignored; see secrets.h.example)
#ifndef NO_SECRETS_FALLBACK
#include "secrets.h"
#else
#error "secrets.h is required unless -DNO_SECRETS_FALLBACK is defined"
#endif

// ===== FIRMWARE VERSION =====
// Format: <PROJECT_ID>@<semver>+<shorthash>
// Example: garagedoor@1.2.0+ab12cd3
#define FIRMWARE_SEMVER "1.2.0"

// GIT_SHORT_HASH is injected by git_version.py at build time
#ifndef GIT_SHORT_HASH
#define GIT_SHORT_HASH "unknown"
#endif

// PROJECT_ID is defined in platformio.ini build flags (default: "garagedoor")
#ifndef PROJECT_ID
#define PROJECT_ID "garagedoor"
#endif

#define FW_VERSION PROJECT_ID "@" FIRMWARE_SEMVER "+" GIT_SHORT_HASH

// ===== BUILD-TIME CONFIG =====
#ifndef PROXY_BASE_URL
#define PROXY_BASE_URL "https://scriptproxy.percolate.one"
#endif

// ===== HARDWARE PINS =====
#define RELAY_1 21
#define RELAY_2 22

// ===== OTA CONFIG =====
#define OTA_CHECK_INTERVAL_MS (24UL * 60 * 60 * 1000)  // 24 hours
#define OTA_RATE_LIMIT_MS 60000  // 60 seconds

// ===== API ROUTES =====
enum APIRoutes
{
  api_unknown,
  api_getChallenge,
  api_checkGarageDoor,
  api_checkGarageDoor2,
  api_checkGarageDoorP256,
  api_checkGarageDoorP256_2,
  api_updateReady,
  api_getVersion,
  api_end
};

std::map<std::string, APIRoutes> s_apiRoutes;
ActionHandler* actionHandler;

// ===== GLOBALS =====
Web3* web3;
KeyID* keyID;
TcpBridge* tcpConnection;
WifiStore wifiStore;
WiFiConnection wifiConnection;

const char* seedWords[] = { "Apples", "Oranges", "Grapes", "DragonFruit", "BreadFruit", 
                             "Pomegranate", "Aubergine", "Fungi", "Falafel", "Cryptokitty", 
                             "Kookaburra", "Elvis", "Koala", nullptr };

const char* adminAddrs[] = { ADMIN_ADDRESS_1, ADMIN_ADDRESS_2 };
const int adminAddrsSz = 2;

string currentChallenge;
unsigned long lastOTACheck = 0;
unsigned long lastOTARequest = 0;
bool lastOTARequestInitialized = false;
static volatile bool otaCheckRequested = false;

// OTA failure tracking (prevent retry of failed versions within 24h)
struct OTAFailure {
  char version[64];
  unsigned long timestamp;
};
OTAFailure lastOTAFailure = {"", 0};
#define OTA_FAILURE_RETRY_INTERVAL_MS (24UL * 60 * 60 * 1000)  // 24 hours

// ===== FORWARD DECLARATIONS =====
void updateChallenge();
void startGarageOpen(int openSeconds);
void operateGarageDoor();
bool checkForUpdate();
void performOTA(const char* firmwareUrl, const char* expectedSha256, size_t expectedSize, const char* versionStr = nullptr);
bool writeWifiStoreFromSecrets();

// ===== UTILITY FUNCTIONS =====
bool equalsIgnoreCase(const string& a, const string& b)
{
    unsigned int sz = a.size();
    if (b.size() != sz)
        return false;
    for (unsigned int i = 0; i < sz; ++i)
        if (tolower(a[i]) != tolower(b[i]))
            return false;
    return true;
}

bool checkAdmin(std::string* userAddress)
{
  for (int i = 0; i < adminAddrsSz; i++)
  {
    if (equalsIgnoreCase(*userAddress, adminAddrs[i]))
    {
      return true;
    }
  }
  return false;
}

bool QueryBalance(const char* contractAddr, std::string* userAddress)
{
  if (checkAdmin(userAddress))
  {
    Serial.println("Is admin");
    return true;
  }
  
  bool hasToken = false;
  Contract contract(web3, contractAddr);
  string func = "balanceOf(address)";
  string param = contract.SetupContractData(func.c_str(), userAddress);
  string result = contract.ViewCall(&param);

  Serial.println(result.c_str());

  uint256_t baseBalance = web3->getUint256(&result);

  if (baseBalance > 0)
  {
    hasToken = true;
    Serial.println("Has token");
  }

  return hasToken;
}

// ===== OTA UPDATE FUNCTIONS =====

/**
 * Parse semver string and extract MAJOR.MINOR.PATCH
 * Handles formats: "1.2.0", "v1.2.0", "1.2.0+hash", "project@1.2.0+hash"
 * Returns true if parsed successfully
 */
bool parseSemver(const char* versionStr, int& major, int& minor, int& patch, char* projectId = nullptr)
{
  if (!versionStr || strlen(versionStr) == 0)
    return false;
  
  const char* semverStart = versionStr;
  
  // Check for project prefix "project@"
  const char* atSign = strchr(versionStr, '@');
  if (atSign)
  {
    if (projectId)
    {
      size_t projectLen = atSign - versionStr;
      if (projectLen >= 32) return false;  // Project ID too long
      strncpy(projectId, versionStr, projectLen);
      projectId[projectLen] = '\0';
    }
    semverStart = atSign + 1;
  }
  else if (projectId)
  {
    projectId[0] = '\0';  // No project prefix
  }
  
  // Skip optional 'v' prefix
  if (semverStart[0] == 'v' || semverStart[0] == 'V')
    semverStart++;
  
  // Parse MAJOR.MINOR.PATCH
  char* end;
  major = strtol(semverStart, &end, 10);
  if (*end != '.') return false;
  
  minor = strtol(end + 1, &end, 10);
  if (*end != '.') return false;
  
  patch = strtol(end + 1, &end, 10);
  
  // End should be '\0', '+' (build metadata), or '-' (prerelease)
  if (*end != '\0' && *end != '+' && *end != '-')
    return false;
  
  return true;
}

/**
 * Compare two semver versions
 * Returns: -1 if v1 < v2, 0 if equal, 1 if v1 > v2
 */
int compareSemver(int major1, int minor1, int patch1, int major2, int minor2, int patch2)
{
  if (major1 != major2) return (major1 > major2) ? 1 : -1;
  if (minor1 != minor2) return (minor1 > minor2) ? 1 : -1;
  if (patch1 != patch2) return (patch1 > patch2) ? 1 : -1;
  return 0;
}

/**
 * Check for firmware updates from SmartLayerProxy
 * Returns true if update was initiated
 */
bool checkForUpdate()
{
  Serial.println("[OTA] Checking for firmware updates...");
  
  WiFiClientSecure client;
  client.setInsecure();
  HTTPClient http;
  
  String url = String(PROXY_BASE_URL) + "/api/firmware/" + PROJECT_ID + "/latest";
  Serial.printf("[OTA] Fetching metadata: %s\n", url.c_str());
  
  if (!http.begin(client, url))
  {
    Serial.println("[OTA] Failed to begin HTTP request");
    return false;
  }
  
  http.setTimeout(10000);
  int httpCode = http.GET();
  
  if (httpCode != HTTP_CODE_OK)
  {
    Serial.printf("[OTA] HTTP error: %d\n", httpCode);
    http.end();
    return false;
  }
  
  String payload = http.getString();
  http.end();
  
  Serial.printf("[OTA] Response: %s\n", payload.c_str());
  
  // Parse JSON response
  JsonDocument doc;
  DeserializationError error = deserializeJson(doc, payload);
  
  if (error)
  {
    Serial.printf("[OTA] JSON parse error: %s\n", error.c_str());
    return false;
  }
  
  const char* newVersion = doc["version"];
  const char* firmwareUrl = doc["url"];
  const char* sha256 = doc["sha256"];
  size_t size = doc["size"];
  
  if (!newVersion || !firmwareUrl || !sha256 || size == 0)
  {
    Serial.println("[OTA] Missing required metadata fields");
    return false;
  }
  
  Serial.printf("[OTA] Current: %s, Available: %s\n", FW_VERSION, newVersion);
  
  // Parse current version (from FIRMWARE_SEMVER)
  int currentMajor, currentMinor, currentPatch;
  if (!parseSemver(FIRMWARE_SEMVER, currentMajor, currentMinor, currentPatch))
  {
    Serial.printf("[OTA] ERROR: Failed to parse current version: %s\n", FIRMWARE_SEMVER);
    return false;
  }
  
  // Parse available version from proxy
  int newMajor, newMinor, newPatch;
  char newProjectId[32];
  if (!parseSemver(newVersion, newMajor, newMinor, newPatch, newProjectId))
  {
    Serial.printf("[OTA] ERROR: Failed to parse available version: %s\n", newVersion);
    return false;
  }
  
  // Validate project ID if present in metadata
  if (strlen(newProjectId) > 0 && strcmp(newProjectId, PROJECT_ID) != 0)
  {
    Serial.printf("[OTA] ERROR: Project ID mismatch: expected '%s', got '%s'\n", PROJECT_ID, newProjectId);
    return false;
  }
  
  // Compare versions
  int cmp = compareSemver(newMajor, newMinor, newPatch, currentMajor, currentMinor, currentPatch);
  
  Serial.printf("[OTA] Version comparison: current=%d.%d.%d, available=%d.%d.%d, cmp=%d\n",
                currentMajor, currentMinor, currentPatch,
                newMajor, newMinor, newPatch, cmp);
  
  if (cmp <= 0)
  {
    if (cmp == 0)
      Serial.println("[OTA] Already running this version (or newer with different build metadata)");
    else
      Serial.printf("[OTA] Available version is OLDER than current (downgrade blocked)\n");
    return false;
  }
  
  // Check if this version failed recently (within 24h)
  if (strlen(lastOTAFailure.version) > 0 &&
      strcmp(lastOTAFailure.version, newVersion) == 0 &&
      (millis() - lastOTAFailure.timestamp) < OTA_FAILURE_RETRY_INTERVAL_MS)
  {
    unsigned long remainingMs = OTA_FAILURE_RETRY_INTERVAL_MS - (millis() - lastOTAFailure.timestamp);
    Serial.printf("[OTA] Version %s failed recently, retry blocked for %lu more seconds\n",
                  newVersion, remainingMs / 1000);
    return false;
  }
  
  Serial.printf("[OTA] Update available: %s -> %s\n", FW_VERSION, newVersion);
  Serial.printf("[OTA] URL: %s\n", firmwareUrl);
  Serial.printf("[OTA] SHA256: %s\n", sha256);
  Serial.printf("[OTA] Size: %zu bytes\n", size);
  
  // Perform OTA update
  performOTA(firmwareUrl, sha256, size, newVersion);
  
  return true;
}

/**
 * Download and install firmware with SHA-256 verification
 */
void performOTA(const char* firmwareUrl, const char* expectedSha256, size_t expectedSize, const char* versionStr)
{
  Serial.println("[OTA] Starting firmware download...");
  
  // Note: Startup watchdog should be disarmed by this point (after successful connection)
  // OTA will complete within reasonable time or fail and restart
  
  WiFiClientSecure client;
  client.setInsecure();
  HTTPClient http;
  
  if (!http.begin(client, firmwareUrl))
  {
    Serial.println("[OTA] Failed to begin firmware download");
    return;
  }
  
  http.setTimeout(60000);  // 1 minute for download
  int httpCode = http.GET();
  
  if (httpCode != HTTP_CODE_OK)
  {
    Serial.printf("[OTA] Download failed: HTTP %d\n", httpCode);
    http.end();
    return;
  }
  
  size_t contentLength = http.getSize();
  Serial.printf("[OTA] Content-Length: %zu bytes\n", contentLength);
  
  if (contentLength != expectedSize)
  {
    Serial.printf("[OTA] Size mismatch: expected %zu, got %zu\n", expectedSize, contentLength);
    http.end();
    
    // Track failure
    if (versionStr && strlen(versionStr) < sizeof(lastOTAFailure.version))
    {
      strncpy(lastOTAFailure.version, versionStr, sizeof(lastOTAFailure.version) - 1);
      lastOTAFailure.version[sizeof(lastOTAFailure.version) - 1] = '\0';
      lastOTAFailure.timestamp = millis();
    }
    return;
  }
  
  if (!Update.begin(contentLength))
  {
    Serial.printf("[OTA] Not enough space for update: %s\n", Update.errorString());
    http.end();
    return;
  }
  
  // Stream download and compute SHA-256
  WiFiClient* stream = http.getStreamPtr();
  uint8_t buff[512];
  size_t bytesRead = 0;
  
  // Initialize SHA-256
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
  mbedtls_md_starts(&ctx);
  
  Serial.println("[OTA] Downloading and verifying...");
  
  while (http.connected() && bytesRead < contentLength)
  {
    size_t available = stream->available();
    if (available)
    {
      size_t toRead = min(available, sizeof(buff));
      size_t read = stream->readBytes(buff, toRead);
      
      if (read > 0)
      {
        // Write to Update partition
        if (Update.write(buff, read) != read)
        {
          Serial.println("[OTA] Write failed");
          Update.abort();
          mbedtls_md_free(&ctx);
          http.end();
          return;
        }
        
        // Update SHA-256
        mbedtls_md_update(&ctx, buff, read);
        bytesRead += read;
        
        if (bytesRead % 10240 == 0)
        {
          Serial.printf("[OTA] Progress: %zu / %zu bytes\n", bytesRead, contentLength);
        }
      }
    }
    else
    {
      delay(10);
    }
  }
  
  http.end();
  
  Serial.printf("[OTA] Download complete: %zu bytes\n", bytesRead);
  
  // Finalize SHA-256
  uint8_t hash[32];
  mbedtls_md_finish(&ctx, hash);
  mbedtls_md_free(&ctx);
  
  // Convert hash to hex string
  char hashStr[65];
  for (int i = 0; i < 32; i++)
  {
    sprintf(&hashStr[i * 2], "%02x", hash[i]);
  }
  hashStr[64] = '\0';
  
  Serial.printf("[OTA] Computed SHA256: %s\n", hashStr);
  Serial.printf("[OTA] Expected SHA256: %s\n", expectedSha256);
  
  // Verify SHA-256
  if (strcasecmp(hashStr, expectedSha256) != 0)
  {
    Serial.println("[OTA] SHA-256 verification FAILED!");
    Update.abort();
    
    // Track failure
    if (versionStr && strlen(versionStr) < sizeof(lastOTAFailure.version))
    {
      strncpy(lastOTAFailure.version, versionStr, sizeof(lastOTAFailure.version) - 1);
      lastOTAFailure.version[sizeof(lastOTAFailure.version) - 1] = '\0';
      lastOTAFailure.timestamp = millis();
    }
    return;
  }
  
  Serial.println("[OTA] SHA-256 verification PASSED");
  
  // Verify size
  if (bytesRead != expectedSize)
  {
    Serial.printf("[OTA] Size verification FAILED: got %zu, expected %zu\n", bytesRead, expectedSize);
    Update.abort();
    return;
  }
  
  // Finalize update
  if (!Update.end(true))
  {
    Serial.printf("[OTA] Update.end() failed: %s\n", Update.errorString());
    return;
  }
  
  Serial.println("[OTA] Update successful! Rebooting...");
  delay(2000);
  ESP.restart();
}

// ===== WIFI STORE MIGRATION =====

/**
 * Write compile-time Wi-Fi credentials from secrets.h to WifiStore
 * This enables migration from hardcoded credentials to EEPROM-based storage
 */
bool writeWifiStoreFromSecrets()
{
  Serial.println("[WiFi] Writing fallback credentials to WifiStore...");
  
  // Prepare credentials array from secrets.h
  struct FallbackCred {
    const char* ssid;
    const char* password;
  };
  
  FallbackCred fallbackCreds[] = {
    {WIFI_SSID_1, WIFI_PASSWORD_1},
    {WIFI_SSID_2, WIFI_PASSWORD_2},
    {WIFI_SSID_3, WIFI_PASSWORD_3},
    {WIFI_SSID_4, WIFI_PASSWORD_4},
  };
  
  int count = sizeof(fallbackCreds) / sizeof(fallbackCreds[0]);
  
  // Remove duplicates and validate
  int validCount = 0;
  for (int i = 0; i < count; i++)
  {
    if (strlen(fallbackCreds[i].ssid) == 0)
      continue;
    
    // Check for duplicate SSIDs
    bool isDuplicate = false;
    for (int j = 0; j < i; j++)
    {
      if (strcmp(fallbackCreds[i].ssid, fallbackCreds[j].ssid) == 0 &&
          strcmp(fallbackCreds[i].password, fallbackCreds[j].password) == 0)
      {
        isDuplicate = true;
        break;
      }
    }
    
    if (!isDuplicate)
    {
      validCount++;
    }
  }
  
  if (validCount == 0)
  {
    Serial.println("[WiFi] No valid fallback credentials");
    return false;
  }
  
  // Build WifiStore data structure
  int offset = WIFI_EEPROM_OFFSET;
  
  // Write magic
  EEPROM.write(offset++, 'W');
  EEPROM.write(offset++, 'I');
  EEPROM.write(offset++, 'F');
  EEPROM.write(offset++, 'I');
  
  // Write version
  EEPROM.write(offset++, 1);
  
  int dataStart = WIFI_EEPROM_OFFSET;
  
  // Write credentials (deduplicated)
  for (int i = 0; i < count; i++)
  {
    if (strlen(fallbackCreds[i].ssid) == 0)
      continue;
    
    // Check for duplicate
    bool isDuplicate = false;
    for (int j = 0; j < i; j++)
    {
      if (strcmp(fallbackCreds[i].ssid, fallbackCreds[j].ssid) == 0 &&
          strcmp(fallbackCreds[i].password, fallbackCreds[j].password) == 0)
      {
        isDuplicate = true;
        break;
      }
    }
    
    if (isDuplicate)
      continue;
    
    uint8_t ssidLen = strlen(fallbackCreds[i].ssid);
    uint8_t pwLen = strlen(fallbackCreds[i].password);
    
    if (ssidLen > MAX_SSID_LENGTH || pwLen > MAX_PASSWORD_LENGTH)
    {
      Serial.printf("[WiFi] Skipping oversized credential: %s\n", fallbackCreds[i].ssid);
      continue;
    }
    
    EEPROM.write(offset++, ssidLen);
    for (int k = 0; k < ssidLen; k++)
    {
      EEPROM.write(offset++, fallbackCreds[i].ssid[k]);
    }
    
    EEPROM.write(offset++, pwLen);
    for (int k = 0; k < pwLen; k++)
    {
      EEPROM.write(offset++, fallbackCreds[i].password[k]);
    }
  }
  
  // Write terminator
  EEPROM.write(offset++, 0x00);
  EEPROM.write(offset++, 0x00);
  
  int dataEnd = offset;
  int dataLen = dataEnd - dataStart;
  
  // Calculate CRC32
  uint8_t* dataBuffer = new uint8_t[dataLen];
  for (int i = 0; i < dataLen; i++)
  {
    dataBuffer[i] = EEPROM.read(dataStart + i);
  }
  
  // CRC32 (same algorithm as WifiStore)
  uint32_t crc = 0xFFFFFFFF;
  const uint32_t crc32_table[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
  };
  
  for (int i = 0; i < dataLen; i++)
  {
    crc = crc32_table[(crc ^ dataBuffer[i]) & 0xFF] ^ (crc >> 8);
  }
  crc = ~crc;
  
  delete[] dataBuffer;
  
  // Write CRC (little-endian)
  EEPROM.write(offset++, crc & 0xFF);
  EEPROM.write(offset++, (crc >> 8) & 0xFF);
  EEPROM.write(offset++, (crc >> 16) & 0xFF);
  EEPROM.write(offset++, (crc >> 24) & 0xFF);
  
  // Commit to EEPROM
  if (!EEPROM.commit())
  {
    Serial.println("[WiFi] EEPROM commit failed");
    return false;
  }
  
  Serial.printf("[WiFi] Wrote %d networks to WifiStore (CRC32: 0x%08lX)\n", validCount, (unsigned long)crc);
  return true;
}

// ===== API HANDLERS =====

void Initialize()
{
  s_apiRoutes["getChallenge"] = api_getChallenge;
  s_apiRoutes["checkGarageSig"] = api_checkGarageDoor;
  s_apiRoutes["checkGarageSig2"] = api_checkGarageDoor2;
  s_apiRoutes["checkGarageSigP256"] = api_checkGarageDoorP256;
  s_apiRoutes["checkGarageSigP256_2"] = api_checkGarageDoorP256_2;
  s_apiRoutes["updateReady"] = api_updateReady;
  s_apiRoutes["getVersion"] = api_getVersion;
  s_apiRoutes["end"] = api_end;
}

std::string handleTCPAPI(APIReturn* apiReturn)
{
  Serial.print("ESP Free Heap: ");
  Serial.println(ESP.getFreeHeap());
  Serial.print("ESP Max alloc Heap: ");
  Serial.println(ESP.getMaxAllocHeap());

  Serial.println(apiReturn->apiName.c_str());
  string address;

  switch (s_apiRoutes[apiReturn->apiName])
  {
  case api_getChallenge:
    Serial.println(currentChallenge.c_str());
    return currentChallenge;
    
  case api_getVersion:
    Serial.printf("Firmware: %s\n", FW_VERSION);
    return string(FW_VERSION);
    
  case api_checkGarageDoor:
  {
    Serial.print("Sig: ");
    Serial.println(apiReturn->params["sig"].c_str());
    address = Crypto::ECRecoverFromPersonalMessage(&apiReturn->params["sig"], &currentChallenge);
    int unlockSeconds = strtol(apiReturn->params["openTime"].c_str(), NULL, 10);
    Serial.print("EC-Addr: ");
    Serial.println(address.c_str());
    boolean hasToken = QueryBalance(DOOR_CONTRACT_ADDRESS, &address);
    updateChallenge();
    if (hasToken)
    {
      startGarageOpen(unlockSeconds);
      return string("pass");
    }
    else
    {
      return string("fail");
    }
  }
  break;
  
  case api_checkGarageDoor2:
  {
    Serial.print("Sig: ");
    Serial.println(apiReturn->params["sig"].c_str());
    address = Crypto::ECRecoverFromPersonalMessage(&apiReturn->params["sig"], &currentChallenge);
    Serial.print("EC-Addr: ");
    Serial.println(address.c_str());
    boolean hasToken = QueryBalance(DOOR_CONTRACT_ADDRESS, &address);
    updateChallenge();
    if (hasToken)
    {
      startGarageOpen(-1);
      return string("pass");
    }
    else
    {
      return string("fail");
    }
  }
  break;
  
  case api_checkGarageDoorP256:
  {
    Serial.print("P256 Sig: ");
    Serial.println(apiReturn->params["sig"].c_str());
    std::string hashType = apiReturn->params.count("hashType") ? apiReturn->params["hashType"] : "keccak";
    std::vector<std::string> addresses;
    if (hashType == "webauthn" && apiReturn->params.count("digest")) {
      addresses = ECRecoverFromDigestP256AllRecids(&apiReturn->params["sig"], &apiReturn->params["digest"]);
    } else if (hashType == "sha256") {
      address = ECRecoverFromMessageP256_SHA256(&apiReturn->params["sig"], &currentChallenge);
      if (!address.empty()) addresses.push_back(address);
    } else {
      addresses = ECRecoverFromPersonalMessageP256AllRecids(&apiReturn->params["sig"], &currentChallenge);
    }
    boolean hasToken = false;
    for (size_t i = 0; i < addresses.size(); i++) {
      address = addresses[i];
      Serial.print("P256-Addr[");
      Serial.print((int)i);
      Serial.print("]: ");
      Serial.println(address.c_str());
      if (QueryBalance(DOOR_CONTRACT_ADDRESS, &address)) {
        hasToken = true;
        break;
      }
    }
    updateChallenge();
    if (hasToken)
    {
      startGarageOpen(20);
      return string("pass");
    }
    else
    {
      return string("fail");
    }
  }
  break;
  
  case api_checkGarageDoorP256_2:
  {
    Serial.print("P256 Sig: ");
    Serial.println(apiReturn->params["sig"].c_str());
    std::string hashType = apiReturn->params.count("hashType") ? apiReturn->params["hashType"] : "keccak";
    std::vector<std::string> addresses;
    if (hashType == "webauthn" && apiReturn->params.count("digest")) {
      addresses = ECRecoverFromDigestP256AllRecids(&apiReturn->params["sig"], &apiReturn->params["digest"]);
    } else if (hashType == "sha256") {
      address = ECRecoverFromMessageP256_SHA256(&apiReturn->params["sig"], &currentChallenge);
      if (!address.empty()) addresses.push_back(address);
    } else {
      addresses = ECRecoverFromPersonalMessageP256AllRecids(&apiReturn->params["sig"], &currentChallenge);
    }
    boolean hasToken = false;
    for (size_t i = 0; i < addresses.size(); i++) {
      address = addresses[i];
      Serial.print("P256-Addr[");
      Serial.print((int)i);
      Serial.print("]: ");
      Serial.println(address.c_str());
      if (QueryBalance(DOOR_CONTRACT_ADDRESS, &address)) {
        hasToken = true;
        break;
      }
    }
    updateChallenge();
    if (hasToken)
    {
      startGarageOpen(-1);
      return string("pass");
    }
    else
    {
      return string("fail");
    }
  }
  break;
  
  case api_updateReady:
  {
    // New unauthenticated OTA trigger (proxy pushes notification)
    // Rate limited to once per 60 seconds (but first request always accepted)
    unsigned long now = millis();
    if (lastOTARequestInitialized && (now - lastOTARequest < OTA_RATE_LIMIT_MS))
    {
      Serial.printf("[OTA] Rate limited (last request %lu ms ago)\n", now - lastOTARequest);
      return string("rate_limited");
    }
    
    lastOTARequest = now;
    lastOTARequestInitialized = true;
    Serial.println("[OTA] Update notification received from proxy");
    
    // Request OTA check in loop() (non-blocking response)
    otaCheckRequested = true;
    
    return string("checking");
  }
  break;
  
  case api_unknown:
    break;
  case api_end:
    break;
  }

  return string("");
}

// ===== SETUP =====

void setup()
{
  Serial.begin(115200);
  delay(2000);
  Serial.println("=== ESP32 GARAGE DOOR CONTROLLER ===");
  Serial.printf("Firmware: %s\n", FW_VERSION);
  Serial.printf("Reset reason: %d\n", (int)esp_reset_reason());
  
  // Arm startup watchdog (covers WiFi and TCP connect)
  TcpBridge::armStartupWatchdog();
  delay(2000);
  
  Initialize();
  delay(100);
  
  // ===== WIFI SETUP =====
  // Try WifiStore first, fallback to secrets.h, then write to EEPROM
  
  if (!wifiStore.begin())
  {
    Serial.println("[WiFi] WifiStore init failed");
    ESP.restart();
  }
  
  WifiCredential storedCreds[MAX_WIFI_NETWORKS];
  int networkCount = 0;
  bool wifiStoreValid = wifiStore.isValid();
  
  if (wifiStoreValid)
  {
    networkCount = wifiStore.readNetworks(storedCreds, MAX_WIFI_NETWORKS);
    Serial.printf("[WiFi] Loaded %d networks from WifiStore\n", networkCount);
  }
  else
  {
    Serial.println("[WiFi] WifiStore empty/invalid, using fallback credentials");
  }
  
  // Convert to WiFiCredentials array
  WiFiCredentials wifiNetworks[MAX_WIFI_NETWORKS + 1];
  
  if (networkCount > 0)
  {
    for (int i = 0; i < networkCount; i++)
    {
      wifiNetworks[i].ssid = storedCreds[i].ssid;
      wifiNetworks[i].password = storedCreds[i].password;
    }
    wifiNetworks[networkCount].ssid = nullptr;
    wifiNetworks[networkCount].password = nullptr;
  }
  else
  {
    // Use fallback from secrets.h
    wifiNetworks[0].ssid = WIFI_SSID_1;
    wifiNetworks[0].password = WIFI_PASSWORD_1;
    wifiNetworks[1].ssid = WIFI_SSID_2;
    wifiNetworks[1].password = WIFI_PASSWORD_2;
    wifiNetworks[2].ssid = WIFI_SSID_3;
    wifiNetworks[2].password = WIFI_PASSWORD_3;
    wifiNetworks[3].ssid = WIFI_SSID_4;
    wifiNetworks[3].password = WIFI_PASSWORD_4;
    wifiNetworks[4].ssid = nullptr;
    wifiNetworks[4].password = nullptr;
  }
  
  // Connect to WiFi
  wifiConnection.setupWifi(wifiNetworks);
  
  if (WiFi.status() != WL_CONNECTED)
  {
    Serial.println("[WiFi] Failed to connect, restarting...");
    delay(5000);
    ESP.restart();
  }
  
  Serial.printf("[WiFi] Connected to: %s\n", WiFi.SSID().c_str());
  Serial.printf("[WiFi] IP Address: %s\n", WiFi.localIP().toString().c_str());
  
  // MIGRATION: If WifiStore was invalid/empty, write fallback creds to it
  if (!wifiStoreValid && networkCount == 0)
  {
    Serial.println("[WiFi] Migrating: Writing fallback credentials to WifiStore...");
    if (writeWifiStoreFromSecrets())
    {
      Serial.println("[WiFi] Migration complete - future boots will use WifiStore");
    }
    else
    {
      Serial.println("[WiFi] Migration failed - will retry on next boot");
    }
  }
  
  // ===== WEB3 INITIALIZATION =====
  actionHandler = new ActionHandler(6);
  web3 = new Web3(BASE_SEPOLIA_ID);
  Serial.print("Init web3");

  keyID = new KeyID(web3);
  Serial.print("Got key");
  updateChallenge();
  Serial.print("Challenge set");

  // ===== RELAY SETUP =====
  pinMode(RELAY_1, OUTPUT);
  pinMode(RELAY_2, OUTPUT);
  digitalWrite(RELAY_1, HIGH);
  digitalWrite(RELAY_2, HIGH);

  // ===== TCP BRIDGE SETUP =====
  tcpConnection = new TcpBridge();
  tcpConnection->setFirmwareVersion(FW_VERSION);
  tcpConnection->setWiFiDiagnostics(wifiConnection.getDiagnostics());
  tcpConnection->setKey(keyID, web3);
  tcpConnection->startConnection();
  
  Serial.println("[Setup] Complete");
  
  // Check for OTA update after connecting
  Serial.println("[OTA] Checking for updates at boot...");
  checkForUpdate();
  lastOTACheck = millis();
}

// ===== MAIN LOOP =====

void loop()
{
  long currentMillis = millis();
  
  // Handle scheduled actions
  actionHandler->CheckEvents(currentMillis);
  
  // Maintain WiFi connection
  wifiConnection.setupWifi(nullptr);
  
  // Handle TCP API
  tcpConnection->checkClientAPI(&handleTCPAPI);
  
  // Check if OTA update was requested via updateReady API
  if (otaCheckRequested)
  {
    otaCheckRequested = false;
    Serial.println("[OTA] Notified update check");
    checkForUpdate();
    lastOTACheck = currentMillis;
  }
  
  // Periodic OTA check (every 24 hours)
  if (currentMillis - lastOTACheck >= OTA_CHECK_INTERVAL_MS)
  {
    Serial.println("[OTA] Periodic update check (24h)");
    checkForUpdate();
    lastOTACheck = currentMillis;
  }

  delay(100);
}

// ===== DOOR CONTROL FUNCTIONS =====

void operateGarageDoor()
{
  digitalWrite(RELAY_1, LOW);
  delay(1500);
  digitalWrite(RELAY_1, HIGH);
}

void operateInteriorDoor()
{
  digitalWrite(RELAY_2, LOW);
  actionHandler->AddEventAfter(10000, RELAY_2, HIGH);
}

void startGarageOpen(int openSeconds)
{
  operateGarageDoor();

  if (openSeconds > 0)
  {
    actionHandler->AddCallback(openSeconds * 1000, &operateGarageDoor);
  }

  actionHandler->AddCallback(15*1000, &operateInteriorDoor);
}

void updateChallenge()
{
  int size = 0;
  while (seedWords[size] != nullptr)
    size++;
  char buffer[32];

  int seedIndex = random(0, size);
  currentChallenge = seedWords[seedIndex];
  currentChallenge += "-";
  long challengeVal = random32();
  currentChallenge += itoa(challengeVal, buffer, 16);

  Serial.print("Challenge: ");
  Serial.println(currentChallenge.c_str());
}
