#include "web3e_flags.h"
#include <Arduino.h>
#include <stdint.h>

#include <ActionHandler.h>
#include "EEPROM.h"
#include <APIReturn.h>
#include "P256Crypto.h"

#include "esp_system.h"
#include "esp_task_wdt.h"
#include <mbedtls/md.h>

#include <Web3.h>
#include <KeyID.h>
#include <UniversalNode.h>
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
#include <Preferences.h>

#define WEB3E_WIFI_PORTAL
#include <Web3EWifiPortal.h>

#include <functional>
#include <string>
#include <vector>
#include <map>
#include <SPI.h>
#include <ctype.h>

// Include secrets (gitignored; see secrets.h.example)
#ifndef NO_SECRETS_FALLBACK
#include "secrets.h"
#else
#error "secrets.h is required unless -DNO_SECRETS_FALLBACK is defined"
#endif

// ===== FIRMWARE VERSION =====
// Format: <PROJECT_ID>@<semver>+<shorthash>
// Example: garagedoor@1.2.0+ab12cd3
#define FIRMWARE_SEMVER "1.2.9"

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
UniversalNode* uninode;
TcpBridge* tcpConnection;
WifiStore wifiStore;
WiFiConnection wifiConnection;
Web3EWifiPortal wifiPortal;

// Store WiFi networks for reconnect (Bug #1 fix)
static WiFiCredentials savedWifiNetworks[MAX_WIFI_NETWORKS + 1];

// Revoke notice → install setup firmware (processed from loop after updateReady)
// Contract: SmartLayerProxy docs/firmware-ota.md + PR #16
static volatile bool revokeRequested = false;
static char pendingRevokeSha256[65] = {0};
static char pendingRevokeVersion[32] = {0};
static size_t pendingRevokeSize = 0;

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

// ===== SCAN RESULT STATES =====
enum ScanResult {
  SCAN_NONE_OR_FAILED = 0,  // 0 networks or scan failed — don't accumulate or reset
  SCAN_KNOWN_SEEN = 1,      // Known SSID visible — reset timeout
  SCAN_ONLY_UNKNOWN = 2     // Networks visible but no known SSID — accumulate timeout
};

// ===== FORWARD DECLARATIONS =====
void updateChallenge();
void startGarageOpen(int openSeconds);
void operateGarageDoor();
bool checkForUpdate();
void performOTA(const char* firmwareUrl, const char* expectedSha256, size_t expectedSize, const char* versionStr = nullptr);
bool writeWifiStoreFromSecrets();
void armMainLoopWatchdog();
bool validateAndQueueRevoke(APIReturn* apiReturn);
bool installSetupFirmwareFromNotice();
void runOfflinePortalAndReboot();
static string normalizeAddress(const string& addr);
static bool parseRevokeMessage(const string& message, string& project, string& device,
                               string& sha256, string& nonce);
bool isWifiEverValidated();
void setWifiEverValidated();
ScanResult scanForKnownSSID(WiFiCredentials* networks);

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
    // Extended OTA notify channel (SmartLayerProxy):
    //   - no args / purpose absent → normal app OTA check → "checking"
    //   - purpose=revoke → admin-signed setup OTA → must reply "revoking"
    const string purpose = apiReturn->params.count("purpose")
                               ? apiReturn->params["purpose"]
                               : string("");

    if (purpose == "revoke")
    {
      Serial.println("[Revoke] Admin-signed revoke notice received");
      if (!validateAndQueueRevoke(apiReturn))
      {
        Serial.println("[Revoke] Notice rejected");
        return string("revoke_rejected");
      }
      // Required ack before stay_portal + setup OTA (proxy marks acknowledged)
      revokeRequested = true;
      return string("revoking");
    }

    // Normal OTA trigger — rate limited to once per 60 seconds
    unsigned long now = millis();
    if (lastOTARequestInitialized && (now - lastOTARequest < OTA_RATE_LIMIT_MS))
    {
      Serial.printf("[OTA] Rate limited (last request %lu ms ago)\n", now - lastOTARequest);
      return string("rate_limited");
    }

    lastOTARequest = now;
    lastOTARequestInitialized = true;
    Serial.println("[OTA] Update notification received from proxy");
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

// ===== REVOKE / PORTAL / WDT HELPERS =====

static string normalizeAddress(const string& addr)
{
  string hex = addr;
  if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
    hex = hex.substr(2);
  for (size_t i = 0; i < hex.size(); i++)
    hex[i] = (char)tolower((unsigned char)hex[i]);
  return string("0x") + hex;
}

static bool parseRevokeMessage(const string& message, string& project, string& device,
                               string& sha256, string& nonce)
{
  // revoke:<project>:<device>:<sha256>:<nonce>
  if (message.size() < 7 || message.compare(0, 7, "revoke:") != 0)
    return false;

  size_t p1 = message.find(':', 7);
  if (p1 == string::npos)
    return false;
  size_t p2 = message.find(':', p1 + 1);
  if (p2 == string::npos)
    return false;
  size_t p3 = message.find(':', p2 + 1);
  if (p3 == string::npos)
    return false;

  project = message.substr(7, p1 - 7);
  device = message.substr(p1 + 1, p2 - p1 - 1);
  sha256 = message.substr(p2 + 1, p3 - p2 - 1);
  nonce = message.substr(p3 + 1);

  if (project.empty() || device.empty() || sha256.size() != 64 || nonce.size() != 64)
    return false;
  return true;
}

bool validateAndQueueRevoke(APIReturn* apiReturn)
{
  if (!apiReturn || !keyID)
    return false;

  const string version = apiReturn->params.count("version") ? apiReturn->params["version"] : "";
  const string sha256 = apiReturn->params.count("sha256") ? apiReturn->params["sha256"] : "";
  const string sizeStr = apiReturn->params.count("size") ? apiReturn->params["size"] : "";
  string message = apiReturn->params.count("message") ? apiReturn->params["message"] : "";
  string signature = apiReturn->params.count("signature") ? apiReturn->params["signature"] : "";

  if (version.empty() || sha256.size() != 64 || sizeStr.empty() || message.empty() || signature.empty())
  {
    Serial.println("[Revoke] Missing required notice fields");
    return false;
  }

  size_t sizeVal = (size_t)strtoul(sizeStr.c_str(), nullptr, 10);
  if (sizeVal == 0)
  {
    Serial.println("[Revoke] Invalid size");
    return false;
  }

  string msgProject, msgDevice, msgSha, msgNonce;
  if (!parseRevokeMessage(message, msgProject, msgDevice, msgSha, msgNonce))
  {
    Serial.println("[Revoke] Bad message format (expected revoke:<project>:<device>:<sha256>:<nonce>)");
    return false;
  }

  if (msgProject != PROJECT_ID)
  {
    Serial.printf("[Revoke] Project mismatch: %s vs %s\n", msgProject.c_str(), PROJECT_ID);
    return false;
  }

  if (!equalsIgnoreCase(msgSha, sha256))
  {
    Serial.println("[Revoke] sha256 arg does not match message binding");
    return false;
  }

  string selfAddr = normalizeAddress(keyID->getAddress());
  string noticeAddr = normalizeAddress(msgDevice);
  if (!equalsIgnoreCase(selfAddr, noticeAddr))
  {
    Serial.printf("[Revoke] Device mismatch: notice=%s self=%s\n",
                  noticeAddr.c_str(), selfAddr.c_str());
    return false;
  }

  // EIP-191 personal_sign recovery → must be a compiled-in admin address
  string recovered = Crypto::ECRecoverFromPersonalMessage(&signature, &message);
  if (recovered.empty() || !checkAdmin(&recovered))
  {
    Serial.printf("[Revoke] Admin signature check failed (recovered=%s)\n", recovered.c_str());
    return false;
  }

  strncpy(pendingRevokeSha256, sha256.c_str(), sizeof(pendingRevokeSha256) - 1);
  pendingRevokeSha256[sizeof(pendingRevokeSha256) - 1] = '\0';
  strncpy(pendingRevokeVersion, version.c_str(), sizeof(pendingRevokeVersion) - 1);
  pendingRevokeVersion[sizeof(pendingRevokeVersion) - 1] = '\0';
  pendingRevokeSize = sizeVal;

  Serial.printf("[Revoke] Accepted — setup version=%s sha256=%.16s... size=%zu\n",
                pendingRevokeVersion, pendingRevokeSha256, pendingRevokeSize);
  return true;
}

bool installSetupFirmwareFromNotice()
{
  Serial.println("[Revoke] Installing setup firmware...");

  // App MUST set stay_portal=1 before OTA-installing setup (Web3E-Setup-Firmware#3)
  if (wifiPortal.requestPortal(PORTAL_REASON_REVOKE))
  {
    Serial.println("[Revoke] stay_portal=1 written (NVS web3e_boot, reason=REVOKE)");
  }
  else
  {
    Serial.println("[Revoke] WARNING: failed to set stay_portal=1");
  }

  // URL is never on the wire — fetch from proxy setup channel
  WiFiClientSecure client;
  client.setInsecure();
  HTTPClient http;

  String url = String(PROXY_BASE_URL) + "/api/firmware/" + PROJECT_ID + "/setup";
  Serial.printf("[Revoke] Fetching setup metadata: %s\n", url.c_str());

  if (!http.begin(client, url))
  {
    Serial.println("[Revoke] Failed to begin setup metadata request");
    return false;
  }

  http.setTimeout(10000);
  int httpCode = http.GET();
  if (httpCode != HTTP_CODE_OK)
  {
    Serial.printf("[Revoke] Setup metadata HTTP error: %d\n", httpCode);
    http.end();
    return false;
  }

  String payload = http.getString();
  http.end();

  JsonDocument doc;
  DeserializationError error = deserializeJson(doc, payload);
  if (error)
  {
    Serial.printf("[Revoke] JSON parse error: %s\n", error.c_str());
    return false;
  }

  const char* metaVersion = doc["version"];
  const char* metaUrl = doc["url"];
  const char* metaSha = doc["sha256"];
  size_t metaSize = doc["size"];

  if (!metaVersion || !metaUrl || !metaSha || metaSize == 0)
  {
    Serial.println("[Revoke] Setup metadata missing fields");
    return false;
  }

  if (strcasecmp(metaSha, pendingRevokeSha256) != 0)
  {
    Serial.println("[Revoke] Setup metadata sha256 does not match notice");
    return false;
  }
  if (metaSize != pendingRevokeSize)
  {
    Serial.printf("[Revoke] Setup metadata size mismatch: meta=%zu notice=%zu\n",
                  metaSize, pendingRevokeSize);
    return false;
  }
  if (strcmp(metaVersion, pendingRevokeVersion) != 0)
  {
    Serial.printf("[Revoke] Setup metadata version mismatch: meta=%s notice=%s\n",
                  metaVersion, pendingRevokeVersion);
    return false;
  }

  // Install even if "older" than app — revoke is not a semver upgrade.
  // performOTA verifies sha256+size and reboots on success.
  performOTA(metaUrl, metaSha, metaSize, metaVersion);
  return true;
}

void armMainLoopWatchdog()
{
  // Cover hung loop() — TcpBridge liveness alone only runs inside checkClientAPI.
#if defined(ESP_IDF_VERSION_MAJOR) && (ESP_IDF_VERSION_MAJOR >= 5)
  esp_task_wdt_config_t cfg = {
      .timeout_ms = 30000,
      .idle_core_mask = 0,
      .trigger_panic = true,
  };
  esp_err_t err = esp_task_wdt_reconfigure(&cfg);
  if (err == ESP_ERR_INVALID_STATE)
    err = esp_task_wdt_init(&cfg);
#else
  esp_err_t err = esp_task_wdt_init(30, true);
#endif
  if (err != ESP_OK && err != ESP_ERR_INVALID_STATE)
    Serial.printf("[WDT] init/reconfigure: %s\n", esp_err_to_name(err));

  err = esp_task_wdt_add(NULL);
  if (err != ESP_OK && err != ESP_ERR_INVALID_STATE)
    Serial.printf("[WDT] add: %s\n", esp_err_to_name(err));
  else
    Serial.println("[WDT] Main loop task watchdog armed (30s)");
}

void runOfflinePortalAndReboot()
{
  Serial.println("[Portal] Offline reset / stay_portal — opening Web3E captive portal");
  Serial.println("[Portal] KeyID + WifiStore preserved; AP opened only for this path");

  // KeyID before any WifiStore begin (EEPROM size contract)
  if (!web3)
    web3 = new Web3(BASE_SEPOLIA_ID);
  if (!keyID)
    keyID = new KeyID(web3);

  bool saved = wifiPortal.run(0);
  Serial.printf("[Portal] Exiting portal (saved=%d) — rebooting to normal operation\n", saved ? 1 : 0);
  delay(500);
  ESP.restart();
}

// ===== WIFI VALIDATION PERSISTENCE =====

/**
 * Check if WiFi has ever been validated (connected or known SSID seen)
 * Persisted in NVS namespace web3e_boot (same as portal) for consistency
 */
bool isWifiEverValidated()
{
  Preferences prefs;
  if (!prefs.begin("web3e_boot", true))  // read-only
  {
    Serial.println("[WiFi] WARNING: Could not open NVS web3e_boot for validation check");
    return false;
  }
  bool validated = prefs.getBool("wifi_validated", false);
  prefs.end();
  return validated;
}

/**
 * Mark WiFi as validated (called after successful connect or known SSID seen)
 * Persists across reboots to enable lost-WiFi portal on "moved house" scenario
 */
void setWifiEverValidated()
{
  Preferences prefs;
  if (!prefs.begin("web3e_boot", false))  // read-write
  {
    Serial.println("[WiFi] WARNING: Could not open NVS web3e_boot to set validation flag");
    return;
  }
  if (!prefs.getBool("wifi_validated", false))
  {
    prefs.putBool("wifi_validated", true);
    Serial.println("[WiFi] Validation flag set (NVS web3e_boot)");
  }
  prefs.end();
}

/**
 * Scan for known SSIDs and attempt connection if found
 * Returns:
 *   SCAN_NONE_OR_FAILED - 0 networks or scan failed (don't accumulate or reset)
 *   SCAN_KNOWN_SEEN - known SSID visible (reset timeout, may or may not connect)
 *   SCAN_ONLY_UNKNOWN - networks visible but no known SSID (accumulate timeout)
 */
ScanResult scanForKnownSSID(WiFiCredentials* networks)
{
  WiFi.mode(WIFI_STA);
  int n = WiFi.scanNetworks();
  
  if (n < 0)
  {
    Serial.println("[WiFi] Scan failed");
    return SCAN_NONE_OR_FAILED;
  }
  
  if (n == 0)
  {
    Serial.println("[WiFi] Scan: 0 networks (antenna/radio fault guard — not counting)");
    return SCAN_NONE_OR_FAILED;
  }
  
  Serial.printf("[WiFi] Scan: %d networks found\n", n);
  
  // Check if any saved SSID is visible
  bool knownSsidFound = false;
  for (int i = 0; networks[i].ssid != nullptr; i++)
  {
    for (int j = 0; j < n; j++)
    {
      if (strcmp(WiFi.SSID(j).c_str(), networks[i].ssid) == 0)
      {
        Serial.printf("[WiFi] Known SSID found: %s (RSSI %ld)\n", networks[i].ssid, (long)WiFi.RSSI(j));
        knownSsidFound = true;
        
        // Set validated flag (known SSID seen = validated)
        setWifiEverValidated();
        
        // Attempt connection
        WiFi.begin(networks[i].ssid, networks[i].password);
        unsigned long connectStart = millis();
        while (WiFi.status() != WL_CONNECTED && (millis() - connectStart < 10000))
        {
          delay(500);
          esp_task_wdt_reset();
        }
        
        if (WiFi.status() == WL_CONNECTED)
        {
          Serial.printf("[WiFi] Connected to: %s\n", WiFi.SSID().c_str());
          WiFi.scanDelete();
          return SCAN_KNOWN_SEEN;  // Connected
        }
        else
        {
          Serial.printf("[WiFi] Connect failed for %s, continuing scan\n", networks[i].ssid);
        }
      }
    }
  }
  
  WiFi.scanDelete();
  
  if (!knownSsidFound)
  {
    Serial.println("[WiFi] No known SSID in scan results");
    return SCAN_ONLY_UNKNOWN;
  }
  
  // Known SSID seen but connect failed
  return SCAN_KNOWN_SEEN;
}

// ===== SETUP =====

void setup()
{
  Serial.begin(115200);
  delay(2000);
  Serial.println("=== ESP32 GARAGE DOOR CONTROLLER ===");
  Serial.printf("Firmware: %s\n", FW_VERSION);
  Serial.printf("Reset reason: %d\n", (int)esp_reset_reason());

  // Web3E WiFi Portal module (NVS namespace web3e_boot)
  // Handles: triple power-cycle, lost-WiFi watchdog, revoke API
  if (!wifiPortal.begin())
  {
    Serial.println("[Portal] WARNING: Portal init failed — continuing without portal support");
  }
  else
  {
    bool forcePortal = wifiPortal.shouldOpenPortal();
    if (forcePortal)
    {
      PortalReason reason = wifiPortal.getPortalReason();
      const char* reasonStr = "unknown";
      switch (reason)
      {
        case PORTAL_REASON_REVOKE: reasonStr = "revoke"; break;
        case PORTAL_REASON_POWER_CYCLE: reasonStr = "triple power-cycle"; break;
        case PORTAL_REASON_LOST_WIFI: reasonStr = "lost WiFi"; break;
        default: reasonStr = "unspecified"; break;
      }
      Serial.printf("[Portal] stay_portal active (reason: %s)\n", reasonStr);
      runOfflinePortalAndReboot();
      return; // not reached
    }
  }

  Initialize();
  delay(100);

  // ===== WIFI SETUP =====
  // Try WifiStore first, fallback to secrets.h, then write to EEPROM.
  // Startup watchdog armed AFTER WiFi connect (covers TCP connect only).

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

  // Build network list in persistent array (Bug #1 fix: used by loop reconnect)
  if (networkCount > 0)
  {
    for (int i = 0; i < networkCount; i++)
    {
      savedWifiNetworks[i].ssid = storedCreds[i].ssid;
      savedWifiNetworks[i].password = storedCreds[i].password;
    }
    savedWifiNetworks[networkCount].ssid = nullptr;
    savedWifiNetworks[networkCount].password = nullptr;
  }
  else
  {
    savedWifiNetworks[0].ssid = WIFI_SSID_1;
    savedWifiNetworks[0].password = WIFI_PASSWORD_1;
    savedWifiNetworks[1].ssid = WIFI_SSID_2;
    savedWifiNetworks[1].password = WIFI_PASSWORD_2;
    savedWifiNetworks[2].ssid = WIFI_SSID_3;
    savedWifiNetworks[2].password = WIFI_PASSWORD_3;
    savedWifiNetworks[3].ssid = WIFI_SSID_4;
    savedWifiNetworks[3].password = WIFI_PASSWORD_4;
    savedWifiNetworks[4].ssid = nullptr;
    savedWifiNetworks[4].password = nullptr;
  }

  // Link Wi-Fi portal for lost-WiFi watchdog
  wifiConnection.setWifiPortal(&wifiPortal);
  wifiConnection.setupWifi(savedWifiNetworks);

  if (WiFi.status() != WL_CONNECTED)
  {
    // Check if WiFi was ever validated (persisted in NVS)
    bool everValidated = isWifiEverValidated();
    
    if (everValidated)
    {
      // "Moved house" scenario: WiFi was validated before but can't connect now.
      // Scan for 5 minutes; if no known SSID seen but other networks visible, open portal.
      Serial.println("[WiFi] Failed to connect, but wifi_validated flag set");
      Serial.println("[WiFi] Entering lost-WiFi scanning loop (5 min threshold)");
      
      unsigned long lastScanTime = 0;
      unsigned long unknownOnlyStartMs = 0;  // Start of "unknown-only" window
      unsigned long knownSeenLoopStartMs = 0;  // Start of "known SSID visible but failing" loop
      const unsigned long SCAN_INTERVAL_MS = 30000;  // 30 seconds between scans
      const unsigned long LOST_WIFI_THRESHOLD_MS = 5 * 60 * 1000;  // 5 minutes
      const unsigned long STUCK_RETRY_THRESHOLD_MS = 10 * 60 * 1000;  // 10 minutes stuck with known SSID
      
      bool portalOpened = false;
      
      while (WiFi.status() != WL_CONNECTED && !portalOpened)
      {
        unsigned long now = millis();
        
        // Periodic scan
        if (now - lastScanTime >= SCAN_INTERVAL_MS)
        {
          lastScanTime = now;
          
          ScanResult scanResult = scanForKnownSSID(savedWifiNetworks);
          
          if (WiFi.status() == WL_CONNECTED)
          {
            // Connection succeeded during scan
            Serial.println("[WiFi] Connected during lost-WiFi scan loop");
            break;
          }
          
          if (scanResult == SCAN_KNOWN_SEEN)
          {
            // Known SSID visible but connect failed — keep retrying, don't count toward portal timeout
            Serial.println("[WiFi] Known SSID visible but connect failed — retrying (no portal)");
            unknownOnlyStartMs = 0;  // Reset portal timeout
            
            // Start/continue stuck-retry timer
            if (knownSeenLoopStartMs == 0)
            {
              knownSeenLoopStartMs = now;
              Serial.println("[WiFi] Starting stuck-retry timer (10 min threshold)");
            }
            else
            {
              unsigned long stuckElapsedMs = now - knownSeenLoopStartMs;
              if (stuckElapsedMs >= STUCK_RETRY_THRESHOLD_MS)
              {
                // Known SSID visible for >10 min but can't connect — restart to restore liveness
                Serial.println("[WiFi] Stuck retrying for 10+ minutes — restarting to restore liveness");
                delay(1000);
                ESP.restart();
              }
              unsigned long stuckRemainingMs = STUCK_RETRY_THRESHOLD_MS - stuckElapsedMs;
              Serial.printf("[WiFi] Known SSID stuck-retry (restart in %lu seconds)\n", stuckRemainingMs / 1000);
            }
          }
          else if (scanResult == SCAN_ONLY_UNKNOWN)
          {
            // Networks visible but no known SSID — accumulate time toward portal threshold
            knownSeenLoopStartMs = 0;  // Reset stuck-retry timer
            
            if (unknownOnlyStartMs == 0)
            {
              unknownOnlyStartMs = now;
              Serial.printf("[WiFi] No known SSID found (timeout in %lu seconds)\n", LOST_WIFI_THRESHOLD_MS / 1000);
            }
            else
            {
              unsigned long elapsedMs = now - unknownOnlyStartMs;
              if (elapsedMs >= LOST_WIFI_THRESHOLD_MS)
              {
                // 5 minutes elapsed with no known SSID — open portal
                Serial.println("[WiFi] Lost-WiFi threshold reached — opening portal");
                wifiPortal.requestPortal(PORTAL_REASON_LOST_WIFI);
                runOfflinePortalAndReboot();  // runs portal, reboots on exit
                portalOpened = true;
              }
              else
              {
                unsigned long remainingMs = LOST_WIFI_THRESHOLD_MS - elapsedMs;
                Serial.printf("[WiFi] No known SSID found (timeout in %lu seconds)\n", remainingMs / 1000);
              }
            }
          }
          else  // SCAN_NONE_OR_FAILED
          {
            // 0 networks or scan failed — don't accumulate or reset
            Serial.println("[WiFi] Scan returned 0 networks or failed — not counting (antenna/power guard)");
            // Keep existing timers as-is
          }
        }
        
        // Feed watchdogs during scanning loop
        esp_task_wdt_reset();
        delay(1000);
      }
    }
    else
    {
      // WiFi never validated before — normal restart behavior
      Serial.println("[WiFi] Failed to connect, restarting (wifi_validated not set)...");
      delay(5000);
      ESP.restart();
    }
  }

  Serial.printf("[WiFi] Connected to: %s\n", WiFi.SSID().c_str());
  Serial.printf("[WiFi] IP Address: %s\n", WiFi.localIP().toString().c_str());
  
  // Mark WiFi as validated (arms lost-WiFi watchdog + persists in NVS)
  setWifiEverValidated();
  wifiConnection.markValidated();
  Serial.println("[WiFi] Validated — lost-WiFi watchdog armed");
  
  // Arm startup watchdog now (covers TCP connect phase only, not WiFi scanning)
  TcpBridge::armStartupWatchdog();

  if (!wifiStoreValid && networkCount == 0)
  {
    Serial.println("[WiFi] Migrating: Writing fallback credentials to WifiStore...");
    if (writeWifiStoreFromSecrets())
      Serial.println("[WiFi] Migration complete - future boots will use WifiStore");
    else
      Serial.println("[WiFi] Migration failed - will retry on next boot");
  }

  // ===== WEB3 INITIALIZATION =====
  // Web3E 1.47+: Web3(chainId) no longer selects an RPC host. NFT balanceOf
  // (Contract::ViewCall → eth_call) needs JSON-RPC, so fetch a signed public
  // RPC pair via universal-node and cache it in EEPROM at offset 828+ (after
  // KeyID 0-32 and WifiStore 33-827). TcpBridge login itself does not need RPC.
  actionHandler = new ActionHandler(6);
  web3 = new Web3(BASE_SEPOLIA_ID);
  Serial.println("Init web3");

  keyID = new KeyID(web3);
  Serial.printf("Device Address: %s\n", keyID->getAddress().c_str());
  updateChallenge();

  uninode = new UniversalNode(web3, keyID);
  Serial.println("[RPC] Syncing NTP for universal-node signed RPC pair...");
  if (!uninode->syncTime())
  {
    Serial.println("[RPC] NTP sync failed — will try EEPROM-cached RPC pair if present");
    Serial.println(uninode->lastError());
  }
  web3->useCachedRpcPair(uninode);
  if (!web3->maintainCachedRpcPair())
  {
    Serial.println("[RPC] WARNING: no usable cached RPC pair yet (NFT balanceOf may fail)");
    Serial.println(uninode->lastError());
  }
  else
  {
    Serial.printf("[RPC] Cached public RPC pair ready (count=%d)\n", web3->getCachedRpcCount());
  }

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

  armMainLoopWatchdog();

  Serial.println("[Setup] Complete");

  Serial.println("[OTA] Checking for updates at boot...");
  checkForUpdate();
  lastOTACheck = millis();
}

// ===== MAIN LOOP =====

void loop()
{
  long currentMillis = millis();
  esp_task_wdt_reset();

  actionHandler->CheckEvents(currentMillis);

  // Maintain WiFi — reconnect + lost-WiFi watchdog (opens portal after 5 min no known SSID)
  wifiConnection.maintain();

  // ~24h-throttled refresh of cached public RPC pair (Web3E 1.47)
  if (web3)
    web3->maintainCachedRpcPair();

  tcpConnection->checkClientAPI(&handleTCPAPI);

  if (revokeRequested)
  {
    revokeRequested = false;
    Serial.println("[Revoke] Starting setup firmware OTA after revoking ack");
    installSetupFirmwareFromNotice();
    // On success performOTA reboots; on failure continue running with stay_portal set
  }

  if (otaCheckRequested)
  {
    otaCheckRequested = false;
    Serial.println("[OTA] Notified update check");
    checkForUpdate();
    lastOTACheck = currentMillis;
  }

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
