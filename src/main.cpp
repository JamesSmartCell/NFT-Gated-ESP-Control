#include "web3e_flags.h" // toggle WEB3E_RELEASE here to strip Web3E Serial dumps
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
#include <HTTPUpdate.h>
#include <WifiServer.h>
#include <TcpBridge.h>
#include <WiFiConnection.h>
#include <functional>
#include <string>
#include <vector>
#include <SPI.h>

// Home SSID is listed twice: the first attempt often returns before DHCP.
static const WiFiCredentials wifiNetworks[] = {
    {ssid, password},
    {ssid, password},
    {ssid2, password2},
    {ssid3, password3},
    {nullptr, nullptr}
};
WiFiConnection wifiConnection;

#define DOOR_CONTRACT "0x3158e836ec0e85A46f7a7208d91EA9837A0C6ccC" //"0xfE22ba5Ff64621F2bAc7b3004343E94252158d5D" //0x8B0FEFd94667FdD8cEf52f8C1EeB5bAEc8d64a00 //0xcd70b89034C8885c29D7eB7A82a46F0E7f0b2859

#define FIRMWARE_VERSION "1.1.0-toggle"

#define RELAY_1 21
#define RELAY_2 22

enum APIRoutes
{
  api_unknown,
  api_getChallenge,
  api_checkSignature,
  api_checkSignatureLock,
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

void Initialize()
{
  s_apiRoutes["getChallenge"] = api_getChallenge;
  s_apiRoutes["checkSignature"] = api_checkSignature;
  s_apiRoutes["checkSignatureLock"] = api_checkSignatureLock;
  s_apiRoutes["checkGarageSig"] = api_checkGarageDoor;
  s_apiRoutes["checkGarageSig2"] = api_checkGarageDoor2;
  s_apiRoutes["checkGarageSigP256"] = api_checkGarageDoorP256;
  s_apiRoutes["checkGarageSigP256_2"] = api_checkGarageDoorP256_2;
  s_apiRoutes["updateReady"] = api_updateReady;
  s_apiRoutes["getVersion"] = api_getVersion;
  s_apiRoutes["end"] = api_end;
}

void generateSeed(BYTE* buffer);
void updateChallenge();
Web3* web3;
KeyID* keyID;

const char* seedWords[] = { "Apples", "Oranges", "Grapes", "DragonFruit", "BreadFruit", "Pomegranate", "Aubergine", "Fungi", "Falafel", "Cryptokitty", "Kookaburra", "Elvis", "Koala", 0 };
const char* adminAddrs[] = { "0xC067A53c91258ba513059919E03B81CF93f57Ac7", "0x7e4b1da13c4a2a73fd05e928a6ed81b0a5d3007b" };
const int adminAddrsSz = 2;

string currentChallenge;

TcpBridge* tcpConnection;

const char* apiRoute = "api/";

bool isLocked;
void startGarageOpen(int openSeconds);
void operateGarageDoor();

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
  // transaction
  bool hasToken = false;
  Contract contract(web3, contractAddr);
  string func = "balanceOf(address)";
  string param = contract.SetupContractData(func.c_str(), userAddress);
  string result = contract.ViewCall(&param);

  Serial.println(result.c_str());

  // break down the result
  uint256_t baseBalance = web3->getUint256(&result);

  if (baseBalance > 0)
  {
    hasToken = true;
    Serial.println("Has token");
  }

  return hasToken;
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
    Serial.printf("Firmware: %s\n", FIRMWARE_VERSION);
    return string(FIRMWARE_VERSION);
  // case api_checkSignature:
  // {
  //   Serial.print("Sig: ");
  //   Serial.println(apiReturn->params["sig"].c_str());
  //   address = Crypto::ECRecoverFromPersonalMessage(&apiReturn->params["sig"], &currentChallenge);
  //   int unlockSeconds = strtol(apiReturn->params["openTime"].c_str(), NULL, 10);
  //   Serial.print("EC-Addr: ");
  //   Serial.println(address.c_str());
  //   boolean hasToken = QueryBalance(DOOR_CONTRACT, &address);
  //   updateChallenge(); // generate a new challenge after each check
  //   if (hasToken)
  //   {
  //     actionHandler->AddCallback(500, &doUnlockCommand);
  //     return string("pass");
  //   }
  //   else
  //   {
  //     return string("fail");
  //   }
  // }
  // break;
  // case api_checkSignatureLock:
  // {
  //   Serial.print("Sig: ");
  //   Serial.println(apiReturn->params["sig"].c_str());
  //   address = Crypto::ECRecoverFromPersonalMessage(&apiReturn->params["sig"], &currentChallenge);
  //   int unlockSeconds = strtol(apiReturn->params["openTime"].c_str(), NULL, 10);
  //   Serial.print("EC-Addr: ");
  //   Serial.println(address.c_str());
  //   boolean hasToken = QueryBalance(DOOR_CONTRACT, &address);
  //   updateChallenge(); // generate a new challenge after each check
  //   if (hasToken)
  //   {
  //     actionHandler->AddCallback(500, &doLockCommand);
  //     return string("pass");
  //   }
  //   else
  //   {
  //     return string("fail");
  //   }
  // }
  // break;
  case api_checkGarageDoor:
  {
    Serial.print("Sig: ");
    Serial.println(apiReturn->params["sig"].c_str());
    address = Crypto::ECRecoverFromPersonalMessage(&apiReturn->params["sig"], &currentChallenge);
    int unlockSeconds = strtol(apiReturn->params["openTime"].c_str(), NULL, 10);
    Serial.print("EC-Addr: ");
    Serial.println(address.c_str());
    boolean hasToken = QueryBalance(DOOR_CONTRACT, &address);
    updateChallenge(); // generate a new challenge after each check
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
    boolean hasToken = QueryBalance(DOOR_CONTRACT, &address);
    updateChallenge(); // generate a new challenge after each check
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
    // P256 passkey signature verification (Tempo/Coinbase-style address derivation)
    // hashType: keccak (default), sha256, or webauthn (digest passed directly)
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
      if (QueryBalance(DOOR_CONTRACT, &address)) {
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
    // P256 passkey signature verification (Tempo/Coinbase-style address derivation)
    // hashType: keccak (default), sha256, or webauthn (digest passed directly)
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
      if (QueryBalance(DOOR_CONTRACT, &address)) {
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
    // P256 passkey verification (same as checkGarageDoorP256)
    std::string url = apiReturn->params.count("url") ? apiReturn->params["url"] : "";
    std::string version = apiReturn->params.count("version") ? apiReturn->params["version"] : "";
    if (url.empty() || version.empty())
    {
      Serial.println("updateReady: missing url or version");
      return string("error:missing_params");
    }
    std::string sig = apiReturn->params.count("sig") ? apiReturn->params["sig"] : "";
    if (sig.empty())
    {
      Serial.println("updateReady: missing sig (P256 auth required)");
      return string("error:auth_required");
    }
    std::string hashType = apiReturn->params.count("hashType") ? apiReturn->params["hashType"] : "keccak";
    std::vector<std::string> addresses;
    if (hashType == "webauthn" && apiReturn->params.count("digest"))
    {
      addresses = ECRecoverFromDigestP256AllRecids(&apiReturn->params["sig"], &apiReturn->params["digest"]);
    }
    else if (hashType == "sha256")
    {
      std::string addr = ECRecoverFromMessageP256_SHA256(&apiReturn->params["sig"], &currentChallenge);
      if (!addr.empty())
        addresses.push_back(addr);
    }
    else
    {
      addresses = ECRecoverFromPersonalMessageP256AllRecids(&apiReturn->params["sig"], &currentChallenge);
    }
    bool hasToken = false;
    for (size_t i = 0; i < addresses.size(); i++)
    {
      if (QueryBalance(DOOR_CONTRACT, &addresses[i]))
      {
        hasToken = true;
        break;
      }
    }
    updateChallenge();
    if (!hasToken)
    {
      Serial.println("updateReady: auth failed (no NFT)");
      return string("error:auth_failed");
    }
    Serial.printf("updateReady: OTA from %s (v%s)\n", url.c_str(), version.c_str());
    WiFiClientSecure client;
    client.setInsecure();
    HTTPUpdate httpUpdate;
    t_httpUpdate_return ret = httpUpdate.update(client, url.c_str(), version.c_str());
    if (ret == HTTP_UPDATE_OK)
    {
      Serial.println("OTA OK, restarting...");
      return string("ok");
    }
    Serial.printf("OTA failed: %d\n", (int)ret);
    return string("error:ota_failed");
  }
  break;
  case api_unknown:
    break;
  case api_end:
    break;
  }

  return string("");
}

void setup()
{
  Serial.begin(115200);
  delay(2000);  // give USB CDC time to enumerate
  Serial.println("=== ESP32-C6 BOOT ===");
  Serial.printf("Firmware: %s\n", FIRMWARE_VERSION);
  Serial.printf("Reset reason: %d\n", (int)esp_reset_reason());
  // Covers WiFi and the blocking TCP connect, which run before loop().
  TcpBridge::armStartupWatchdog();
  delay(2000);
  
  Initialize();
  //augustLock.init();
  delay(100);
  wifiConnection.setupWifi(wifiNetworks);
  actionHandler = new ActionHandler(6);
  web3 = new Web3(BASE_SEPOLIA_ID);
  Serial.print("Init web3");

  keyID = new KeyID(web3);
  Serial.print("Got key");
  updateChallenge();
  Serial.print("Challenge set");

  pinMode(RELAY_1, OUTPUT);
  pinMode(RELAY_2, OUTPUT);
  digitalWrite(RELAY_1, HIGH);
  digitalWrite(RELAY_2, HIGH);

  tcpConnection = new TcpBridge();
  tcpConnection->setKey(keyID, web3);
  tcpConnection->startConnection();
}

void loop()
{
  long currentMillis = millis();
  actionHandler->CheckEvents(currentMillis);
  wifiConnection.setupWifi(wifiNetworks);
  tcpConnection->checkClientAPI(&handleTCPAPI);

  delay(100);
}

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
  //first operate the open, 1 second
  operateGarageDoor();

  if (openSeconds > 0)
  {
    actionHandler->AddCallback(openSeconds * 1000, &operateGarageDoor);
  }

  //after 20 seconds, operate interior door
  actionHandler->AddCallback(15*1000, &operateInteriorDoor);
}

void updateChallenge()
{
  // generate a new challenge
  int size = 0;
  while (seedWords[size] != 0)
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
