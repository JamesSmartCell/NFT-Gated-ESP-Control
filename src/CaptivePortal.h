#pragma once

/**
 * Embedded captive portal for offline (triple power-cycle) Wi-Fi reconfiguration.
 *
 * UX aligns with Web3E-Setup-Firmware (AP ESP32-Setup-XXXX @ 192.168.4.1):
 *   - Scan once at boot + explicit Refresh (no periodic AP_STA rescans)
 *   - Does NOT download / install firmware
 *   - On Done: clears stay_portal via PortalBoot, keeps WifiStore/KeyID, returns
 *     so the caller can reboot into normal operation
 *
 * The AP is NEVER opened automatically on Wi-Fi outage — only when the caller
 * invokes captivePortalRun() after stay_portal / triple power-cycle.
 */

#include <stdbool.h>

class PortalBoot;

#ifndef AP_SSID_PREFIX
#define AP_SSID_PREFIX "ESP32-Setup"
#endif

#ifndef AP_PASSWORD
#define AP_PASSWORD ""
#endif

#ifndef APP_NAME
#define APP_NAME "GarageDoor"
#endif

/**
 * Run until the user saves networks and clicks Done.
 * portalBoot: optional; if provided, Done clears stay_portal.
 * deviceAddress: optional 0x… string for display.
 * Returns true if credentials were saved (caller should reboot).
 */
bool captivePortalRun(PortalBoot* portalBoot, const char* deviceAddress);
