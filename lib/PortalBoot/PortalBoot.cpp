#ifndef NATIVE_TEST
#include <Arduino.h>
#include <Preferences.h>
#include "esp_system.h"
#include "esp_timer.h"
#endif

#include "PortalBoot.h"

#ifndef NATIVE_TEST
static Preferences portalPrefs;
static esp_timer_handle_t bootCountClearTimer = nullptr;
static PortalBoot* bootCountClearInstance = nullptr;

// Timer callback to clear boot_count after 10s (Bug #2 fix)
static void bootCountClearTimerCallback(void* arg) {
    if (bootCountClearInstance && bootCountClearInstance->isInitialized()) {
        if (!bootCountClearInstance->isBootCountCleared()) {
            Serial.println("[PortalBoot] Timer: 10s uptime reached — clearing boot_count");
            bootCountClearInstance->clearBootCountNow();
        }
    }
}
#endif

bool PortalBoot::begin() {
#ifndef NATIVE_TEST
    // Read/write NVS namespace shared with app firmware. Never touches EEPROM.
    if (!portalPrefs.begin(PORTAL_BOOT_NVS_NAMESPACE, false)) {
        Serial.println("ERROR: PortalBoot NVS begin failed");
        initialized = false;
        return false;
    }
#endif
    initialized = true;
    bootCountCleared = false;
    
#ifndef NATIVE_TEST
    // Bug #2 fix: Arm timer to clear boot_count after 10s regardless of loop()
    bootCountClearInstance = this;
    if (bootCountClearTimer == nullptr) {
        const esp_timer_create_args_t timerArgs = {
            .callback = &bootCountClearTimerCallback,
            .arg = nullptr,
            .dispatch_method = ESP_TIMER_TASK,
            .name = "boot_count_clear",
            .skip_unhandled_events = false
        };
        esp_err_t err = esp_timer_create(&timerArgs, &bootCountClearTimer);
        if (err == ESP_OK) {
            err = esp_timer_start_once(bootCountClearTimer, PORTAL_BOOT_STABLE_MS * 1000ULL);
            if (err == ESP_OK) {
                Serial.printf("[PortalBoot] Timer armed: will clear boot_count after %lu ms\n",
                              (unsigned long)PORTAL_BOOT_STABLE_MS);
            } else {
                Serial.printf("[PortalBoot] WARNING: Failed to start timer: %s\n", esp_err_to_name(err));
            }
        } else {
            Serial.printf("[PortalBoot] WARNING: Failed to create timer: %s\n", esp_err_to_name(err));
        }
    }
#endif
    
    return readState();
}

bool PortalBoot::readState() {
    if (!initialized) return false;
#ifndef NATIVE_TEST
    stayPortal = portalPrefs.getUChar(PORTAL_BOOT_KEY_STAY_PORTAL, 0) != 0;
    bootCount = portalPrefs.getUChar(PORTAL_BOOT_KEY_BOOT_COUNT, 0);
#else
    stayPortal = false;
    bootCount = 0;
#endif
    return true;
}

bool PortalBoot::writeStayPortal(uint8_t value) {
    if (!initialized) return false;
#ifndef NATIVE_TEST
    size_t written = portalPrefs.putUChar(PORTAL_BOOT_KEY_STAY_PORTAL, value);
    if (written == 0) {
        // putUChar returns 0 on failure; also returns 0 if value unchanged on
        // some cores — re-read to confirm.
        if (portalPrefs.getUChar(PORTAL_BOOT_KEY_STAY_PORTAL, 0xFF) != value) {
            return false;
        }
    }
#endif
    stayPortal = (value != 0);
    return true;
}

bool PortalBoot::writeBootCount(uint8_t value) {
    if (!initialized) return false;
#ifndef NATIVE_TEST
    size_t written = portalPrefs.putUChar(PORTAL_BOOT_KEY_BOOT_COUNT, value);
    if (written == 0) {
        if (portalPrefs.getUChar(PORTAL_BOOT_KEY_BOOT_COUNT, 0xFF) != value) {
            return false;
        }
    }
#endif
    bootCount = value;
    return true;
}

bool PortalBoot::checkAndHandlePowerCycle() {
    if (!initialized) return shouldStayInPortal();

#ifndef NATIVE_TEST
    // Bug #2 fix: Only count real power-on/external resets, not software/watchdog resets
    esp_reset_reason_t reason = esp_reset_reason();
    bool isRealPowerCycle = (reason == ESP_RST_POWERON || reason == ESP_RST_EXT);
    
    Serial.printf("[PortalBoot] Reset reason: %d (%s)\n", (int)reason,
                  isRealPowerCycle ? "POWER/EXTERNAL" : "SOFTWARE/WATCHDOG");
    
    if (!isRealPowerCycle) {
        // Software/watchdog reset: do not increment boot_count
        Serial.println("[PortalBoot] Not a real power cycle — boot_count unchanged");
        return shouldStayInPortal();
    }
#endif

    // Real power cycle: increment boot_count
    uint8_t next = bootCount;
    if (next < 255) {
        next++;
    }
    writeBootCount(next);

#ifndef NATIVE_TEST
    Serial.printf("[PortalBoot] Real power cycle: boot_count = %u (threshold %u)\n",
                  (unsigned)bootCount, (unsigned)PORTAL_BOOT_TRIPLE_THRESHOLD);
#endif

    if (bootCount >= PORTAL_BOOT_TRIPLE_THRESHOLD) {
#ifndef NATIVE_TEST
        Serial.println("[PortalBoot] Triple power-cycle detected — forcing portal");
#endif
        writeStayPortal(1);
        writeBootCount(0);
        bootCountCleared = true;
        return true;
    }

    return shouldStayInPortal();
}

bool PortalBoot::shouldStayInPortal() const {
    return stayPortal;
}

bool PortalBoot::setStayInPortal(bool stay) {
    return writeStayPortal(stay ? 1 : 0);
}

bool PortalBoot::clearStayInPortal() {
    return writeStayPortal(0);
}

void PortalBoot::clearBootCountIfStable(unsigned long uptimeMs) {
    if (!initialized || bootCountCleared) return;
    if (uptimeMs < PORTAL_BOOT_STABLE_MS) return;
    clearBootCountNow();
}

void PortalBoot::clearBootCountNow() {
    if (!initialized || bootCountCleared) return;
    if (bootCount == 0) {
        bootCountCleared = true;
        return;
    }
    writeBootCount(0);
    bootCountCleared = true;
}

uint8_t PortalBoot::getBootCount() const {
    return bootCount;
}
