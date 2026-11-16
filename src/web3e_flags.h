#pragma once

// Sketch-side Web3E build switch (included from main.cpp).
// Also force-included into Web3E library .cpp files via platformio.ini
// build_flags = -include src/web3e_flags.h
//
// Uncomment to strip Web3E logging (WEB3E_PRINT / WEB3E_PRINTLN become no-ops;
// strings and log-only expressions are discarded at preprocess time):
#define WEB3E_RELEASE
