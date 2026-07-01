// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#pragma once

#include <Arduino.h>
#include <NimBLEDevice.h>

#include <functional>

#include "scanner.h"

namespace connection {

struct SecurityConfig {
    bool    bond    = true;
    bool    mitm    = false;
    bool    lesc    = true;
    uint8_t iocap   = BLE_HS_IO_NO_INPUT_OUTPUT;
};

void init();

// Connect to a scanned device. The connect runs asynchronously and this blocks
// until it completes, fails, times out, or cancelCheck() returns true (called
// repeatedly while waiting - the UI uses it to abort a hanging connect on ESC).
bool connectTo(const scanner::Result& target, std::function<bool()> cancelCheck = nullptr);

// Connect by raw MAC + address type (no prior scan needed) - used by the MITM
// proxy to reconnect to its target after the reboot.
bool connectByMac(const std::string& mac, uint8_t addr_type);

bool isConnected();

// True once the current link has completed encryption (set in
// onAuthenticationComplete). Lets a UI wait for pairing before reading GATT.
bool isEncrypted();

void disconnect();

NimBLEClient* client();

bool secure();

// Auto-initiate pairing/encryption immediately after connect. Useful for HID
// peripherals that lead with a security request and drop the link otherwise.
void setAutoSecure(bool on);
bool autoSecure();

// Inject a passkey for a pending Passkey Entry pairing (peer displayed the digits).
// No-op unless a pairing is currently awaiting passkey entry.
bool injectPasskey(uint32_t pin);

// True while a Passkey Entry pairing is waiting for digits (peer is showing them).
// A UI polls this to pop up an on-screen passkey entry.
bool awaitingPasskey();

// True when a failed-auth reconnect is queued (serviceAutoRetry will run it).
bool authRetryPending();

// Returns the last Numeric Comparison code (and clears it), or 0 if none pending.
// The code is auto-accepted; this lets a UI display it for the user to verify.
uint32_t takeNumericPin();

// Call from the main loop. If a connect dropped with an authentication failure
// while using Just Works, this retries once with MITM numeric comparison +
// auto-secure enabled. No-op otherwise.
void serviceAutoRetry();

// Negotiate a large ATT MTU once, lazily, before the first GATT operation
// (deferred out of the connect handshake so it doesn't race device-led pairing).
void ensureMtuNegotiated();

bool requestMtu(uint16_t mtu);

void setSecurityConfig(const SecurityConfig& cfg);

const SecurityConfig& securityConfig();

void printSecurityConfig();

const char* iocapName(uint8_t cap);

// Returns true if the token was recognized (and the config mutated).
bool applySecurityToken(const char* tok, SecurityConfig& cfg);

void printStatus();

void listBonds();

bool forgetBond(const char* mac_or_all);

}
