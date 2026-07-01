// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#pragma once

#include <Arduino.h>
#include <stdint.h>
#include <string>

namespace fs { class FS; }   // forward-decl so includers don't need <FS.h>

// IEEE OUI (MA-L /24) -> vendor lookup, backed by a sorted binary file
// (/oui.bin, generated from Wireshark's manuf database - see tools/make_oui_bin.py).
// Binary-searched directly on the file at runtime, so the ~39k-entry table costs
// almost no RAM and no program flash. Only meaningful for public BLE addresses
// (random addresses aren't OUI-assigned).
//
// The backing store is pluggable: the serial CLI builds keep it on LittleFS
// (init()), while the Cardputer reads it from the SD card (begin(SD, ...)) - the
// Cardputer is loaded via the M5 launcher under a different partition table, so
// our embedded LittleFS partition isn't present at runtime there.
namespace oui_db {

// Open <path> on the given filesystem and validate its header. Safe to call if
// the file is absent or malformed (logs a one-line warning; lookups then return
// "" so callers degrade to "unknown vendor"). Reusable for SD or LittleFS.
void begin(fs::FS& fs, const char* path);

// Convenience wrapper: begin(LittleFS, "/oui.bin"). Used by the serial CLI
// builds, which ship the DB in the LittleFS partition (`pio run -t uploadfs`).
void init();

bool available();

// Vendor name for a 24-bit OUI (e.g. 0xFCB97E), or "" if not found / unavailable.
std::string lookup(uint32_t oui24);

// Convenience: parse the first three octets of "aa:bb:cc:..." and look up.
std::string lookupMac(const std::string& mac);

}
