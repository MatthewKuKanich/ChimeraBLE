// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#pragma once

#include <Arduino.h>
#include <stdint.h>
#include <string>
#include <vector>

// Best-effort device identification from advertising data alone (no connection
// needed). Combines service-data protocol UUIDs (Eddystone/Fast Pair/BTHome/...),
// manufacturer company IDs (+ Apple Continuity sub-type), SIG service UUIDs
// (device-type inference), appearance, and BLE address type. Aimed at naming
// devices that broadcast no local name.
namespace fingerprint {

// One-line best-guess label, e.g. "Apple (Nearby)", "BTHome sensor",
// "HID input device · Nordic Semiconductor". Returns "unknown" if nothing
// identifiable is present.
std::string identify(const std::string& addr, uint8_t addr_type,
                     const std::vector<uint8_t>& adv);

// Short address-type annotation for display: " [RPA]", " [rand]", or "".
std::string addrTag(const std::string& addr, uint8_t addr_type);

// Multi-line breakdown of every identifying signal, for `info`.
void describe(const std::string& addr, uint8_t addr_type,
              const std::vector<uint8_t>& adv);

}
