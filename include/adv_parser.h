// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#pragma once

#include <Arduino.h>
#include <stddef.h>
#include <stdint.h>

namespace adv_parser {

// Decode and pretty-print an advertising payload per
// Core Spec Vol 3 Part C §11 (AD records: length | ad_type | data).
// Handles common AD types and dispatches manufacturer data (0xFF) to
// vendor-specific sub-decoders for Apple iBeacon, MS Swift Pair, etc.
void decode(const uint8_t* data, size_t len, const char* indent = "  ");

}
