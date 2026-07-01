// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#pragma once

#include <Arduino.h>
#include <NimBLEDevice.h>

namespace uuid_db {

const char* serviceName(uint16_t uuid16);
const char* charName(uint16_t uuid16);
const char* descName(uint16_t uuid16);
const char* companyName(uint16_t company_id);

// Member / allocated 16-bit service UUIDs (0xFCxx-0xFFFF): beacon/product
// protocols (Eddystone, Fast Pair, BTHome, Exposure Notification, ...).
const char* memberServiceName(uint16_t uuid16);

const char* lookup(const NimBLEUUID& uuid);

}
