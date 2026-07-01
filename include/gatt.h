// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#pragma once

#include <Arduino.h>
#include <NimBLEDevice.h>
#include <string>
#include <vector>

namespace gatt {

struct DescEntry {
    uint16_t    handle;
    NimBLEUUID  uuid;
    NimBLERemoteDescriptor* ptr;   // valid only while connected
    std::vector<uint8_t> value;    // snapshot captured during dump
    bool        value_cached = false;
};

struct CharEntry {
    uint16_t    handle;
    NimBLEUUID  uuid;
    uint8_t     props;
    NimBLERemoteCharacteristic* ptr;  // valid only while connected
    std::vector<uint8_t> value;       // snapshot captured during dump
    bool        value_cached = false;
    std::vector<DescEntry> descs;
};

struct SvcEntry {
    uint16_t    start_handle;
    uint16_t    end_handle;
    NimBLEUUID  uuid;
    NimBLERemoteService* ptr;
    std::vector<CharEntry> chars;
};

void discoverAndCache();

void clearCache();

bool hasCache();

const std::vector<SvcEntry>& cache();

// Address of the device the current cache snapshot was built from. Survives
// disconnect, so a clone can be saved after the link drops.
const std::string& cachedPeer();

CharEntry*  findCharByHandle(uint16_t handle);
CharEntry*  findCharByUuid(const NimBLEUUID& uuid);

// Accepts "0x002A" (handle), "002A" (handle), "42" (decimal handle),
// or "uuid:2A19" / "uuid:6e400001-b5a3-..." (UUID lookup, first match).
CharEntry*  resolveChar(const char* spec);

void dump(bool readValues = true);

bool readChar(uint16_t handle);
bool writeChar(uint16_t handle, const uint8_t* data, size_t len, bool withResponse);

bool subscribe(uint16_t handle);
bool unsubscribe(uint16_t handle);
void listSubscriptions();

const char* propsString(uint8_t props, char* buf, size_t n);

// Human-readable interpretation of a characteristic value for common SIG types
// (Battery Level -> "64%", Device Name / DIS strings -> text, Appearance ->
// category). Returns "" when there's no friendly decode. Used by the GATT views
// and the SD dump.
std::string describeValue(const NimBLEUUID& uuid, const uint8_t* data, size_t len);

}
