// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#pragma once

#include <Arduino.h>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

namespace hid_parser {

// Decode a USB-HID Report Descriptor (HID 1.11 §6.2.2) and pretty-print it to
// `out` (defaults to Serial; pass an SD File to capture into a dump). Emits both
// the item-by-item tree and a per-Report-ID byte-layout cheatsheet.
void parse(const uint8_t* data, size_t len, Print& out = Serial);

// Convenience: connect to a connected/discovered GATT cache, locate the HID
// service (0x1812) + Report Map (0x2A4B), read it, and parse. No-op if HID
// service is absent. Returns true if parsed.
bool parseFromGatt();

// Live notification stream: subscribe to selected notify characteristics and
// decode them live - HID input reports (keyboard -> key names), Heart Rate
// (-> "HR 72 bpm"), Battery (-> "Batt N%"), or any other notify char as raw hex.
// Requires a connected device with a prior `dump`.

// A streamable notify characteristic, for a "which notifications?" picker.
struct StreamSource {
  uint16_t    handle;       // characteristic value handle (stable key)
  std::string label;        // friendly name, e.g. "Heart Rate", "HID keyboard"
  bool        defaultOn;    // sensible default for the picker
};

// Enumerate the connected device's streamable notify characteristics (from the
// dump cache). Empty if not connected / not dumped.
std::vector<StreamSource> streamSources();

// Subscribe to the given characteristic handles and start streaming. Returns
// false if none could be subscribed.
bool streamStart(const std::vector<uint16_t>& handles);

// Convenience: stream every defaultOn source (used by the serial CLI).
bool streamStart();

void streamStop();
bool streamActive();

// UI access to the live decoded-line ring buffer (also printed to Serial).
// streamSeq() bumps on each new line; streamLine(i) indexes oldest..newest.
uint32_t streamSeq();
size_t   streamLineCount();
const std::string& streamLine(size_t i);

}
