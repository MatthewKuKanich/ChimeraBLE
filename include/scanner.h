// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#pragma once

#include <Arduino.h>
#include <NimBLEDevice.h>
#include <string>
#include <vector>

namespace scanner {

struct Result {
    int     idx;
    std::string addr;
    std::string name;
    int     rssi;
    std::vector<uint8_t> adv_payload;
    std::vector<uint8_t> scan_response;
    uint8_t addr_type;
};

void init();

void start(uint32_t duration_secs);

void stop();

bool isScanning();

// Call from the main loop. Emits the deferred "scan complete" line (printing it
// from the host-task callback races Serial and drops output intermittently).
void poll();

// Foxhunt: continuously track one device's RSSI (for RF direction finding).
// Streams a live signal-strength bar until stopped. addr is a MAC string;
// addr_type is the BLE address type (for the controller whitelist filter).
bool foxhuntStart(const std::string& addr, uint8_t addr_type, const std::string& name);
void foxhuntStop();
bool foxhuntActive();
void foxhuntPoll();   // call from the main loop (emits a "no signal" note on dropout)

// Live foxhunt readouts for a UI (last/peak RSSI in dBm, reading count, ms since
// last advert from the target). last/peak are -127 before the first reading.
int      foxhuntLastRssi();
int      foxhuntPeakRssi();
uint32_t foxhuntCount();
uint32_t foxhuntSinceSeenMs();
const std::string& foxhuntName();
const std::string& foxhuntTarget();

const std::vector<Result>& results();

void clear();

const Result* findByIndex(int idx);
const Result* findByMac(const char* mac);

void printList();

void printInfo(const Result& r);

}
