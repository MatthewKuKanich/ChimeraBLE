// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#pragma once

#include <Arduino.h>
#include <string>
#include <vector>
#include <string>
#include <vector>

// Phase 8 - peripheral / GATT cloning.
//
// After a `dump` of a connected device, capture its attribute table + advertising
// data into a profile (saved to LittleFS as JSON), then re-expose it as a BLE
// peripheral. Useful for impersonation testing and replaying a captured device
// to a host.
//
// The clone spoofs the target's MAC by overriding the controller's BT address
// before init (esp_iface_mac_addr_set), so `clone advertise` reboots once to
// apply it; advertising payload (name, service UUIDs, mfr data) is replayed
// verbatim too.
//
// The GAP service (0x1800) is owned by the stack and can't be recreated, but the
// target's Device Name (0x2A00) and Appearance (0x2A01) are pushed into the
// stack's GAP service so a connecting host reads the target's identity.
//
// Limitations:
//   - Cloned characteristics use open access (no encryption). Hosts that require
//     an encrypted/bonded link to the original may behave differently.
//   - GATT (0x1801) service and the CCCD (0x2902) are stack-provided and skipped.
//   - 0x1800 handle numbers and config-only chars (PPCP 0x2A04, Central Address
//     Resolution 0x2AA6) follow the stack's build, not the target's exact layout.
namespace fs { class FS; }   // forward-decl so includers don't need <FS.h>

namespace clone {

void init();

// Storage backend for profiles + the reboot markers (.active/.mitm). Defaults to
// LittleFS (on-chip flash). On a board with a microSD card (e.g. Cardputer), call
// setStorage(&SD, "/clones") BEFORE applyBootSpoof()/init() so profiles live on
// the card; with no card it stays on LittleFS automatically. All clone/MITM file
// I/O goes through this backend so save -> reboot -> load stays consistent.
void        setStorage(fs::FS* fs, const char* dir);
fs::FS&     storageFs();      // active backend (LittleFS unless redirected)
const char* storageDir();     // active profile directory ("/clones")
bool        storageIsSd();    // true once redirected off LittleFS

// Call BEFORE NimBLEDevice::init(). The BT controller latches its public address
// at init time, so spoofing the target's MAC must happen first. If a previous
// `clone advertise` requested a MAC change (it reboots to apply it), this loads
// that profile, sets the controller's BT MAC to the target's, and returns true
// so the caller can auto-advertise once the stack is up. Returns false otherwise.
bool applyBootSpoof();

// Serialize the dumped GATT snapshot + captured adv data to /clones/<name>.json.
// Works from the offline snapshot (requires gatt::hasCache()), so it still
// succeeds after the device drops the link - a prior connect + dump is the only
// requirement.
bool save(const char* name);

void list();
bool remove(const char* name);

// Saved profile base names (no path/extension), for a UI menu.
std::vector<std::string> listNames();

// Load a saved profile into memory (does not start advertising).
bool load(const char* name);
void info();
bool hasLoaded();

// Loaded-profile summary for a UI (empty / 0 if none loaded).
const std::string& loadedName();
size_t loadedServiceCount();

// Bring up a NimBLEServer mirroring the loaded profile and start advertising.
// Disconnects any active central link first.
bool advertise();

// Tear down the server and stop advertising.
void stop();
bool isAdvertising();

// ---- Honeypot: observe what a connected host does to the clone ----
// Clone server/characteristic callbacks (BLE host task) push event lines into a
// mutex-guarded queue. The UI (main task) drains it for display + SD logging.

// Increments each time a host connects - the UI watches this to auto-open the
// Honeypot screen and start a fresh SD log.
uint32_t hostConnSeq();
bool     hostConnected();

// Move all queued event lines into `out` (clears the queue). Main-task safe.
void drainHoneypot(std::vector<std::string>& out);

// Name of the currently loaded/advertised profile (for log headers).
std::string activeName();

// Read-only view of a loaded profile's GATT structure, for an external mirror
// builder (the MITM proxy). Populated by load().
struct MirrorDesc { std::string uuid; std::vector<uint8_t> value; };
struct MirrorChar { std::string uuid; uint8_t props; std::vector<uint8_t> value; std::vector<MirrorDesc> descs; };
struct MirrorSvc  { std::string uuid; std::vector<MirrorChar> chars; };
const std::vector<MirrorSvc>& loadedMirror();
std::string loadedAddr();

// Push a line into the honeypot event stream (also mirrored to serial). Lets
// other modules (e.g. the MITM proxy) feed the same Honeypot screen + SD log.
void honeypotLog(const std::string& line);

// Mark host connect/disconnect for the Honeypot auto-open (bumps hostConnSeq on
// connect). Used by peripheral server callbacks outside this module.
void honeypotSetHostConnected(bool connected);

}
