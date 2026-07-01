// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#include "oui_db.h"

#include <FS.h>
#include <LittleFS.h>
#include <map>
#include <stdio.h>

// On-disk format (little-endian), produced by tools/make_oui_bin.py from the
// Wireshark `manuf` registry:
//
//   magic   "OUI2"                       (4 bytes)
//   count   uint32                       (4 bytes)
//   index   count * { oui[3], off[3] }   sorted ascending by oui (24-bit big-endian
//                                         value packed LE), one fixed 6-byte record
//                                         per OUI  ->  record offset = 8 + i*6
//   names   concatenated NUL-terminated UTF-8 strings; `off` is the byte offset of
//           a name within this blob (names are de-duplicated, so several OUIs may
//           share one offset)
//
// Lookup is a binary search directly on the file: each probe is one seek + 6-byte
// read, then one seek + read of the matched name. Nothing but the open File handle
// and a small result cache lives in RAM.
namespace oui_db {

namespace {
fs::FS*  g_fs = nullptr;
File     g_file;
bool     g_ok = false;
uint32_t g_count = 0;
uint32_t g_namesStart = 0;

// Bounded result cache. fingerprint::identify() runs per visible row every frame,
// so without this the device list would hammer the SD card with binary searches.
// Stores hits AND misses ("") so unknown OUIs aren't re-searched each frame.
std::map<uint32_t, std::string> g_cache;
constexpr size_t kCacheCap = 128;

uint32_t rd3(const uint8_t* b) { return (uint32_t)b[0] | (b[1] << 8) | (b[2] << 16); }

// Binary search the on-file index; "" on miss / read error.
std::string searchFile(uint32_t oui24) {
    int lo = 0, hi = (int)g_count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        uint8_t rec[6];
        if (!g_file.seek(8 + (uint32_t)mid * 6) || g_file.read(rec, 6) != 6) return "";
        uint32_t oui = rd3(rec);
        if (oui == oui24) {
            uint32_t off = rd3(rec + 3);
            if (!g_file.seek(g_namesStart + off)) return "";
            std::string name;
            for (int c; (c = g_file.read()) > 0; ) name += (char)c;   // until NUL/EOF
            return name;
        }
        if (oui < oui24) lo = mid + 1;
        else             hi = mid - 1;
    }
    return "";
}
}  // namespace

void begin(fs::FS& fs, const char* path) {
    g_ok = false;
    g_count = 0;
    g_cache.clear();
    if (g_file) g_file.close();
    g_fs = &fs;

    if (!fs.exists(path)) {
        Serial.printf("[oui] %s not found - vendor lookups disabled (copy oui.bin to the SD card)\n", path);
        return;
    }
    g_file = fs.open(path, "r");
    if (!g_file) {
        Serial.printf("[oui] cannot open %s - vendor lookups disabled\n", path);
        return;
    }
    uint8_t hdr[8];
    if (g_file.read(hdr, 8) != 8 || memcmp(hdr, "OUI2", 4) != 0) {
        Serial.printf("[oui] %s header invalid - vendor lookups disabled\n", path);
        g_file.close();
        return;
    }
    g_count = (uint32_t)hdr[4] | (hdr[5] << 8) | (hdr[6] << 16) | ((uint32_t)hdr[7] << 24);
    g_namesStart = 8 + g_count * 6;
    g_ok = true;
    Serial.printf("[oui] loaded %u OUI entries from %s\n", (unsigned)g_count, path);
}

void init() { begin(LittleFS, "/oui.bin"); }

bool available() { return g_ok; }

std::string lookup(uint32_t oui24) {
    if (!g_ok) return "";
    auto it = g_cache.find(oui24);
    if (it != g_cache.end()) return it->second;   // hit or cached-miss

    std::string name = searchFile(oui24);
    if (g_cache.size() >= kCacheCap) g_cache.clear();   // simple bound; refills cheaply
    g_cache[oui24] = name;
    return name;
}

std::string lookupMac(const std::string& mac) {
    unsigned b0, b1, b2;
    if (sscanf(mac.c_str(), "%2x:%2x:%2x", &b0, &b1, &b2) != 3) return "";
    return lookup((b0 << 16) | (b1 << 8) | b2);
}

}  // namespace oui_db
