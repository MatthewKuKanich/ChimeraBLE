// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#include "scanner.h"

#include "adv_parser.h"
#include "fingerprint.h"
#include "hexdump.h"
#include "log.h"

#include <algorithm>
#include <math.h>

namespace scanner {

static std::vector<Result> g_results;
static bool g_scanning = false;
static volatile bool g_scan_report = false;   // scan finished; print from main task
static volatile bool g_results_dirty = false; // new/updated result; resort on main task

// ---- foxhunt (live RSSI tracking of one device) ----
static bool        g_foxhunt = false;
static std::string g_fox_target;          // lowercase MAC
static std::string g_fox_name;
static int         g_fox_peak = -127;     // strongest seen
static int         g_fox_last = -127;     // last displayed (for trend)
static int         g_fox_window_max = -127;  // peak-hold within the print window
static uint32_t    g_fox_count = 0;
static uint32_t    g_fox_last_print = 0;
static uint32_t    g_fox_seen = 0;        // millis of last advert from target
static uint32_t    g_fox_wd = 0;          // watchdog: last scan-alive check
static uint8_t     g_fox_addr_type = 0;   // target address type (for whitelist)

// Foxhunt bar scaling - a BLEND of two normalized fills over the [kFoxLo,kFoxHi]
// window so it's useful both far and near:
//   * dBm-linear term: moves steadily with distance (log-distance), so the bar
//     fills early/far out and gives "warmer/colder" feedback across a room.
//   * power-linear term (10^(dBm/10)): each +3 dB ~doubles its contribution, so
//     increments grow as you close in - the big jumps that let you pinpoint.
// kFoxBlend weights them (0 = pure dBm, 1 = pure power). kFoxHi (≈ right next to
// the device) = full bar; kFoxLo = empty.
static constexpr int   kFoxHi    = -20;   // dBm -> full bar
static constexpr int   kFoxLo    = -95;   // dBm -> empty
static constexpr float kFoxBlend = 0.5f;  // power vs dBm mix
static constexpr int   kBarW     = 32;    // bar cells (eighth-block sub-resolution)

// Render a 0..1 fraction as a kBarW-wide bar using Unicode eighth-blocks
// (U+2588 full .. U+258F one-eighth) for sub-character precision. out needs
// kBarW*3 + 1 bytes (each block char is 3 UTF-8 bytes).
static void renderBar(float frac, char* out) {
    if (frac < 0) frac = 0;
    if (frac > 1) frac = 1;
    int eighths = (int)lroundf(frac * kBarW * 8);
    int full = eighths / 8;
    int rem  = eighths % 8;
    char* p = out;
    for (int i = 0; i < kBarW; i++) {
        if (i < full) {                         // full block U+2588
            *p++ = (char)0xE2; *p++ = (char)0x96; *p++ = (char)0x88;
        } else if (i == full && rem > 0) {      // partial: U+2588 + (8-rem)
            uint16_t cp = 0x2588 + (8 - rem);   // 0x2589(7/8) .. 0x258F(1/8)
            *p++ = (char)(0xE0 | (cp >> 12));
            *p++ = (char)(0x80 | ((cp >> 6) & 0x3F));
            *p++ = (char)(0x80 | (cp & 0x3F));
        } else {
            *p++ = ' ';
        }
    }
    *p = '\0';
}

static void foxReport(int rssi) {
    g_fox_count++;
    if (rssi > g_fox_peak) g_fox_peak = rssi;

    // dBm-linear fill: steady with distance (fills far out).
    float fDb = (float)(rssi - kFoxLo) / (float)(kFoxHi - kFoxLo);
    // power-linear fill: explosive in the endgame (big jumps up close).
    float pLo = powf(10.f, kFoxLo / 10.f);
    float pHi = powf(10.f, kFoxHi / 10.f);
    float pRs = powf(10.f, rssi   / 10.f);
    float fPw = (pRs - pLo) / (pHi - pLo);
    // Blend.
    float frac = kFoxBlend * fPw + (1.f - kFoxBlend) * fDb;

    char bar[kBarW * 3 + 1];
    renderBar(frac, bar);

    const char* trend = "...";
    if (g_fox_last != -127) {
        if (rssi >= g_fox_last + 3)      trend = "closer";
        else if (rssi <= g_fox_last - 3) trend = "farther";
    }
    Serial.printf("[fox] %4d dBm  [%s]  peak %d  %s\n", rssi, bar, g_fox_peak, trend);
    g_fox_last = rssi;
}

// Sort strongest-first and renumber idx 0..N so `list` reads nearest→farthest
// and connect/info indices line up. Called once when scanning finishes, so the
// indices stay stable across later `list`/`connect` calls.
static void sortByRssiDesc() {
    std::sort(g_results.begin(), g_results.end(),
              [](const Result& a, const Result& b) { return a.rssi > b.rssi; });
    for (size_t i = 0; i < g_results.size(); i++) g_results[i].idx = (int)i;
}

static int findIndexByAddr(const std::string& addr) {
    for (size_t i = 0; i < g_results.size(); i++) {
        if (g_results[i].addr == addr) return (int)i;
    }
    return -1;
}

class ScanCb : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice* dev) override {
        std::string addr = dev->getAddress().toString();

        // Foxhunt mode: only care about the target; report its RSSI with peak-hold
        // throttling (~4 Hz) so fast advertisers don't flood the console.
        if (g_foxhunt) {
            std::string a = addr;
            for (auto& c : a) c = (char)tolower((unsigned char)c);
            if (a == g_fox_target) {
                int rssi = dev->getRSSI();
                g_fox_seen = millis();
                if (rssi > g_fox_window_max) g_fox_window_max = rssi;
                uint32_t now = millis();
                if (now - g_fox_last_print >= 250) {
                    foxReport(g_fox_window_max);
                    g_fox_window_max = -127;
                    g_fox_last_print = now;
                }
            }
            return;
        }

        int existing = findIndexByAddr(addr);

        Result* r;
        if (existing >= 0) {
            r = &g_results[existing];
            r->rssi = dev->getRSSI();
            if (!dev->getName().empty()) {
                r->name = dev->getName();
            }
        } else {
            Result nr;
            nr.idx       = (int)g_results.size();
            nr.addr      = addr;
            nr.name      = dev->getName();
            nr.rssi      = dev->getRSSI();
            nr.addr_type = dev->getAddressType();
            g_results.push_back(nr);
            r = &g_results.back();
        }

        const std::vector<uint8_t>& payload = dev->getPayload();
        if (!payload.empty()) {
            r->adv_payload = payload;
        }
        g_results_dirty = true;   // main task will resort by RSSI (see poll())
    }

    void onScanEnd(const NimBLEScanResults&, int) override {
        if (g_foxhunt) return;   // foxhunt manages its own lifecycle
        g_scanning = false;
        // Sorting + the "done" print both run on the main task (poll()) - never
        // from this host-task callback (avoids racing the main task's reads/draws).
        g_results_dirty = true;
        g_scan_report = true;
    }
};

static ScanCb g_scanCb;

void init() {
    auto* scan = NimBLEDevice::getScan();
    scan->setScanCallbacks(&g_scanCb, false);
    scan->setActiveScan(true);
    scan->setInterval(45);
    scan->setWindow(15);
}

void start(uint32_t duration_secs) {
    if (g_scanning) {
        Serial.println("[scan] already scanning");
        return;
    }
    clear();
    g_results.reserve(128);   // avoid reallocation while the main task reads/sorts mid-scan
    g_results_dirty = false;
    g_scanning = true;
    Serial.printf("[scan] starting %u second active scan...\n", (unsigned)duration_secs);
    NimBLEDevice::getScan()->start(duration_secs * 1000, false, true);
}

void stop() {
    if (!g_scanning) return;
    NimBLEDevice::getScan()->stop();
    g_scanning = false;
    sortByRssiDesc();   // in case onScanEnd doesn't fire on manual stop
    Serial.println("[scan] stopped");
}

bool foxhuntActive() { return g_foxhunt; }

bool foxhuntStart(const std::string& addr, uint8_t addr_type, const std::string& name) {
    if (g_scanning) {
        Serial.println("[fox] busy scanning/hunting - 'stop' first");
        return false;
    }
    g_fox_target = addr;
    for (auto& c : g_fox_target) c = (char)tolower((unsigned char)c);
    g_fox_name = name;
    g_fox_addr_type = addr_type;
    g_fox_peak = -127; g_fox_last = -127; g_fox_window_max = -127;
    g_fox_count = 0; g_fox_last_print = 0; g_fox_seen = millis(); g_fox_wd = millis();

    // Whitelist the target and tell the controller to only report whitelisted
    // devices. This is the key to a stable continuous hunt: NimBLE only ever
    // processes the target, so its internal device vector never grows (no leak),
    // and the target stays resident so duplicate-unfiltered scanning keeps
    // reporting it. No periodic restart needed (restarting re-filters duplicates
    // and gives only one reading per restart).
    NimBLEDevice::whiteListAdd(NimBLEAddress(g_fox_target, addr_type));

    auto* scan = NimBLEDevice::getScan();
    scan->setScanCallbacks(&g_scanCb, true);   // want duplicate advertisements
    scan->setDuplicateFilter(0);               // report every advert, not just first
    scan->setFilterPolicy(BLE_HCI_SCAN_FILT_USE_WL);  // only whitelisted (the target)
    // PASSIVE scan: report every ADV_IND immediately. Active scanning would hold a
    // scannable device on a waiting list pending its scan response, throttling and
    // dropping RSSI updates. RSSI is in the advert itself, so passive is denser.
    scan->setActiveScan(false);
    scan->setInterval(160);                    // 100ms interval, ...
    scan->setWindow(160);                      // ...100% duty cycle to hear more

    g_foxhunt = true;
    g_scanning = true;
    if (name.empty())
        Serial.printf("\n[fox] hunting %s - move around, stronger = closer. Type 'stop' to end.\n",
                      g_fox_target.c_str());
    else
        Serial.printf("\n[fox] hunting %s (%s) - move around, stronger = closer. Type 'stop' to end.\n",
                      g_fox_target.c_str(), name.c_str());
    scan->start(0, false, true);               // continuous until stopped
    return true;
}

void foxhuntStop() {
    if (!g_foxhunt) { Serial.println("[fox] not active"); return; }
    auto* scan = NimBLEDevice::getScan();
    scan->stop();
    g_foxhunt = false;
    g_scanning = false;
    // Restore normal scan configuration and clear the whitelist filter.
    scan->setFilterPolicy(BLE_HCI_SCAN_FILT_NO_WL);
    NimBLEDevice::whiteListRemove(NimBLEAddress(g_fox_target, g_fox_addr_type));
    scan->setScanCallbacks(&g_scanCb, false);
    scan->setDuplicateFilter(1);
    scan->setInterval(45);
    scan->setWindow(15);
    Serial.printf("[fox] stopped. peak %d dBm over %u reading(s).\n",
                  g_fox_peak, (unsigned)g_fox_count);
}

void poll() {
    // Live RSSI sort on the main task: as results arrive (host-task callback sets
    // g_results_dirty), resort strongest-first so the list populates nearest-first
    // during the scan, not just after. Throttled so a burst of adverts doesn't
    // resort every loop (and to keep the list from churning too fast to read).
    if (g_results_dirty) {
        static uint32_t lastSortMs = 0;
        uint32_t now = millis();
        if (now - lastSortMs >= 300) {
            sortByRssiDesc();
            g_results_dirty = false;
            lastSortMs = now;
        }
    }

    // Print the deferred scan-complete line here, on the main task, so it never
    // races the host-task Serial writes (which dropped it ~20% of the time).
    if (g_scan_report) {
        g_scan_report = false;
        if (log_out::isJson()) {
            Serial.printf("{\"ev\":\"scan_end\",\"t\":%lu,\"count\":%u}\n",
                          (unsigned long)millis(), (unsigned)g_results.size());
        } else {
            Serial.printf("[scan] done. %u device(s) found. Type 'list' to see them.\n",
                          (unsigned)g_results.size());
        }
    }
}

void foxhuntPoll() {
    if (!g_foxhunt) return;
    uint32_t now = millis();
    // Watchdog: re-arm ONLY if the scan actually stopped. We don't restart on a
    // timer - a restart re-filters duplicates and yields just one reading per
    // restart. The whitelist keeps the scan leak-free, so it should run forever.
    if (now - g_fox_wd > 1000) {
        g_fox_wd = now;
        if (!NimBLEDevice::getScan()->isScanning()) {
            NimBLEDevice::getScan()->start(0, false, true);
        }
    }
    // Only flag a genuine dropout (4 s+), and report how long it's been rather
    // than spamming - many connectable devices advertise only every 1-2 s.
    if (now - g_fox_seen > 4000 && now - g_fox_last_print > 3000) {
        Serial.printf("[fox]  --- no signal for %lus (out of range / not advertising) ---\n",
                      (unsigned long)((now - g_fox_seen) / 1000));
        g_fox_last_print = now;
    }
}

int      foxhuntLastRssi()      { return g_fox_last; }
int      foxhuntPeakRssi()      { return g_fox_peak; }
uint32_t foxhuntCount()         { return g_fox_count; }
uint32_t foxhuntSinceSeenMs()   { return millis() - g_fox_seen; }
const std::string& foxhuntName()   { return g_fox_name; }
const std::string& foxhuntTarget() { return g_fox_target; }

bool isScanning() { return g_scanning; }

const std::vector<Result>& results() { return g_results; }

void clear() { g_results.clear(); }

const Result* findByIndex(int idx) {
    if (idx < 0 || (size_t)idx >= g_results.size()) return nullptr;
    return &g_results[idx];
}

const Result* findByMac(const char* mac) {
    std::string m(mac);
    for (auto& r : m) r = (char)tolower((unsigned char)r);
    for (const auto& r : g_results) {
        std::string a = r.addr;
        for (auto& c : a) c = (char)tolower((unsigned char)c);
        if (a == m) return &r;
    }
    return nullptr;
}

static void emitDeviceJson(const Result& r) {
    Serial.printf("{\"ev\":\"device\",\"t\":%lu,\"idx\":%d,\"mac\":\"%s\",\"addr_type\":%u,\"rssi\":%d,\"name\":\"",
                  (unsigned long)millis(), r.idx, r.addr.c_str(), r.addr_type, r.rssi);
    log_out::jsonEscape(r.name.c_str());
    Serial.print("\",\"guess\":\"");
    log_out::jsonEscape(fingerprint::identify(r.addr, r.addr_type, r.adv_payload).c_str());
    Serial.print("\"");
    if (!r.adv_payload.empty()) {
        Serial.print(",");
        log_out::jsonHexField("adv", r.adv_payload.data(), r.adv_payload.size());
    }
    Serial.println("}");
}

void printList() {
    if (g_results.empty()) {
        if (!log_out::isJson()) Serial.println("[scan] no results. Run 'scan' first.");
        return;
    }
    if (log_out::isJson()) {
        for (const auto& r : g_results) emitDeviceJson(r);
        return;
    }
    Serial.printf("\n%3s  %-17s  %-4s  %-3s  %s\n",
                  "idx", "address", "rssi", "adv", "name / guess");
    Serial.println("---  -----------------  ----  ---  --------------------------------");
    for (const auto& r : g_results) {
        std::string guess = fingerprint::identify(r.addr, r.addr_type, r.adv_payload);
        std::string tag   = fingerprint::addrTag(r.addr, r.addr_type);
        // No name -> show the guess (prefixed '~' to mark it inferred). Has a
        // name -> show it, plus the guess after '|' when it adds something (many
        // self-reported names are cryptic, e.g. "Vertuo_DV6_..." is a Nespresso).
        std::string disp;
        if (r.name.empty()) {
            disp = "~" + guess;
        } else {
            disp = r.name;
            if (guess != "unknown") disp += "  |  " + guess;
        }
        disp += tag;
        Serial.printf("%3d  %-17s  %4d  %3u  %s\n",
                      r.idx, r.addr.c_str(), r.rssi,
                      (unsigned)r.adv_payload.size(), disp.c_str());
    }
    Serial.println();
}

void printInfo(const Result& r) {
    if (log_out::isJson()) { emitDeviceJson(r); return; }
    Serial.printf("\n[device %d]\n", r.idx);
    Serial.printf("  address    : %s (type=%u)\n", r.addr.c_str(), r.addr_type);
    Serial.printf("  name       : %s\n", r.name.empty() ? "(none)" : r.name.c_str());
    Serial.printf("  rssi       : %d dBm\n", r.rssi);
    if (!r.adv_payload.empty()) {
        hexdump::line("adv_payload", r.adv_payload.data(), r.adv_payload.size(), "  ");
        Serial.println("  decoded:");
        adv_parser::decode(r.adv_payload.data(), r.adv_payload.size(), "    ");
    }
    if (!r.scan_response.empty()) {
        hexdump::line("scan_resp", r.scan_response.data(), r.scan_response.size(), "  ");
    }
    fingerprint::describe(r.addr, r.addr_type, r.adv_payload);
    Serial.println();
}

}
