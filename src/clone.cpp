// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#include "clone.h"

#include "connection.h"
#include "gatt.h"
#include "scanner.h"

#include <ArduinoJson.h>
#include <LittleFS.h>
#include <NimBLEDevice.h>
#include <esp_mac.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#include <atomic>
#include <cstring>
#include <stdio.h>
#include <string>
#include <vector>

// NimBLE host C API for the stack-provided GAP service (0x1800). Declared here
// rather than including the host header, whose path differs between the bundled
// NimBLE (classic ESP32) and the IDF NimBLE (C5/C6/...). The symbols link on both.
extern "C" {
int ble_svc_gap_device_name_set(const char* name);
int ble_svc_gap_device_appearance_set(uint16_t appearance);
}

namespace clone {

namespace {

constexpr const char* kDir = "/clones";

// Active storage backend (see clone::setStorage). Defaults to on-chip LittleFS;
// the app redirects this to an SD card when one is mounted.
fs::FS*     g_fs  = &LittleFS;
std::string g_dir = kDir;
bool        g_isSd = false;

struct PDesc { std::string uuid; std::vector<uint8_t> value; };
struct PChar { std::string uuid; uint8_t props; std::vector<uint8_t> value; std::vector<PDesc> descs; };
struct PSvc  { std::string uuid; std::vector<PChar> chars; };

struct Profile {
    bool        loaded = false;
    std::string name;
    std::string addr;
    std::vector<uint8_t> adv;
    std::vector<PSvc>    svcs;
};

Profile        g_profile;
std::vector<MirrorSvc> g_mirror;     // read-only view of g_profile for the MITM proxy
NimBLEServer*  g_server = nullptr;
bool           g_advertising = false;

// Honeypot event queue (host-task producers -> main-task consumer).
SemaphoreHandle_t        g_hpMux = nullptr;
std::vector<std::string> g_hpQueue;
// Cross-task honeypot signals: written from the BLE host-task server callbacks,
// read from the main task. std::atomic gives correct cross-task visibility (and a
// non-deprecated ++), which plain volatile does not.
std::atomic<bool>        g_hostConnected{false};
std::atomic<uint32_t>    g_hostConnSeq{0};

void hpPush(const std::string& s) {
    Serial.println(s.c_str());          // always mirror to serial
    if (!g_hpMux) return;
    xSemaphoreTake(g_hpMux, portMAX_DELAY);
    if (g_hpQueue.size() < 256) g_hpQueue.push_back(s);   // bound memory
    xSemaphoreGive(g_hpMux);
}
bool           g_built = false;          // GATT table has been constructed
std::string    g_built_name;             // which profile the server was built from
std::string    g_reboot_done_for;        // profile we already rebooted-to-spoof this boot

bool parseMac(const std::string& s, uint8_t out[6]) {
    unsigned v[6];
    if (sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) {
        return false;
    }
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)v[i];
    return true;
}

// ---- hex helpers ----

std::string bytesToHex(const std::vector<uint8_t>& v) {
    std::string s;
    char buf[4];
    for (size_t i = 0; i < v.size(); i++) {
        snprintf(buf, sizeof(buf), "%s%02x", i ? " " : "", v[i]);
        s += buf;
    }
    return s;
}

int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::vector<uint8_t> hexToBytes(const char* s) {
    std::vector<uint8_t> out;
    if (!s) return out;
    while (*s) {
        while (*s == ' ' || *s == ':' || *s == '-' || *s == ',') s++;
        if (!*s) break;
        int hi = hexNibble(*s++);
        if (hi < 0 || !*s) break;
        int lo = hexNibble(*s++);
        if (lo < 0) break;
        out.push_back((uint8_t)((hi << 4) | lo));
    }
    return out;
}

// ---- uuid storage ----

std::string uuidToStorage(const NimBLEUUID& uuid) {
    if (uuid.bitSize() == 16) {
        const uint8_t* b = uuid.getValue();
        char buf[8];
        snprintf(buf, sizeof(buf), "%04x", (unsigned)(b[0] | (b[1] << 8)));
        return buf;
    }
    return uuid.toString();
}

// ---- property letter string <-> byte ----
// Letter layout matches gatt::propsString(): R W w N I B

uint8_t propsFromLetters(const char* s) {
    uint8_t p = 0;
    if (!s) return p;
    for (; *s; s++) {
        switch (*s) {
            case 'R': p |= BLE_GATT_CHR_PROP_READ;          break;
            case 'W': p |= BLE_GATT_CHR_PROP_WRITE;         break;
            case 'w': p |= BLE_GATT_CHR_PROP_WRITE_NO_RSP;  break;
            case 'N': p |= BLE_GATT_CHR_PROP_NOTIFY;        break;
            case 'I': p |= BLE_GATT_CHR_PROP_INDICATE;      break;
            case 'B': p |= BLE_GATT_CHR_PROP_BROADCAST;     break;
            default: break;
        }
    }
    return p;
}

uint16_t propsToNimble(uint8_t p) {
    uint16_t n = 0;
    if (p & BLE_GATT_CHR_PROP_READ)         n |= NIMBLE_PROPERTY::READ;
    if (p & BLE_GATT_CHR_PROP_WRITE)        n |= NIMBLE_PROPERTY::WRITE;
    if (p & BLE_GATT_CHR_PROP_WRITE_NO_RSP) n |= NIMBLE_PROPERTY::WRITE_NR;
    if (p & BLE_GATT_CHR_PROP_NOTIFY)       n |= NIMBLE_PROPERTY::NOTIFY;
    if (p & BLE_GATT_CHR_PROP_INDICATE)     n |= NIMBLE_PROPERTY::INDICATE;
    if (p & BLE_GATT_CHR_PROP_BROADCAST)    n |= NIMBLE_PROPERTY::BROADCAST;
    return n;
}

bool isGapOrGatt(const std::string& u) { return u == "1800" || u == "1801"; }
bool isCccd(const std::string& u)      { return u == "2902"; }

std::string pathFor(const char* name) {
    return g_dir + "/" + name + ".json";
}
std::string activePath() { return g_dir + "/.active"; }

// ---- Peripheral (clone) callbacks ----------------------------------------
// Make the clone actually connectable + observable: handle pairing like the
// real device (auto-accept numeric comparison) and LOG how the host drives it
// (connects, subscribes, writes, reads) - the latter reveals device behavior.

class CloneCharCb : public NimBLECharacteristicCallbacks {
    void onSubscribe(NimBLECharacteristic* c, NimBLEConnInfo&, uint16_t sub) override {
        const char* what = (sub == 0) ? "UNSUB" : (sub & 2) ? "INDICATE" : "NOTIFY";
        char buf[80];
        snprintf(buf, sizeof(buf), "%6lus %s h=0x%04X %s",
                 (unsigned long)(millis() / 1000), what, c->getHandle(),
                 c->getUUID().toString().c_str());
        hpPush(buf);
    }
    void onWrite(NimBLECharacteristic* c, NimBLEConnInfo&) override {
        NimBLEAttValue v = c->getValue();
        std::string s;
        char buf[80];
        snprintf(buf, sizeof(buf), "%6lus WRITE h=0x%04X %s: ",
                 (unsigned long)(millis() / 1000), c->getHandle(),
                 c->getUUID().toString().c_str());
        s = buf;
        for (size_t i = 0; i < v.size() && i < 24; i++) {
            snprintf(buf, sizeof(buf), "%02X ", v.data()[i]);
            s += buf;
        }
        hpPush(s);
    }
    void onRead(NimBLECharacteristic* c, NimBLEConnInfo&) override {
        char buf[80];
        snprintf(buf, sizeof(buf), "%6lus READ  h=0x%04X %s",
                 (unsigned long)(millis() / 1000), c->getHandle(),
                 c->getUUID().toString().c_str());
        hpPush(buf);
    }
};

class CloneServerCb : public NimBLEServerCallbacks {
    void onConnect(NimBLEServer*, NimBLEConnInfo& info) override {
        g_hostConnected = true;
        g_hostConnSeq++;
        hpPush(std::string("HOST CONNECTED ") + info.getAddress().toString().c_str());
    }
    void onDisconnect(NimBLEServer*, NimBLEConnInfo&, int reason) override {
        g_hostConnected = false;
        char buf[48];
        snprintf(buf, sizeof(buf), "host disconnected reason=0x%04X", reason);
        hpPush(buf);
    }
    void onMTUChange(uint16_t mtu, NimBLEConnInfo&) override {
        char buf[32]; snprintf(buf, sizeof(buf), "MTU=%u", mtu); hpPush(buf);
    }
    // Numeric Comparison (what the Mac uses for a HID keyboard): auto-accept so
    // pairing completes (the whole point of an emulated device).
    void onConfirmPassKey(NimBLEConnInfo& info, uint32_t pin) override {
        char buf[48]; snprintf(buf, sizeof(buf), "NUMERIC CMP %06u (auto-accept)", (unsigned)pin);
        hpPush(buf);
        NimBLEDevice::injectConfirmPasskey(info, true);
    }
    // Passkey Entry: host wants to type a code we display. Use a fixed one.
    uint32_t onPassKeyDisplay() override {
        hpPush("PASSKEY ENTRY: enter 123456 on host");
        return 123456;
    }
    void onAuthenticationComplete(NimBLEConnInfo& info) override {
        char buf[48];
        snprintf(buf, sizeof(buf), "pairing done encrypted=%d bonded=%d",
                 info.isEncrypted(), info.isBonded());
        hpPush(buf);
    }
};

CloneServerCb g_serverCb;
CloneCharCb   g_charCb;

// The GAP service (0x1800) is owned by the NimBLE stack, so we can't recreate it
// as an app service. Instead we push the target's captured Device Name (0x2A00)
// and Appearance (0x2A01) into the stack's GAP service, so a host that connects
// and reads them sees the target's identity, not the ESP32 default. Must run
// after NimBLEDevice::init() (the GAP service is registered there).
void applyGapIdentity() {
    for (const auto& s : g_profile.svcs) {
        if (s.uuid != "1800") continue;
        for (const auto& c : s.chars) {
            if (c.uuid == "2a00" && !c.value.empty()) {
                std::string name(c.value.begin(), c.value.end());
                ble_svc_gap_device_name_set(name.c_str());
                Serial.printf("[clone] GAP 0x2A00 Device Name = '%s'\n", name.c_str());
            } else if (c.uuid == "2a01" && c.value.size() >= 2) {
                uint16_t app = (uint16_t)(c.value[0] | (c.value[1] << 8));
                ble_svc_gap_device_appearance_set(app);
                Serial.printf("[clone] GAP 0x2A01 Appearance = 0x%04X\n", app);
            }
        }
        return;
    }
}

} // anonymous namespace

void setStorage(fs::FS* fs, const char* dir) {
    if (!fs) return;
    g_fs   = fs;
    g_dir  = (dir && *dir) ? dir : kDir;
    g_isSd = (g_fs != static_cast<fs::FS*>(&LittleFS));
    if (!g_fs->exists(g_dir.c_str())) g_fs->mkdir(g_dir.c_str());
    Serial.printf("[clone] storage = %s dir=%s\n", g_isSd ? "SD" : "LittleFS", g_dir.c_str());
}
fs::FS&     storageFs()  { return *g_fs; }
const char* storageDir() { return g_dir.c_str(); }
bool        storageIsSd() { return g_isSd; }

void init() {
    if (!g_fs->exists(g_dir.c_str())) g_fs->mkdir(g_dir.c_str());
    if (!g_hpMux) g_hpMux = xSemaphoreCreateMutex();
}

uint32_t hostConnSeq() { return g_hostConnSeq; }
bool     hostConnected() { return g_hostConnected; }
std::string activeName() { return g_profile.name; }

void drainHoneypot(std::vector<std::string>& out) {
    if (!g_hpMux) return;
    xSemaphoreTake(g_hpMux, portMAX_DELAY);
    for (auto& s : g_hpQueue) out.push_back(std::move(s));
    g_hpQueue.clear();
    xSemaphoreGive(g_hpMux);
}

void honeypotLog(const std::string& line) { hpPush(line); }

void honeypotSetHostConnected(bool connected) {
    g_hostConnected = connected;
    if (connected) g_hostConnSeq++;
}

bool applyBootSpoof() {
    std::string active = activePath();
    if (!g_fs->exists(active.c_str())) return false;
    File f = g_fs->open(active.c_str(), "r");
    String name = f ? f.readStringUntil('\n') : String();
    if (f) f.close();
    g_fs->remove(active.c_str());      // one-shot: a manual power cycle returns to normal
    name.trim();
    if (name.length() == 0) return false;

    if (!load(name.c_str())) {
        Serial.printf("[clone] boot: pending profile '%s' failed to load\n", name.c_str());
        return false;
    }
    g_reboot_done_for = g_profile.name;

    uint8_t mac[6];
    if (parseMac(g_profile.addr, mac)) {
        esp_err_t e = esp_iface_mac_addr_set(mac, ESP_MAC_BT);
        Serial.printf("[clone] boot: set BT MAC = %s (%s)\n",
                      g_profile.addr.c_str(), e == ESP_OK ? "ok" : "FAILED");
    } else {
        Serial.println("[clone] boot: profile has no usable MAC; advertising with default address");
    }
    return true;
}

bool save(const char* name) {
    // Works from the offline snapshot captured during `dump` - no live link
    // required, so it still works after a device drops an idle connection.
    if (!gatt::hasCache()) {
        Serial.println("[clone] no GATT snapshot - connect to a device and run 'dump' first");
        return false;
    }

    JsonDocument doc;
    std::string peer = gatt::cachedPeer();
    doc["name"] = name;
    doc["addr"] = peer;

    // Replay-able advertising payload, if we captured it during scan.
    const scanner::Result* r = peer.empty() ? nullptr : scanner::findByMac(peer.c_str());
    if (r && !r->adv_payload.empty()) {
        doc["adv"] = bytesToHex(r->adv_payload);
    }

    JsonArray jsvcs = doc["services"].to<JsonArray>();
    char pbuf[8];
    for (const auto& svc : gatt::cache()) {
        JsonObject js = jsvcs.add<JsonObject>();
        js["uuid"] = uuidToStorage(svc.uuid);
        JsonArray jchars = js["chars"].to<JsonArray>();
        for (const auto& ch : svc.chars) {
            JsonObject jc = jchars.add<JsonObject>();
            jc["uuid"]  = uuidToStorage(ch.uuid);
            // Wrap in std::string: ArduinoJson stores const char* by reference,
            // and pbuf is reused each iteration - a raw pointer would alias.
            jc["props"] = std::string(gatt::propsString(ch.props, pbuf, sizeof(pbuf)));
            if (ch.value_cached && !ch.value.empty()) {
                jc["value"] = bytesToHex(ch.value);
            }
            JsonArray jdescs = jc["descs"].to<JsonArray>();
            for (const auto& d : ch.descs) {
                JsonObject jd = jdescs.add<JsonObject>();
                jd["uuid"] = uuidToStorage(d.uuid);
                if (d.value_cached && !d.value.empty()) {
                    jd["value"] = bytesToHex(d.value);
                }
            }
        }
    }

    std::string path = pathFor(name);
    File f = g_fs->open(path.c_str(), "w");
    if (!f) {
        Serial.printf("[clone] cannot open %s for writing\n", path.c_str());
        return false;
    }
    size_t written = serializeJsonPretty(doc, f);
    f.close();
    Serial.printf("[clone] saved '%s' (%u bytes) -> %s\n",
                  name, (unsigned)written, path.c_str());
    return true;
}

void list() {
    File dir = g_fs->open(g_dir.c_str());
    if (!dir || !dir.isDirectory()) {
        Serial.println("[clone] no saved profiles");
        return;
    }
    Serial.println("[clone] saved profiles:");
    int n = 0;
    for (File f = dir.openNextFile(); f; f = dir.openNextFile()) {
        std::string fn = f.name();
        size_t dot = fn.rfind(".json");
        std::string base = (dot != std::string::npos) ? fn.substr(0, dot) : fn;
        Serial.printf("  %-24s  %u bytes\n", base.c_str(), (unsigned)f.size());
        n++;
    }
    if (n == 0) Serial.println("  (none)");
}

std::vector<std::string> listNames() {
    std::vector<std::string> names;
    File dir = g_fs->open(g_dir.c_str());
    if (!dir || !dir.isDirectory()) return names;
    for (File f = dir.openNextFile(); f; f = dir.openNextFile()) {
        std::string fn = f.name();
        size_t slash = fn.rfind('/');
        if (slash != std::string::npos) fn = fn.substr(slash + 1);
        size_t dot = fn.rfind(".json");
        if (dot != std::string::npos) names.push_back(fn.substr(0, dot));
    }
    return names;
}

const std::string& loadedName() { return g_profile.name; }
size_t loadedServiceCount() { return g_profile.loaded ? g_profile.svcs.size() : 0; }

bool remove(const char* name) {
    std::string path = pathFor(name);
    if (!g_fs->exists(path.c_str())) {
        Serial.printf("[clone] no such profile '%s'\n", name);
        return false;
    }
    bool ok = g_fs->remove(path.c_str());
    Serial.printf("[clone] delete '%s': %s\n", name, ok ? "OK" : "FAILED");
    return ok;
}

bool load(const char* name) {
    std::string path = pathFor(name);
    File f = g_fs->open(path.c_str(), "r");
    if (!f) {
        Serial.printf("[clone] no such profile '%s'\n", name);
        return false;
    }
    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, f);
    f.close();
    if (err) {
        Serial.printf("[clone] parse error: %s\n", err.c_str());
        return false;
    }

    Profile p;
    p.name = doc["name"] | name;
    p.addr = doc["addr"] | "";
    const char* advHex = doc["adv"] | "";
    p.adv = hexToBytes(advHex);

    for (JsonObject js : doc["services"].as<JsonArray>()) {
        PSvc svc;
        svc.uuid = js["uuid"] | "";
        for (JsonObject jc : js["chars"].as<JsonArray>()) {
            PChar ch;
            ch.uuid  = jc["uuid"] | "";
            ch.props = propsFromLetters(jc["props"] | "");
            ch.value = hexToBytes(jc["value"] | "");
            for (JsonObject jd : jc["descs"].as<JsonArray>()) {
                PDesc d;
                d.uuid  = jd["uuid"] | "";
                d.value = hexToBytes(jd["value"] | "");
                ch.descs.push_back(d);
            }
            svc.chars.push_back(ch);
        }
        p.svcs.push_back(svc);
    }

    p.loaded = true;
    g_profile = p;

    // Mirror view for the MITM proxy.
    g_mirror.clear();
    for (const auto& s : g_profile.svcs) {
        MirrorSvc ms; ms.uuid = s.uuid;
        for (const auto& c : s.chars) {
            MirrorChar mc; mc.uuid = c.uuid; mc.props = c.props; mc.value = c.value;
            for (const auto& d : c.descs) mc.descs.push_back({d.uuid, d.value});
            ms.chars.push_back(std::move(mc));
        }
        g_mirror.push_back(std::move(ms));
    }

    Serial.printf("[clone] loaded '%s': %u services, adv %u bytes\n",
                  p.name.c_str(), (unsigned)p.svcs.size(), (unsigned)p.adv.size());
    return true;
}

const std::vector<MirrorSvc>& loadedMirror() { return g_mirror; }
std::string loadedAddr() { return g_profile.addr; }

bool hasLoaded() { return g_profile.loaded; }

void info() {
    if (!g_profile.loaded) {
        Serial.println("[clone] no profile loaded");
        return;
    }
    Serial.printf("\n[clone profile] %s\n", g_profile.name.c_str());
    Serial.printf("  origin addr : %s\n", g_profile.addr.c_str());
    Serial.printf("  adv payload : %u bytes\n", (unsigned)g_profile.adv.size());
    Serial.printf("  services    : %u\n", (unsigned)g_profile.svcs.size());
    char pbuf[8];
    for (const auto& s : g_profile.svcs) {
        const char* note = "";
        if (s.uuid == "1800")      note = "  (stack GAP; Device Name + Appearance replicated)";
        else if (s.uuid == "1801") note = "  (stack GATT; skipped)";
        Serial.printf("  SVC %s%s\n", s.uuid.c_str(), note);
        for (const auto& c : s.chars) {
            Serial.printf("    CHR %s  [%s]  value=%u bytes  descs=%u\n",
                          c.uuid.c_str(),
                          gatt::propsString(c.props, pbuf, sizeof(pbuf)),
                          (unsigned)c.value.size(),
                          (unsigned)c.descs.size());
        }
    }
    Serial.println();
}

bool advertise() {
    if (!g_profile.loaded) {
        Serial.println("[clone] no profile loaded - 'clone load <name>' first");
        return false;
    }
    if (g_advertising) {
        Serial.println("[clone] already advertising - 'clone stop' first");
        return false;
    }
    // NimBLE can't cleanly rebuild a GATT table at runtime, so a server is built
    // exactly once per boot. Switching to a different profile needs a reboot.
    if (g_built && g_built_name != g_profile.name) {
        Serial.printf("[clone] server already built from '%s'; reboot to advertise a different profile\n",
                      g_built_name.c_str());
        return false;
    }
    // MAC spoofing: the BT public address is latched at controller init, so to
    // advertise under the target's MAC we set it before init and reboot once.
    // The reboot writes the profile name to the .active marker; applyBootSpoof()
    // consumes it on the next boot. g_reboot_done_for breaks any loop if it fails.
    uint8_t target[6];
    if (parseMac(g_profile.addr, target)) {
        uint8_t cur[6] = {0};
        esp_read_mac(cur, ESP_MAC_BT);
        if (memcmp(cur, target, 6) != 0) {
            if (g_reboot_done_for == g_profile.name) {
                Serial.printf("[clone] WARNING: BT MAC is still not %s after spoof attempt; "
                              "advertising with current address\n", g_profile.addr.c_str());
            } else {
                std::string active = activePath();
                File f = g_fs->open(active.c_str(), "w");
                if (f) { f.print(g_profile.name.c_str()); f.close(); }
                Serial.printf("[clone] rebooting to advertise under target MAC %s ...\n",
                              g_profile.addr.c_str());
                delay(400);
                ESP.restart();
                return false;  // unreached
            }
        }
    }

    if (connection::isConnected()) {
        Serial.println("[clone] dropping central link before switching to peripheral role");
        connection::disconnect();
        delay(200);
    }

    // Populate the stack's GAP service (0x1800) with the target's identity.
    applyGapIdentity();

    int svc_count = 0, chr_count = 0;
    if (!g_built) {
        // Let the clone accept pairing the way the real device does. Numeric
        // Comparison (DisplayYesNo) matches a typical HID host (e.g. macOS); the
        // server callbacks auto-accept it. Without this the host's pairing stalls
        // and the connection hangs forever.
        NimBLEDevice::setSecurityAuth(true /*bond*/, true /*mitm*/, true /*lesc*/);
        NimBLEDevice::setSecurityIOCap(BLE_HS_IO_DISPLAY_YESNO);

        g_server = NimBLEDevice::createServer();
        g_server->setCallbacks(&g_serverCb);
        for (const auto& s : g_profile.svcs) {
            if (isGapOrGatt(s.uuid)) continue;
            bool isHid = (s.uuid == "1812");
            NimBLEService* svc = g_server->createService(NimBLEUUID(s.uuid));
            if (!svc) continue;
            for (const auto& c : s.chars) {
                uint16_t nprops = propsToNimble(c.props);
                if (nprops == 0) nprops = NIMBLE_PROPERTY::READ;
                // HID characteristics require an encrypted link on the real
                // device - mark them so the host pairs before access.
                if (isHid) {
                    if (nprops & NIMBLE_PROPERTY::READ)  nprops |= NIMBLE_PROPERTY::READ_ENC;
                    if (nprops & NIMBLE_PROPERTY::WRITE) nprops |= NIMBLE_PROPERTY::WRITE_ENC;
                }
                NimBLECharacteristic* chr = svc->createCharacteristic(NimBLEUUID(c.uuid), nprops);
                if (!chr) continue;
                chr->setCallbacks(&g_charCb);   // log host reads/writes/subscribes
                if (!c.value.empty()) chr->setValue(c.value.data(), c.value.size());
                for (const auto& d : c.descs) {
                    if (isCccd(d.uuid)) continue;  // stack auto-adds CCCD for notify/indicate
                    NimBLEDescriptor* desc = chr->createDescriptor(
                        NimBLEUUID(d.uuid), NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::WRITE);
                    if (desc && !d.value.empty()) desc->setValue(d.value.data(), d.value.size());
                }
                chr_count++;
            }
            svc_count++;   // NimBLE 2.x auto-starts services with the server (no svc->start())
        }
        g_built = true;
        g_built_name = g_profile.name;
    }

    NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
    if (!g_profile.adv.empty()) {
        // Replay the captured advertising payload verbatim (name, flags, UUIDs,
        // manufacturer data) so the clone looks like the original device.
        NimBLEAdvertisementData advData;
        advData.addData(g_profile.adv.data(), g_profile.adv.size());
        adv->setAdvertisementData(advData);
    } else {
        adv->setName(g_profile.name.c_str());
        for (const auto& s : g_profile.svcs) {
            if (!isGapOrGatt(s.uuid)) adv->addServiceUUID(NimBLEUUID(s.uuid));
        }
    }
    adv->start();
    g_advertising = true;

    uint8_t cur[6] = {0};
    esp_read_mac(cur, ESP_MAC_BT);
    Serial.printf("[clone] advertising as '%s' on MAC %02X:%02X:%02X:%02X:%02X:%02X - %d services, %d characteristics\n",
                  g_profile.name.c_str(),
                  cur[0], cur[1], cur[2], cur[3], cur[4], cur[5],
                  svc_count, chr_count);
    if (!g_profile.addr.empty()) {
        bool match = false;
        uint8_t t[6];
        if (parseMac(g_profile.addr, t)) match = (memcmp(cur, t, 6) == 0);
        Serial.printf("[clone] target MAC %s %s\n", g_profile.addr.c_str(),
                      match ? "(matched)" : "(NOT matched - advertising under ESP32 address)");
    }
    return true;
}

void stop() {
    if (!g_advertising) {
        Serial.println("[clone] not advertising");
        return;
    }
    NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
    adv->stop();
    g_advertising = false;
    Serial.println("[clone] stopped advertising (GATT server stays built; reboot to load a different profile)");
}

bool isAdvertising() { return g_advertising; }

}
