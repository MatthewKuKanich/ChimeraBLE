// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#include "gatt.h"

#include "connection.h"
#include "hexdump.h"
#include "log.h"
#include "uuid_db.h"

#include <set>

namespace gatt {

// Format a UUID for log output. 16-bit known UUIDs render as "0x2A19 (Battery Level)";
// unknown 16-bit as "0x2A19"; 128-bit always as the full dashed string.
static std::string formatUuid(const NimBLEUUID& uuid, const char* (*named)(uint16_t)) {
    char buf[80];
    if (uuid.bitSize() == 16) {
        const uint8_t* b = uuid.getValue();
        uint16_t u = (uint16_t)(b[0] | (b[1] << 8));
        const char* name = named ? named(u) : uuid_db::lookup(uuid);
        if (name) snprintf(buf, sizeof(buf), "0x%04X (%s)", u, name);
        else      snprintf(buf, sizeof(buf), "0x%04X", u);
        return buf;
    }
    return uuid.toString();
}

static uint8_t buildPropsByte(NimBLERemoteCharacteristic* chr) {
    uint8_t p = 0;
    if (chr->canRead())             p |= BLE_GATT_CHR_PROP_READ;
    if (chr->canWrite())            p |= BLE_GATT_CHR_PROP_WRITE;
    if (chr->canWriteNoResponse())  p |= BLE_GATT_CHR_PROP_WRITE_NO_RSP;
    if (chr->canNotify())           p |= BLE_GATT_CHR_PROP_NOTIFY;
    if (chr->canIndicate())         p |= BLE_GATT_CHR_PROP_INDICATE;
    if (chr->canBroadcast())        p |= BLE_GATT_CHR_PROP_BROADCAST;
    return p;
}

static std::vector<SvcEntry> g_cache;
static std::set<uint16_t>    g_subs;

// Compact UUID string for JSON output: "0x180F" for 16-bit, full dashed form for 128-bit.
static std::string uuidJsonStr(const NimBLEUUID& uuid) {
    char buf[40];
    if (uuid.bitSize() == 16) {
        const uint8_t* b = uuid.getValue();
        uint16_t u = (uint16_t)(b[0] | (b[1] << 8));
        snprintf(buf, sizeof(buf), "0x%04X", u);
        return buf;
    }
    return uuid.toString();
}

static void notifyCb(NimBLERemoteCharacteristic* chr, uint8_t* data, size_t len, bool isNotify) {
    if (log_out::isJson()) {
        Serial.printf("{\"ev\":\"%s\",\"t\":%lu,\"svc\":\"%s\",\"uuid\":\"%s\",\"handle\":\"0x%04X\",",
                      isNotify ? "notify" : "indicate",
                      (unsigned long)millis(),
                      uuidJsonStr(chr->getRemoteService()->getUUID()).c_str(),
                      uuidJsonStr(chr->getUUID()).c_str(),
                      chr->getHandle());
        log_out::jsonHexField("bytes", data, len);
        Serial.println("}");
        return;
    }
    Serial.printf("\n[%s] t=%lu  svc=%s  chr=%s  h=0x%04X\n",
                  isNotify ? "NOTIFY" : "INDIC ",
                  (unsigned long)millis(),
                  chr->getRemoteService()->getUUID().toString().c_str(),
                  chr->getUUID().toString().c_str(),
                  chr->getHandle());
    hexdump::line("payload", data, len, "  ");
}

std::string describeValue(const NimBLEUUID& uuid, const uint8_t* data, size_t len) {
    if (uuid.bitSize() != 16 || !data || len == 0) return "";
    const uint8_t* b = uuid.getValue();
    uint16_t u = (uint16_t)(b[0] | (b[1] << 8));

    auto asText = [&]() -> std::string {
        std::string s;
        for (size_t i = 0; i < len && i < 40; i++) {
            char c = (char)data[i];
            s += (c >= 0x20 && c < 0x7F) ? c : '.';
        }
        return s;
    };

    switch (u) {
        case 0x2A19: return std::to_string(data[0]) + "%";               // Battery Level
        case 0x2A00:                                                     // Device Name
        case 0x2A24: case 0x2A25: case 0x2A26: case 0x2A27:              // Model/Serial/FW/HW
        case 0x2A28: case 0x2A29:                                        // SW rev / Manufacturer
            return asText();
        case 0x2A01: {                                                   // Appearance
            if (len < 2) return "";
            uint16_t a = (uint16_t)(data[0] | (data[1] << 8));
            uint16_t cat = a >> 6;
            const char* n = nullptr;
            switch (cat) {
                case 1: n = "Phone"; break;            case 2: n = "Computer"; break;
                case 3: n = "Watch"; break;            case 5: n = "Display"; break;
                case 6: n = "Remote"; break;           case 8: n = "Tag"; break;
                case 10: n = "Media Player"; break;    case 13: n = "Heart Rate"; break;
                case 15: n = "HID"; break;             case 17: n = "Run/Walk"; break;
                case 18: n = "Cycling"; break;         case 21: n = "Sensor"; break;
                case 49: n = "Outdoor"; break;         case 81: n = "Audio Sink"; break;
                case 82: n = "Audio Source"; break;
            }
            char buf[32];
            snprintf(buf, sizeof(buf), "0x%04X%s%s", a, n ? " " : "", n ? n : "");
            return buf;
        }
        case 0x2A23: {                                                   // System ID
            char buf[24]; snprintf(buf, sizeof(buf), "%u bytes", (unsigned)len); return buf;
        }
        default: return "";
    }
}

const char* propsString(uint8_t props, char* buf, size_t n) {
    snprintf(buf, n, "%c%c%c%c%c%c",
        (props & BLE_GATT_CHR_PROP_READ)              ? 'R' : '-',
        (props & BLE_GATT_CHR_PROP_WRITE)             ? 'W' : '-',
        (props & BLE_GATT_CHR_PROP_WRITE_NO_RSP)      ? 'w' : '-',
        (props & BLE_GATT_CHR_PROP_NOTIFY)            ? 'N' : '-',
        (props & BLE_GATT_CHR_PROP_INDICATE)          ? 'I' : '-',
        (props & BLE_GATT_CHR_PROP_BROADCAST)         ? 'B' : '-');
    return buf;
}

static std::string g_cache_peer;

void clearCache() {
    g_cache.clear();
    g_subs.clear();
    g_cache_peer.clear();
}

bool hasCache() { return !g_cache.empty(); }

const std::vector<SvcEntry>& cache() { return g_cache; }

const std::string& cachedPeer() { return g_cache_peer; }

// Read every readable characteristic + descriptor value into the cache, so the
// snapshot survives disconnect (used by `clone save`). Only runs while connected.
static void captureValues() {
    if (!connection::isConnected()) return;
    for (auto& svc : g_cache) {
        for (auto& ch : svc.chars) {
            if (ch.props & BLE_GATT_CHR_PROP_READ) {
                std::string v = ch.ptr->readValue();
                ch.value.assign(v.begin(), v.end());
                ch.value_cached = !v.empty();
            }
            for (auto& d : ch.descs) {
                std::string dv = d.ptr->readValue();
                d.value.assign(dv.begin(), dv.end());
                d.value_cached = !dv.empty();
            }
        }
    }
}

void discoverAndCache() {
    clearCache();
    NimBLEClient* c = connection::client();
    if (!c || !c->isConnected()) {
        Serial.println("[gatt] not connected");
        return;
    }
    g_cache_peer = c->getPeerAddress().toString();

    // Negotiate a larger MTU now (deferred out of connect to avoid racing
    // device-led pairing); speeds up reads of long characteristics.
    connection::ensureMtuNegotiated();

    Serial.println("[gatt] discovering services...");
    auto svcs = c->getServices(true);
    for (auto* svc : svcs) {
        SvcEntry s;
        s.start_handle = svc->getHandle();
        s.end_handle   = svc->getEndHandle();
        s.uuid         = svc->getUUID();
        s.ptr          = svc;

        auto chrs = svc->getCharacteristics(true);
        for (auto* chr : chrs) {
            CharEntry ch;
            ch.handle = chr->getHandle();
            ch.uuid   = chr->getUUID();
            ch.props  = buildPropsByte(chr);
            ch.ptr    = chr;

            auto descs = chr->getDescriptors(true);
            for (auto* d : descs) {
                DescEntry de;
                de.handle = d->getHandle();
                de.uuid   = d->getUUID();
                de.ptr    = d;
                ch.descs.push_back(de);
            }
            s.chars.push_back(ch);
        }
        g_cache.push_back(s);
    }
    Serial.printf("[gatt] cached %u services\n", (unsigned)g_cache.size());
}

CharEntry* findCharByHandle(uint16_t handle) {
    for (auto& s : g_cache) {
        for (auto& c : s.chars) {
            if (c.handle == handle) return &c;
        }
    }
    return nullptr;
}

CharEntry* findCharByUuid(const NimBLEUUID& uuid) {
    for (auto& s : g_cache) {
        for (auto& c : s.chars) {
            if (c.uuid == uuid) return &c;
        }
    }
    return nullptr;
}

CharEntry* resolveChar(const char* spec) {
    if (!spec || !*spec) return nullptr;
    if (strncmp(spec, "uuid:", 5) == 0) {
        const char* u = spec + 5;
        NimBLEUUID uuid(u);
        if (uuid.bitSize() == 0) {
            Serial.printf("[gatt] could not parse UUID '%s'\n", u);
            return nullptr;
        }
        return findCharByUuid(uuid);
    }
    char* end = nullptr;
    unsigned long h = strtoul(spec, &end, 0);
    if (end == spec || h > 0xFFFF) return nullptr;
    return findCharByHandle((uint16_t)h);
}

static void dumpJson(bool readValues) {
    for (auto& svc : g_cache) {
        Serial.printf("{\"ev\":\"svc\",\"t\":%lu,\"uuid\":\"%s\",\"start\":\"0x%04X\",\"end\":\"0x%04X\"}\n",
                      (unsigned long)millis(),
                      uuidJsonStr(svc.uuid).c_str(),
                      svc.start_handle, svc.end_handle);
        for (auto& chr : svc.chars) {
            char pbuf[8];
            Serial.printf("{\"ev\":\"chr\",\"t\":%lu,\"svc\":\"%s\",\"uuid\":\"%s\",\"handle\":\"0x%04X\",\"props\":\"%s\"",
                          (unsigned long)millis(),
                          uuidJsonStr(svc.uuid).c_str(),
                          uuidJsonStr(chr.uuid).c_str(),
                          chr.handle,
                          propsString(chr.props, pbuf, sizeof(pbuf)));
            if (readValues && chr.value_cached) {
                Serial.print(",");
                log_out::jsonHexField("value", chr.value.data(), chr.value.size());
            }
            Serial.println("}");
            for (auto& d : chr.descs) {
                Serial.printf("{\"ev\":\"dsc\",\"t\":%lu,\"chr_handle\":\"0x%04X\",\"uuid\":\"%s\",\"handle\":\"0x%04X\"",
                              (unsigned long)millis(),
                              chr.handle,
                              uuidJsonStr(d.uuid).c_str(),
                              d.handle);
                if (readValues && d.value_cached) {
                    Serial.print(",");
                    log_out::jsonHexField("value", d.value.data(), d.value.size());
                }
                Serial.println("}");
            }
        }
    }
    Serial.printf("{\"ev\":\"dump_end\",\"t\":%lu}\n", (unsigned long)millis());
}

void dump(bool readValues) {
    if (!connection::isConnected()) {
        Serial.println("[gatt] not connected");
        return;
    }
    if (!hasCache()) discoverAndCache();
    if (readValues) captureValues();

    if (log_out::isJson()) { dumpJson(readValues); return; }

    Serial.println("\n========== GATT DUMP ==========");
    for (auto& svc : g_cache) {
        Serial.printf("\nSVC %s  handles=0x%04X-0x%04X\n",
                      formatUuid(svc.uuid, uuid_db::serviceName).c_str(),
                      svc.start_handle, svc.end_handle);

        for (auto& chr : svc.chars) {
            char pbuf[8];
            Serial.printf("  CHR %s  h=0x%04X  [%s]\n",
                          formatUuid(chr.uuid, uuid_db::charName).c_str(),
                          chr.handle,
                          propsString(chr.props, pbuf, sizeof(pbuf)));

            if (readValues && (chr.props & BLE_GATT_CHR_PROP_READ)) {
                if (chr.value_cached) {
                    hexdump::line("value", chr.value.data(), chr.value.size());
                    std::string dec = describeValue(chr.uuid, chr.value.data(), chr.value.size());
                    if (!dec.empty()) Serial.printf("    decoded: %s\n", dec.c_str());
                } else {
                    Serial.println("    (empty / read failed)");
                }
            }

            for (auto& d : chr.descs) {
                Serial.printf("    DSC %s  h=0x%04X\n",
                              formatUuid(d.uuid, uuid_db::descName).c_str(), d.handle);
                if (readValues && d.value_cached) {
                    hexdump::line("dvalue", d.value.data(), d.value.size(), "      ");
                }
            }
        }
    }
    Serial.println("\n========== DUMP COMPLETE ==========");
}

bool readChar(uint16_t handle) {
    if (!connection::isConnected()) {
        Serial.println("[gatt] not connected (cache is an offline snapshot)");
        return false;
    }
    CharEntry* ch = findCharByHandle(handle);
    if (!ch) {
        Serial.printf("[gatt] no characteristic at handle 0x%04X\n", handle);
        return false;
    }
    if (!(ch->props & BLE_GATT_CHR_PROP_READ)) {
        Serial.println("[gatt] characteristic is not readable");
        return false;
    }
    std::string v = ch->ptr->readValue();
    if (log_out::isJson()) {
        Serial.printf("{\"ev\":\"read\",\"t\":%lu,\"uuid\":\"%s\",\"handle\":\"0x%04X\"",
                      (unsigned long)millis(),
                      uuidJsonStr(ch->uuid).c_str(),
                      handle);
        if (!v.empty()) {
            Serial.print(",");
            log_out::jsonHexField("value", (const uint8_t*)v.data(), v.length());
        }
        Serial.println("}");
        return !v.empty();
    }
    Serial.printf("[read] h=0x%04X uuid=%s\n",
                  handle, formatUuid(ch->uuid, uuid_db::charName).c_str());
    if (v.empty()) {
        Serial.println("  (empty / read failed)");
        return false;
    }
    hexdump::line("value", (const uint8_t*)v.data(), v.length(), "  ");
    return true;
}

bool writeChar(uint16_t handle, const uint8_t* data, size_t len, bool withResponse) {
    if (!connection::isConnected()) {
        Serial.println("[gatt] not connected (cache is an offline snapshot)");
        return false;
    }
    CharEntry* ch = findCharByHandle(handle);
    if (!ch) {
        Serial.printf("[gatt] no characteristic at handle 0x%04X\n", handle);
        return false;
    }
    uint8_t need = withResponse ? BLE_GATT_CHR_PROP_WRITE : BLE_GATT_CHR_PROP_WRITE_NO_RSP;
    if (!(ch->props & need)) {
        Serial.printf("[gatt] characteristic does not support %s\n",
                      withResponse ? "write-with-response" : "write-no-response");
        return false;
    }
    bool ok = ch->ptr->writeValue(data, len, withResponse);
    Serial.printf("[write] h=0x%04X len=%u %s\n",
                  handle, (unsigned)len, ok ? "OK" : "FAILED");
    return ok;
}

bool subscribe(uint16_t handle) {
    if (!connection::isConnected()) {
        Serial.println("[gatt] not connected (cache is an offline snapshot)");
        return false;
    }
    CharEntry* ch = findCharByHandle(handle);
    if (!ch) {
        Serial.printf("[gatt] no characteristic at handle 0x%04X\n", handle);
        return false;
    }
    bool notify   = ch->props & BLE_GATT_CHR_PROP_NOTIFY;
    bool indicate = ch->props & BLE_GATT_CHR_PROP_INDICATE;
    if (!notify && !indicate) {
        Serial.println("[gatt] characteristic supports neither notify nor indicate");
        return false;
    }
    bool ok = ch->ptr->subscribe(notify, notifyCb);
    if (ok) {
        g_subs.insert(handle);
        Serial.printf("[sub] subscribed h=0x%04X (%s)\n", handle, notify ? "notify" : "indicate");
    } else {
        Serial.printf("[sub] subscribe failed h=0x%04X\n", handle);
    }
    return ok;
}

bool unsubscribe(uint16_t handle) {
    if (!connection::isConnected()) {
        Serial.println("[gatt] not connected (cache is an offline snapshot)");
        return false;
    }
    CharEntry* ch = findCharByHandle(handle);
    if (!ch) return false;
    bool ok = ch->ptr->unsubscribe();
    if (ok) {
        g_subs.erase(handle);
        Serial.printf("[sub] unsubscribed h=0x%04X\n", handle);
    }
    return ok;
}

void listSubscriptions() {
    if (g_subs.empty()) {
        Serial.println("[sub] no active subscriptions");
        return;
    }
    Serial.printf("[sub] %u active subscription(s):\n", (unsigned)g_subs.size());
    for (uint16_t h : g_subs) {
        CharEntry* ch = findCharByHandle(h);
        if (!ch) continue;
        Serial.printf("  h=0x%04X  uuid=%s\n",
                      h, formatUuid(ch->uuid, uuid_db::charName).c_str());
    }
}

}
