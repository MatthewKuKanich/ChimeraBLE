// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#include "fingerprint.h"

#include "oui_db.h"
#include "uuid_db.h"

#include <stdio.h>
#include <string.h>

namespace fingerprint {

namespace {

// Nordic UART Service base UUID 6E400001-B5A3-F393-E0A9-E50E24DCCA9E, in the
// little-endian byte order it appears in an AD record.
static const uint8_t NORDIC_UART_LE[16] = {
    0x9E, 0xCA, 0xDC, 0x24, 0x0E, 0xE5, 0xA9, 0xE0,
    0x93, 0xF3, 0xA3, 0xB5, 0x01, 0x00, 0x40, 0x6E};

struct Parsed {
    bool     hasFlags = false;  uint8_t  flags = 0;
    bool     hasCompany = false; uint16_t company = 0;
    const uint8_t* mfr = nullptr; size_t mfrLen = 0;
    std::vector<uint16_t> svc16;
    std::vector<uint16_t> svcData16;
    int      n128 = 0;
    bool     nordicUart = false;
    bool     hasAppearance = false; uint16_t appearance = 0;
    bool     hasName = false;
};

Parsed walk(const std::vector<uint8_t>& adv) {
    Parsed p;
    size_t i = 0;
    while (i < adv.size()) {
        uint8_t reclen = adv[i++];
        if (reclen == 0 || i + reclen > adv.size()) break;
        uint8_t t = adv[i];
        const uint8_t* d = &adv[i + 1];
        size_t n = reclen - 1;

        switch (t) {
            case 0x01: if (n >= 1) { p.hasFlags = true; p.flags = d[0]; } break;
            case 0x02: case 0x03:
                for (size_t k = 0; k + 1 < n; k += 2)
                    p.svc16.push_back((uint16_t)(d[k] | (d[k + 1] << 8)));
                break;
            case 0x06: case 0x07:
                for (size_t k = 0; k + 15 < n; k += 16) {
                    p.n128++;
                    if (memcmp(d + k, NORDIC_UART_LE, 16) == 0) p.nordicUart = true;
                }
                break;
            case 0x08: case 0x09: p.hasName = true; break;
            case 0x16: if (n >= 2) p.svcData16.push_back((uint16_t)(d[0] | (d[1] << 8))); break;
            case 0x19: if (n >= 2) { p.hasAppearance = true;
                                     p.appearance = (uint16_t)(d[0] | (d[1] << 8)); } break;
            case 0xFF: if (n >= 2) { p.hasCompany = true;
                                     p.company = (uint16_t)(d[0] | (d[1] << 8));
                                     p.mfr = d + 2; p.mfrLen = n - 2; } break;
            default: break;
        }
        i += reclen;
    }
    return p;
}

// Apple Continuity advertising TLV: first byte is the message type.
const char* appleType(const uint8_t* mfr, size_t len) {
    if (!mfr || len < 1) return nullptr;
    switch (mfr[0]) {
        case 0x02: return "iBeacon";
        case 0x05: return "AirDrop";
        case 0x07: return "Proximity Pairing (AirPods)";
        case 0x09: return "AirPlay Source";
        case 0x0A: return "AirPlay Target";
        case 0x0B: return "Watch Pairing";
        case 0x0C: return "Handoff";
        case 0x0D: return "Tethering Target";
        case 0x0E: return "Tethering Source";
        case 0x0F: return "Nearby Action";
        case 0x10: return "Nearby";
        case 0x12: return "FindMy";
        default:   return nullptr;
    }
}

// Infer a device class from advertised SIG service UUIDs.
const char* deviceTypeFromServices(const std::vector<uint16_t>& svc16) {
    for (uint16_t u : svc16) {
        switch (u) {
            case 0x1812: return "HID input device";
            case 0x180D: return "Heart Rate monitor";
            case 0x1816: return "Cycling speed/cadence";
            case 0x1814: return "Running speed/cadence";
            case 0x1818: return "Cycling power";
            case 0x1826: return "Fitness machine";
            case 0x181A: return "Environmental sensor";
            case 0x1808: return "Glucose meter";
            case 0x1809: return "Thermometer";
            case 0x1810: return "Blood pressure";
            case 0x1822: return "Pulse oximeter";
            case 0x1819: return "Location & navigation";
            case 0x1843: case 0x1844: case 0x184E: case 0x1850: return "LE Audio";
            default: break;
        }
    }
    return nullptr;
}

const char* appearanceCat(uint16_t a) {
    switch (a >> 6) {
        case 1:  return "Phone";
        case 2:  return "Computer";
        case 3:  return "Watch";
        case 5:  return "Display";
        case 6:  return "Remote Control";
        case 7:  return "Eye Glasses";
        case 8:  return "Tag";
        case 9:  return "Keyring";
        case 10: return "Media Player";
        case 13: return "Heart Rate Sensor";
        case 15: return "HID";
        case 17: return "Running/Walking Sensor";
        case 18: return "Cycling";
        case 21: return "Sensor";
        case 31: return "Pulse Oximeter";
        case 32: return "Weight Scale";
        case 81: return "Audio Sink";
        case 82: return "Audio Source";
        default: return nullptr;
    }
}

// Random address sub-type lives in the top two bits of the MSB octet.
std::string addrTypeStr(const std::string& addr, uint8_t addr_type) {
    if (addr_type == 0) return "public";
    unsigned b0 = 0;
    sscanf(addr.c_str(), "%2x", &b0);
    switch ((b0 >> 6) & 0x3) {
        case 0x3: return "random-static";
        case 0x1: return "random-resolvable (RPA, rotates)";
        case 0x0: return "random-non-resolvable";
        default:  return "random-reserved";
    }
}

std::string hex16(uint16_t v) {
    char b[8];
    snprintf(b, sizeof(b), "0x%04X", v);
    return b;
}

} // anonymous namespace

std::string identify(const std::string& addr, uint8_t addr_type,
                     const std::vector<uint8_t>& adv) {
    Parsed p = walk(adv);
    std::vector<std::string> tags;
    auto add = [&](const std::string& s) {
        for (auto& t : tags) if (t == s) return;
        tags.push_back(s);
    };

    // 1. Service-data protocol UUIDs - strongest signal for nameless beacons.
    for (uint16_t sd : p.svcData16)
        if (const char* m = uuid_db::memberServiceName(sd)) add(m);
    // 2. Member protocol advertised as a service UUID.
    for (uint16_t u : p.svc16)
        if (const char* m = uuid_db::memberServiceName(u)) add(m);
    // 3. Manufacturer vendor (+ Apple Continuity sub-type).
    if (p.hasCompany) {
        const char* v = uuid_db::companyName(p.company);
        std::string vendor = v ? v : ("company " + hex16(p.company));
        if (p.company == 0x004C)
            if (const char* sub = appleType(p.mfr, p.mfrLen))
                vendor += std::string(" (") + sub + ")";
        add(vendor);
    }
    // 3b. OUI vendor - only public addresses carry a real IEEE OUI (random
    //     addresses are device-generated). Distinct from the SIG company ID:
    //     OUI is the IEEE product-brand assignee (e.g. "GE Appliances").
    if (addr_type == 0) {
        std::string oui = oui_db::lookupMac(addr);
        if (!oui.empty()) add("OUI: " + oui);
    }
    // 4. Recognizable custom 128-bit service.
    if (p.nordicUart) add("Nordic UART");
    // 5. Device class from SIG services.
    if (const char* dt = deviceTypeFromServices(p.svc16)) add(dt);
    // 6. Appearance category.
    if (p.hasAppearance)
        if (const char* c = appearanceCat(p.appearance)) add(c);
    // 7. Last resort hints.
    if (tags.empty() && p.n128 > 0) add("custom 128-bit service");

    std::string label;
    size_t cap = tags.size() < 3 ? tags.size() : 3;   // keep the line short
    for (size_t k = 0; k < cap; k++) {
        if (!label.empty()) label += " \xC2\xB7 ";     // " · "
        label += tags[k];
    }
    if (label.empty()) label = "unknown";
    (void)addr;
    return label;
}

// Short display annotation for privacy addresses, appended by callers after the
// guess/name. Empty for public and (common, unremarkable) static-random addrs.
std::string addrTag(const std::string& addr, uint8_t addr_type) {
    if (addr_type == 0) return "";
    std::string at = addrTypeStr(addr, addr_type);
    if (at.rfind("random-resolvable", 0) == 0) return " [RPA]";
    if (at == "random-non-resolvable")          return " [rand]";
    return "";
}

void describe(const std::string& addr, uint8_t addr_type,
              const std::vector<uint8_t>& adv) {
    Parsed p = walk(adv);
    Serial.println("  [fingerprint]");
    Serial.printf("    guess      : %s\n", identify(addr, addr_type, adv).c_str());
    Serial.printf("    address    : %s (%s)\n", addr.c_str(),
                  addrTypeStr(addr, addr_type).c_str());
    if (addr_type == 0) {
        std::string oui = oui_db::lookupMac(addr);
        if (!oui.empty()) Serial.printf("    oui vendor : %s\n", oui.c_str());
    }
    Serial.printf("    local name : %s\n", p.hasName ? "present" : "ABSENT");

    if (p.hasCompany) {
        const char* v = uuid_db::companyName(p.company);
        Serial.printf("    company    : 0x%04X (%s)", p.company, v ? v : "unknown");
        if (p.company == 0x004C)
            if (const char* sub = appleType(p.mfr, p.mfrLen)) Serial.printf("  Continuity: %s", sub);
        Serial.println();
    }
    if (!p.svc16.empty()) {
        Serial.print("    svc 16-bit :");
        for (uint16_t u : p.svc16) {
            const char* n = uuid_db::serviceName(u);
            if (!n) n = uuid_db::memberServiceName(u);
            Serial.printf(" 0x%04X%s%s%s", u, n ? "(" : "", n ? n : "", n ? ")" : "");
        }
        Serial.println();
    }
    if (p.n128 > 0)
        Serial.printf("    svc 128-bit: %d%s\n", p.n128, p.nordicUart ? " (Nordic UART)" : "");
    if (!p.svcData16.empty()) {
        Serial.print("    svc data   :");
        for (uint16_t sd : p.svcData16) {
            const char* m = uuid_db::memberServiceName(sd);
            if (!m) m = uuid_db::serviceName(sd);
            Serial.printf(" 0x%04X%s%s%s", sd, m ? "(" : "", m ? m : "", m ? ")" : "");
        }
        Serial.println();
    }
    if (p.hasAppearance) {
        const char* c = appearanceCat(p.appearance);
        Serial.printf("    appearance : 0x%04X%s%s\n", p.appearance,
                      c ? "  " : "", c ? c : "");
    }
    if (p.hasFlags)
        Serial.printf("    adv flags  : 0x%02X\n", p.flags);
}

}
