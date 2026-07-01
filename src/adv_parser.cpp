// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#include "adv_parser.h"

#include "hexdump.h"
#include "uuid_db.h"

#include <ctype.h>
#include <string.h>

namespace adv_parser {

namespace {

static const char* adTypeName(uint8_t t) {
    switch (t) {
        case 0x01: return "Flags";
        case 0x02: return "Incomplete 16-bit Service UUIDs";
        case 0x03: return "Complete 16-bit Service UUIDs";
        case 0x04: return "Incomplete 32-bit Service UUIDs";
        case 0x05: return "Complete 32-bit Service UUIDs";
        case 0x06: return "Incomplete 128-bit Service UUIDs";
        case 0x07: return "Complete 128-bit Service UUIDs";
        case 0x08: return "Shortened Local Name";
        case 0x09: return "Complete Local Name";
        case 0x0A: return "Tx Power Level";
        case 0x0D: return "Class of Device";
        case 0x10: return "Device ID";
        case 0x11: return "Security Manager OOB Flags";
        case 0x12: return "Slave Connection Interval Range";
        case 0x14: return "16-bit Service Solicitation UUIDs";
        case 0x15: return "128-bit Service Solicitation UUIDs";
        case 0x16: return "Service Data (16-bit UUID)";
        case 0x17: return "Public Target Address";
        case 0x18: return "Random Target Address";
        case 0x19: return "Appearance";
        case 0x1A: return "Advertising Interval";
        case 0x1B: return "LE Bluetooth Device Address";
        case 0x1C: return "LE Role";
        case 0x1F: return "32-bit Service Solicitation UUIDs";
        case 0x20: return "Service Data (32-bit UUID)";
        case 0x21: return "Service Data (128-bit UUID)";
        case 0x24: return "URI";
        case 0x2C: return "Mesh Provisioning Service";
        case 0x2D: return "Mesh Message";
        case 0x2E: return "PB-ADV";
        case 0x3D: return "3D Information Data";
        case 0xFF: return "Manufacturer Specific Data";
        default:   return nullptr;
    }
}

static const char* appearanceCategory(uint16_t a) {
    // Appearance is a 16-bit value where the top 10 bits are category and the
    // bottom 6 are sub-type. We only resolve common categories.
    uint16_t cat = a >> 6;
    switch (cat) {
        case 0:  return "Unknown";
        case 1:  return "Phone";
        case 2:  return "Computer";
        case 3:  return "Watch";
        case 4:  return "Clock";
        case 5:  return "Display";
        case 6:  return "Remote Control";
        case 7:  return "Eye Glasses";
        case 8:  return "Tag";
        case 9:  return "Keyring";
        case 10: return "Media Player";
        case 11: return "Barcode Scanner";
        case 12: return "Thermometer";
        case 13: return "Heart Rate Sensor";
        case 14: return "Blood Pressure";
        case 15: return "Human Interface Device";
        case 16: return "Glucose Meter";
        case 17: return "Running/Walking Sensor";
        case 18: return "Cycling";
        case 19: return "Control Device";
        case 20: return "Network Device";
        case 21: return "Sensor";
        case 22: return "Light Fixtures";
        case 23: return "Fan";
        case 24: return "HVAC";
        case 25: return "Air Conditioning";
        case 26: return "Humidifier";
        case 27: return "Heating";
        case 31: return "Pulse Oximeter";
        case 32: return "Weight Scale";
        case 33: return "Personal Mobility Device";
        case 34: return "Continuous Glucose Monitor";
        case 35: return "Insulin Pump";
        case 36: return "Medication Delivery";
        case 49: return "Outdoor Sports Activity";
        case 81: return "Audio Sink";
        case 82: return "Audio Source";
        default: return "Other";
    }
}

static void decodeFlags(const uint8_t* d, size_t n, const char* indent) {
    if (n < 1) return;
    uint8_t f = d[0];
    Serial.printf("%s  flags=0x%02X", indent, f);
    if (f & 0x01) Serial.print(" LE-Limited");
    if (f & 0x02) Serial.print(" LE-General");
    if (f & 0x04) Serial.print(" BR/EDR-NotSupported");
    if (f & 0x08) Serial.print(" Simul-LE-BR/EDR-Controller");
    if (f & 0x10) Serial.print(" Simul-LE-BR/EDR-Host");
    Serial.println();
}

static void decodeUUIDs16(const uint8_t* d, size_t n, const char* indent) {
    for (size_t i = 0; i + 1 < n; i += 2) {
        uint16_t u = (uint16_t)(d[i] | (d[i + 1] << 8));
        const char* name = uuid_db::serviceName(u);
        if (!name) name = uuid_db::charName(u);
        Serial.printf("%s  0x%04X%s%s\n", indent, u,
                      name ? "  " : "", name ? name : "");
    }
}

static void decodeUUIDs128(const uint8_t* d, size_t n, const char* indent) {
    for (size_t i = 0; i + 15 < n; i += 16) {
        Serial.printf("%s  ", indent);
        // 128-bit UUIDs are little-endian on wire; print big-endian canonical.
        for (int j = 15; j >= 0; j--) {
            Serial.printf("%02x", d[i + j]);
            if (j == 12 || j == 10 || j == 8 || j == 6) Serial.print("-");
        }
        Serial.println();
    }
}

static void decodeName(const uint8_t* d, size_t n, const char* indent) {
    Serial.printf("%s  \"", indent);
    for (size_t i = 0; i < n; i++) {
        char c = (char)d[i];
        Serial.print(isprint((unsigned char)c) ? c : '.');
    }
    Serial.println("\"");
}

static void decodeTxPower(const uint8_t* d, size_t n, const char* indent) {
    if (n < 1) return;
    Serial.printf("%s  %d dBm\n", indent, (int8_t)d[0]);
}

static void decodeAppearance(const uint8_t* d, size_t n, const char* indent) {
    if (n < 2) return;
    uint16_t a = (uint16_t)(d[0] | (d[1] << 8));
    Serial.printf("%s  0x%04X  category=%s  sub=%u\n",
                  indent, a, appearanceCategory(a), a & 0x3F);
}

static void decodeServiceData16(const uint8_t* d, size_t n, const char* indent) {
    if (n < 2) return;
    uint16_t u = (uint16_t)(d[0] | (d[1] << 8));
    const char* name = uuid_db::serviceName(u);
    Serial.printf("%s  svc=0x%04X%s%s\n", indent, u,
                  name ? "  " : "", name ? name : "");
    if (n > 2) hexdump::line("data", d + 2, n - 2, indent);
}

// ---- Manufacturer data sub-decoders ----

static void decodeApple(const uint8_t* d, size_t n, const char* indent) {
    // Apple uses a TLV: type(1) | length(1) | data[length], possibly repeated.
    Serial.printf("%s  vendor=Apple\n", indent);
    size_t i = 0;
    while (i + 1 < n) {
        uint8_t t = d[i];
        uint8_t l = d[i + 1];
        if (i + 2 + l > n) break;
        const uint8_t* p = d + i + 2;

        const char* tname = "Unknown";
        switch (t) {
            case 0x02: tname = "iBeacon"; break;
            case 0x05: tname = "AirDrop"; break;
            case 0x07: tname = "AirPods/Proximity Pairing"; break;
            case 0x09: tname = "AirPlay Source"; break;
            case 0x0A: tname = "AirPlay Target"; break;
            case 0x0C: tname = "Handoff"; break;
            case 0x10: tname = "Nearby"; break;
            case 0x12: tname = "FindMy"; break;
        }
        Serial.printf("%s    type=0x%02X (%s)  len=%u\n", indent, t, tname, l);

        if (t == 0x02 && l == 0x15) {
            // iBeacon: UUID(16) | Major(2 BE) | Minor(2 BE) | Tx(1 signed)
            Serial.printf("%s      uuid=", indent);
            for (int j = 0; j < 16; j++) {
                Serial.printf("%02x", p[j]);
                if (j == 3 || j == 5 || j == 7 || j == 9) Serial.print("-");
            }
            Serial.println();
            uint16_t major = (uint16_t)((p[16] << 8) | p[17]);
            uint16_t minor = (uint16_t)((p[18] << 8) | p[19]);
            int8_t   tx    = (int8_t)p[20];
            Serial.printf("%s      major=%u  minor=%u  measured_tx=%d dBm\n",
                          indent, major, minor, tx);
        } else if (l > 0) {
            char buf[32];
            snprintf(buf, sizeof(buf), "%s    payload", indent);
            hexdump::line(buf, p, l, "");
        }
        i += 2 + l;
    }
}

static void decodeMicrosoft(const uint8_t* d, size_t n, const char* indent) {
    Serial.printf("%s  vendor=Microsoft\n", indent);
    // Common: Swift Pair = first byte 0x03 (BLE pairing)
    if (n >= 1) {
        const char* scenario = "Unknown";
        switch (d[0]) {
            case 0x01: scenario = "Cross-device communication (XDC)"; break;
            case 0x02: scenario = "Cross-device communication (XDC) Beacon"; break;
            case 0x03: scenario = "Swift Pair (BLE pairing)"; break;
            case 0x04: scenario = "Beacon"; break;
            case 0x06: scenario = "Swift Pair (BR/EDR)"; break;
            case 0x07: scenario = "Swift Pair (Bluetooth LE pairing v2)"; break;
        }
        Serial.printf("%s    scenario=0x%02X (%s)\n", indent, d[0], scenario);
    }
    if (n > 1) hexdump::line("payload", d + 1, n - 1, indent);
}

static void decodeGoogle(const uint8_t* d, size_t n, const char* indent) {
    Serial.printf("%s  vendor=Google\n", indent);
    if (n > 0) hexdump::line("payload", d, n, indent);
}

static void decodeManufacturer(const uint8_t* d, size_t n, const char* indent) {
    if (n < 2) return;
    uint16_t cid = (uint16_t)(d[0] | (d[1] << 8));
    const char* cname = uuid_db::companyName(cid);
    Serial.printf("%s  company=0x%04X%s%s\n", indent, cid,
                  cname ? "  " : "", cname ? cname : "");
    const uint8_t* payload = d + 2;
    size_t plen = n - 2;
    switch (cid) {
        case 0x004C: decodeApple(payload, plen, indent);     return;
        case 0x0006: decodeMicrosoft(payload, plen, indent); return;
        case 0x00E0: decodeGoogle(payload, plen, indent);    return;
        default:
            if (plen > 0) hexdump::line("payload", payload, plen, indent);
            return;
    }
}

} // anonymous namespace

void decode(const uint8_t* data, size_t len, const char* indent) {
    if (!data || len == 0) {
        Serial.printf("%s(empty)\n", indent);
        return;
    }
    size_t i = 0;
    while (i < len) {
        uint8_t reclen = data[i++];
        if (reclen == 0) break;
        if (i + reclen > len) {
            Serial.printf("%struncated AD record\n", indent);
            break;
        }
        uint8_t t = data[i];
        const uint8_t* d = data + i + 1;
        size_t  n = reclen - 1;

        const char* tname = adTypeName(t);
        Serial.printf("%s[0x%02X %s] len=%u\n", indent, t,
                      tname ? tname : "Unknown", (unsigned)n);

        switch (t) {
            case 0x01: decodeFlags(d, n, indent);          break;
            case 0x02: case 0x03: decodeUUIDs16(d, n, indent);  break;
            case 0x06: case 0x07: decodeUUIDs128(d, n, indent); break;
            case 0x08: case 0x09: decodeName(d, n, indent);     break;
            case 0x0A: decodeTxPower(d, n, indent);             break;
            case 0x19: decodeAppearance(d, n, indent);          break;
            case 0x16: decodeServiceData16(d, n, indent);       break;
            case 0xFF: decodeManufacturer(d, n, indent);        break;
            default:
                if (n > 0) hexdump::line("data", d, n, indent);
                break;
        }

        i += reclen;
    }
}

}
