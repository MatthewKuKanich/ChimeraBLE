// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#include "uuid_db.h"

#include "company_ids_gen.h"

#include <stdio.h>
#include <string.h>

namespace uuid_db {

struct Entry { uint16_t id; const char* name; };

// On ESP32 all `const` data lives in flash (.rodata) - no PROGMEM macros needed.
// Source: Bluetooth SIG Assigned Numbers (assigned_numbers/uuids/).
// Covers the most common entries used in consumer BLE devices.

static const Entry SERVICES[] = {
    {0x1800, "Generic Access"},
    {0x1801, "Generic Attribute"},
    {0x1802, "Immediate Alert"},
    {0x1803, "Link Loss"},
    {0x1804, "Tx Power"},
    {0x1805, "Current Time"},
    {0x1806, "Reference Time Update"},
    {0x1807, "Next DST Change"},
    {0x1808, "Glucose"},
    {0x1809, "Health Thermometer"},
    {0x180A, "Device Information"},
    {0x180D, "Heart Rate"},
    {0x180E, "Phone Alert Status"},
    {0x180F, "Battery"},
    {0x1810, "Blood Pressure"},
    {0x1811, "Alert Notification"},
    {0x1812, "Human Interface Device"},
    {0x1813, "Scan Parameters"},
    {0x1814, "Running Speed and Cadence"},
    {0x1815, "Automation IO"},
    {0x1816, "Cycling Speed and Cadence"},
    {0x1818, "Cycling Power"},
    {0x1819, "Location and Navigation"},
    {0x181A, "Environmental Sensing"},
    {0x181B, "Body Composition"},
    {0x181C, "User Data"},
    {0x181D, "Weight Scale"},
    {0x181E, "Bond Management"},
    {0x181F, "Continuous Glucose Monitoring"},
    {0x1820, "Internet Protocol Support"},
    {0x1821, "Indoor Positioning"},
    {0x1822, "Pulse Oximeter"},
    {0x1823, "HTTP Proxy"},
    {0x1824, "Transport Discovery"},
    {0x1825, "Object Transfer"},
    {0x1826, "Fitness Machine"},
    {0x1827, "Mesh Provisioning"},
    {0x1828, "Mesh Proxy"},
    {0x1829, "Reconnection Configuration"},
    {0x183A, "Insulin Delivery"},
    {0x183B, "Binary Sensor"},
    {0x183C, "Emergency Configuration"},
    {0x183D, "Authorization Control"},
    {0x183E, "Physical Activity Monitor"},
    {0x1843, "Audio Input Control"},
    {0x1844, "Volume Control"},
    {0x1845, "Volume Offset Control"},
    {0x1846, "Coordinated Set Identification"},
    {0x1847, "Device Time"},
    {0x1848, "Media Control"},
    {0x1849, "Generic Media Control"},
    {0x184A, "Constant Tone Extension"},
    {0x184B, "Telephone Bearer"},
    {0x184C, "Generic Telephone Bearer"},
    {0x184D, "Microphone Control"},
    {0x184E, "Audio Stream Control"},
    {0x184F, "Broadcast Audio Scan"},
    {0x1850, "Published Audio Capabilities"},
    {0x1851, "Basic Audio Announcement"},
    {0x1852, "Broadcast Audio Announcement"},
    {0x1853, "Common Audio"},
    {0x1854, "Hearing Access"},
    {0x1855, "Telephony and Media Audio"},
    {0x1856, "Public Broadcast Announcement"},
    {0x1857, "Electronic Shelf Label"},
};

static const Entry CHARS[] = {
    // Generic Access (0x1800)
    {0x2A00, "Device Name"},
    {0x2A01, "Appearance"},
    {0x2A02, "Peripheral Privacy Flag"},
    {0x2A03, "Reconnection Address"},
    {0x2A04, "Peripheral Preferred Connection Parameters"},
    {0x2AA6, "Central Address Resolution"},
    {0x2AC9, "Resolvable Private Address Only"},
    // Generic Attribute (0x1801)
    {0x2A05, "Service Changed"},
    {0x2B29, "Client Supported Features"},
    {0x2B2A, "Database Hash"},
    // Immediate Alert / Link Loss / Tx Power
    {0x2A06, "Alert Level"},
    {0x2A07, "Tx Power Level"},
    // Current Time / DST
    {0x2A08, "Date Time"},
    {0x2A09, "Day of Week"},
    {0x2A0A, "Day Date Time"},
    {0x2A0C, "Exact Time 256"},
    {0x2A0D, "DST Offset"},
    {0x2A0E, "Time Zone"},
    {0x2A0F, "Local Time Information"},
    {0x2A11, "Time with DST"},
    {0x2A12, "Time Accuracy"},
    {0x2A13, "Time Source"},
    {0x2A14, "Reference Time Information"},
    {0x2A16, "Time Update Control Point"},
    {0x2A17, "Time Update State"},
    {0x2A2B, "Current Time"},
    {0x2A66, "Cycling Power Control Point"},
    // Device Information (0x180A)
    {0x2A23, "System ID"},
    {0x2A24, "Model Number String"},
    {0x2A25, "Serial Number String"},
    {0x2A26, "Firmware Revision String"},
    {0x2A27, "Hardware Revision String"},
    {0x2A28, "Software Revision String"},
    {0x2A29, "Manufacturer Name String"},
    {0x2A2A, "IEEE 11073-20601 Regulatory Cert. Data List"},
    {0x2A50, "PnP ID"},
    // Battery
    {0x2A19, "Battery Level"},
    {0x2B18, "Battery Level Status"},
    {0x2BED, "Battery Information"},
    // HID (0x1812)
    {0x2A4A, "HID Information"},
    {0x2A4B, "Report Map"},
    {0x2A4C, "HID Control Point"},
    {0x2A4D, "Report"},
    {0x2A4E, "Protocol Mode"},
    {0x2A22, "Boot Keyboard Input Report"},
    {0x2A32, "Boot Keyboard Output Report"},
    {0x2A33, "Boot Mouse Input Report"},
    // Heart Rate
    {0x2A37, "Heart Rate Measurement"},
    {0x2A38, "Body Sensor Location"},
    {0x2A39, "Heart Rate Control Point"},
    // Scan Parameters
    {0x2A4F, "Scan Interval Window"},
    {0x2A31, "Scan Refresh"},
    // Health Thermometer
    {0x2A1C, "Temperature Measurement"},
    {0x2A1D, "Temperature Type"},
    {0x2A1E, "Intermediate Temperature"},
    {0x2A21, "Measurement Interval"},
    // Blood Pressure
    {0x2A35, "Blood Pressure Measurement"},
    {0x2A36, "Intermediate Cuff Pressure"},
    {0x2A49, "Blood Pressure Feature"},
    // Glucose
    {0x2A18, "Glucose Measurement"},
    {0x2A34, "Glucose Measurement Context"},
    {0x2A51, "Glucose Feature"},
    {0x2A52, "Record Access Control Point"},
    // Alert Notification
    {0x2A47, "Supported New Alert Category"},
    {0x2A46, "New Alert"},
    {0x2A48, "Supported Unread Alert Category"},
    {0x2A45, "Unread Alert Status"},
    {0x2A44, "Alert Notification Control Point"},
    // Environmental Sensing (subset)
    {0x2A6E, "Temperature"},
    {0x2A6F, "Humidity"},
    {0x2A6D, "Pressure"},
    {0x2A77, "Irradiance"},
    {0x2A76, "UV Index"},
    {0x2A7A, "Heat Index"},
    {0x2A7B, "Dew Point"},
    {0x2A75, "Wind Chill"},
    {0x2AA3, "Barometric Pressure Trend"},
    // Cycling / Running
    {0x2A53, "RSC Measurement"},
    {0x2A54, "RSC Feature"},
    {0x2A5B, "CSC Measurement"},
    {0x2A5C, "CSC Feature"},
    {0x2A63, "Cycling Power Measurement"},
    {0x2A65, "Cycling Power Feature"},
    {0x2A5D, "Sensor Location"},
    // Indoor positioning
    {0x2AAD, "Indoor Positioning Configuration"},
    {0x2AAE, "Latitude"},
    {0x2AAF, "Longitude"},
};

static const Entry DESCS[] = {
    {0x2900, "Characteristic Extended Properties"},
    {0x2901, "Characteristic User Description"},
    {0x2902, "Client Characteristic Configuration"},
    {0x2903, "Server Characteristic Configuration"},
    {0x2904, "Characteristic Presentation Format"},
    {0x2905, "Characteristic Aggregate Format"},
    {0x2906, "Valid Range"},
    {0x2907, "External Report Reference"},
    {0x2908, "Report Reference"},
    {0x2909, "Number of Digitals"},
    {0x290A, "Value Trigger Setting"},
    {0x290B, "Environmental Sensing Configuration"},
    {0x290C, "Environmental Sensing Measurement"},
    {0x290D, "Environmental Sensing Trigger Setting"},
    {0x290E, "Time Trigger Setting"},
    {0x290F, "Complete BR-EDR Transport Block Data"},
};

// Company identifiers come from the full auto-generated COMPANY_IDS table
// (see company_ids_gen.h / .cpp - the complete Bluetooth SIG list). companyName()
// below binary-searches it.

// Member / allocated 16-bit service UUIDs (0xFCxx-0xFFFF). These identify a
// product or beacon protocol and are the strongest signal for naming devices
// that advertise no local name. Verified against the SIG/Nordic DB + community.
static const Entry MEMBER_SVCS[] = {
    {0xFCD2, "BTHome sensor"},
    {0xFD6F, "Exposure Notification"},
    {0xFE0F, "Philips Hue (Signify)"},
    {0xFE2C, "Google Fast Pair"},
    {0xFE59, "Nordic Secure DFU"},
    {0xFE95, "Xiaomi / MiBeacon"},
    {0xFEAA, "Eddystone beacon (Google)"},
    {0xFEBB, "Adafruit File Transfer"},
    {0xFEEC, "Tile tracker"},
    {0xFEED, "Tile tracker"},
};

static const char* lookupTable(const Entry* table, size_t n, uint16_t id) {
    for (size_t i = 0; i < n; i++) {
        if (table[i].id == id) return table[i].name;
    }
    return nullptr;
}

const char* serviceName(uint16_t u) {
    return lookupTable(SERVICES, sizeof(SERVICES) / sizeof(SERVICES[0]), u);
}
const char* charName(uint16_t u) {
    return lookupTable(CHARS, sizeof(CHARS) / sizeof(CHARS[0]), u);
}
const char* descName(uint16_t u) {
    return lookupTable(DESCS, sizeof(DESCS) / sizeof(DESCS[0]), u);
}
const char* companyName(uint16_t cid) {
    // Binary search the generated, code-sorted full SIG company list.
    int lo = 0, hi = (int)COMPANY_IDS_COUNT - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        uint16_t c = COMPANY_IDS[mid].code;
        if (c == cid) return COMPANY_IDS[mid].name;
        if (c < cid)  lo = mid + 1;
        else          hi = mid - 1;
    }
    return nullptr;
}
const char* memberServiceName(uint16_t u) {
    return lookupTable(MEMBER_SVCS, sizeof(MEMBER_SVCS) / sizeof(MEMBER_SVCS[0]), u);
}

// Try all three SIG tables in priority order: service → char → descriptor.
// For runtime "I have a UUID, what is it?" lookups in mixed contexts.
const char* lookup(const NimBLEUUID& uuid) {
    if (uuid.bitSize() != 16) return nullptr;
    const uint8_t* b = uuid.getValue();
    uint16_t u = (uint16_t)(b[0] | (b[1] << 8));
    const char* n;
    if ((n = serviceName(u))) return n;
    if ((n = charName(u)))    return n;
    if ((n = descName(u)))    return n;
    return nullptr;
}

}
