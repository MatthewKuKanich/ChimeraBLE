// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#include "hid_parser.h"

#include "connection.h"
#include "gatt.h"

#include <NimBLEDevice.h>
#include <map>
#include <set>
#include <stdio.h>
#include <string.h>
#include <vector>

// Implements USB HID 1.11 §6.2.2.4 (Report Descriptor item format).
//
// Short item byte 0: bSize(2) | bType(2) | bTag(4)
//   bSize: 0=>0 data bytes, 1=>1, 2=>2, 3=>4
//   bType: 0=Main, 1=Global, 2=Local, 3=Reserved
// Long item: 0xFE | bSize(8) | bTag(8) | data[bSize]
//
// The walker maintains Global state (Usage Page, Report Size/Count/ID, Logical
// Min/Max) per the spec rules - Globals persist until changed, Locals reset
// after each Main item.

namespace hid_parser {

namespace {

// ---- Static name tables ----

struct U16Name { uint16_t id; const char* name; };
struct U8Name  { uint8_t  id; const char* name; };

static const U16Name USAGE_PAGES[] = {
    {0x01, "Generic Desktop"},
    {0x02, "Simulation Controls"},
    {0x03, "VR Controls"},
    {0x04, "Sport Controls"},
    {0x05, "Game Controls"},
    {0x06, "Generic Device Controls"},
    {0x07, "Keyboard/Keypad"},
    {0x08, "LEDs"},
    {0x09, "Button"},
    {0x0A, "Ordinal"},
    {0x0B, "Telephony Device"},
    {0x0C, "Consumer"},
    {0x0D, "Digitizers"},
    {0x0E, "Haptics"},
    {0x0F, "Physical Input Device"},
    {0x14, "Alphanumeric Display"},
    {0x20, "Sensors"},
    {0x40, "Medical Instruments"},
    {0x80, "Monitor"},
    {0x84, "Power"},
    {0x8C, "Bar Code Scanner"},
    {0x8D, "Scales"},
    {0x90, "Camera Control"},
    {0xF1D0, "FIDO Alliance"},
};

static const U16Name USAGES_GENERIC_DESKTOP[] = {
    {0x01, "Pointer"},   {0x02, "Mouse"},      {0x04, "Joystick"},
    {0x05, "Game Pad"},  {0x06, "Keyboard"},   {0x07, "Keypad"},
    {0x08, "Multi-axis Controller"}, {0x09, "Tablet PC System Controls"},
    {0x30, "X"},  {0x31, "Y"},  {0x32, "Z"},  {0x33, "Rx"},  {0x34, "Ry"},  {0x35, "Rz"},
    {0x36, "Slider"}, {0x37, "Dial"}, {0x38, "Wheel"}, {0x39, "Hat Switch"},
    {0x3A, "Counted Buffer"}, {0x3B, "Byte Count"}, {0x3C, "Motion Wakeup"},
    {0x3D, "Start"}, {0x3E, "Select"}, {0x40, "Vx"}, {0x80, "System Control"},
    {0x81, "System Power Down"}, {0x82, "System Sleep"}, {0x83, "System Wake Up"},
    {0x84, "System Context Menu"}, {0x85, "System Main Menu"},
    {0x86, "System App Menu"}, {0x87, "System Menu Help"}, {0x88, "System Menu Exit"},
    {0x89, "System Menu Select"}, {0x8A, "System Menu Right"},
    {0x8B, "System Menu Left"}, {0x8C, "System Menu Up"}, {0x8D, "System Menu Down"},
};

static const U16Name USAGES_CONSUMER[] = {
    {0x001, "Consumer Control"}, {0x002, "Numeric Key Pad"},
    {0x040, "Menu"}, {0x041, "Menu Pick"}, {0x042, "Menu Up"},
    {0x043, "Menu Down"}, {0x044, "Menu Left"}, {0x045, "Menu Right"},
    {0x046, "Menu Escape"}, {0x047, "Menu Value Increase"}, {0x048, "Menu Value Decrease"},
    {0x06F, "Brightness Increment"}, {0x070, "Brightness Decrement"},
    {0x0B0, "Play"}, {0x0B1, "Pause"}, {0x0B2, "Record"}, {0x0B3, "Fast Forward"},
    {0x0B4, "Rewind"}, {0x0B5, "Scan Next Track"}, {0x0B6, "Scan Previous Track"},
    {0x0B7, "Stop"}, {0x0B8, "Eject"}, {0x0CD, "Play/Pause"},
    {0x0E2, "Mute"}, {0x0E5, "Bass Boost"}, {0x0E9, "Volume Increment"},
    {0x0EA, "Volume Decrement"}, {0x183, "AL Consumer Control Configuration"},
    {0x18A, "AL Email Reader"}, {0x192, "AL Calculator"},
    {0x194, "AL Local Machine Browser"}, {0x196, "AL Internet Browser"},
    {0x221, "AC Search"}, {0x223, "AC Home"}, {0x224, "AC Back"},
    {0x225, "AC Forward"}, {0x226, "AC Stop"}, {0x227, "AC Refresh"},
    {0x22D, "AC Zoom In"}, {0x22E, "AC Zoom Out"},
};

static const U8Name COLLECTION_TYPES[] = {
    {0x00, "Physical"},   {0x01, "Application"}, {0x02, "Logical"},
    {0x03, "Report"},     {0x04, "Named Array"}, {0x05, "Usage Switch"},
    {0x06, "Usage Modifier"},
};

template<typename T, size_t N>
static const char* findByU16(const T (&table)[N], uint16_t id) {
    for (size_t i = 0; i < N; i++) if (table[i].id == id) return table[i].name;
    return nullptr;
}

template<typename T, size_t N>
static const char* findByU8(const T (&table)[N], uint8_t id) {
    for (size_t i = 0; i < N; i++) if (table[i].id == id) return table[i].name;
    return nullptr;
}

static const char* usagePageName(uint16_t up) {
    return findByU16(USAGE_PAGES, up);
}

static const char* usageName(uint16_t up, uint32_t usage) {
    uint16_t u16 = (uint16_t)(usage & 0xFFFF);
    if (up == 0x01) return findByU16(USAGES_GENERIC_DESKTOP, u16);
    if (up == 0x0C) return findByU16(USAGES_CONSUMER, u16);
    if (up == 0x09) return nullptr; // Buttons: name is just the number
    return nullptr;
}

// ---- Per-report layout tracking ----

struct ReportField {
    uint16_t usage_page;
    uint32_t usage;     // first usage, or 0 if range
    uint32_t usage_min;
    uint32_t usage_max;
    uint16_t report_size;
    uint16_t report_count;
    bool     is_const;
    bool     is_var;
};

struct ReportTrack {
    uint8_t  report_id;
    char     kind; // 'I' input, 'O' output, 'F' feature
    std::vector<ReportField> fields;
};

static std::vector<ReportTrack> g_reports;

// reportId -> primary usage page of its Input report (0x07 keyboard, 0x0C consumer,
// ...). Populated by parse(), consumed by the live stream decoder.
static std::map<uint8_t, uint16_t> g_report_usage;

static ReportTrack* getOrCreateReport(uint8_t id, char kind) {
    for (auto& r : g_reports) {
        if (r.report_id == id && r.kind == kind) return &r;
    }
    g_reports.push_back({id, kind, {}});
    return &g_reports.back();
}

// ---- Item type / tag tables ----

static const char* mainTagName(uint8_t tag) {
    switch (tag) {
        case 0x8: return "Input";
        case 0x9: return "Output";
        case 0xA: return "Collection";
        case 0xB: return "Feature";
        case 0xC: return "End Collection";
        default:  return "Reserved Main";
    }
}

static const char* globalTagName(uint8_t tag) {
    switch (tag) {
        case 0x0: return "Usage Page";
        case 0x1: return "Logical Minimum";
        case 0x2: return "Logical Maximum";
        case 0x3: return "Physical Minimum";
        case 0x4: return "Physical Maximum";
        case 0x5: return "Unit Exponent";
        case 0x6: return "Unit";
        case 0x7: return "Report Size";
        case 0x8: return "Report ID";
        case 0x9: return "Report Count";
        case 0xA: return "Push";
        case 0xB: return "Pop";
        default:  return "Reserved Global";
    }
}

static const char* localTagName(uint8_t tag) {
    switch (tag) {
        case 0x0: return "Usage";
        case 0x1: return "Usage Minimum";
        case 0x2: return "Usage Maximum";
        case 0x3: return "Designator Index";
        case 0x4: return "Designator Minimum";
        case 0x5: return "Designator Maximum";
        case 0x7: return "String Index";
        case 0x8: return "String Minimum";
        case 0x9: return "String Maximum";
        case 0xA: return "Delimiter";
        default:  return "Reserved Local";
    }
}

// ---- Data extraction ----

static uint32_t readDataUnsigned(const uint8_t* p, uint8_t bytes) {
    uint32_t v = 0;
    for (uint8_t i = 0; i < bytes; i++) v |= ((uint32_t)p[i]) << (8 * i);
    return v;
}

static int32_t readDataSigned(const uint8_t* p, uint8_t bytes) {
    uint32_t u = readDataUnsigned(p, bytes);
    if (bytes == 0) return 0;
    uint32_t sign_bit = 1UL << (8 * bytes - 1);
    if (u & sign_bit) {
        uint32_t mask = (bytes >= 4) ? 0xFFFFFFFFUL : ((1UL << (8 * bytes)) - 1);
        return (int32_t)(u | ~mask);
    }
    return (int32_t)u;
}

static void printIndent(Print& out, int depth) {
    for (int i = 0; i < depth; i++) out.print("  ");
}

static void printIOFlags(Print& out, uint32_t f) {
    out.printf(" (%s,%s,%s",
                  (f & 0x01) ? "Const" : "Data",
                  (f & 0x02) ? "Var"   : "Array",
                  (f & 0x04) ? "Rel"   : "Abs");
    if (f & 0x08) out.print(",Wrap");
    if (f & 0x10) out.print(",NonLin");
    if (f & 0x20) out.print(",NoPref");
    if (f & 0x40) out.print(",Null");
    if (f & 0x80) out.print(",Vol");
    if (f & 0x100) out.print(",Buf");
    out.print(")");
}

} // anonymous namespace

// ---- Main parser ----

void parse(const uint8_t* data, size_t len, Print& out) {
    if (!data || len == 0) {
        out.println("[hid] empty report map");
        return;
    }

    out.printf("\n========== HID REPORT MAP (%u bytes) ==========\n", (unsigned)len);

    // Tracked state per HID 1.11 §6.2.2:
    //   Global items persist until explicitly changed.
    //   Local items reset to defaults after every Main item.
    uint16_t cur_usage_page = 0;
    uint8_t  cur_report_id  = 0;
    uint16_t cur_report_size  = 0;
    uint16_t cur_report_count = 0;
    int32_t  cur_logical_min  = 0;
    int32_t  cur_logical_max  = 0;
    std::vector<uint32_t> local_usages;
    uint32_t local_usage_min = 0;
    uint32_t local_usage_max = 0;
    bool     have_usage_range = false;
    int      depth = 0;

    g_reports.clear();
    g_report_usage.clear();

    size_t i = 0;
    while (i < len) {
        uint8_t b0 = data[i];

        // Long item - rare in practice, but spec-compliant
        if (b0 == 0xFE) {
            if (i + 2 >= len) break;
            uint8_t dsize = data[i + 1];
            uint8_t tag   = data[i + 2];
            printIndent(out, depth);
            out.printf("Long Item tag=0x%02X size=%u\n", tag, dsize);
            i += 3 + dsize;
            continue;
        }

        uint8_t bSize = b0 & 0x03;
        uint8_t bType = (b0 >> 2) & 0x03;
        uint8_t bTag  = (b0 >> 4) & 0x0F;
        uint8_t nbytes = (bSize == 3) ? 4 : bSize;

        if (i + 1 + nbytes > len) {
            out.println("[hid] truncated item");
            break;
        }
        const uint8_t* dptr = data + i + 1;

        uint32_t uval = readDataUnsigned(dptr, nbytes);
        int32_t  sval = readDataSigned(dptr, nbytes);

        if (bType == 0) {
            // ----- Main -----
            const char* name = mainTagName(bTag);
            if (bTag == 0xC) depth = (depth > 0) ? depth - 1 : 0;
            printIndent(out, depth);
            out.printf("%s", name);

            if (bTag == 0x8 || bTag == 0x9 || bTag == 0xB) {
                // Input/Output/Feature
                printIOFlags(out, uval);
                out.printf("  rid=%u size=%u count=%u\n",
                              cur_report_id, cur_report_size, cur_report_count);
                ReportField rf{};
                rf.usage_page  = cur_usage_page;
                rf.usage       = local_usages.empty() ? 0 : local_usages[0];
                rf.usage_min   = local_usage_min;
                rf.usage_max   = local_usage_max;
                rf.report_size = cur_report_size;
                rf.report_count= cur_report_count;
                rf.is_const    = (uval & 0x01);
                rf.is_var      = (uval & 0x02);
                char kind = (bTag == 0x8) ? 'I' : (bTag == 0x9) ? 'O' : 'F';
                getOrCreateReport(cur_report_id, kind)->fields.push_back(rf);
                // Record the primary usage page of each Input report for the
                // live stream decoder (keep the first non-zero page seen).
                if (kind == 'I' && cur_usage_page != 0 &&
                    g_report_usage.find(cur_report_id) == g_report_usage.end()) {
                    g_report_usage[cur_report_id] = cur_usage_page;
                }
            } else if (bTag == 0xA) {
                // Collection
                const char* ct = findByU8(COLLECTION_TYPES, (uint8_t)uval);
                out.printf(" (%s)\n", ct ? ct : "Unknown");
                depth++;
            } else {
                out.println();
            }

            // Locals reset after each Main item
            local_usages.clear();
            have_usage_range = false;
            local_usage_min = local_usage_max = 0;
        }
        else if (bType == 1) {
            // ----- Global -----
            printIndent(out, depth);
            const char* name = globalTagName(bTag);
            switch (bTag) {
                case 0x0: { // Usage Page
                    cur_usage_page = (uint16_t)uval;
                    const char* upn = usagePageName(cur_usage_page);
                    out.printf("%s (0x%04X%s%s)\n", name, cur_usage_page,
                                  upn ? " " : "", upn ? upn : "");
                    break;
                }
                case 0x1: cur_logical_min  = sval; out.printf("%s = %d\n", name, sval); break;
                case 0x2: cur_logical_max  = sval; out.printf("%s = %d\n", name, sval); break;
                case 0x7: cur_report_size  = (uint16_t)uval; out.printf("%s = %u\n", name, (unsigned)uval); break;
                case 0x8: cur_report_id    = (uint8_t)uval;  out.printf("%s = %u\n", name, (unsigned)uval); break;
                case 0x9: cur_report_count = (uint16_t)uval; out.printf("%s = %u\n", name, (unsigned)uval); break;
                default:
                    out.printf("%s = %u (0x%X)\n", name, (unsigned)uval, (unsigned)uval);
                    break;
            }
        }
        else if (bType == 2) {
            // ----- Local -----
            printIndent(out, depth);
            const char* name = localTagName(bTag);
            switch (bTag) {
                case 0x0: { // Usage
                    local_usages.push_back(uval);
                    const char* un = usageName(cur_usage_page, uval);
                    out.printf("%s (0x%04X%s%s)\n", name, (unsigned)uval,
                                  un ? " " : "", un ? un : "");
                    break;
                }
                case 0x1: local_usage_min = uval; have_usage_range = true;
                          out.printf("%s (0x%04X)\n", name, (unsigned)uval); break;
                case 0x2: local_usage_max = uval; have_usage_range = true;
                          out.printf("%s (0x%04X)\n", name, (unsigned)uval); break;
                default:
                    out.printf("%s = %u\n", name, (unsigned)uval);
                    break;
            }
        }
        else {
            printIndent(out, depth);
            out.printf("Reserved bType=%u bTag=0x%X data=0x%X\n", bType, bTag, (unsigned)uval);
        }

        i += 1 + nbytes;
    }

    // ---- Per-report layout cheatsheet ----
    if (!g_reports.empty()) {
        out.println("\n---------- Report layouts ----------");
        for (const auto& r : g_reports) {
            const char* kindStr = (r.kind == 'I') ? "Input"
                                : (r.kind == 'O') ? "Output" : "Feature";
            out.printf("\nReport ID %u (%s):\n", r.report_id, kindStr);
            unsigned bit_off = 0;
            for (const auto& f : r.fields) {
                unsigned width = (unsigned)f.report_size * (unsigned)f.report_count;
                out.printf("  bits %3u..%-3u (%2u bits)  page=0x%04X",
                              bit_off, bit_off + width - 1, width, f.usage_page);
                if (f.is_const) {
                    out.print("  [padding/const]");
                } else if (f.is_var && f.report_count > 1 && (f.usage_min || f.usage_max)) {
                    out.printf("  usage 0x%04X..0x%04X", (unsigned)f.usage_min, (unsigned)f.usage_max);
                } else if (f.usage) {
                    const char* un = usageName(f.usage_page, f.usage);
                    out.printf("  usage 0x%04X%s%s", (unsigned)f.usage,
                                  un ? " " : "", un ? un : "");
                }
                out.println();
                bit_off += width;
            }
            out.printf("  total: %u bits (%u bytes)\n", bit_off, (bit_off + 7) / 8);
        }
    }

    out.println("\n========== END HID REPORT MAP ==========\n");
    (void)have_usage_range;
    (void)cur_logical_min;
    (void)cur_logical_max;
}

// ---- Live HID input stream ----

namespace {

enum StreamKind { SK_RAW, SK_KEYBOARD, SK_CONSUMER, SK_HEARTRATE, SK_BATTERY };

std::vector<NimBLERemoteCharacteristic*> g_streamChars;
std::map<uint16_t, StreamKind>           g_streamKind;   // char handle -> decode kind
std::map<uint16_t, std::set<uint8_t>>    g_prevKeys;     // char handle -> last pressed keycodes
std::map<uint16_t, uint8_t>              g_prevMod;       // char handle -> last modifier byte
bool                                     g_streamActive = false;

// Ring buffer of recent decoded stream lines, for a UI to display (the engine
// also prints them to Serial). g_streamSeq increments on each push so a UI can
// cheaply detect new lines.
constexpr size_t kStreamRing = 24;
std::string  g_streamLines[kStreamRing];
size_t       g_streamHead = 0;   // index of oldest
size_t       g_streamLen  = 0;
uint32_t     g_streamSeq  = 0;

void pushStreamLine(const std::string& s) {
    size_t tail = (g_streamHead + g_streamLen) % kStreamRing;
    if (g_streamLen < kStreamRing) {
        g_streamLines[tail] = s;
        g_streamLen++;
    } else {
        g_streamLines[g_streamHead] = s;
        g_streamHead = (g_streamHead + 1) % kStreamRing;
    }
    g_streamSeq++;
}

void modString(uint8_t mod, char* out, size_t n) {
    out[0] = 0;
    static const char* names[8] = {"LCtrl", "LShift", "LAlt", "LGUI",
                                   "RCtrl", "RShift", "RAlt", "RGUI"};
    for (int i = 0; i < 8; i++) {
        if (mod & (1 << i)) {
            if (out[0]) strncat(out, "+", n - strlen(out) - 1);
            strncat(out, names[i], n - strlen(out) - 1);
        }
    }
}

// HID Keyboard/Keypad usage page (0x07) keycode -> label. Letters/digits/F-keys
// are generated; named keys come from the switch. Literal returns are static
// storage; generated names go in the caller's buffer.
const char* keyName(uint8_t kc, char* buf, size_t n) {
    if (kc >= 0x04 && kc <= 0x1D) { snprintf(buf, n, "%c", 'A' + (kc - 0x04)); return buf; }
    if (kc >= 0x1E && kc <= 0x26) { snprintf(buf, n, "%c", '1' + (kc - 0x1E)); return buf; }
    if (kc == 0x27) return "0";
    if (kc >= 0x3A && kc <= 0x45) { snprintf(buf, n, "F%d", kc - 0x39); return buf; }
    switch (kc) {
        case 0x28: return "Enter";   case 0x29: return "Esc";    case 0x2A: return "Backspace";
        case 0x2B: return "Tab";     case 0x2C: return "Space";  case 0x2D: return "-";
        case 0x2E: return "=";       case 0x2F: return "[";      case 0x30: return "]";
        case 0x31: return "\\";      case 0x33: return ";";      case 0x34: return "'";
        case 0x35: return "`";       case 0x36: return ",";      case 0x37: return ".";
        case 0x38: return "/";       case 0x39: return "CapsLock";
        case 0x46: return "PrtScr";  case 0x47: return "ScrollLock"; case 0x48: return "Pause";
        case 0x49: return "Insert";  case 0x4A: return "Home";   case 0x4B: return "PageUp";
        case 0x4C: return "Delete";  case 0x4D: return "End";    case 0x4E: return "PageDown";
        case 0x4F: return "Right";   case 0x50: return "Left";   case 0x51: return "Down";
        case 0x52: return "Up";      case 0x53: return "NumLock";
    }
    snprintf(buf, n, "0x%02X", kc);
    return buf;
}

// Standard boot-style keyboard input report: [modifiers][reserved][keycode x6].
// Prints each newly-pressed key (down-edge) with the active modifiers.
void decodeKeyboard(uint16_t handle, const uint8_t* d, size_t len) {
    if (len < 1) return;
    uint8_t mod = d[0];
    char mods[80];
    modString(mod, mods, sizeof(mods));

    std::set<uint8_t> cur;
    for (size_t i = 2; i < len; i++) {
        if (d[i] >= 0x04) cur.insert(d[i]);
    }

    std::set<uint8_t>& prev = g_prevKeys[handle];
    int printed = 0;
    for (uint8_t kc : cur) {
        if (!prev.count(kc)) {
            char kb[8];
            const char* kn = keyName(kc, kb, sizeof(kb));
            std::string line = mods[0] ? (std::string(mods) + "+" + kn) : std::string(kn);
            Serial.printf("[hid kbd] %s\n", line.c_str());
            pushStreamLine(line);
            printed++;
        }
    }
    if (printed == 0 && cur.empty() && mod != g_prevMod[handle] && mod != 0) {
        Serial.printf("[hid kbd] (modifiers) %s\n", mods);
        pushStreamLine(std::string("(mod) ") + mods);
    }
    prev = cur;
    g_prevMod[handle] = mod;
}

// Heart Rate Measurement (0x2A37), per the BLE Heart Rate Service spec:
//   byte0 = flags: bit0 HR is uint16 (else uint8), bit1 contact detected,
//           bit2 contact supported, bit3 energy expended present, bit4 RR present
//   then the HR value (1 or 2 bytes LE), optional energy (uint16), optional
//   RR intervals (uint16 each, units of 1/1024 s).
void decodeHeartRate(const uint8_t* d, size_t len) {
    if (len < 2) return;
    uint8_t flags = d[0];
    size_t i;
    uint16_t hr;
    if (flags & 0x01) { if (len < 3) return; hr = (uint16_t)(d[1] | (d[2] << 8)); i = 3; }
    else              { hr = d[1]; i = 2; }
    (void)i;
    std::string line = "HR ";
    char b[24];
    snprintf(b, sizeof(b), "%u bpm", (unsigned)hr); line += b;
    if ((flags & 0x04) && !(flags & 0x02)) line += " (no contact)";   // supported but not detected
    // Energy-expended and RR-intervals are intentionally NOT shown - RR (HRV)
    // data floods the live view; this is a heart-rate readout, not an HRV logger.
    Serial.printf("[hr] %s\n", line.c_str());
    pushStreamLine(line);
}

void decodeBattery(const uint8_t* d, size_t len) {
    if (len < 1) return;
    char b[24]; snprintf(b, sizeof(b), "Batt %u%%", (unsigned)d[0]);
    Serial.printf("[batt] %u%%\n", (unsigned)d[0]);
    pushStreamLine(b);
}

void hidStreamCb(NimBLERemoteCharacteristic* chr, uint8_t* data, size_t len, bool) {
    uint16_t h = chr->getHandle();
    auto it = g_streamKind.find(h);
    StreamKind kind = (it != g_streamKind.end()) ? it->second : SK_RAW;
    if (kind == SK_KEYBOARD)  { decodeKeyboard(h, data, len); return; }
    if (kind == SK_HEARTRATE) { decodeHeartRate(data, len);   return; }
    if (kind == SK_BATTERY)   { decodeBattery(data, len);     return; }
    char hdr[32];
    snprintf(hdr, sizeof(hdr), "%s ", kind == SK_CONSUMER ? "consumer" : "raw");
    std::string line = hdr;
    char b[4];
    for (size_t i = 0; i < len; i++) { snprintf(b, sizeof(b), "%02X ", data[i]); line += b; }
    Serial.printf("[hid h=0x%04X] %s\n", h, line.c_str());
    pushStreamLine(line);
}

} // anonymous namespace

bool streamActive() { return g_streamActive; }

uint32_t streamSeq() { return g_streamSeq; }
size_t   streamLineCount() { return g_streamLen; }
const std::string& streamLine(size_t i) {
    static const std::string empty;
    if (i >= g_streamLen) return empty;
    return g_streamLines[(g_streamHead + i) % kStreamRing];   // 0 = oldest
}

namespace {
// Classify a notify characteristic into a decode kind + a friendly label for the
// picker. ok=false means it isn't streamable (not notify, or a non-input HID rpt).
struct SrcInfo { StreamKind kind; std::string label; bool defaultOn; bool ok; };

SrcInfo classifySource(const NimBLEUUID& svcUuid, const gatt::CharEntry& chr) {
    SrcInfo s{SK_RAW, "", false, false};
    if (!(chr.props & BLE_GATT_CHR_PROP_NOTIFY)) return s;   // only notify chars stream

    static const NimBLEUUID HID_SVC((uint16_t)0x1812);
    static const NimBLEUUID REPORT((uint16_t)0x2A4D);
    static const NimBLEUUID BOOT_KBD((uint16_t)0x2A22);
    static const NimBLEUUID RPT_REF((uint16_t)0x2908);
    static const NimBLEUUID HR_SVC((uint16_t)0x180D);
    static const NimBLEUUID HR_MEAS((uint16_t)0x2A37);
    static const NimBLEUUID BATT_SVC((uint16_t)0x180F);
    static const NimBLEUUID BATT_LVL((uint16_t)0x2A19);

    if (svcUuid == HR_SVC   && chr.uuid == HR_MEAS)  return {SK_HEARTRATE, "Heart Rate", true, true};
    if (svcUuid == BATT_SVC && chr.uuid == BATT_LVL) return {SK_BATTERY,   "Battery",    true, true};
    if (svcUuid == HID_SVC) {
        if (chr.uuid == BOOT_KBD) return {SK_KEYBOARD, "HID keyboard (boot)", true, true};
        if (chr.uuid == REPORT) {
            bool isInput = false; uint8_t reportId = 0;
            for (const auto& d : chr.descs)
                if (d.uuid == RPT_REF && d.value.size() >= 2) { reportId = d.value[0]; isInput = (d.value[1] == 1); }
            if (!isInput) return s;
            auto u = g_report_usage.find(reportId);
            uint16_t page = (u != g_report_usage.end()) ? u->second : 0;
            if (page == 0x07) return {SK_KEYBOARD, "HID keyboard", true, true};
            if (page == 0x0C) return {SK_CONSUMER, "HID media keys", true, true};
            char b[24]; snprintf(b, sizeof(b), "HID report %u", reportId);
            return {SK_RAW, b, true, true};
        }
        return s;   // other HID char (not an input report)
    }
    // Any other notify characteristic: streamable as raw hex, default off.
    std::string u = chr.uuid.toString();
    size_t dash = u.find('-');
    std::string label = "Notify ";
    label += (dash != std::string::npos && u.size() >= 8) ? u.substr(4, 4) : u;   // 128-bit: distinguishing nibble
    return {SK_RAW, label, false, true};
}
}  // namespace

std::vector<StreamSource> streamSources() {
    std::vector<StreamSource> out;
    if (!connection::isConnected() || !gatt::hasCache()) return out;
    if (g_report_usage.empty()) parseFromGatt();   // needed to label HID reports
    for (const auto& svc : gatt::cache())
        for (const auto& chr : svc.chars) {
            SrcInfo c = classifySource(svc.uuid, chr);
            if (c.ok) out.push_back({chr.handle, c.label, c.defaultOn});
        }
    return out;
}

bool streamStart(const std::vector<uint16_t>& handles) {
    if (!connection::isConnected()) { Serial.println("[stream] not connected"); return false; }
    if (!gatt::hasCache())          { Serial.println("[stream] no GATT cache - run 'dump' first"); return false; }
    if (g_streamActive) streamStop();
    if (handles.empty())            { Serial.println("[stream] no characteristics selected"); return false; }
    g_streamHead = 0; g_streamLen = 0;   // fresh ring for this session
    if (g_report_usage.empty()) parseFromGatt();

    std::set<uint16_t> want(handles.begin(), handles.end());
    int n = 0;
    for (const auto& svc : gatt::cache()) {
        for (const auto& chr : svc.chars) {
            if (!want.count(chr.handle)) continue;
            SrcInfo c = classifySource(svc.uuid, chr);
            if (!c.ok) continue;
            if (chr.ptr->subscribe(true, hidStreamCb)) {
                g_streamChars.push_back(chr.ptr);
                g_streamKind[chr.handle] = c.kind;
                n++;
                Serial.printf("[stream] subscribed h=0x%04X (%s)\n", chr.handle, c.label.c_str());
            }
        }
    }
    if (n == 0) { Serial.println("[stream] nothing subscribable in selection"); return false; }
    g_streamActive = true;
    Serial.printf("[stream] active on %d characteristic(s)\n", n);
    return true;
}

bool streamStart() {
    std::vector<uint16_t> on;
    for (const auto& s : streamSources()) if (s.defaultOn) on.push_back(s.handle);
    return streamStart(on);
}

void streamStop() {
    if (!g_streamActive) {
        Serial.println("[hid] stream not active");
        return;
    }
    if (connection::isConnected()) {
        for (auto* c : g_streamChars) c->unsubscribe();
    }
    g_streamChars.clear();
    g_streamKind.clear();
    g_prevKeys.clear();
    g_prevMod.clear();
    g_streamActive = false;
    Serial.println("[hid] stream stopped");
}

bool parseFromGatt() {
    static const NimBLEUUID HID_SVC((uint16_t)0x1812);
    static const NimBLEUUID REPORT_MAP((uint16_t)0x2A4B);

    if (!gatt::hasCache()) {
        Serial.println("[hid] no gatt cache - run 'dump' first");
        return false;
    }
    for (const auto& svc : gatt::cache()) {
        if (!(svc.uuid == HID_SVC)) continue;
        for (const auto& chr : svc.chars) {
            if (!(chr.uuid == REPORT_MAP)) continue;
            // Prefer the snapshot captured during dump (works offline). Fall back
            // to a live read only if the snapshot is empty and we're connected.
            if (chr.value_cached) {
                parse(chr.value.data(), chr.value.size());
                return true;
            }
            if (connection::isConnected()) {
                std::string v = chr.ptr->readValue();
                if (!v.empty()) {
                    parse((const uint8_t*)v.data(), v.length());
                    return true;
                }
            }
            Serial.println("[hid] could not read Report Map (encryption / permissions?)");
            return false;
        }
    }
    Serial.println("[hid] no HID service (0x1812) on this peer");
    return false;
}

}
