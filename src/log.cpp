// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#include "log.h"

namespace log_out {

static bool g_json = false;

void setJson(bool on) { g_json = on; }
bool isJson()         { return g_json; }

void jsonEscape(const char* s) {
    if (!s) return;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '\"': Serial.print("\\\""); break;
            case '\\': Serial.print("\\\\"); break;
            case '\n': Serial.print("\\n");  break;
            case '\r': Serial.print("\\r");  break;
            case '\t': Serial.print("\\t");  break;
            default:
                if (c < 0x20) Serial.printf("\\u%04X", c);
                else          Serial.write(c);
        }
    }
}

void jsonHexField(const char* key, const uint8_t* data, size_t len) {
    Serial.printf("\"%s\":\"", key);
    for (size_t i = 0; i < len; i++) {
        Serial.printf("%s%02x", i ? " " : "", data[i]);
    }
    Serial.print("\"");
}

}
