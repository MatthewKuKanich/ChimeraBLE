// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#include "hexdump.h"

#include <ctype.h>

namespace hexdump {

void line(const char* label, const uint8_t* data, size_t len, const char* indent) {
    Serial.printf("%s%s [%u bytes]:\n%s  ", indent, label, (unsigned)len, indent);
    for (size_t i = 0; i < len; i++) {
        Serial.printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < len) {
            Serial.printf("\n%s  ", indent);
        }
    }
    Serial.println();
    if (len > 0) {
        Serial.printf("%s  ascii: ", indent);
        for (size_t i = 0; i < len; i++) {
            char c = (char)data[i];
            Serial.print(isprint((unsigned char)c) ? c : '.');
        }
        Serial.println();
    }
}

void bytes(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        Serial.printf("%02X ", data[i]);
    }
}

static int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool parse(const char* s, uint8_t* out, size_t out_max, size_t* out_len) {
    size_t n = 0;
    while (*s && n < out_max) {
        while (*s == ' ' || *s == ':' || *s == '-' || *s == ',') s++;
        if (!*s) break;
        int hi = hexNibble(*s++);
        if (hi < 0) return false;
        if (!*s) return false;
        int lo = hexNibble(*s++);
        if (lo < 0) return false;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = n;
    return true;
}

}
