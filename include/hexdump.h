// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#pragma once

#include <Arduino.h>
#include <stddef.h>
#include <stdint.h>

namespace hexdump {

void line(const char* label, const uint8_t* data, size_t len, const char* indent = "    ");

void bytes(const uint8_t* data, size_t len);

bool parse(const char* s, uint8_t* out, size_t out_max, size_t* out_len);

}
