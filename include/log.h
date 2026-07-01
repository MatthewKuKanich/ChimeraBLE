// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#pragma once

#include <Arduino.h>
#include <stddef.h>
#include <stdint.h>

// Output-mode switch. In human mode (default) the tool prints formatted text
// for interactive use. In json mode it emits one JSON object per line for
// each machine-parseable event (dump entries, notify, scan results) - pipe
// the serial port through jq or a script to do offline analysis.
namespace log_out {

void setJson(bool on);
bool isJson();

// Print a string with JSON escaping. Quotes and newlines get backslash-escaped;
// non-printable bytes become \uXXXX.
void jsonEscape(const char* s);

// Print "key":"hex hex hex" - space-separated lowercase hex.
void jsonHexField(const char* key, const uint8_t* data, size_t len);

}
