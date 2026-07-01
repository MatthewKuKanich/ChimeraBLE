// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#pragma once

#include <Arduino.h>

namespace cli {

void init();

void poll();

void prompt();

// Tokenize and dispatch a single command line (no trailing newline needed).
// Shared by the serial poll() and the Cardputer UI command mode. Output still
// goes to Serial. `line` is copied internally, so a const string is fine.
void execute(const char* line);

}
