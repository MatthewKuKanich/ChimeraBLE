// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

// Cardputer ADV entry point. Replaces the serial main.cpp for the `cardputer`
// build env (see build_src_filter in platformio.ini). Runs the ChimeraBLE
// engine natively + the on-device M5 UI.
#include "App.h"

static App g_app;

void setup() {
  g_app.begin();
}

void loop() {
  g_app.loop();
}
