// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#include <Arduino.h>
#include <LittleFS.h>
#include <NimBLEDevice.h>

#include "cli.h"
#include "clone.h"
#include "connection.h"
#include "gatt.h"
#include "hid_parser.h"
#include "oui_db.h"
#include "scanner.h"

static void banner() {
    Serial.println();
    Serial.println("=========================================");
    Serial.println("  ChimeraBLE  -  ESP32 BLE security tool");
    Serial.println("  (c) 2026 Matthew Kukanich - GPL-3.0");
    Serial.println("  github.com/MatthewKuKanich/ChimeraBLE");
    Serial.println("=========================================");
    Serial.println("Type 'help' for commands. Start with 'scan'.");
    Serial.println();
}

void setup() {
    Serial.begin(115200);
    delay(500);

    banner();

    if (!LittleFS.begin(true)) {
        Serial.println("[fs] LittleFS mount failed (clone save/load + OUI DB unavailable)");
    } else {
        Serial.println("[fs] LittleFS mounted");
        oui_db::init();
    }

    // Must run before NimBLEDevice::init() - the BT controller latches its public
    // address at init. If a `clone advertise` requested a MAC spoof (and rebooted),
    // this sets the BT MAC to the target's now.
    bool pendingClone = clone::applyBootSpoof();

    NimBLEDevice::init("ChimeraBLE");
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);

    scanner::init();
    connection::init();
    clone::init();
    cli::init();

    if (pendingClone) {
        Serial.println("[clone] resuming advertise after MAC-spoof reboot");
        clone::advertise();
    }

    cli::prompt();
}

static bool g_was_connected = false;

void loop() {
    cli::poll();

    // Handle a deferred auth-failure retry (scheduled from the disconnect
    // callback) here on the main task, never from the BLE host callback.
    connection::serviceAutoRetry();

    // Scanner main-task work: deferred "scan complete" line + foxhunt dropout note.
    scanner::poll();
    scanner::foxhuntPoll();

    // Clear the GATT cache when a NEW link comes up (the old snapshot's live
    // pointers belong to the previous connection). Deliberately NOT cleared on
    // disconnect, so the dumped snapshot survives for `clone save` after a device
    // drops an idle link.
    bool connected = connection::isConnected();
    if (!g_was_connected && connected) {
        gatt::clearCache();
    }
    if (g_was_connected && !connected && hid_parser::streamActive()) {
        hid_parser::streamStop();   // drop stale subscriptions when the link goes away
    }
    g_was_connected = connected;

    delay(10);
}
