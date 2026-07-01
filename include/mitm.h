// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#pragma once

#include <Arduino.h>

#include "scanner.h"

// BLE man-in-the-middle / passthrough proxy.
//
// Sits between a real target device and a host. Because a GATT server can only
// be built before NimBLE commits its database (which happens at the first
// connection), the proxy is set up over a reboot - exactly like the clone:
//
//   requestStart(): connected + dumped target -> persist its structure + a
//                   marker, then reboot.
//   applyBoot()   : on the next boot (no connections yet) rebuild the mirror
//                   server, advertise (own address + target name), THEN connect
//                   to the target as a central and wire the relays:
//                     - target notifications  -> forwarded out to the host
//                     - host writes            -> forwarded in to the target
//                   everything logged to the Honeypot stream (screen + SD).
namespace mitm {

// Pre-reboot: requires a connected + dumped target. Persists it and reboots.
void requestStart(const scanner::Result& target);

// Post-reboot (call early in setup, after NimBLEDevice::init). Returns true if a
// MITM session was pending and is now live.
bool applyBoot();

void stop();
bool active();

// Call from the main loop: re-starts advertising whenever the proxy is live and
// no host is connected (the central connect / a host disconnect stops the
// advertiser, so the clone would otherwise vanish from scans).
void loopTick();

}
