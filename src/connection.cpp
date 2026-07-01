// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#include "connection.h"

#include <ctype.h>
#include <string.h>

namespace connection {

static NimBLEClient*   g_client = nullptr;
static SecurityConfig  g_sec;
static bool            g_lastAuthEncrypted = false;
static bool            g_lastAuthBonded    = false;
static bool            g_autosecure = false;   // auto-initiate pairing on connect
static bool            g_mtu_done   = false;   // MTU exchanged this connection
static bool            g_awaitingPasskey = false;  // pairing is waiting on `passkey <n>`
static volatile uint32_t g_numericPin = 0;          // last Numeric Comparison code (UI display)

// Async-connect result, set from the host-task connect callbacks and polled by
// doConnect's wait loop (so the loop can also watch for a UI cancel / timeout).
static volatile bool   g_conn_done = false;   // a connect attempt has resolved
static volatile bool   g_conn_ok   = false;   // ... and it succeeded
static constexpr uint32_t kConnectTimeoutMs = 15000;

// Auto-upgrade-and-retry on authentication failure: if a connect drops because
// the peer rejected our (Just Works) pairing, retry once with MITM numeric
// comparison + auto-secure enabled.
static scanner::Result g_last_target;
static bool            g_have_last_target  = false;
static bool            g_auth_upgrade_tried = false;     // already auto-upgraded this attempt
static volatile bool   g_pending_auth_retry = false;     // set in cb, serviced in main loop

static bool doConnect(const scanner::Result& target, std::function<bool()> cancelCheck = nullptr);

// NimBLE encodes HCI-originated disconnect reasons as 0x200 + HCI status code.
// Translate the common ones so the cause is obvious.
static const char* disconnectReasonStr(int reason) {
    switch (reason) {
        case 0x205: return "Authentication Failure (key mismatch - clear bonds on both sides)";
        case 0x206: return "PIN or Key Missing (stale/absent bond)";
        case 0x208: return "Connection Timeout";
        case 0x213: return "Remote User Terminated Connection";
        case 0x216: return "Connection Terminated By Local Host";
        case 0x21A: return "Unsupported Remote Feature";
        case 0x23D: return "Connection Terminated due to MIC Failure (bad encryption key)";
        case 0x222: return "LL Response Timeout";
        case 0x23E: return "Failed to Establish Connection";
        default:    return nullptr;
    }
}

class ClientCb : public NimBLEClientCallbacks {
    void onConnect(NimBLEClient* c) override {
        Serial.printf("[link] connected to %s\n", c->getPeerAddress().toString().c_str());
        g_conn_ok = true;
        g_conn_done = true;
    }
    void onConnectFail(NimBLEClient*, int reason) override {
        const char* s = disconnectReasonStr(reason);
        if (s) Serial.printf("[link] connect failed reason=0x%04X (%s)\n", reason, s);
        else   Serial.printf("[link] connect failed reason=0x%04X\n", reason);
        g_conn_ok = false;
        g_conn_done = true;
    }
    void onDisconnect(NimBLEClient*, int reason) override {
        g_awaitingPasskey = false;   // clear any pending passkey prompt
        const char* s = disconnectReasonStr(reason);
        if (s) Serial.printf("[link] disconnected reason=0x%04X (%s)\n", reason, s);
        else   Serial.printf("[link] disconnected reason=0x%04X\n", reason);

        // Authentication Failure (0x205) / Key Missing (0x206): the peer rejected
        // our pairing. Only auto-upgrade to MITM numeric comparison if the user
        // hadn't already enabled authenticated pairing - otherwise respect their
        // explicit config (e.g. mitm + iocap=keyboard for Passkey Entry); a 0x205
        // there is a stale bond / wrong passkey, not a config gap. Serviced from
        // the main loop - never reconnect from inside the host-task callback.
        bool upgradeWouldHelp = !g_autosecure || !g_sec.mitm;
        if ((reason == 0x205 || reason == 0x206) &&
            g_have_last_target && !g_auth_upgrade_tried && upgradeWouldHelp) {
            g_pending_auth_retry = true;
        }
    }
    void onAuthenticationComplete(NimBLEConnInfo& info) override {
        g_awaitingPasskey = false;
        g_lastAuthEncrypted = info.isEncrypted();
        g_lastAuthBonded    = info.isBonded();
        Serial.printf("[sec] auth complete  encrypted=%d  bonded=%d  authenticated=%d\n",
                      info.isEncrypted(), info.isBonded(), info.isAuthenticated());
        if (!info.isEncrypted()) {
            Serial.println("[sec] link NOT encrypted - pairing failed or was rejected");
        }
    }

    // Numeric Comparison (LE Secure Connections): both sides show the same 6-digit
    // value and the user confirms they match. We print it (verify against the peer's
    // display) and auto-accept so the pairing completes.
    void onConfirmPasskey(NimBLEConnInfo& info, uint32_t pin) override {
        g_numericPin = pin ? pin : 1;   // expose for UI (1 if the code is literally 0)
        Serial.printf("\n[sec] >>> NUMERIC COMPARISON  passkey = %06u <<<\n", (unsigned)pin);
        Serial.println("[sec] verify this matches the value shown on the peer, then confirm on the peer");
        Serial.println("[sec] auto-accepting on the ESP32 side");
        NimBLEDevice::injectConfirmPasskey(info, true);
    }

    // Passkey Entry: the peer displays a 6-digit passkey we must input. Reading
    // serial here would block the host task, so we defer - stash the connection and
    // let the user run `passkey <digits>` from the CLI.
    void onPassKeyEntry(NimBLEConnInfo&) override {
        g_awaitingPasskey = true;
        Serial.println("\n[sec] >>> PASSKEY ENTRY REQUIRED <<<");
        Serial.println("[sec] the peer is displaying a 6-digit passkey;");
        Serial.println("[sec] type:  passkey <digits>   (e.g. passkey 481516)");
    }
};

static ClientCb g_clientCb;

void init() {
    NimBLEDevice::setSecurityAuth(g_sec.bond, g_sec.mitm, g_sec.lesc);
    NimBLEDevice::setSecurityIOCap(g_sec.iocap);
}

void setSecurityConfig(const SecurityConfig& cfg) {
    g_sec = cfg;
    NimBLEDevice::setSecurityAuth(g_sec.bond, g_sec.mitm, g_sec.lesc);
    NimBLEDevice::setSecurityIOCap(g_sec.iocap);
}

const SecurityConfig& securityConfig() { return g_sec; }

bool connectByMac(const std::string& mac, uint8_t addr_type) {
    scanner::Result r;
    r.addr = mac;
    r.addr_type = addr_type;
    r.rssi = 0;
    g_auth_upgrade_tried = false;
    return doConnect(r);
}

bool connectTo(const scanner::Result& target, std::function<bool()> cancelCheck) {
    // User-initiated connect: allow one automatic MITM upgrade if pairing fails.
    g_auth_upgrade_tried = false;
    return doConnect(target, cancelCheck);
}

static bool doConnect(const scanner::Result& target, std::function<bool()> cancelCheck) {
    if (g_client && g_client->isConnected()) {
        Serial.println("[link] already connected; disconnect first");
        return false;
    }

    g_last_target = target;
    g_have_last_target = true;

    if (!g_client) {
        g_client = NimBLEDevice::createClient();
        g_client->setClientCallbacks(&g_clientCb, false);
        g_client->setConnectionParams(12, 12, 0, 200);
        g_client->setConnectTimeout(kConnectTimeoutMs);   // give up sooner than the 30s default
    }

    NimBLEAddress addr(target.addr, target.addr_type);
    Serial.printf("[link] connecting to %s...\n", target.addr.c_str());

    // Async connect so the wait loop below stays responsive: it can abort on a
    // UI cancel (ESC) or our own timeout instead of blocking ~30s in the stack.
    // (asyncConnect=true; exchangeMTU=false - MTU is negotiated lazily later so
    // it doesn't race a device-led security handshake.)
    g_conn_done = false;
    g_conn_ok = false;
    if (!g_client->connect(addr, true, true, false)) {
        Serial.println("[link] connect could not be initiated");
        return false;
    }

    const uint32_t t0 = millis();
    while (!g_conn_done) {
        if (cancelCheck && cancelCheck()) {
            Serial.println("[link] connect canceled by user");
            g_client->cancelConnect();
            break;
        }
        if (millis() - t0 > kConnectTimeoutMs + 500) {   // backstop past the stack's own timeout
            Serial.println("[link] connect timed out");
            g_client->cancelConnect();
            break;
        }
        delay(10);
    }
    // Let a cancel/timeout settle into a result (onConnectFail) before reporting.
    for (uint32_t c0 = millis(); !g_conn_done && millis() - c0 < 800; ) delay(10);

    if (!g_conn_done || !g_conn_ok) return false;

    g_mtu_done = false;
    g_lastAuthEncrypted = false;
    g_lastAuthBonded = false;

    // Deliberately do NOT exchange MTU here. Devices that lead with a security
    // request (e.g. HID keyboards) can drop the link if we jam an ATT MTU
    // exchange in front of the pairing handshake. MTU is negotiated lazily on the
    // first GATT op (ensureMtuNegotiated), by which point encryption has settled.
    if (g_autosecure) {
        Serial.println("[sec] auto-secure on connect enabled");
        secure();
    }
    return true;
}

// Negotiate a large ATT MTU once per connection, right before the first GATT
// operation. A 247-byte MTU collapses multi-round-trip READ_BLOB sequences for
// long characteristics (e.g. HID Report Map) into single reads.
void ensureMtuNegotiated() {
    if (!isConnected() || g_mtu_done) return;
    NimBLEDevice::setMTU(247);
    if (g_client->exchangeMTU()) {
        Serial.printf("[mtu] negotiated MTU = %u\n", g_client->getMTU());
    }
    g_mtu_done = true;
}

void setAutoSecure(bool on) { g_autosecure = on; }
bool autoSecure()           { return g_autosecure; }

void serviceAutoRetry() {
    if (!g_pending_auth_retry) return;
    g_pending_auth_retry = false;
    g_auth_upgrade_tried = true;   // only ever auto-upgrade once per user connect

    // Escalate to keyboard_display (the most capable IO cap): lets the peer pick
    // either Numeric Comparison (we auto-accept) or Passkey Entry (UI prompts for
    // the digits) - so the one retry covers both authenticated-pairing methods.
    Serial.println("\n[sec] pairing was rejected - auto-enabling MITM "
                   "(iocap=keyboard_display) + auto-secure and retrying once");
    SecurityConfig cfg = g_sec;
    cfg.mitm  = true;
    cfg.lesc  = true;
    cfg.iocap = BLE_HS_IO_KEYBOARD_DISPLAY;
    setSecurityConfig(cfg);
    g_autosecure = true;

    if (g_have_last_target) {
        delay(300);   // let the stack settle after the failed link
        doConnect(g_last_target);
    }
}

bool injectPasskey(uint32_t pin) {
    if (!g_awaitingPasskey) {
        Serial.println("[sec] no passkey entry pending");
        return false;
    }
    if (!isConnected()) {
        Serial.println("[sec] link dropped before passkey could be injected");
        g_awaitingPasskey = false;
        return false;
    }
    NimBLEConnInfo info = g_client->getConnInfo();
    bool ok = NimBLEDevice::injectPassKey(info, pin);
    g_awaitingPasskey = false;
    Serial.printf("[sec] passkey %06u injected (%s)\n", (unsigned)pin, ok ? "ok" : "failed");
    return ok;
}

bool awaitingPasskey()    { return g_awaitingPasskey; }
bool authRetryPending()   { return g_pending_auth_retry; }

uint32_t takeNumericPin() {
    uint32_t p = g_numericPin;
    g_numericPin = 0;
    return p;
}

bool isConnected() {
    return g_client && g_client->isConnected();
}

bool isEncrypted() {
    return isConnected() && g_lastAuthEncrypted;
}

void disconnect() {
    if (!g_client || !g_client->isConnected()) {
        Serial.println("[link] not connected");
        return;
    }
    g_client->disconnect();
}

NimBLEClient* client() { return g_client; }

bool secure() {
    if (!isConnected()) {
        Serial.println("[sec] not connected");
        return false;
    }
    Serial.println("[sec] requesting encryption / bonding (async)...");
    // Async initiation is essential: secureConnection() in blocking mode parks the
    // main loop until pairing finishes, which deadlocks interactive Passkey Entry
    // (the user can't run `passkey <n>` because the CLI is blocked). Async returns
    // immediately; the result arrives via onAuthenticationComplete / onDisconnect.
    // A false return usually means the peer already started pairing (EALREADY) -
    // harmless for HID devices that lead with a security request.
    g_client->secureConnection(true);
    return true;
}

bool requestMtu(uint16_t mtu) {
    if (!isConnected()) {
        Serial.println("[mtu] not connected");
        return false;
    }
    if (!NimBLEDevice::setMTU(mtu)) {
        Serial.printf("[mtu] setMTU(%u) failed\n", mtu);
        return false;
    }
    Serial.printf("[mtu] local MTU set to %u; negotiated value will appear after next GATT op\n", mtu);
    return true;
}

const char* iocapName(uint8_t cap) {
    switch (cap) {
        case BLE_HS_IO_DISPLAY_ONLY:        return "display_only";
        case BLE_HS_IO_DISPLAY_YESNO:       return "display_yesno";
        case BLE_HS_IO_KEYBOARD_ONLY:       return "keyboard_only";
        case BLE_HS_IO_NO_INPUT_OUTPUT:     return "no_input_output";
        case BLE_HS_IO_KEYBOARD_DISPLAY:    return "keyboard_display";
        default:                            return "unknown";
    }
}

void printSecurityConfig() {
    Serial.printf("[sec] config: bond=%d mitm=%d lesc=%d iocap=%s\n",
                  g_sec.bond, g_sec.mitm, g_sec.lesc, iocapName(g_sec.iocap));
}

bool applySecurityToken(const char* tok, SecurityConfig& cfg) {
    if      (!strcmp(tok, "bond"))    { cfg.bond = true;  return true; }
    else if (!strcmp(tok, "nobond"))  { cfg.bond = false; return true; }
    else if (!strcmp(tok, "mitm"))    { cfg.mitm = true;  return true; }
    else if (!strcmp(tok, "nomitm"))  { cfg.mitm = false; return true; }
    else if (!strcmp(tok, "lesc"))    { cfg.lesc = true;  return true; }
    else if (!strcmp(tok, "legacy"))  { cfg.lesc = false; return true; }

    if (!strncmp(tok, "iocap=", 6)) {
        const char* v = tok + 6;
        if      (!strcmp(v, "none") || !strcmp(v, "no_input_output")) cfg.iocap = BLE_HS_IO_NO_INPUT_OUTPUT;
        else if (!strcmp(v, "display") || !strcmp(v, "display_only")) cfg.iocap = BLE_HS_IO_DISPLAY_ONLY;
        else if (!strcmp(v, "display_yesno"))                         cfg.iocap = BLE_HS_IO_DISPLAY_YESNO;
        else if (!strcmp(v, "keyboard") || !strcmp(v, "keyboard_only")) cfg.iocap = BLE_HS_IO_KEYBOARD_ONLY;
        else if (!strcmp(v, "keyboard_display"))                      cfg.iocap = BLE_HS_IO_KEYBOARD_DISPLAY;
        else { Serial.printf("[sec] unknown iocap '%s'\n", v); return true; }
        return true;
    }
    return false;
}

void listBonds() {
    int n = NimBLEDevice::getNumBonds();
    if (n <= 0) {
        Serial.println("[bonds] no bonded devices");
        return;
    }
    Serial.printf("[bonds] %d bonded device(s):\n", n);
    for (int i = 0; i < n; i++) {
        NimBLEAddress a = NimBLEDevice::getBondedAddress(i);
        Serial.printf("  %d: %s\n", i, a.toString().c_str());
    }
}

bool forgetBond(const char* mac_or_all) {
    if (!mac_or_all) return false;
    if (!strcmp(mac_or_all, "all")) {
        bool ok = NimBLEDevice::deleteAllBonds();
        Serial.printf("[bonds] delete all: %s\n", ok ? "OK" : "FAILED");
        return ok;
    }
    NimBLEAddress addr(std::string(mac_or_all), BLE_ADDR_PUBLIC);
    bool ok = NimBLEDevice::deleteBond(addr);
    Serial.printf("[bonds] delete %s: %s\n", mac_or_all, ok ? "OK" : "FAILED");
    return ok;
}

void printStatus() {
    if (!g_client) {
        Serial.println("status: no client created");
        return;
    }
    Serial.printf("status: connected=%d  peer=%s  encrypted=%d  bonded=%d\n",
                  g_client->isConnected(),
                  g_client->getPeerAddress().toString().c_str(),
                  g_lastAuthEncrypted,
                  g_lastAuthBonded);
}

}
