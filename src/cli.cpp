// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#include "cli.h"

#include "clone.h"
#include "connection.h"
#include "gatt.h"
#include "hexdump.h"
#include "hid_parser.h"
#include "log.h"
#include "scanner.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

namespace cli {

static constexpr size_t kLineMax = 256;
static char    g_line[kLineMax];
static size_t  g_len = 0;

static constexpr size_t kMaxArgs = 8;
struct Args {
    int   argc;
    char* argv[kMaxArgs];
};

static void printHelp();

static bool parseU16(const char* s, uint16_t* out) {
    char* end = nullptr;
    unsigned long v = strtoul(s, &end, 0);
    if (end == s || v > 0xFFFF) return false;
    *out = (uint16_t)v;
    return true;
}

static bool parseU32(const char* s, uint32_t* out) {
    char* end = nullptr;
    unsigned long v = strtoul(s, &end, 0);
    if (end == s) return false;
    *out = (uint32_t)v;
    return true;
}

static int tokenize(char* line, Args& a) {
    a.argc = 0;
    char* p = line;
    while (*p && a.argc < (int)kMaxArgs) {
        while (*p == ' ' || *p == '\t') *p++ = '\0';
        if (!*p) break;
        a.argv[a.argc++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
    }
    return a.argc;
}

static void cmdScan(Args& a) {
    uint32_t secs = 10;
    if (a.argc >= 2) parseU32(a.argv[1], &secs);
    scanner::start(secs);
}

static void cmdList(Args&) {
    scanner::printList();
}

static void cmdInfo(Args& a) {
    if (a.argc < 2) { Serial.println("usage: info <idx>"); return; }
    uint16_t idx;
    if (!parseU16(a.argv[1], &idx)) { Serial.println("bad idx"); return; }
    const auto* r = scanner::findByIndex(idx);
    if (!r) { Serial.println("idx out of range"); return; }
    scanner::printInfo(*r);
}

static void cmdConnect(Args& a) {
    if (a.argc < 2) { Serial.println("usage: connect <idx|mac>"); return; }
    const scanner::Result* r = nullptr;
    if (strchr(a.argv[1], ':')) {
        r = scanner::findByMac(a.argv[1]);
        if (!r) { Serial.println("mac not in scan results; run 'scan' first"); return; }
    } else {
        uint16_t idx;
        if (!parseU16(a.argv[1], &idx)) { Serial.println("bad idx"); return; }
        r = scanner::findByIndex(idx);
        if (!r) { Serial.println("idx out of range"); return; }
    }
    if (scanner::isScanning()) scanner::stop();
    connection::connectTo(*r);
}

static void cmdDisconnect(Args&) {
    gatt::clearCache();
    connection::disconnect();
}

static void cmdSecure(Args& a) {
    // `secure auto {on|off}` toggles auto-pairing on connect (separate from the
    // flag-config path below).
    if (a.argc >= 2 && !strcmp(a.argv[1], "auto")) {
        if (a.argc < 3) {
            Serial.printf("auto-secure on connect: %s\n", connection::autoSecure() ? "on" : "off");
            return;
        }
        if      (!strcmp(a.argv[2], "on"))  connection::setAutoSecure(true);
        else if (!strcmp(a.argv[2], "off")) connection::setAutoSecure(false);
        else { Serial.println("usage: secure auto {on|off}"); return; }
        Serial.printf("auto-secure on connect: %s\n", connection::autoSecure() ? "on" : "off");
        return;
    }

    connection::SecurityConfig cfg = connection::securityConfig();
    bool show_only = false;
    bool mutated   = false;
    for (int i = 1; i < a.argc; i++) {
        if (!strcmp(a.argv[i], "show")) { show_only = true; continue; }
        if (connection::applySecurityToken(a.argv[i], cfg)) {
            mutated = true;
        } else {
            Serial.printf("[sec] unknown token '%s'\n", a.argv[i]);
            Serial.println("       valid: bond|nobond mitm|nomitm lesc|legacy "
                           "iocap={none|display|display_yesno|keyboard|keyboard_display} show");
            return;
        }
    }
    if (mutated) connection::setSecurityConfig(cfg);
    connection::printSecurityConfig();
    if (!show_only) connection::secure();
}

static void cmdBonds(Args&) {
    connection::listBonds();
}

static void cmdPasskey(Args& a) {
    if (a.argc < 2) { Serial.println("usage: passkey <6 digits>"); return; }
    uint32_t pin;
    if (!parseU32(a.argv[1], &pin) || pin > 999999) {
        Serial.println("bad passkey (expect 0-999999)");
        return;
    }
    connection::injectPasskey(pin);
}

static void cmdForget(Args& a) {
    if (a.argc < 2) { Serial.println("usage: forget <mac|all>"); return; }
    connection::forgetBond(a.argv[1]);
}

static void cmdClone(Args& a) {
    if (a.argc < 2) {
        Serial.println("usage: clone <save|list|load|info|advertise|stop|delete> [name]");
        return;
    }
    const char* sub = a.argv[1];
    if      (!strcmp(sub, "save")) {
        if (a.argc < 3) { Serial.println("usage: clone save <name>"); return; }
        clone::save(a.argv[2]);
    } else if (!strcmp(sub, "list")) {
        clone::list();
    } else if (!strcmp(sub, "load")) {
        if (a.argc < 3) { Serial.println("usage: clone load <name>"); return; }
        clone::load(a.argv[2]);
    } else if (!strcmp(sub, "info")) {
        clone::info();
    } else if (!strcmp(sub, "advertise")) {
        if (a.argc >= 3 && !clone::load(a.argv[2])) return;
        clone::advertise();
    } else if (!strcmp(sub, "stop")) {
        clone::stop();
    } else if (!strcmp(sub, "delete")) {
        if (a.argc < 3) { Serial.println("usage: clone delete <name>"); return; }
        clone::remove(a.argv[2]);
    } else {
        Serial.printf("[clone] unknown subcommand '%s'\n", sub);
    }
}

static void cmdJson(Args& a) {
    if (a.argc < 2) {
        Serial.printf("json mode: %s\n", log_out::isJson() ? "on" : "off");
        return;
    }
    if      (!strcmp(a.argv[1], "on"))  log_out::setJson(true);
    else if (!strcmp(a.argv[1], "off")) log_out::setJson(false);
    else { Serial.println("usage: json {on|off}"); return; }
    Serial.printf("json mode: %s\n", log_out::isJson() ? "on" : "off");
}

static void cmdMtu(Args& a) {
    if (a.argc < 2) { Serial.println("usage: mtu <bytes 23-517>"); return; }
    uint16_t m;
    if (!parseU16(a.argv[1], &m) || m < 23 || m > 517) {
        Serial.println("bad mtu");
        return;
    }
    connection::requestMtu(m);
}

static void cmdDump(Args&) {
    gatt::dump(true);
    // Convenience: if a HID service was discovered, parse its Report Map right
    // after the GATT dump so the user immediately gets the decoded report layout.
    static const NimBLEUUID HID_SVC((uint16_t)0x1812);
    for (const auto& svc : gatt::cache()) {
        if (svc.uuid == HID_SVC) {
            hid_parser::parseFromGatt();
            break;
        }
    }
}

static gatt::CharEntry* resolveOrComplain(const char* spec) {
    gatt::CharEntry* ch = gatt::resolveChar(spec);
    if (!ch) Serial.printf("no characteristic matches '%s' (try a handle or 'uuid:<uuid>')\n", spec);
    return ch;
}

static void cmdRead(Args& a) {
    if (a.argc < 2) { Serial.println("usage: read <handle|uuid:UUID>"); return; }
    gatt::CharEntry* ch = resolveOrComplain(a.argv[1]);
    if (ch) gatt::readChar(ch->handle);
}

static void cmdWrite(Args& a, bool withResponse) {
    if (a.argc < 3) {
        Serial.printf("usage: %s <handle|uuid:UUID> <hex bytes>\n", withResponse ? "write" : "writenr");
        return;
    }
    gatt::CharEntry* ch = resolveOrComplain(a.argv[1]);
    if (!ch) return;
    uint8_t buf[64];
    size_t  len = 0;
    if (!hexdump::parse(a.argv[2], buf, sizeof(buf), &len) || len == 0) {
        Serial.println("bad hex bytes");
        return;
    }
    gatt::writeChar(ch->handle, buf, len, withResponse);
}

static void cmdSub(Args& a) {
    if (a.argc < 2) { Serial.println("usage: sub <handle|uuid:UUID>"); return; }
    gatt::CharEntry* ch = resolveOrComplain(a.argv[1]);
    if (ch) gatt::subscribe(ch->handle);
}

static void cmdUnsub(Args& a) {
    if (a.argc < 2) { Serial.println("usage: unsub <handle|uuid:UUID>"); return; }
    gatt::CharEntry* ch = resolveOrComplain(a.argv[1]);
    if (ch) gatt::unsubscribe(ch->handle);
}

static void cmdSubs(Args&) {
    gatt::listSubscriptions();
}

static void cmdStatus(Args&) {
    connection::printStatus();
    Serial.printf("scanning=%d  scan_results=%u  gatt_cached=%d\n",
                  scanner::isScanning(),
                  (unsigned)scanner::results().size(),
                  gatt::hasCache());
}

static void cmdStop(Args&) {
    if (scanner::foxhuntActive()) scanner::foxhuntStop();
    else scanner::stop();
}

static void cmdFoxhunt(Args& a) {
    if (a.argc >= 2 && (!strcmp(a.argv[1], "off") || !strcmp(a.argv[1], "stop"))) {
        scanner::foxhuntStop();
        return;
    }
    if (a.argc < 2) {
        Serial.println("usage: foxhunt <idx|mac>   (live RSSI tracking; 'stop' to end)");
        return;
    }
    std::string addr, name;
    uint8_t addr_type = 0;   // default public for a directly-typed MAC
    if (strchr(a.argv[1], ':')) {
        addr = a.argv[1];
        const auto* r = scanner::findByMac(a.argv[1]);
        if (r) { name = r->name; addr_type = r->addr_type; }
    } else {
        uint16_t idx;
        if (!parseU16(a.argv[1], &idx)) { Serial.println("bad idx"); return; }
        const auto* r = scanner::findByIndex(idx);
        if (!r) { Serial.println("idx out of range; run 'scan' + 'list' first"); return; }
        addr = r->addr;
        name = r->name;
        addr_type = r->addr_type;
    }
    scanner::foxhuntStart(addr, addr_type, name);
}

static void cmdHid(Args& a) {
    if (a.argc >= 2 && !strcmp(a.argv[1], "stream")) {
        if (a.argc >= 3 && !strcmp(a.argv[2], "off")) hid_parser::streamStop();
        else hid_parser::streamStart();
        return;
    }
    hid_parser::parseFromGatt();
}

static void dispatch(Args& a) {
    if (a.argc == 0) return;
    const char* cmd = a.argv[0];

    if      (!strcmp(cmd, "help"))       printHelp();
    else if (!strcmp(cmd, "scan"))       cmdScan(a);
    else if (!strcmp(cmd, "stop"))       cmdStop(a);
    else if (!strcmp(cmd, "foxhunt"))    cmdFoxhunt(a);
    else if (!strcmp(cmd, "list"))       cmdList(a);
    else if (!strcmp(cmd, "info"))       cmdInfo(a);
    else if (!strcmp(cmd, "connect"))    cmdConnect(a);
    else if (!strcmp(cmd, "disconnect")) cmdDisconnect(a);
    else if (!strcmp(cmd, "secure"))     cmdSecure(a);
    else if (!strcmp(cmd, "mtu"))        cmdMtu(a);
    else if (!strcmp(cmd, "dump"))       cmdDump(a);
    else if (!strcmp(cmd, "read"))       cmdRead(a);
    else if (!strcmp(cmd, "write"))      cmdWrite(a, true);
    else if (!strcmp(cmd, "writenr"))    cmdWrite(a, false);
    else if (!strcmp(cmd, "sub"))        cmdSub(a);
    else if (!strcmp(cmd, "unsub"))      cmdUnsub(a);
    else if (!strcmp(cmd, "subs"))       cmdSubs(a);
    else if (!strcmp(cmd, "status"))     cmdStatus(a);
    else if (!strcmp(cmd, "hid"))        cmdHid(a);
    else if (!strcmp(cmd, "bonds"))      cmdBonds(a);
    else if (!strcmp(cmd, "passkey"))    cmdPasskey(a);
    else if (!strcmp(cmd, "forget"))     cmdForget(a);
    else if (!strcmp(cmd, "json"))       cmdJson(a);
    else if (!strcmp(cmd, "clone"))      cmdClone(a);
    else Serial.printf("unknown command: '%s'  (try 'help')\n", cmd);
}

static void printHelp() {
    Serial.println(
        "\nCommands:\n"
        "  scan [secs]              active scan (default 10s)\n"
        "  stop                     stop in-progress scan\n"
        "  list                     show last scan results (sorted by signal strength)\n"
        "  info <idx>               full advertising payload for device\n"
        "  foxhunt <idx|mac>        live RSSI tracking of one device (RF direction finding)\n"
        "  connect <idx|mac>        GAP connect (no security yet)\n"
        "  disconnect               drop link\n"
        "  secure [flags] [show]    request encryption / bonding (flags update config first)\n"
        "                           flags: bond|nobond mitm|nomitm lesc|legacy\n"
        "                           iocap={none|display|display_yesno|keyboard|keyboard_display}\n"
        "  secure auto {on|off}     auto-initiate pairing on connect (for HID devices)\n"
        "  bonds                    list stored bonds (NVS)\n"
        "  passkey <digits>         supply a passkey when prompted during pairing\n"
        "  forget <mac|all>         delete a bond\n"
        "  json {on|off}            toggle JSON-line output for events\n"
        "  clone save <name>        save connected device's GATT+adv to a profile (LittleFS)\n"
        "  clone list               list saved profiles\n"
        "  clone load <name>        load a profile into memory\n"
        "  clone info               show the loaded profile\n"
        "  clone advertise [name]   mirror profile as a peripheral (reboots once to spoof MAC)\n"
        "  clone stop               stop advertising the clone\n"
        "  clone delete <name>      delete a saved profile\n"
        "  mtu <bytes>              request ATT MTU (23-517)\n"
        "  dump                     enumerate services/chars/descs; read all readables\n"
        "  read <h|uuid:U>          one-shot read; h=handle (hex or dec), uuid:U=lookup\n"
        "  write <h|uuid:U> <hex>   write with response\n"
        "  writenr <h|uuid:U> <hex> write without response\n"
        "  sub <h|uuid:U>           subscribe notify/indicate\n"
        "  unsub <h|uuid:U>         unsubscribe\n"
        "  subs                     list active subscriptions\n"
        "  hid                      parse HID Report Map (0x2A4B) into report layouts\n"
        "  hid stream [off]         live-decode HID input reports (keyboard keys, etc.)\n"
        "  status                   show current link / scan / cache state\n"
        "  help                     this help\n");
}

void init() {
    g_len = 0;
}

void prompt() {
    if (log_out::isJson()) return;
    Serial.print(connection::isConnected() ? "ble-connected> " : "ble> ");
}

void execute(const char* line) {
    if (!line) return;
    char buf[kLineMax];
    strncpy(buf, line, kLineMax - 1);
    buf[kLineMax - 1] = '\0';
    Args a;
    tokenize(buf, a);
    dispatch(a);
}

void poll() {
    while (Serial.available() > 0) {
        int c = Serial.read();
        if (c < 0) break;

        if (c == '\r') continue;
        if (c == '\n') {
            Serial.println();
            g_line[g_len] = '\0';
            if (g_len > 0) {
                Args a;
                tokenize(g_line, a);
                dispatch(a);
            }
            g_len = 0;
            prompt();
            continue;
        }
        if ((c == 0x08 || c == 0x7F) && g_len > 0) {
            g_len--;
            Serial.print("\b \b");
            continue;
        }
        if (g_len + 1 < kLineMax && c >= 0x20 && c < 0x7F) {
            g_line[g_len++] = (char)c;
            Serial.write((char)c);
        }
    }
}

}
