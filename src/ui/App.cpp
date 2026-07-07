// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#include "App.h"

#include <LittleFS.h>
#include <NimBLEDevice.h>
#include <SD.h>
#include <SPI.h>
#include <cctype>
#include <ctype.h>

#include "cli.h"
#include "clone.h"
#include "connection.h"
#include "fingerprint.h"
#include "gatt.h"
#include "hid_parser.h"
#include "mitm.h"
#include "oui_db.h"
#include "scanner.h"
#include "sentry.h"
#include "uuid_db.h"

namespace {

// Main menu has 5 entries; item 0 (Scan) is built dynamically (shows the current
// scan time) into App::mainItems_. The rest open categories / Sentry / Settings.
constexpr size_t kMainCount = 5;

// Manual-rule match types shown on the SentryType screen (index-aligned below).
const char* kMatchTypeMenu[] = {
    "MAC address",
    "OUI (vendor prefix)",
    "Company ID",
    "Service UUID",
    "Name contains",
};

// Category submenus reached from the main menu.
const char* kReconMenu[] = {
    "Devices",
    "GATT",
    "Live Stream",
    "Saved Dumps",
};
const char* kAdvMenu[] = {
    "Clone",
    "BLE Honeypot",
    "MITM proxy",
};

// Scan-time presets cycled on the Settings screen.
const uint16_t kScanPresets[] = {5, 10, 15, 20, 30, 45, 60, 90, 120};

// Sentry re-arms a fresh timed scan each cycle (proven-safe vs the continuous
// start(0) path, which leaks NimBLE's result vector). 6s balances latency/churn.
constexpr uint32_t kSentryScanSecs = 6;

// Battery is sampled this often (boot + ~every 10s) - enough to catch a charger
// plug-in jump within a few seconds without polling the PMIC every frame.
constexpr uint32_t kBatSampleMs = 10000;

// Charging-screen backlight: dim to save power, but legible (6 was too dark).
constexpr uint8_t kChargeBrightness = 30;

const char* kCloneActionItems[] = {
    "Save current dump...",
    "Advertise loaded",
    "Stop advertising",
};

const char* kDetailMenu[] = {
    "Connect",
    "Foxhunt / Track",
    "Clone",   // MITM stays on the Adversarial menu; Clone is the reliable action here
};

template <size_t N>
constexpr size_t countOf(const char* const (&)[N]) { return N; }

// ---- SD card (Cardputer ADV microSD) ----
// Everything ChimeraBLE writes to the card lives under one folder (App::sdBase_)
// so it never litters the SD root (clone profiles, Sentry rules, dumps, honeypot
// logs, and the OUI DB). The folder is resolved case-insensitively at mount and
// created if missing (see App::resolveSdBase); CHIMERA_SD_DIR is the canonical
// name used when none exists yet.
#define CHIMERA_SD_DIR "/ChimeraBLE"
constexpr int kSdSck = 40, kSdMiso = 39, kSdMosi = 14, kSdCs = 12;

// Filesystem-safe slug: keep alphanumerics, collapse runs of other chars to a
// single '_', trim, cap length. e.g. "Sonos Roam!" -> "Sonos_Roam".
String slug(const String& in, size_t maxLen = 24) {
  String out;
  bool lastUs = false;
  for (size_t i = 0; i < in.length() && out.length() < maxLen; ++i) {
    char c = in[i];
    if (isalnum((unsigned char)c)) { out += c; lastUs = false; }
    else if (!lastUs && out.length() > 0) { out += '_'; lastUs = true; }
  }
  while (out.length() && out[out.length() - 1] == '_') out.remove(out.length() - 1);
  return out;
}

String fileUuid(const NimBLEUUID& u, const char* (*named)(uint16_t)) {
  if (u.bitSize() == 16) {
    const uint8_t* b = u.getValue();
    uint16_t v = (uint16_t)(b[0] | (b[1] << 8));
    const char* n = named ? named(v) : nullptr;
    char buf[52];
    if (n) snprintf(buf, sizeof(buf), "0x%04X (%s)", v, n);
    else   snprintf(buf, sizeof(buf), "0x%04X", v);
    return buf;
  }
  return String(u.toString().c_str());
}

}  // namespace

// Drain clone honeypot events into the on-screen list + a real-time SD log.
// Auto-opens the Honeypot screen (and a fresh log file) the moment a host
// connects, so no events are missed.
void App::honeypotTick() {
  // New host connection? Auto-open the screen + start a fresh SD log.
  uint32_t seq = clone::hostConnSeq();
  if (seq != lastHostSeq_) {
    lastHostSeq_ = seq;
    hpLines_.clear();
    if (hpFileOpen_) { hpFile_.close(); hpFileOpen_ = false; }
    if (sdInit()) {
      String hpDir = sdBase_ + "/honeypot";
      if (!SD.exists(hpDir.c_str())) SD.mkdir(hpDir.c_str());
      char path[96];
      snprintf(path, sizeof(path), "%s/hp_%lu.log", hpDir.c_str(), (unsigned long)millis());
      hpFile_ = SD.open(path, FILE_WRITE);
      hpFileOpen_ = (bool)hpFile_;
      if (hpFileOpen_) {
        hpFile_.printf("BLE Honeypot log - clone '%s'\n", clone::activeName().c_str());
        hpFile_.flush();
        log(String("honeypot log: ") + path);
      }
    }
    enterScreen(MenuScreen::Honeypot);   // don't miss anything
  }

  // Drain queued events -> screen ring + SD (real-time, flushed each line).
  std::vector<std::string> ev;
  clone::drainHoneypot(ev);
  for (auto& e : ev) {
    hpLines_.push_back(String(e.c_str()));
    if (hpLines_.size() > 120) hpLines_.erase(hpLines_.begin());
    if (hpFileOpen_) { hpFile_.println(e.c_str()); }
  }
  if (!ev.empty() && hpFileOpen_) hpFile_.flush();

  // Close the log when the host drops (one file per connection).
  if (hpFileOpen_ && !clone::hostConnected()) {
    hpFile_.close();
    hpFileOpen_ = false;
  }
}

void App::loadSettings() {
  prefs_.begin("blere", false);
  scanSecs_ = prefs_.getUInt("scan", 10);
  if (scanSecs_ < 1 || scanSecs_ > 300) scanSecs_ = 10;
  audio_      = prefs_.getBool("audio", false);
  volume_     = prefs_.getUChar("vol", 80);
  brightness_ = prefs_.getUChar("bright", 160);
  autoSecure_ = prefs_.getBool("autosec", false);
}

void App::adjustVolume(int delta) {
  int v = (int)volume_ + delta;
  if (v < 0) v = 0; if (v > 255) v = 255;
  volume_ = (uint8_t)v;
  M5Cardputer.Speaker.setVolume(volume_);
  prefs_.putUChar("vol", volume_);
  M5Cardputer.Speaker.tone(1500, 30);   // sample blip at the new volume
}

void App::buildScanLabel() {
  snprintf(scanLabel_, sizeof(scanLabel_), "Scan (%us)", (unsigned)scanSecs_);
}

// Geiger-counter fox-hunt: beep faster + higher-pitched as the signal strengthens.
// Silent when out of range. Called every loop; gated by audio_ + foxhunt active.
void App::foxhuntAudioTick() {
  if (!audio_ || !scanner::foxhuntActive()) return;
  if (scanner::foxhuntSinceSeenMs() > 4000) return;       // no signal -> silence
  int rssi = scanner::foxhuntLastRssi();
  if (rssi <= -127) return;
  float f = (float)(rssi + 95) / 75.0f;                   // -95..-20 dBm -> 0..1
  if (f < 0) f = 0; if (f > 1) f = 1;
  uint32_t interval = (uint32_t)(1000.0f - f * 940.0f);   // 1000ms far -> 60ms near
  uint32_t now = millis();
  if (now - lastBeepMs_ >= interval) {
    M5Cardputer.Speaker.tone(700.0f + f * 2000.0f, 25);   // 700Hz far -> 2700Hz near
    lastBeepMs_ = now;
  }
}

void App::buildMainItems() {
  mainItems_[0] = scanLabel_;
  mainItems_[1] = "Recon & Analysis";
  mainItems_[2] = "Adversarial";
  mainItems_[3] = "Sentry";
  mainItems_[4] = "Settings";
}

void App::begin() {
  Serial.begin(115200);
  delay(100);

  loadSettings();      // scan time + audio pref from NVS
  buildScanLabel();
  buildMainItems();

  ui_.begin();
  M5Cardputer.Speaker.setVolume(volume_);
  M5Cardputer.Display.setBrightness(brightness_);
  sampleBattery(true);   // establish a battery baseline before the first draw

  // Brief branded boot splash, then on into the rest of init + the main menu.
  ui_.drawSplash();
  delay(1000);

  // LittleFS is still used as a fallback store for clone profiles/markers when no
  // SD is present. NOTE: under the M5 launcher our partition table isn't active,
  // so this may mount the launcher's data partition or fail - handled gracefully.
  if (!LittleFS.begin(true)) log("LittleFS mount failed (clone fallback unavailable)");

  // Prefer the microSD card for clone profiles + reboot markers when one is
  // present (bigger, removable, shareable); fall back to on-chip flash if not.
  // The OUI vendor DB lives ONLY on SD here: the Cardputer is sideloaded via the
  // M5 launcher under a different partition table, so the embedded LittleFS OUI
  // partition isn't present at runtime. Must run before applyBootSpoof so a
  // pending spoof/MITM profile loads from whichever store it was saved to.
  if (sdInit()) {
    clone::setStorage(&SD, (sdBase_ + "/clones").c_str());
    sentry::setStorage(&SD, (sdBase_ + "/sentry").c_str());
    // Locate oui.bin flexibly: base folder first, then the SD root, filename
    // matched case-insensitively - a misplaced or oddly-cased file still loads.
    String ouiPath = findOuiPath();
    if (ouiPath.length()) {
      oui_db::begin(SD, ouiPath.c_str());
      if (oui_db::available()) log(String("OUI vendor DB: ") + ouiPath);
    }
    if (!oui_db::available())
      log(String("no oui.bin found (put it in ") + sdBase_ + " for vendor names)");
    log("clone storage: SD card");
  } else {
    log("no SD - clone uses flash; OUI vendor lookups disabled");
  }
  sentry::load();   // watchlist rules (SD or flash)

  // MAC-spoof must be applied before NimBLE init (see clone::applyBootSpoof).
  bool pendingClone = clone::applyBootSpoof();

  NimBLEDevice::init("ChimeraBLE");
  NimBLEDevice::setPower(ESP_PWR_LVL_P9);

  scanner::init();
  connection::init();
  connection::setAutoSecure(autoSecure_);   // reactive by default (Settings: Auto-pair)
  clone::init();

  if (pendingClone) {
    clone::advertise();
    log("resumed clone advertise after reboot");
  }

  // Resume a pending MITM session: builds the mirror (clean GATT DB), advertises,
  // then connects to the target + wires relays.
  if (mitm::applyBoot()) {
    log("MITM proxy active - open BLE Honeypot");
  }

  log("ChimeraBLE (c) 2026 Matthew Kukanich - GPL-3.0");
  log("github.com/MatthewKuKanich/ChimeraBLE");
  log("ChimeraBLE ready");
  log("nav: Up/Down move, Left back, Right open, ' cmd");
}

void App::loop() {
  M5Cardputer.update();
  if (chargingMode_) { chargingTick(); return; }   // low-power battery screen
  engineTick();
  honeypotTick();
  mitm::loopTick();
  sentryTick();
  syncDeviceSelection();   // pin the device highlight to its address across live-scan re-sorts
  handleKeyboard();
  foxhuntAudioTick();

  if (passkeyMode_) {
    String shown = passkeyBuf_;
    while (shown.length() < 6) shown += "_";
    ui_.message("Enter passkey", (shown + "   Enter=ok").c_str());
    return;
  }

  if (sentryEntry_) {
    ui_.message(sentry::typeName(sentryEntryType_),
                (inputBuffer_ + "_   Enter=save").c_str());
    return;
  }

  if (confirmDelete_) {
    // Modal overlay; Enter confirms, anything else cancels (handled in handleKeyboard).
    ui_.message(sentryDelIdx_ >= 0 ? "Delete rule?" : "Delete this dump?",
                (deleteTarget_ + "   Enter=yes  any=no").c_str());
    return;
  }

  if (cloneNameEntry_) {
    ui_.message("Save clone as", (inputBuffer_ + "_").c_str(), 1, "Enter=save  Bksp=cancel");
    return;
  }

  if (cloneReplayConfirm_) {
    ui_.message("Advertise clone?", cloneSaveName_.c_str(), 1, "Enter=yes (reboots)  any=no");
    return;
  }

  if (escMenu_) {
    if (connection::isConnected())
      ui_.message("Disconnect?", "Enter=yes   c=forget bonds   any=no");
    else
      ui_.message("Forget all bonds?", "c=yes   any=no");
    return;
  }

  MenuView mv;
  buildMenuView(mv);
  ui_.draw(mv, inputBuffer_, logLines_, logHead_, logCount_);
}

void App::engineTick() {
  // Surface a queued auth-failure retry before it runs (serviceAutoRetry blocks
  // on the reconnect, so this message stays visible during it).
  if (connection::authRetryPending()) {
    log("auth failed - retrying with secure pairing");
    ui_.message("Auth failed", "retrying securely...");
  }
  connection::serviceAutoRetry();

  scanner::poll();
  scanner::foxhuntPoll();
  sampleBattery();   // throttled; keeps the header gauge corrected

  // Numeric Comparison: code was auto-accepted; show it so the user can verify
  // it matched the peer's display.
  uint32_t np = connection::takeNumericPin();
  if (np) { log(String("pairing code ") + np); popup("Pairing code", String(np).c_str(), 2500); }

  // Passkey Entry: peer is showing a 6-digit code we must type. Reflect the
  // engine's pending state into our modal input mode.
  passkeyMode_ = connection::awaitingPasskey();

  const bool connected = connection::isConnected();
  if (!wasConnected_ && connected) {
    // Clear only a STALE cache from a different device - never wipe a fresh dump
    // we just built for the device we're now connected to (connectSelected dumps
    // in the same loop iteration, before this transition is observed).
    std::string peer = connection::client() ? connection::client()->getPeerAddress().toString() : "";
    if (gatt::cachedPeer() != peer) gatt::clearCache();
  }
  if (wasConnected_ && !connected) {
    if (hid_parser::streamActive()) hid_parser::streamStop();
    log("link dropped");
  }
  wasConnected_ = connected;

  const bool scanning = scanner::isScanning();
  if (wasScanning_ && !scanning && !scanner::foxhuntActive() && !sentryWatching_) {
    log(String("scan done: ") + scanner::results().size() + " devices");
  }
  wasScanning_ = scanning;
}

// ----------------------------------------------------------------- input

void App::handleKeyboard() {
  if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed()) {
    return;
  }
  Keyboard_Class::KeysState keys = M5Cardputer.Keyboard.keysState();

  // Passkey-entry modal: type the digits shown on the peer. Enter injects,
  // backspace edits (or cancels+disconnects when empty).
  if (passkeyMode_) {
    for (char c : keys.word)
      if (c >= '0' && c <= '9' && passkeyBuf_.length() < 6) passkeyBuf_ += c;
    if (keys.enter && passkeyBuf_.length() > 0) {
      connection::injectPasskey((uint32_t)passkeyBuf_.toInt());
      passkeyBuf_ = "";
      passkeyMode_ = false;
    } else if (keys.del) {
      if (passkeyBuf_.length()) passkeyBuf_.remove(passkeyBuf_.length() - 1);
      else { connection::disconnect(); passkeyBuf_ = ""; passkeyMode_ = false; }
    }
    return;
  }

  // Sentry manual-value entry: type the value(s), Enter saves, backspace edits
  // (or cancels back to the type chooser when empty).
  if (sentryEntry_) {
    for (char c : keys.word)
      if (c >= 32 && c <= 126 && inputBuffer_.length() < kInputMaxLen) inputBuffer_ += c;
    if (keys.enter) sentryCommitManual();
    else if (keys.del) {
      if (inputBuffer_.length()) inputBuffer_.remove(inputBuffer_.length() - 1);
      else { sentryEntry_ = false; inputBuffer_.clear(); }   // cancel -> stay on SentryType
    }
    return;
  }

  // Delete-confirmation modal swallows all input: Enter confirms, anything else cancels.
  if (confirmDelete_) {
    if (keys.enter) performDelete();
    else if (keys.del || !keys.word.empty()) { confirmDelete_ = false; sentryDelIdx_ = -1; }
    return;
  }

  // Clone-name entry: type the profile name, Enter saves, backspace edits (or
  // cancels back when empty). Kept filename-safe (alnum / - / _).
  if (cloneNameEntry_) {
    for (char c : keys.word)
      if ((isalnum((unsigned char)c) || c == '-' || c == '_') &&
          inputBuffer_.length() < 24) inputBuffer_ += c;
    if (keys.enter) commitCloneSave();
    else if (keys.del) {
      if (inputBuffer_.length()) inputBuffer_.remove(inputBuffer_.length() - 1);
      else { cloneNameEntry_ = false; inputBuffer_.clear(); }   // empty backspace cancels
    }
    return;
  }

  // Replay confirm (after a save): right/Enter loads the just-saved profile and
  // advertises it (reboots to spoof the MAC); any other key ends the chain.
  if (cloneReplayConfirm_) {
    bool yes = keys.enter;
    for (char c : keys.word) if (c == '/') yes = true;   // '/' is the right-arrow key
    if (yes) {
      cloneReplayConfirm_ = false;
      if (clone::load(cloneSaveName_.c_str())) {
        log(String("advertising clone '") + cloneSaveName_ + "'");
        ui_.message("Advertise clone", "loading + starting...");
        if (!clone::advertise())            // normally reboots here (never returns)
          popup("Can't advertise", "stop the current clone first");
      } else {
        popup("Load failed", cloneSaveName_.c_str());
      }
    } else if (keys.del || !keys.word.empty()) {
      cloneReplayConfirm_ = false;          // any other key ends the chain
      log("clone replay declined");
    }
    return;
  }

  // ESC action menu: c = forget all bonds, Enter = disconnect (if connected),
  // anything else cancels.
  if (escMenu_) {
    bool wantForget = false, other = false;
    for (char c : keys.word) { if (c == 'c' || c == 'C') wantForget = true; else other = true; }
    if (wantForget) {
      escMenu_ = false;
      runCommand("forget all");
      popup("Bonds cleared", "all bonds forgotten", 2000);
    } else if (keys.enter) {
      escMenu_ = false;
      if (connection::isConnected()) { connection::disconnect(); log("disconnected"); }
    } else if (keys.del || other) {
      escMenu_ = false;
    }
    return;
  }

  for (char c : keys.word) handleChar(c);

  if (keys.del) {
    if (commandMode_) {
      if (!inputBuffer_.isEmpty()) inputBuffer_.remove(inputBuffer_.length() - 1);
      else commandMode_ = false;
    } else {
      onBack();
    }
  }
  if (keys.enter) onEnter();
}

void App::handleChar(char c) {
  if (commandMode_) {
    if (c >= 32 && c <= 126 && inputBuffer_.length() < kInputMaxLen) inputBuffer_ += c;
    return;
  }
  // 'a' on the Foxhunt screen toggles Geiger-counter audio.
  if ((c == 'a' || c == 'A') && screen_ == MenuScreen::Foxhunt) {
    audio_ = !audio_;
    prefs_.putBool("audio", audio_);
    log(String("foxhunt audio ") + (audio_ ? "on" : "off"));
    if (!audio_) M5Cardputer.Speaker.stop();
    return;
  }
  // ESC (top-left key emits '`') on the main menu opens a small action menu:
  // Enter = disconnect (if connected), c = forget all bonds. (No footer hint.)
  if (c == '`' && screen_ == MenuScreen::Main) {
    escMenu_ = true;
    return;
  }
  // 'x' arms delete-confirm for the selected/viewed dump.
  if ((c == 'x' || c == 'X') &&
      (screen_ == MenuScreen::Dumps || screen_ == MenuScreen::DumpView)) {
    String target;
    if (screen_ == MenuScreen::DumpView) target = dumpViewName_;
    else if (selection_ >= 0 && (size_t)selection_ < dumpFiles_.size()) target = dumpFiles_[selection_];
    if (target.length()) { deleteTarget_ = target; confirmDelete_ = true; }
    return;
  }
  // 'x' on the Sentry screen arms delete-confirm for the selected rule.
  if ((c == 'x' || c == 'X') && screen_ == MenuScreen::Sentry &&
      selection_ >= kSentryActions) {
    size_t i = (size_t)(selection_ - kSentryActions);
    if (i < sentry::rules().size()) {
      sentryDelIdx_ = (int)i;
      deleteTarget_ = String(sentry::rules()[i].label.c_str());
      confirmDelete_ = true;
    }
    return;
  }
  // Type a custom scan time while "Scan" is highlighted on the main menu.
  if (screen_ == MenuScreen::Main && selection_ == 0 && c >= '0' && c <= '9') {
    uint32_t v = scanEditing_ ? (scanSecs_ * 10 + (c - '0')) : (uint32_t)(c - '0');
    if (v > 300) v = 300;
    scanSecs_ = v;
    scanEditing_ = true;
    buildScanLabel();
    return;
  }
  switch (c) {
    case ';':
      if (screen_ == MenuScreen::Foxhunt && audio_) adjustVolume(+16);   // louder
      else if (screen_ == MenuScreen::Logs || screen_ == MenuScreen::Honeypot) scrollOffset_++;  // older
      else if (screen_ == MenuScreen::Gatt || screen_ == MenuScreen::DumpView)
        scrollOffset_ = max(0, scrollOffset_ - 1);
      else moveSelection(-1);
      break;
    case '.':
      if (screen_ == MenuScreen::Foxhunt && audio_) adjustVolume(-16);   // quieter
      else if (screen_ == MenuScreen::Logs || screen_ == MenuScreen::Honeypot) scrollOffset_ = max(0, scrollOffset_ - 1);  // newer
      else if (screen_ == MenuScreen::Gatt || screen_ == MenuScreen::DumpView)
        scrollOffset_++;       // clamped in renderer
      else moveSelection(1);
      break;
    case ',': onBack(); break;
    case '/': activate(); break;
    case '\'': commandMode_ = true; inputBuffer_.clear(); break;
    default: break;
  }
}

void App::onEnter() {
  if (commandMode_) {
    String cmd = inputBuffer_;
    inputBuffer_.clear();
    commandMode_ = false;
    cmd.trim();
    if (!cmd.isEmpty()) runCommand(cmd);
    return;
  }
  activate();
}

// One level up the menu tree. Categories return to Main; leaf screens return to
// their category. Devices returns to whichever category launched it.
MenuScreen App::parentOf(MenuScreen s) const {
  switch (s) {
    case MenuScreen::ReconMenu:
    case MenuScreen::AdvMenu:
    case MenuScreen::Sentry:
    case MenuScreen::Settings:      return MenuScreen::Main;
    case MenuScreen::Devices:       return deviceAction_ == DeviceAction::Mitm     ? MenuScreen::AdvMenu
                                         : deviceAction_ == DeviceAction::SentryAdd ? MenuScreen::Sentry
                                                                                    : MenuScreen::ReconMenu;
    case MenuScreen::DeviceDetail:  return MenuScreen::Devices;
    case MenuScreen::Foxhunt:       return foxhuntReturn_;
    case MenuScreen::Gatt:
    case MenuScreen::HidStream:
    case MenuScreen::Dumps:         return MenuScreen::ReconMenu;
    case MenuScreen::DumpView:      return MenuScreen::Dumps;
    case MenuScreen::Clone:
    case MenuScreen::Honeypot:      return MenuScreen::AdvMenu;
    case MenuScreen::SentryPick:
    case MenuScreen::SentryType:
    case MenuScreen::Alert:         return MenuScreen::Sentry;
    case MenuScreen::StreamSelect:  return MenuScreen::ReconMenu;
    case MenuScreen::Logs:          return MenuScreen::Settings;
    case MenuScreen::About:         return MenuScreen::Settings;
    default:                        return MenuScreen::Main;
  }
}

void App::onBack() {
  if (commandMode_) { commandMode_ = false; inputBuffer_.clear(); return; }
  if (screen_ == MenuScreen::Foxhunt && scanner::foxhuntActive()) {
    scanner::foxhuntStop();
  }
  if (screen_ == MenuScreen::HidStream && hid_parser::streamActive()) {
    hid_parser::streamStop();
  }
  if (screen_ == MenuScreen::Main) return;
  enterScreen(parentOf(screen_));
}

void App::moveSelection(int delta) {
  size_t count = 0;
  if (screen_ == MenuScreen::Main)            count = kMainCount;
  else if (screen_ == MenuScreen::ReconMenu)  count = countOf(kReconMenu);
  else if (screen_ == MenuScreen::AdvMenu)    count = countOf(kAdvMenu);
  else if (screen_ == MenuScreen::Devices)    count = scanner::results().size();
  else if (screen_ == MenuScreen::DeviceDetail) count = countOf(kDetailMenu);
  else if (screen_ == MenuScreen::Clone)      count = kCloneActions + cloneNames_.size();
  else if (screen_ == MenuScreen::Dumps)      count = dumpFiles_.size();
  else if (screen_ == MenuScreen::Settings)   count = settingsKinds_.size();
  else if (screen_ == MenuScreen::Sentry)     count = sentryRows_.size();
  else if (screen_ == MenuScreen::SentryPick) count = sentryPickRows_.size();
  else if (screen_ == MenuScreen::SentryType) count = countOf(kMatchTypeMenu);
  else if (screen_ == MenuScreen::Alert)      count = 3;
  else if (screen_ == MenuScreen::StreamSelect) count = streamRows_.size();
  if (count == 0) return;

  selection_ += delta;
  if (selection_ < 0) selection_ = (int)count - 1;
  else if (selection_ >= (int)count) selection_ = 0;

  // On the Devices list, remember the hovered device by address so a live-scan
  // re-sort keeps the highlight on it instead of sliding to a new device.
  if (screen_ == MenuScreen::Devices) {
    const auto& devs = scanner::results();
    if (selection_ >= 0 && (size_t)selection_ < devs.size())
      pinnedAddr_ = devs[selection_].addr;
  }

  // moving off "Scan" ends scan-time editing (next focus starts a fresh value),
  // and reverting to a sane default if they left it blank/zero
  if (scanEditing_ && !(screen_ == MenuScreen::Main && selection_ == 0)) {
    scanEditing_ = false;
    if (scanSecs_ == 0) { scanSecs_ = 10; buildScanLabel(); }
  }
}

// Keep the device highlight pinned to its address as a live scan re-sorts by RSSI:
// re-find the pinned device each frame and move the selection to its current row,
// so a device that shifts position doesn't slide the cursor onto a neighbor (and a
// right-press can't connect to the wrong device). Runs after scanner::poll()'s sort.
void App::syncDeviceSelection() {
  const auto& devs = scanner::results();
  if (screen_ == MenuScreen::Devices) {
    if (devs.empty()) { selection_ = 0; return; }
    if (pinnedAddr_.empty()) { selection_ = 0; return; }   // no pick yet: track the strongest
    for (size_t i = 0; i < devs.size(); ++i)
      if (devs[i].addr == pinnedAddr_) { selection_ = (int)i; return; }
    // Pinned device fell off the list: clamp + re-pin to whatever's under the cursor.
    if (selection_ >= (int)devs.size()) selection_ = (int)devs.size() - 1;
    if (selection_ < 0) selection_ = 0;
    pinnedAddr_ = devs[selection_].addr;
  } else if (screen_ == MenuScreen::DeviceDetail) {
    // Keep the drilled-in device correct too, so the detail view + connect/foxhunt/
    // MITM act on the intended device rather than a shifted index.
    if (pinnedAddr_.empty()) return;
    for (size_t i = 0; i < devs.size(); ++i)
      if (devs[i].addr == pinnedAddr_) { selectedDevice_ = (int)i; return; }
  }
}

// ----------------------------------------------------------------- nav

void App::enterScreen(MenuScreen s) {
  screen_ = s;
  selection_ = 0;
  scrollOffset_ = 0;
  // screen-entry side effects
  if (s == MenuScreen::StreamSelect) {
    streamSources_ = hid_parser::streamSources();   // requires connected + dumped
    streamEnabled_.assign(streamSources_.size(), false);
    for (size_t i = 0; i < streamSources_.size(); ++i) streamEnabled_[i] = streamSources_[i].defaultOn;
    buildStreamRows();
  } else if (s == MenuScreen::Clone) {
    refreshCloneNames();
  } else if (s == MenuScreen::Dumps) {
    refreshDumpFiles();
  } else if (s == MenuScreen::Settings) {
    refreshSettings();
  } else if (s == MenuScreen::Sentry) {
    buildSentryRows();
  }
}

void App::activate() {
  switch (screen_) {
    case MenuScreen::Main:
      switch (selection_) {
        case 0: doScan(); break;                          // Scan keeps Devices in Normal mode (set in doScan)
        case 1: enterScreen(MenuScreen::ReconMenu); break;
        case 2: enterScreen(MenuScreen::AdvMenu); break;
        case 3: enterScreen(MenuScreen::Sentry); break;
        case 4: enterScreen(MenuScreen::Settings); break;
      }
      break;

    case MenuScreen::ReconMenu:
      switch (selection_) {
        case 0: deviceAction_ = DeviceAction::Normal; enterScreen(MenuScreen::Devices); break;
        case 1: enterScreen(MenuScreen::Gatt); break;
        case 2: enterScreen(MenuScreen::StreamSelect); break;   // pick notifications, then stream
        case 3: enterScreen(MenuScreen::Dumps); break;
      }
      break;

    case MenuScreen::AdvMenu:
      switch (selection_) {
        case 0: enterScreen(MenuScreen::Clone); break;
        case 1: enterScreen(MenuScreen::Honeypot); break;
        case 2: deviceAction_ = DeviceAction::Mitm; enterScreen(MenuScreen::Devices); break;  // pick a target -> auto MITM
      }
      break;

    case MenuScreen::Devices:
      if (selection_ >= 0 && (size_t)selection_ < scanner::results().size()) {
        selectedDevice_ = selection_;
        pinnedAddr_ = scanner::results()[selection_].addr;   // pin for the detail view + downstream sync
        if (deviceAction_ == DeviceAction::Mitm) mitmSelected();          // start the proxy
        else if (deviceAction_ == DeviceAction::SentryAdd) {             // capture as a watch rule
          buildSentryPick();
          enterScreen(MenuScreen::SentryPick);
        } else enterScreen(MenuScreen::DeviceDetail);
      }
      break;

    case MenuScreen::Sentry:
      if (selection_ < kSentryActions) {
        switch (selection_) {
          case 0: sentryToggleWatching(); break;
          case 1:   // add from scan - ensure there's a list to pick from
            deviceAction_ = DeviceAction::SentryAdd;
            pinnedAddr_.clear();
            if (scanner::results().empty() && !scanner::isScanning()) scanner::start(scanSecs_);
            enterScreen(MenuScreen::Devices);
            break;
          case 2: enterScreen(MenuScreen::SentryType); break;
        }
      } else {
        size_t i = (size_t)(selection_ - kSentryActions);   // toggle a rule's enabled flag
        if (i < sentry::rules().size()) {
          sentry::setEnabled(i, !sentry::rules()[i].enabled);
          buildSentryRows();
        }
      }
      break;

    case MenuScreen::SentryPick:
      sentryAddFromPick(selection_);
      break;

    case MenuScreen::SentryType:
      if (selection_ >= 0 && selection_ < (int)countOf(kMatchTypeMenu))
        sentryStartManual((sentry::MatchType)selection_);
      break;

    case MenuScreen::StreamSelect:
      if (streamRows_.empty()) break;
      if (selection_ == 0) startSelectedStream();              // row 0 = Start
      else {
        size_t i = (size_t)(selection_ - 1);
        if (i < streamEnabled_.size()) { streamEnabled_[i] = !streamEnabled_[i]; buildStreamRows(); }
      }
      break;

    case MenuScreen::Alert:
      switch (selection_) {
        case 0: alertConnect(); break;
        case 1: alertFoxhunt(); break;
        case 2: alertDismiss(); break;
      }
      break;

    case MenuScreen::DeviceDetail:
      switch (selection_) {
        case 0: connectSelected(); break;
        case 1: foxhuntSelected(); break;
        case 2: cloneSelected(); break;
      }
      break;

    case MenuScreen::Gatt:
      // No dump yet -> Right dumps this device. Once a dump exists, Right saves it
      // as a clone profile (the natural scan->connect->dump->clone flow). Re-dump
      // stays available from the command line ('dump').
      if (gatt::hasCache()) startCloneSave();
      else doDump();
      break;

    case MenuScreen::Dumps:
      if (selection_ >= 0 && (size_t)selection_ < dumpFiles_.size()) {
        loadDumpFile(dumpFiles_[selection_]);
        enterScreen(MenuScreen::DumpView);
      }
      break;

    case MenuScreen::Clone:
      activateClone();
      break;

    case MenuScreen::Settings:
      activateSetting();
      break;

    default:
      break;
  }
}

void App::activateClone() {
  if (selection_ < kCloneActions) {
    switch (selection_) {
      case 0:  // Save current dump as a clone profile (guards that a dump exists)
        startCloneSave();
        break;
      case 1:  // Advertise loaded (reboots to spoof MAC, per clone::advertise)
        if (clone::hasLoaded()) { log("advertising clone..."); clone::advertise(); }
        else log("no profile loaded");
        break;
      case 2:
        clone::stop();
        log("clone advertising stopped");
        break;
    }
  } else {
    // a saved profile name → load it
    size_t i = (size_t)(selection_ - kCloneActions);
    if (i < cloneNames_.size()) {
      if (clone::load(cloneNames_[i].c_str()))
        log(String("loaded ") + cloneNames_[i].c_str());
    }
  }
}

void App::refreshCloneNames() {
  cloneNames_ = clone::listNames();
}

// Begin clone-name entry, but only if there's a dumped snapshot to serialize -
// otherwise the save would silently no-op (clone::save needs gatt::hasCache()).
void App::startCloneSave() {
  if (!gatt::hasCache()) {
    log("clone save: nothing dumped yet");
    popup("Nothing to clone", "connect + dump a device first", 2200);
    return;
  }
  cloneNameEntry_ = true;
  inputBuffer_.clear();
}

// Commit the typed name: save the profile, refresh the Clone list if it's on
// screen, then offer to advertise it immediately (the replay chain).
void App::commitCloneSave() {
  String name = inputBuffer_;
  name.trim();
  cloneNameEntry_ = false;
  inputBuffer_.clear();
  if (name.length() == 0) { popup("Name required", "no clone saved", 1500); return; }
  if (!clone::save(name.c_str())) { popup("Save failed", "could not write profile", 2000); return; }
  cloneSaveName_ = name;
  log(String("clone saved: ") + name);
  if (screen_ == MenuScreen::Clone) refreshCloneNames();
  cloneReplayConfirm_ = true;   // -> "Advertise clone?" (rendered by loop())
}

void App::refreshSettings() {
  settingsKinds_.clear();
  settingsLabels_.clear();
  char buf[40];
  auto add = [&](SettingKind k, const String& label) {
    settingsKinds_.push_back(k);
    settingsLabels_.push_back(label);
  };
  snprintf(buf, sizeof(buf), "Volume: %d", volume_);       add(SettingKind::Volume, buf);
  snprintf(buf, sizeof(buf), "Brightness: %d", brightness_); add(SettingKind::Brightness, buf);
  snprintf(buf, sizeof(buf), "Scan time: %us", (unsigned)scanSecs_); add(SettingKind::ScanTime, buf);
  add(SettingKind::AutoPair, autoSecure_ ? "Auto-pair: on" : "Auto-pair: off");
  add(SettingKind::OpenLogs, "Logs");
  add(SettingKind::ChargeMode, "Charging mode");
  if (connection::isConnected()) add(SettingKind::Disconnect, "Disconnect device");
  if (clone::isAdvertising())    add(SettingKind::StopAdv, "Stop advertising");
  if (mitm::active())            add(SettingKind::StopMitm, "Stop MITM proxy");
  add(SettingKind::ClearBonds, "Clear all bonds");
  add(SettingKind::About, "About");
}

void App::activateSetting() {
  if (selection_ < 0 || selection_ >= (int)settingsKinds_.size()) return;
  switch (settingsKinds_[selection_]) {
    case SettingKind::Volume: {                      // cycle to next 32-step (wrap)
      uint16_t nv = ((volume_ / 32) + 1) * 32;
      if (nv > 255) nv = 0;
      volume_ = (uint8_t)nv;
      M5Cardputer.Speaker.setVolume(volume_);
      prefs_.putUChar("vol", volume_);
      M5Cardputer.Speaker.tone(1500, 40);            // audible sample at new level
      break;
    }
    case SettingKind::Brightness: {                  // cycle, keep a readable minimum
      uint16_t nb = ((brightness_ / 32) + 1) * 32;
      if (nb > 255) nb = 32;
      brightness_ = (uint8_t)nb;
      M5Cardputer.Display.setBrightness(brightness_);
      prefs_.putUChar("bright", brightness_);
      break;
    }
    case SettingKind::ScanTime: {                    // cycle preset
      const int n = sizeof(kScanPresets) / sizeof(kScanPresets[0]);
      int cur = -1;
      for (int i = 0; i < n; i++) if (kScanPresets[i] == scanSecs_) { cur = i; break; }
      scanSecs_ = kScanPresets[(cur + 1) % n];
      prefs_.putUInt("scan", scanSecs_);
      buildScanLabel();
      break;
    }
    case SettingKind::AutoPair:                      // toggle proactive pairing on connect
      autoSecure_ = !autoSecure_;
      connection::setAutoSecure(autoSecure_);
      prefs_.putBool("autosec", autoSecure_);
      break;
    case SettingKind::Disconnect:
      connection::disconnect(); log("disconnected"); break;
    case SettingKind::StopAdv:
      clone::stop(); log("advertising stopped"); break;
    case SettingKind::StopMitm:
      mitm::stop(); log("MITM proxy stopped"); break;
    case SettingKind::ClearBonds:
      if (confirmBlocking("Clear all bonds?", "deletes all pairings")) {
        runCommand("forget all");
        popup("Bonds cleared", "all bonds forgotten", 1500);
      }
      break;
    case SettingKind::OpenLogs:
      enterScreen(MenuScreen::Logs);
      return;   // navigated away - skip the settings-row refresh below
    case SettingKind::ChargeMode:
      enterChargingMode();
      return;   // takes over the loop until a keypress
    case SettingKind::About:
      enterScreen(MenuScreen::About);
      return;   // navigated away
  }
  refreshSettings();
  if (selection_ >= (int)settingsKinds_.size()) selection_ = max(0, (int)settingsKinds_.size() - 1);
}

void App::buildMenuView(MenuView& mv) const {
  mv.screen = screen_;
  mv.commandMode = commandMode_;
  mv.scrollOffset = scrollOffset_;
  mv.selectedDevice = selectedDevice_;
  mv.cloneNames = &cloneNames_;
  mv.cloneActions = kCloneActions;
  mv.dumpFiles = &dumpFiles_;
  mv.dumpViewLines = &dumpViewLines_;
  mv.dumpViewName = dumpViewName_.c_str();
  mv.audioOn = audio_;
  mv.volume = volume_;
  mv.settingsLabels = &settingsLabels_;
  mv.honeypotLines = &hpLines_;
  mv.honeypotConnected = clone::hostConnected();
  mv.honeypotLogging = hpFileOpen_;
  mv.sentryWatching = sentryWatching_;
  mv.sentryRows = (screen_ == MenuScreen::SentryPick)   ? &sentryPickRows_
                : (screen_ == MenuScreen::StreamSelect) ? &streamRows_
                                                        : &sentryRows_;
  mv.alertLabel = alertLabel_.c_str();
  mv.alertReason = alertReason_.c_str();
  mv.alertInfo = alertInfo_.c_str();
  mv.batLevel = batTrueLevel_;
  mv.batCharging = batCharging_;

  const char* title = nullptr;
  const char* const* items = nullptr;
  size_t count = 0;
  currentMenu(title, items, count);
  mv.title = title;
  mv.items = items;
  mv.itemCount = count;

  int sel = selection_;
  if (count > 0) {
    if (sel < 0) sel = 0;
    if (sel >= (int)count) sel = (int)count - 1;
  } else {
    sel = 0;
  }
  mv.selectedIndex = sel;
}

void App::currentMenu(const char*& title, const char* const*& items, size_t& count) const {
  switch (screen_) {
    case MenuScreen::Main:
      title = " ChimeraBLE"; items = mainItems_; count = kMainCount; break;
    case MenuScreen::ReconMenu:
      title = "Recon & Analysis"; items = kReconMenu; count = countOf(kReconMenu); break;
    case MenuScreen::AdvMenu:
      title = "Adversarial"; items = kAdvMenu; count = countOf(kAdvMenu); break;
    case MenuScreen::Devices:
      title = (deviceAction_ == DeviceAction::Mitm) ? "MITM: pick target" : "Devices";
      items = nullptr; count = scanner::results().size(); break;
    case MenuScreen::DeviceDetail:
      title = "Device"; items = kDetailMenu; count = countOf(kDetailMenu); break;
    case MenuScreen::Gatt:
      title = "GATT"; items = nullptr; count = 0; break;
    case MenuScreen::HidStream:
      title = "Live Stream"; items = nullptr; count = 0; break;
    case MenuScreen::Foxhunt:
      title = "Foxhunt"; items = nullptr; count = 0; break;
    case MenuScreen::Clone:
      title = "Clone"; items = kCloneActionItems;
      count = kCloneActions + cloneNames_.size(); break;
    case MenuScreen::Dumps:
      title = "Saved Dumps"; items = nullptr; count = dumpFiles_.size(); break;
    case MenuScreen::DumpView:
      title = "Dump"; items = nullptr; count = 0; break;
    case MenuScreen::Settings:
      title = "Settings"; items = nullptr; count = settingsKinds_.size(); break;
    case MenuScreen::Honeypot:
      title = "BLE Honeypot"; items = nullptr; count = 0; break;
    case MenuScreen::Sentry:
      title = sentryWatching_ ? "Sentry (watching)" : "Sentry";
      items = nullptr; count = sentryRows_.size(); break;
    case MenuScreen::SentryPick:
      title = "Add: pick attribute"; items = nullptr; count = sentryPickRows_.size(); break;
    case MenuScreen::SentryType:
      title = "Add: match type"; items = kMatchTypeMenu; count = countOf(kMatchTypeMenu); break;
    case MenuScreen::Alert:
      title = "! MATCH"; items = nullptr; count = 3; break;
    case MenuScreen::StreamSelect:
      title = "Live Stream"; items = nullptr; count = streamRows_.size(); break;
    case MenuScreen::Logs:
      title = "Logs"; items = nullptr; count = 0; break;
    case MenuScreen::About:
      title = "About"; items = nullptr; count = 0; break;
  }
}

// ----------------------------------------------------------------- actions

void App::doScan() {
  scanEditing_ = false;
  deviceAction_ = DeviceAction::Normal;   // selecting a result opens its detail, not MITM
  pinnedAddr_.clear();                     // fresh scan: highlight starts at the strongest device
  prefs_.putUInt("scan", scanSecs_);   // remember the chosen scan time
  scanner::start(scanSecs_);
  log(String("scanning ") + scanSecs_ + "s...");
  enterScreen(MenuScreen::Devices);
}

// Polled by the blocking connect: pump M5 input and report an ESC press so a
// hanging connect can be aborted (ESC = the top-left `` ` `` key -> '`').
bool App::connectCancelRequested() {
  M5Cardputer.update();
  if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) {
    for (char c : M5Cardputer.Keyboard.keysState().word)
      if (c == '`') { connectCanceled_ = true; return true; }
  }
  return false;
}

// Connect only - pairing (auto-secure) proceeds in the background. Dumping is a
// separate step on the GATT screen, since connect may need auth first.
void App::connectSelected() {
  const auto* r = scanner::findByIndex(selectedDevice_);
  if (!r) { log("no device selected"); return; }
  if (scanner::isScanning()) scanner::stop();

  // Already connected? Offer to switch instead of just failing with "busy".
  if (connection::isConnected()) {
    std::string cur = connection::client()->getPeerAddress().toString();
    std::string want = r->addr;
    for (auto& c : cur)  c = (char)tolower((unsigned char)c);
    for (auto& c : want) c = (char)tolower((unsigned char)c);
    if (cur == want) { log("already connected to this device"); enterScreen(MenuScreen::Gatt); return; }
    if (!confirmBlocking("Switch device?", "drop current connection")) return;  // user declined
    connection::disconnect();
    uint32_t t0 = millis();
    while (connection::isConnected() && millis() - t0 < 2000) { M5Cardputer.update(); delay(20); }
  }

  gatt::clearCache();   // drop any stale cache from a previous device

  ui_.message("Connecting...", r->addr.c_str(), 2, "ESC = stop");   // larger MAC + cancel hint
  log(String("connecting ") + r->addr.c_str());
  connectCanceled_ = false;
  if (!connection::connectTo(*r, [this] { return connectCancelRequested(); })) {
    if (connectCanceled_) { log("connect canceled"); popup("Canceled", "connection stopped", 1200); }
    else { log("connect failed"); popup("Connect failed", "out of range or busy"); }
    return;   // stays on the Device Detail screen
  }

  log("connected (pairing in background)");
  enterScreen(MenuScreen::Gatt);   // GATT screen: press / to dump
}

void App::popup(const char* title, const char* sub, uint32_t ms) {
  ui_.message(title, sub);
  const uint32_t t0 = millis();
  while (millis() - t0 < ms) {
    M5Cardputer.update();
    if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) break;
    delay(20);
  }
}

bool App::confirmBlocking(const char* title, const char* sub, uint32_t timeoutMs) {
  ui_.message(title, (String(sub) + "   Enter=yes  any=no").c_str());
  const uint32_t t0 = millis();
  while (millis() - t0 < timeoutMs) {
    M5Cardputer.update();
    if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) {
      auto keys = M5Cardputer.Keyboard.keysState();
      if (keys.enter) return true;
      if (keys.del || !keys.word.empty()) return false;
    }
    delay(20);
  }
  return false;   // timed out = no
}

void App::doDump() {
  if (!connection::isConnected()) { log("not connected"); return; }
  ui_.message("Dumping...", connection::client()
                                ? connection::client()->getPeerAddress().toString().c_str()
                                : nullptr,
              2);   // larger MAC
  gatt::dump(true);
  log(String("GATT: ") + gatt::cache().size() + " services");
  saveDumpToSd();
}

bool App::sdInit() {
  if (sdReady_) return true;
  if (!spiBegun_) { SPI.begin(kSdSck, kSdMiso, kSdMosi, kSdCs); spiBegun_ = true; }
  sdReady_ = SD.begin(kSdCs, SPI, 25000000);
  // Resolve (case-insensitively) or create the ChimeraBLE base folder before
  // anything writes beneath it. mkdir isn't recursive, so the parent must exist.
  if (sdReady_) resolveSdBase();
  return sdReady_;
}

// Find the ChimeraBLE working folder on the card. FAT is usually case-insensitive,
// but to be safe we scan the root for a directory matching "ChimeraBLE" in any
// case (so a user who made "chimerable" still works) and adopt its real name;
// otherwise we create the canonical one. Sets sdBase_.
void App::resolveSdBase() {
  sdBase_ = CHIMERA_SD_DIR;                 // canonical default
  File root = SD.open("/");
  if (root && root.isDirectory()) {
    for (File e = root.openNextFile(); e; e = root.openNextFile()) {
      if (!e.isDirectory()) continue;
      String name = e.name();
      int slash = name.lastIndexOf('/');
      if (slash >= 0) name = name.substring(slash + 1);
      if (name.equalsIgnoreCase("ChimeraBLE")) { sdBase_ = String("/") + name; break; }
    }
  }
  if (root) root.close();
  if (!SD.exists(sdBase_.c_str())) SD.mkdir(sdBase_.c_str());
}

// Case-insensitive lookup of <name> directly inside <dir>. Returns the full path
// or "" if absent - so a mis-cased oui.bin (OUI.BIN, Oui.bin) still loads.
String App::findFileCI(const String& dir, const char* name) {
  File d = SD.open(dir.c_str());
  String found;
  if (d && d.isDirectory()) {
    for (File e = d.openNextFile(); e; e = d.openNextFile()) {
      if (e.isDirectory()) continue;
      String base = e.name();
      int slash = base.lastIndexOf('/');
      if (slash >= 0) base = base.substring(slash + 1);
      if (base.equalsIgnoreCase(name)) {
        found = dir;
        if (!found.endsWith("/")) found += "/";
        found += base;
        break;
      }
    }
  }
  if (d) d.close();
  return found;
}

// Locate oui.bin: prefer the ChimeraBLE base folder, then fall back to the SD
// root. Both matched case-insensitively. "" if nowhere on the card.
String App::findOuiPath() {
  String p = findFileCI(sdBase_, "oui.bin");
  if (p.length()) return p;
  return findFileCI("/", "oui.bin");
}

// Auto-save the just-dumped device (info + GATT tree) to
// /ble_dumps/<name-or-guess>_<MAC>.txt on the microSD card.
void App::saveDumpToSd() {
  if (!gatt::hasCache()) return;
  ui_.message("Saving to SD...");
  if (!sdInit()) { log("SD not available (no card?)"); return; }
  String ddir = dumpDir();
  if (!SD.exists(ddir.c_str())) SD.mkdir(ddir.c_str());

  std::string peer = gatt::cachedPeer();
  const scanner::Result* r = peer.empty() ? nullptr : scanner::findByMac(peer.c_str());

  // filename base: device name, else fingerprint guess
  String base;
  if (r && !r->name.empty()) base = slug(String(r->name.c_str()));
  if (base.length() == 0 && r) {
    String g = fingerprint::identify(r->addr, r->addr_type, r->adv_payload).c_str();
    if (g != "unknown") base = slug(g);
  }
  String mac;
  for (char c : peer) if (c != ':') mac += (char)toupper((unsigned char)c);
  if (mac.length() == 0) mac = "unknown";
  String path = ddir + "/" + (base.length() ? base + "_" : "") + mac + ".txt";

  File f = SD.open(path.c_str(), FILE_WRITE);
  if (!f) { log("SD open failed"); return; }

  char pbuf[8];
  f.println("ChimeraBLE device dump");
  f.println("=======================");
  f.printf("address : %s\n", peer.c_str());
  if (r) {
    f.printf("name    : %s\n", r->name.empty() ? "(none)" : r->name.c_str());
    f.printf("rssi    : %d dBm\n", r->rssi);
    f.printf("guess   : %s\n", fingerprint::identify(r->addr, r->addr_type, r->adv_payload).c_str());
    f.print("adv     : ");
    for (uint8_t b : r->adv_payload) f.printf("%02X ", b);
    f.println();
  }
  f.printf("uptime  : %lu ms\n\n", (unsigned long)millis());

  f.println("== GATT ==");
  for (const auto& svc : gatt::cache()) {
    f.printf("SVC %s\n", fileUuid(svc.uuid, uuid_db::serviceName).c_str());
    for (const auto& c : svc.chars) {
      f.printf("  CHR %s  h=0x%04X  [%s]\n",
               fileUuid(c.uuid, uuid_db::charName).c_str(), c.handle,
               gatt::propsString(c.props, pbuf, sizeof(pbuf)));
      if (c.value_cached && !c.value.empty()) {
        f.print("    value: ");
        for (uint8_t b : c.value) f.printf("%02X ", b);
        f.print(" | ");
        for (uint8_t b : c.value) f.print(isprint(b) ? (char)b : '.');
        f.println();
        std::string dec = gatt::describeValue(c.uuid, c.value.data(), c.value.size());
        if (!dec.empty()) f.printf("    decoded: %s\n", dec.c_str());
      }
      for (const auto& d : c.descs) {
        f.printf("    DSC %s  h=0x%04X\n", fileUuid(d.uuid, uuid_db::descName).c_str(), d.handle);
        if (d.value_cached && !d.value.empty()) {
          f.print("      value: ");
          for (uint8_t b : d.value) f.printf("%02X ", b);
          f.println();
        }
      }
    }
  }

  // Decoded HID Report Map (the most useful artifact for RE): if a HID service
  // (0x1812) has a cached Report Map (0x2A4B), decode it straight into the file.
  static const NimBLEUUID kHidSvc((uint16_t)0x1812);
  static const NimBLEUUID kReportMap((uint16_t)0x2A4B);
  for (const auto& svc : gatt::cache()) {
    if (!(svc.uuid == kHidSvc)) continue;
    for (const auto& c : svc.chars) {
      if (c.uuid == kReportMap && c.value_cached && !c.value.empty()) {
        f.println();
        hid_parser::parse(c.value.data(), c.value.size(), f);
      }
    }
  }

  f.close();
  log(String("saved ") + path);
}

void App::refreshDumpFiles() {
  dumpFiles_.clear();
  if (!sdInit()) { log("SD not available"); return; }
  File dir = SD.open(dumpDir().c_str());
  if (!dir || !dir.isDirectory()) return;
  for (File e = dir.openNextFile(); e; e = dir.openNextFile()) {
    if (e.isDirectory()) continue;
    String n = e.name();
    int slash = n.lastIndexOf('/');
    if (slash >= 0) n = n.substring(slash + 1);
    dumpFiles_.push_back(n);
  }
}

void App::loadDumpFile(const String& name) {
  dumpViewName_ = name;
  dumpViewLines_.clear();
  if (!sdInit()) return;
  File f = SD.open((dumpDir() + "/" + name).c_str(), FILE_READ);
  if (!f) { dumpViewLines_.push_back("(failed to open)"); return; }
  String line;
  // Read line-by-line, capped so a huge file can't exhaust RAM.
  while (f.available() && dumpViewLines_.size() < 600) {
    char c = (char)f.read();
    if (c == '\r') continue;
    if (c == '\n') { dumpViewLines_.push_back(line); line = ""; }
    else if (line.length() < 200) line += c;
  }
  if (line.length()) dumpViewLines_.push_back(line);
  f.close();
}

void App::performDelete() {
  confirmDelete_ = false;
  // Sentry rule delete (armed with 'x' on the Sentry screen).
  if (sentryDelIdx_ >= 0) {
    sentry::removeRule((size_t)sentryDelIdx_);
    log(String("deleted rule ") + deleteTarget_);
    sentryDelIdx_ = -1;
    deleteTarget_ = "";
    buildSentryRows();
    if (selection_ >= (int)sentryRows_.size()) selection_ = max(0, (int)sentryRows_.size() - 1);
    return;
  }
  if (!sdInit() || deleteTarget_.length() == 0) return;
  String path = dumpDir() + "/" + deleteTarget_;
  bool ok = SD.remove(path.c_str());
  log(String(ok ? "deleted " : "delete failed ") + deleteTarget_);
  deleteTarget_ = "";
  refreshDumpFiles();
  if (screen_ == MenuScreen::DumpView) enterScreen(MenuScreen::Dumps);
  if (selection_ >= (int)dumpFiles_.size()) selection_ = max(0, (int)dumpFiles_.size() - 1);
}

// Live Stream picker: row 0 = Start, then one checkbox row per notify source.
void App::buildStreamRows() {
  streamRows_.clear();
  if (streamSources_.empty()) return;   // drawSentryList shows the empty hint
  int on = 0;
  for (bool b : streamEnabled_) if (b) on++;
  streamRows_.push_back(String("Start streaming (") + on + ")");
  for (size_t i = 0; i < streamSources_.size(); ++i)
    streamRows_.push_back(String(streamEnabled_[i] ? "[*] " : "[ ] ") + streamSources_[i].label.c_str());
}

void App::startSelectedStream() {
  std::vector<uint16_t> handles;
  for (size_t i = 0; i < streamSources_.size(); ++i)
    if (streamEnabled_[i]) handles.push_back(streamSources_[i].handle);
  if (handles.empty()) { log("stream: select at least one notification"); return; }
  if (hid_parser::streamStart(handles)) { log("live stream started"); enterScreen(MenuScreen::HidStream); }
  else log("stream: failed to subscribe");
}

void App::foxhuntSelected() {
  const auto* r = scanner::findByIndex(selectedDevice_);
  if (!r) { log("no device selected"); return; }
  if (scanner::isScanning()) scanner::stop();
  scanner::foxhuntStart(r->addr, r->addr_type, r->name);
  log(String("foxhunt ") + r->addr.c_str());
  foxhuntReturn_ = MenuScreen::DeviceDetail;
  enterScreen(MenuScreen::Foxhunt);
}

// One-tap clone from the Device Detail screen: connect to the device (reusing the
// link if it's already this one), dump its GATT tree, then jump straight into the
// clone-save flow (name entry -> save -> optional advertise). MITM stays on the
// Adversarial menu; Clone is the reliable action to surface here.
void App::cloneSelected() {
  const auto* r = scanner::findByIndex(selectedDevice_);
  if (!r) { log("no device selected"); return; }
  if (scanner::isScanning()) scanner::stop();

  // Already connected to THIS device? Keep the link (and any dump we have).
  bool sameDevice = false;
  if (connection::isConnected() && connection::client()) {
    std::string cur = connection::client()->getPeerAddress().toString();
    std::string want = r->addr;
    for (auto& c : cur)  c = (char)tolower((unsigned char)c);
    for (auto& c : want) c = (char)tolower((unsigned char)c);
    sameDevice = (cur == want);
  }

  if (!sameDevice) {
    if (connection::isConnected()) {
      if (!confirmBlocking("Switch device?", "drop current connection")) return;
      connection::disconnect();
      uint32_t t0 = millis();
      while (connection::isConnected() && millis() - t0 < 2000) { M5Cardputer.update(); delay(20); }
    }
    gatt::clearCache();
    ui_.message("Connecting...", r->addr.c_str(), 2, "ESC = stop");
    log(String("connecting ") + r->addr.c_str());
    connectCanceled_ = false;
    if (!connection::connectTo(*r, [this] { return connectCancelRequested(); })) {
      if (connectCanceled_) { log("connect canceled"); popup("Canceled", "connection stopped", 1200); }
      else { log("connect failed"); popup("Connect failed", "out of range or busy"); }
      return;
    }
    log("connected (pairing in background)");
  }

  // Need a dumped tree to clone; dump now if we don't already have one.
  if (!gatt::hasCache()) doDump();
  if (!gatt::hasCache()) { popup("Clone", "dump failed - try Connect first"); return; }

  enterScreen(MenuScreen::Gatt);   // show the dumped tree behind the name prompt
  startCloneSave();                // name entry -> save -> advertise chain
}

// Connect to the target, wait for pairing, dump it, then stand up the MITM proxy.
void App::mitmSelected() {
  const auto* r = scanner::findByIndex(selectedDevice_);
  if (!r) { log("no device selected"); return; }
  if (scanner::isScanning()) scanner::stop();
  if (connection::isConnected()) {
    if (!confirmBlocking("Switch device?", "drop current connection")) return;
    connection::disconnect();
    uint32_t t0 = millis();
    while (connection::isConnected() && millis() - t0 < 2000) { M5Cardputer.update(); delay(20); }
  }
  gatt::clearCache();

  ui_.message("MITM: connecting", r->addr.c_str(), 2, "ESC = stop");
  connectCanceled_ = false;
  if (!connection::connectTo(*r, [this] { return connectCancelRequested(); })) {
    if (connectCanceled_) popup("Canceled", "connection stopped", 1200);
    else popup("Connect failed", "out of range or busy");
    return;
  }

  // Wait for an encrypted link - the proxy must read/subscribe the target's
  // (often encryption-gated) HID characteristics. MITM needs this even when the
  // global auto-pair default is off, so initiate pairing explicitly here.
  ui_.message("MITM: pairing", r->addr.c_str(), 2);
  connection::secure();
  uint32_t t0 = millis();
  while (connection::isConnected() && !connection::isEncrypted() && millis() - t0 < 6000) {
    M5Cardputer.update();
    connection::serviceAutoRetry();
    delay(20);
  }
  if (!connection::isConnected()) { popup("MITM: link dropped", "during pairing"); return; }

  ui_.message("MITM: dumping", r->addr.c_str(), 2);
  gatt::dump(true);

  // The mirror server must be built on a clean boot (NimBLE locks its GATT DB at
  // the first connection), so persist the target and reboot into proxy mode.
  ui_.message("MITM: rebooting", "into proxy mode");
  delay(600);
  mitm::requestStart(*r);   // saves profile + marker, then ESP.restart()
}

// ----------------------------------------------------------------- sentry

void App::buildSentryRows() {
  sentryRows_.clear();
  sentryRows_.push_back(sentryWatching_ ? "[#] Stop watching" : "[ ] Start watching");
  sentryRows_.push_back("Add from scan");
  sentryRows_.push_back("Add manually");
  for (const auto& r : sentry::rules()) {
    sentryRows_.push_back(String(r.enabled ? "[*] " : "[ ] ") + r.label.c_str() +
                          " (" + sentry::typeName(r.type) + ")");
  }
}

void App::buildSentryPick() {
  sentryPickRows_.clear();
  sentryPickAttrs_.clear();
  const auto* r = scanner::findByIndex(selectedDevice_);
  if (!r) return;
  sentryPickAttrs_ = sentry::attributesOf(*r);
  for (const auto& a : sentryPickAttrs_) sentryPickRows_.push_back(String(a.display.c_str()));
}

void App::sentryToggleWatching() {
  sentryWatching_ = !sentryWatching_;
  if (!sentryWatching_) {
    if (scanner::isScanning()) scanner::stop();
    M5Cardputer.Speaker.stop();
  } else {
    sentryCooldown_.clear();   // fresh session: let everything re-alert
    if (sentry::enabledCount() == 0) log("Sentry: no enabled rules to watch");
  }
  log(String("Sentry watching ") + (sentryWatching_ ? "ON" : "OFF"));
  buildSentryRows();
}

void App::sentryAddFromPick(int i) {
  if (i < 0 || i >= (int)sentryPickAttrs_.size()) return;
  const auto& a = sentryPickAttrs_[i];
  // Resolve by pinned address - the list may have re-sorted since the pick opened.
  const auto* dev = pinnedAddr_.empty() ? scanner::findByIndex(selectedDevice_)
                                        : scanner::findByMac(pinnedAddr_.c_str());
  sentry::Rule rule;
  rule.type = a.type;
  rule.values.push_back(a.value);
  rule.enabled = true;
  // Prefer the device's name as the label, else the attribute description.
  rule.label = (dev && !dev->name.empty()) ? dev->name : a.display;
  if (sentry::addRule(rule)) log(String("Sentry rule added: ") + rule.label.c_str());
  deviceAction_ = DeviceAction::Normal;
  enterScreen(MenuScreen::Sentry);
}

void App::sentryStartManual(sentry::MatchType t) {
  sentryEntryType_ = t;
  sentryEntry_ = true;
  inputBuffer_.clear();   // reused as the value buffer
}

void App::sentryCommitManual() {
  sentry::Rule rule;
  bool ok = sentry::makeRule(sentryEntryType_, std::string(inputBuffer_.c_str()), rule);
  sentryEntry_ = false;
  inputBuffer_.clear();
  if (ok && sentry::addRule(rule)) log(String("Sentry rule added: ") + rule.label.c_str());
  else log("Sentry: invalid value, rule not added");
  enterScreen(MenuScreen::Sentry);
}

// Drive the background watch scan and run the matcher (called every loop).
void App::sentryTick() {
  if (!sentryWatching_) return;
  if (connection::isConnected()) return;          // busy with a device
  if (scanner::foxhuntActive()) return;           // foxhunt owns the radio
  // Don't pop alerts over interactive entry / the add flow / an active alert.
  if (sentryEntry_ || commandMode_ || passkeyMode_ || confirmDelete_ ||
      cloneNameEntry_ || cloneReplayConfirm_ || escMenu_)
    return;
  if (screen_ == MenuScreen::Alert || screen_ == MenuScreen::SentryPick ||
      screen_ == MenuScreen::SentryType)
    return;
  if (screen_ == MenuScreen::Devices && deviceAction_ == DeviceAction::SentryAdd) return;

  if (!scanner::isScanning()) scanner::start(kSentryScanSecs);  // re-arm a fresh timed scan

  uint32_t now = millis();
  if (now - lastSentryMatchMs_ < 300) return;     // throttle the matcher
  lastSentryMatchMs_ = now;
  if (sentry::enabledCount() == 0) return;

  for (const auto& r : scanner::results()) {
    auto it = sentryCooldown_.find(r.addr);
    if (it != sentryCooldown_.end() && (it->second == UINT32_MAX || now < it->second)) continue;
    sentry::Hit h;
    if (sentry::check(r, h)) { alertOpen(r, h); break; }
  }
}

void App::alertOpen(const scanner::Result& r, const sentry::Hit& h) {
  alertResult_ = r;
  alertReason_ = String(h.reason.c_str());
  alertLabel_  = (h.ruleIndex >= 0 && h.ruleIndex < (int)sentry::rules().size())
                     ? String(sentry::rules()[h.ruleIndex].label.c_str())
                     : String("match");
  String nm = r.name.empty() ? String("(no name)") : String(r.name.c_str());
  alertInfo_ = nm + "  " + r.addr.c_str() + "  " + r.rssi + "dBm";
  sentryCooldown_[r.addr] = millis() + 120000;    // 2-min re-alert cooldown

  // Attention chirp (respect the user's volume).
  M5Cardputer.Speaker.setVolume(volume_);
  for (int i = 0; i < 3; ++i) { M5Cardputer.Speaker.tone(2000 + i * 500, 110); delay(130); }

  log(String("SENTRY MATCH: ") + alertLabel_ + " (" + alertReason_ + ") " + r.addr.c_str());
  enterScreen(MenuScreen::Alert);
}

void App::alertConnect() {
  scanner::Result r = alertResult_;               // copy (results may churn)
  if (scanner::isScanning()) scanner::stop();
  gatt::clearCache();
  ui_.message("Connecting...", r.addr.c_str(), 2, "ESC = stop");
  connectCanceled_ = false;
  if (!connection::connectTo(r, [this] { return connectCancelRequested(); })) {
    if (connectCanceled_) popup("Canceled", "connection stopped", 1200);
    else popup("Connect failed", "out of range or busy");
    enterScreen(MenuScreen::Sentry);
    return;
  }
  log("connected (pairing in background)");
  enterScreen(MenuScreen::Gatt);
}

void App::alertFoxhunt() {
  scanner::Result r = alertResult_;
  if (scanner::isScanning()) scanner::stop();
  scanner::foxhuntStart(r.addr, r.addr_type, r.name);
  foxhuntReturn_ = MenuScreen::Sentry;            // Back from foxhunt resumes watching
  enterScreen(MenuScreen::Foxhunt);
}

void App::alertDismiss() {
  sentryCooldown_[alertResult_.addr] = UINT32_MAX;  // ignore for the rest of this session
  log(String("Sentry: dismissed ") + alertResult_.addr.c_str());
  enterScreen(MenuScreen::Sentry);
}

// ----------------------------------------------------------------- battery

// Read the PMIC (throttled) and compute a charger-jump-compensated %. Plugging
// in 5V instantly inflates the measured % (the input raises the cell's terminal
// voltage); we snapshot the last on-battery reading and subtract that jump while
// charging, so the displayed % stays honest and only climbs as it really charges.
void App::sampleBattery(bool force) {
  uint32_t now = millis();
  if (!force && batLastSampleMs_ != 0 && now - batLastSampleMs_ < kBatSampleMs) return;
  batLastSampleMs_ = now;

  int  raw      = (int)M5Cardputer.Power.getBatteryLevel();
  bool charging = ((int)M5Cardputer.Power.isCharging() == 1);
  batMilliVolts_ = M5Cardputer.Power.getBatteryVoltage();
  batMilliAmps_  = M5Cardputer.Power.getBatteryCurrent();

  if (!charging) {
    if (raw >= 0) lastDischargeLevel_ = raw;   // remember the honest on-battery %
    batChargeOffset_ = 0;
  } else if (!batWasCharging_) {
    // Just plugged in: capture the instantaneous jump (vs the last on-battery %).
    // If we booted already charging there's no baseline, so don't correct.
    batChargeOffset_ = (lastDischargeLevel_ >= 0 && raw >= 0) ? (raw - lastDischargeLevel_) : 0;
    if (batChargeOffset_ < 0) batChargeOffset_ = 0;   // only correct upward jumps
  }
  batWasCharging_ = charging;

  int shown = raw;
  if (charging && raw >= 0) {
    shown = raw - batChargeOffset_;
    if (shown < 0) shown = 0;
    if (shown > 100) shown = 100;
  }
  batTrueLevel_ = shown;
  batCharging_  = charging;
}

// ----------------------------------------------------------------- charging

void App::enterChargingMode() {
  // Quiet the radio + speaker so charging isn't fighting active consumers.
  if (scanner::isScanning())      scanner::stop();
  if (scanner::foxhuntActive())   scanner::foxhuntStop();
  sentryWatching_ = false;        // pause background detection
  M5Cardputer.Speaker.stop();

  // Drop the CPU clock (80 MHz keeps BLE/USB stable) and dim the LCD hard - the
  // backlight is the dominant draw, and a near-off panel avoids burn-in.
  savedCpuMhz_ = getCpuFrequencyMhz();
  setCpuFrequencyMhz(80);
  M5Cardputer.Display.setBrightness(kChargeBrightness);

  lastChargeDrawMs_ = 0;          // force an immediate first draw
  chargingMode_ = true;
  log("charging mode on (press any key to exit)");
}

void App::exitChargingMode() {
  chargingMode_ = false;
  setCpuFrequencyMhz(savedCpuMhz_ ? savedCpuMhz_ : 240);
  M5Cardputer.Display.setBrightness(brightness_);   // restore the user's brightness
  enterScreen(MenuScreen::Settings);
  log("charging mode off");
}

void App::chargingTick() {
  // Any keypress leaves charging mode.
  if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) {
    exitChargingMode();
    return;
  }
  sampleBattery();   // engineTick is bypassed in charging mode, so sample here
  uint32_t now = millis();
  if (lastChargeDrawMs_ == 0 || now - lastChargeDrawMs_ >= 3000) {   // slow redraw
    lastChargeDrawMs_ = now;
    ui_.drawCharging(batTrueLevel_, batCharging_, batMilliVolts_, batMilliAmps_);
  }
  delay(50);   // ease off the CPU between checks
}

void App::runCommand(const String& cmd) {
  log(String("> ") + cmd);
  cli::execute(cmd.c_str());
  // A `clone save` adds a profile; refresh the Clone screen list so the new
  // entry shows up without a manual refresh.
  if (screen_ == MenuScreen::Clone && cmd.startsWith("clone save"))
    refreshCloneNames();
}

// ----------------------------------------------------------------- logs

void App::log(const String& line) {
  if (logCount_ < kMaxLogLines) {
    logLines_[(logHead_ + logCount_) % kMaxLogLines] = line;
    ++logCount_;
  } else {
    logLines_[logHead_] = line;
    logHead_ = (logHead_ + 1) % kMaxLogLines;
  }
  Serial.println(line);
}
