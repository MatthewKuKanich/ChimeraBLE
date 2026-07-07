// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#pragma once

#include <Arduino.h>
#include <FS.h>
#include <Preferences.h>
#include <map>
#include <string>
#include <vector>

#include "UI.h"
#include "hid_parser.h"
#include "scanner.h"
#include "sentry.h"

// Rows that can appear on the Settings screen (action set varies by state).
enum class SettingKind : uint8_t { Volume, Brightness, ScanTime, AutoPair, OpenLogs, ChargeMode, Disconnect, StopAdv, StopMitm, ClearBonds, About };

// On-device front-end for the Cardputer ADV. Orchestrates menu navigation,
// drives the shared ChimeraBLE engine directly (no transport), and renders via
// UI. Modeled on the CANCommander companion App, minus Wi-Fi/TCP + LineParser.
class App {
 public:
  void begin();
  void loop();

 private:
  // ---- engine housekeeping (mirrors the serial main.cpp loop) ----
  void engineTick();

  // ---- input ----
  void handleKeyboard();
  void handleChar(char c);
  void onEnter();
  void onBack();
  void moveSelection(int delta);

  // ---- navigation / actions ----
  void enterScreen(MenuScreen s);
  void activate();              // act on current selection
  MenuScreen parentOf(MenuScreen s) const;   // back-target (one level up the menu tree)
  void buildMenuView(MenuView& mv) const;
  void currentMenu(const char*& title, const char* const*& items, size_t& count) const;

  // What selecting a device on the Devices list does: open its detail screen
  // (normal), start the MITM proxy (Adversarial -> MITM), or capture it as a
  // Sentry watch rule (Sentry -> Add from scan).
  enum class DeviceAction : uint8_t { Normal, Mitm, SentryAdd };
  DeviceAction deviceAction_ = DeviceAction::Normal;

  // Show a modal popup and hold it until a keypress or timeout (for transient
  // notices like a failed connect, before returning to the previous screen).
  void popup(const char* title, const char* sub = nullptr, uint32_t ms = 2500);

  // Live Stream notification picker (StreamSelect screen): choose which notify
  // characteristics to subscribe to before streaming.
  std::vector<hid_parser::StreamSource> streamSources_;
  std::vector<bool>                     streamEnabled_;   // parallel to streamSources_
  std::vector<String>                   streamRows_;      // rendered rows (Start + checkboxes)
  void buildStreamRows();
  void startSelectedStream();

  void doScan();
  void connectSelected();
  // Polled from inside a blocking connect: pumps input and returns true if the
  // user pressed ESC to abort (sets connectCanceled_ so callers can distinguish
  // a user cancel from a real failure).
  bool connectCancelRequested();
  bool connectCanceled_ = false;
  void doDump();
  void foxhuntSelected();
  void cloneSelected();  // connect + dump the target, then start the clone-save flow
  void mitmSelected();   // connect+pair+dump target, then start the MITM proxy
  void runCommand(const String& cmd);

  // SD card (Cardputer): auto-save each dump to /ble_dumps/<name>_<MAC>.txt
  bool sdReady_ = false;
  bool spiBegun_ = false;
  bool sdInit();
  void saveDumpToSd();
  // SD is organized under one ChimeraBLE folder, resolved case-insensitively at
  // mount (adopts an existing "chimerable" / "CHIMERABLE" / ... else creates the
  // canonical name), so a mis-cased folder still works. oui.bin is located
  // flexibly: the base folder first, then the SD root, filename matched any-case.
  String sdBase_ = "/ChimeraBLE";
  void   resolveSdBase();
  String dumpDir() const { return sdBase_ + "/ble_dumps"; }
  String findFileCI(const String& dir, const char* name);
  String findOuiPath();

  // scan-time entry (typing digits while "Scan" is highlighted on the main menu)
  uint32_t scanSecs_ = 10;
  bool     scanEditing_ = false;
  char     scanLabel_[24] = "Scan (10s)";
  const char* mainItems_[5];     // [0] = scanLabel_, then Recon / Adversarial / Sentry / Settings
  void buildScanLabel();
  void buildMainItems();

  // ---- Sentry (detection / alert watchlist) ----
  bool                 sentryWatching_ = false;     // detection mode running
  std::vector<String>  sentryRows_;                 // management list rows (actions + rules)
  std::vector<String>  sentryPickRows_;             // attribute picker rows (add-from-scan)
  std::vector<sentry::Attr> sentryPickAttrs_;       // parallel to sentryPickRows_
  bool                 sentryEntry_ = false;        // manual value text-entry modal
  sentry::MatchType    sentryEntryType_ = sentry::MatchType::Mac;
  int                  sentryDelIdx_ = -1;          // rule index pending delete-confirm
  scanner::Result      alertResult_;                // device that triggered an alert (copy)
  String               alertLabel_, alertReason_, alertInfo_;
  std::map<std::string, uint32_t> sentryCooldown_;  // MAC -> suppress-until millis (UINT32_MAX = dismissed)
  uint32_t             lastSentryMatchMs_ = 0;
  MenuScreen           foxhuntReturn_ = MenuScreen::DeviceDetail;  // where Back from Foxhunt goes
  static constexpr int kSentryActions = 3;          // Start/Stop, Add from scan, Add manually

  void sentryTick();              // drive the watch scan + run the matcher
  void buildSentryRows();
  void buildSentryPick();         // from selectedDevice_
  void sentryToggleWatching();
  void sentryAddFromPick(int i);
  void sentryStartManual(sentry::MatchType t);
  void sentryCommitManual();
  void alertOpen(const scanner::Result& r, const sentry::Hit& h);
  void alertConnect();
  void alertFoxhunt();
  void alertDismiss();

  // saved-dump browser (SD /ble_dumps)
  std::vector<String> dumpFiles_;       // filenames in /ble_dumps
  String              dumpViewName_;    // currently viewed file
  std::vector<String> dumpViewLines_;   // its contents, split into lines
  bool                confirmDelete_ = false;
  // Clone-name text entry (Clone menu "Save current dump" / GATT-screen Clone),
  // then an optional "advertise it now?" confirm. cloneSaveName_ carries the name
  // from the save into the replay step.
  bool                cloneNameEntry_ = false;      // typing the profile name
  bool                cloneReplayConfirm_ = false;  // offer to advertise the just-saved profile
  String              cloneSaveName_;
  void                startCloneSave();             // guard on a dumped snapshot, then enter name mode
  void                commitCloneSave();            // save + arm the replay confirm
  String              deleteTarget_;    // filename pending delete confirmation
  bool                escMenu_ = false;            // ESC on main menu: disconnect / forget-bonds

  // Blocking yes/no modal (Enter=yes, any other key / timeout = no). For flows
  // that already block, e.g. switching the active connection.
  bool confirmBlocking(const char* title, const char* sub, uint32_t timeoutMs = 12000);

  // on-screen passkey entry (peer-displayed code we must type)
  bool                passkeyMode_ = false;
  String              passkeyBuf_;

  // audio fox-hunt (Geiger-counter beeps; off by default, toggle with 'a')
  bool                audio_ = false;
  uint32_t            lastBeepMs_ = 0;
  void                foxhuntAudioTick();
  void                adjustVolume(int delta);   // step + clamp + apply + persist

  // device settings
  uint8_t             volume_ = 80;
  uint8_t             brightness_ = 160;
  // Auto-pair on connect. Default OFF (reactive, like nRF Connect): many sensors
  // with an open GATT drop a central that sends an unsolicited bond request, and
  // NimBLE already responds to a peripheral's own security request. HID devices
  // that lead with a security request still pair; turn this on for the rare HID
  // that gates everything behind encryption without requesting it.
  bool                autoSecure_ = false;

  // Battery sampling + charger-jump compensation. Plugging in 5V instantly bumps
  // the measured % up ~20% (input raises the cell terminal voltage), so we record
  // the last on-battery reading and subtract that instantaneous jump while
  // charging to show a "true" %. Sampled lazily (boot + ~every 10s).
  int                 batTrueLevel_ = -1;     // corrected % (what the UI shows)
  bool                batCharging_  = false;
  int16_t             batMilliVolts_ = 0;
  int32_t             batMilliAmps_  = 0;
  int                 lastDischargeLevel_ = -1;  // last % seen while NOT charging
  int                 batChargeOffset_ = 0;      // the plug-in jump to subtract
  bool                batWasCharging_ = false;
  uint32_t            batLastSampleMs_ = 0;
  void                sampleBattery(bool force = false);

  // charging mode: dim screen + battery-only readout + low-power tweaks, so the
  // Cardputer can charge (it only charges while powered on) without LCD burn or
  // extra draw. Exits on any keypress.
  bool                chargingMode_ = false;
  uint32_t            savedCpuMhz_ = 240;     // CPU freq to restore on exit
  uint32_t            lastChargeDrawMs_ = 0;  // throttle the (slow) battery redraw
  void                enterChargingMode();
  void                exitChargingMode();
  void                chargingTick();
  std::vector<SettingKind> settingsKinds_;   // current Settings rows (dynamic)
  std::vector<String>      settingsLabels_;
  void                refreshSettings();
  void                activateSetting();

  // BLE honeypot - live host activity against the clone, mirrored to SD
  std::vector<String> hpLines_;        // display ring (newest at end)
  File                hpFile_;         // open SD log while a host is connected
  bool                hpFileOpen_ = false;
  uint32_t            lastHostSeq_ = 0;
  void                honeypotTick();  // drain events -> screen + SD; auto-open

  // persistent settings (NVS)
  Preferences         prefs_;
  void                loadSettings();
  void refreshDumpFiles();
  void loadDumpFile(const String& name);
  void performDelete();

  // clone screen
  static constexpr int kCloneActions = 3;   // Save / Advertise / Stop
  std::vector<std::string> cloneNames_;
  void refreshCloneNames();
  void activateClone();

  // ---- logs ----
  void log(const String& line);

  UI ui_;

  MenuScreen screen_ = MenuScreen::Main;
  int  selection_ = 0;
  int  scrollOffset_ = 0;
  int  selectedDevice_ = -1;    // index into scanner::results()

  // The scan list re-sorts by RSSI as devices stream in, so a bare row index would
  // slide the highlight onto a different device mid-scan (and a right-press could
  // connect to the wrong one). Pin the hovered/selected device by address and let
  // the highlight follow it across re-sorts (see syncDeviceSelection).
  std::string pinnedAddr_;
  void        syncDeviceSelection();

  bool   commandMode_ = false;
  String inputBuffer_;
  static constexpr size_t kInputMaxLen = 120;

  // log ring buffer
  static constexpr size_t kMaxLogLines = 60;
  String   logLines_[kMaxLogLines];
  size_t   logHead_ = 0;
  size_t   logCount_ = 0;

  // edge-detect engine state for housekeeping
  bool wasConnected_ = false;
  bool wasScanning_ = false;
};
