// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#pragma once

#include <Arduino.h>
#include <M5Cardputer.h>
#include <string>
#include <vector>

// Screens for the ChimeraBLE Cardputer UI.
enum class MenuScreen : uint8_t {
  Main = 0,
  Devices,        // scan-result list
  DeviceDetail,   // one device: identity + fingerprint + actions
  Gatt,           // GATT tree of the connected device
  HidStream,      // live decoded HID input reports
  Foxhunt,        // live RSSI tracking
  Clone,          // clone profiles: save/load/advertise
  Dumps,          // list of saved SD dumps
  DumpView,       // contents of one saved dump
  Settings,       // volume / brightness / scan time / actions / logs
  Honeypot,       // live host activity against the clone (+ SD log)
  Logs,
  ReconMenu,      // category: Devices / GATT / HID Stream / Saved Dumps
  AdvMenu,        // category: Clone / BLE Honeypot / MITM
  Sentry,         // watchlist management + start/stop watching
  SentryPick,     // pick which attribute of a scanned device to track
  SentryType,     // pick a match type for a manual rule
  Alert,          // a watchlist match fired
  StreamSelect,   // pick which notify characteristics to live-stream
  About,          // app identity: author / github / license / version
};

// Snapshot of UI state the renderer needs (App builds this each frame).
struct MenuView {
  MenuScreen screen = MenuScreen::Main;
  const char* title = "";
  const char* const* items = nullptr;
  size_t itemCount = 0;
  int selectedIndex = 0;
  int scrollOffset = 0;
  int selectedDevice = -1;
  bool commandMode = false;
  const std::vector<std::string>* cloneNames = nullptr;   // for the Clone screen
  int cloneActions = 0;                                   // # fixed actions before names
  const std::vector<String>* dumpFiles = nullptr;         // for the Dumps screen
  const std::vector<String>* dumpViewLines = nullptr;     // for the DumpView screen
  const char* dumpViewName = "";
  bool audioOn = false;                                   // fox-hunt audio state
  uint8_t volume = 0;                                     // current speaker volume
  const std::vector<String>* settingsLabels = nullptr;    // for the Settings screen
  const std::vector<String>* honeypotLines = nullptr;     // for the Honeypot screen
  bool honeypotConnected = false;
  bool honeypotLogging = false;
  const std::vector<String>* sentryRows = nullptr;        // Sentry + SentryPick row labels
  bool sentryWatching = false;                            // detection mode running
  const char* alertLabel = "";                            // matched rule label
  const char* alertInfo = "";                             // device name / MAC / RSSI line
  const char* alertReason = "";                           // why it matched
  int  batLevel = -1;                                     // corrected battery % (App-sampled)
  bool batCharging = false;
};

class UI {
 public:
  void begin();
  void draw(const MenuView& menu, const String& inputBuffer,
            const String* logLines, size_t logHead, size_t logCount);

  // Immediately draw a centered modal message and push it to the screen - used
  // to show progress during a blocking op (connect/dump) that stalls the loop.
  // subSize scales the secondary line (1 = small default; 2 for a MAC so it's
  // readable). The box grows to fit a larger sub. hint, if given, draws a small
  // dim line at the bottom (e.g. "ESC = stop").
  void message(const char* title, const char* sub = nullptr, uint8_t subSize = 1,
               const char* hint = nullptr);

  // Branded boot splash (standalone full-screen draw), shown briefly at startup.
  void drawSplash();

 private:
  static constexpr size_t kLogCapacity = 60;
  static constexpr uint32_t kDrawIntervalMs = 60;

  // Default-constructed (no parent). Binding to M5Cardputer.Display here would
  // capture it at static-init time - before the M5Cardputer global is built -
  // giving a null parent and a pushSprite() null-deref crash. We pass the
  // display explicitly to pushSprite() at runtime instead.
  M5Canvas canvas_;
  bool canvasReady_ = false;
  uint32_t lastDrawMs_ = 0;

  void drawHeader(const MenuView& menu, int16_t w);
  void drawBattery(int16_t x, int16_t y, int level, bool charging);
  void drawFooter(const MenuView& menu, const String& inputBuffer, int16_t w, int16_t h);
  void drawMenuList(const MenuView& menu, int16_t w, int16_t h);
  void drawDevices(const MenuView& menu, int16_t w, int16_t h);
  void drawDeviceDetail(const MenuView& menu, int16_t w, int16_t h);
  void drawGatt(const MenuView& menu, int16_t w, int16_t h);
  void drawHidStream(int16_t w, int16_t h);
  void drawFoxhunt(const MenuView& menu, int16_t w, int16_t h);
  void drawClone(const MenuView& menu, int16_t w, int16_t h);
  void drawDumps(const MenuView& menu, int16_t w, int16_t h);
  void drawDumpView(const MenuView& menu, int16_t w, int16_t h);
  void drawSettings(const MenuView& menu, int16_t w, int16_t h);
  void drawHoneypot(const MenuView& menu, int16_t w, int16_t h);
  void drawSentryList(const MenuView& menu, int16_t w, int16_t h);   // Sentry + SentryPick
  void drawAlert(const MenuView& menu, int16_t w, int16_t h);
  void drawAbout(const MenuView& menu, int16_t w, int16_t h);

 public:
  // Minimal battery-stats screen for charging mode: mostly-black, no header/
  // footer banners, slow gentle pixel drift to avoid burn-in. Drawn directly
  // (bypasses the normal screen dispatch) so the rest of the UI stays idle.
  // Values are App-sampled (corrected %) and passed in.
  void drawCharging(int level, bool charging, int16_t milliVolts, int32_t milliAmps);

 private:
  void drawLogs(const String* logLines, size_t logHead, size_t logCount, int scrollOffset,
                int16_t w, int16_t h);

  String trimToWidth(const String& text, size_t maxChars) const;
  size_t maxCharsForWidth(int16_t pixelWidth, uint8_t textSize) const;

  // Print a string at size 1 with UTF8 decoding off so CP437 arrow glyphs
  // (0x18-0x1B) render - used for footer key hints (the Cardputer's ;./, keys
  // are labeled with orange arrows). Restores UTF8 afterward.
  void printHint(int16_t x, int16_t y, const String& s, uint16_t fg, uint16_t bg);
};
