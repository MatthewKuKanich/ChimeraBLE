// SPDX-License-Identifier: GPL-3.0-or-later
//
// Waveshare ESP32-C5-Touch-LCD-3.5 board layer: see M5Cardputer.h in this folder.

#if defined(CHIMERA_TOUCH_UI) && defined(CHIMERA_BOARD_WS_C5_35)

#include "M5Cardputer.h"

#include <board/ws_c5_35/ws_c5_35_battery.h>
#include <board/ws_c5_35/ws_c5_35_board.h>

#include "TouchUI.h"

chimera_ws::CardputerShim M5Cardputer;

namespace {

using chimera_ws::kScale;

TFT_eSPI& tft() {
  static TFT_eSPI t;
  return t;
}

// Every colour the UI draws with (the UI.cpp palette plus its literal greens,
// yellows, reds and greys): exactly sixteen, so a 4-bit sprite loses nothing.
// A colour that is not listed falls back to the nearest entry.
uint16_t g_palette[16] = {
    0x0821, 0x1063, 0x18A5, 0x4015, 0xFFFF, 0xBDF7, 0xFD20, 0x0000,
    0x07FF, 0x07E0, 0x2104, 0xFFE0, 0xF800, 0x8410, 0x630C, 0x4208,
};
uint16_t g_paletteBus[16];   // same colours, byte order as the panel wants them

uint8_t colorIndex(uint16_t c) {
  static uint16_t lastColor = 0x0821;
  static uint8_t lastIndex = 0;
  if (c == lastColor) return lastIndex;
  uint8_t best = 0;
  uint32_t bestDist = UINT32_MAX;
  for (uint8_t i = 0; i < 16; ++i) {
    const uint16_t p = g_palette[i];
    if (p == c) { best = i; break; }
    const int dr = ((p >> 11) & 0x1F) - ((c >> 11) & 0x1F);
    const int dg = ((p >> 5) & 0x3F) - ((c >> 5) & 0x3F);
    const int db = (p & 0x1F) - (c & 0x1F);
    const uint32_t d = (uint32_t)(4 * dr * dr + dg * dg + 4 * db * db);
    if (d < bestDist) { bestDist = d; best = i; }
  }
  lastColor = c;
  lastIndex = best;
  return best;
}

}  // namespace

// ------------------------------------------------------------------- canvas

M5Canvas::M5Canvas() : spr_(&tft()) {}

bool M5Canvas::createSprite(int16_t w, int16_t h) {
  w_ = w;
  h_ = h;
  spr_.setAttribute(PSRAM_ENABLE, false);   // 77 KB fits in internal RAM
  spr_.setColorDepth(4);
  if (!spr_.createSprite(w * kScale, h * kScale)) { w_ = h_ = 0; return false; }
  spr_.createPalette(g_palette, 16);
  spr_.setTextWrap(false, false);
  for (uint8_t i = 0; i < 16; ++i)
    g_paletteBus[i] = (uint16_t)((g_palette[i] >> 8) | (g_palette[i] << 8));
  rowHash_ = (uint32_t*)calloc((size_t)h * kScale, sizeof(uint32_t));
  return rowHash_ != nullptr;
}

void M5Canvas::fillSprite(uint16_t color) { spr_.fillSprite(colorIndex(color)); }

void M5Canvas::fillRect(int16_t x, int16_t y, int16_t w, int16_t h, uint16_t color) {
  spr_.fillRect(x * kScale, y * kScale, w * kScale, h * kScale, colorIndex(color));
}

void M5Canvas::drawRect(int16_t x, int16_t y, int16_t w, int16_t h, uint16_t color) {
  const uint8_t c = colorIndex(color);
  for (int16_t t = 0; t < kScale; ++t)
    spr_.drawRect(x * kScale + t, y * kScale + t, w * kScale - 2 * t, h * kScale - 2 * t, c);
}

void M5Canvas::fillRoundRect(int16_t x, int16_t y, int16_t w, int16_t h, int16_t r,
                             uint16_t color) {
  spr_.fillRoundRect(x * kScale, y * kScale, w * kScale, h * kScale, r * kScale,
                     colorIndex(color));
}

void M5Canvas::drawRoundRect(int16_t x, int16_t y, int16_t w, int16_t h, int16_t r,
                             uint16_t color) {
  const uint8_t c = colorIndex(color);
  for (int16_t t = 0; t < kScale; ++t)
    spr_.drawRoundRect(x * kScale + t, y * kScale + t, w * kScale - 2 * t, h * kScale - 2 * t,
                       r * kScale - t, c);
}

void M5Canvas::setTextSize(uint8_t size) { spr_.setTextSize(size * kScale); }

void M5Canvas::setTextColor(uint16_t fg, uint16_t bg) {
  spr_.setTextColor(colorIndex(fg), colorIndex(bg));
}

void M5Canvas::setCursor(int16_t x, int16_t y) { spr_.setCursor(x * kScale, y * kScale); }

void M5Canvas::setClipRect(int16_t x, int16_t y, int16_t w, int16_t h) {
  spr_.setViewport(x * kScale, y * kScale, w * kScale, h * kScale, false);
}

void M5Canvas::clearClipRect() { spr_.resetViewport(); }

// Send the frame to the panel: hash each row and write only the runs of rows
// whose hash changed since the last push. A static screen costs no SPI traffic;
// a full redraw is one 480x320 window.
void M5Canvas::pushSprite(chimera_ws::DisplayShim*, int16_t, int16_t) {
  const uint8_t* img = (const uint8_t*)spr_.getPointer();
  if (!img || !rowHash_) return;
  const int W = w_ * kScale, H = h_ * kScale;
  const int rowBytes = W / 2;   // two pixels per byte, left pixel in the high nibble

  static uint8_t dirty[320];
  bool any = false;
  for (int y = 0; y < H; ++y) {
    const uint8_t* p = img + (size_t)y * rowBytes;
    uint32_t hsh = 2166136261u;   // FNV-1a
    for (int i = 0; i < rowBytes; ++i) hsh = (hsh ^ p[i]) * 16777619u;
    hsh |= 1;                     // never 0, so a fresh table is all dirty
    dirty[y] = hsh != rowHash_[y];
    rowHash_[y] = hsh;
    any = any || dirty[y];
  }
  if (!any) return;

  static uint16_t line[480] __attribute__((aligned(4)));
  TFT_eSPI& t = tft();
  t.startWrite();
  int y = 0;
  while (y < H) {
    if (!dirty[y]) { ++y; continue; }
    int y1 = y;
    while (y1 < H && dirty[y1]) ++y1;
    t.setAddrWindow(0, y, W, y1 - y);
    for (; y < y1; ++y) {
      const uint8_t* p = img + (size_t)y * rowBytes;
      uint16_t* out = line;
      for (int i = 0; i < rowBytes; ++i) {
        *out++ = g_paletteBus[p[i] >> 4];
        *out++ = g_paletteBus[p[i] & 0x0F];
      }
      t.pushPixels(line, W);
    }
  }
  t.endWrite();
}

// ----------------------------------------------------------------- display

namespace chimera_ws {

void DisplayShim::fillScreen(uint16_t color) { tft().fillScreen(color); }

void DisplayShim::setCursor(int16_t x, int16_t y) {
  tft().setTextSize(kScale);
  tft().setTextColor(0xFFFF, 0x0000);
  tft().setCursor(x * kScale, y * kScale);
}

size_t DisplayShim::print(const char* s) { return tft().print(s); }

void DisplayShim::setBrightness(uint8_t level) { WsC5_35::Expander::backlight(level); }

// ---------------------------------------------------------------- keyboard

void KeyboardShim::latch(char key) {
  state_ = KeysState();
  if (key == touchui::kEnter) state_.enter = true;
  else if (key == touchui::kBackspace) state_.del = true;
  else state_.word.push_back(key);
  fresh_ = true;
}

// ------------------------------------------------------------------- power

int PowerShim::getBatteryLevel() {
  if (!WsC5_35::Battery::present()) return -1;
  WsC5_35::Battery::refresh();
  if (!WsC5_35::Battery::batteryConnected()) return -1;
  return WsC5_35::Battery::percent();
}

int PowerShim::isCharging() {
  return (WsC5_35::Battery::present() && WsC5_35::Battery::charging()) ? 1 : 0;
}

int16_t PowerShim::getBatteryVoltage() {
  return WsC5_35::Battery::present() ? (int16_t)WsC5_35::Battery::voltageMv() : 0;
}

// ------------------------------------------------------------------- board

void CardputerShim::begin(const Config&, bool) {
  // Expander first: it releases the ST7796 reset. Backlight stays off until the
  // App sets the brightness, after the panel has been cleared.
  const bool exio = WsC5_35::begin(0);
  TFT_eSPI& t = tft();
  t.init();
  t.setRotation(1);   // landscape, 480x320
  t.invertDisplay(WsC5_35::PANEL_NEEDS_INVERSION);
  t.fillScreen(0x0000);
  const bool gauge = WsC5_35::Battery::begin();
  Serial.printf("[ws-c5-35] expander %s, touch %s, battery gauge %s, free heap %u\n",
                exio ? "up" : "MISSING", WsC5_35::Touch::present() ? "present" : "missing",
                gauge ? "present" : "missing", (unsigned)ESP.getFreeHeap());
}

void CardputerShim::update() {
  Keyboard.clear();
  if (WsC5_35::Touch::present()) {
    // Touch reports native-portrait panel coordinates; the screen is rotated to
    // landscape: screen x = touch y, screen y = (panel width - 1) - touch x.
    uint16_t tx = 0, ty = 0;
    const bool down = WsC5_35::Touch::poll(tx, ty);
    const int16_t lx = (int16_t)(ty / kScale);
    const int16_t ly = (int16_t)((WsC5_35::PANEL_W - 1 - tx) / kScale);
    touchui::feed(down, lx, ly);
  }
  const char k = touchui::takeKey();
  if (k) Keyboard.latch(k);
}

}  // namespace chimera_ws

#endif  // CHIMERA_TOUCH_UI && CHIMERA_BOARD_WS_C5_35
