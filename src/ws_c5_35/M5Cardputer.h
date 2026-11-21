// SPDX-License-Identifier: GPL-3.0-or-later
//
// Waveshare ESP32-C5-Touch-LCD-3.5 board layer for the on-device UI.
//
// The UI (src/ui) is written against the M5Cardputer API: an M5Canvas sprite,
// the Cardputer keyboard, its speaker and its power chip. This header stands in
// for <M5Cardputer.h> on the ws_c5_35 build (the env puts this directory on the
// include path), so App.cpp and UI.cpp need only the small CHIMERA_TOUCH_UI
// additions and no M5 library.
//
//   Display  ST7796 320x480 in landscape, driven by TFT_eSPI. The UI draws in a
//            240x160 logical space; the canvas doubles every coordinate and text
//            size, so upstream's 6x8 font lands at 12x16 on the glass.
//   Canvas   4-bit palette sprite (77 KB instead of 307 KB at 16-bit). Only the
//            rows that changed since the last frame are sent to the panel.
//   Keyboard Fed by the touch layer (TouchUI.h): taps on on-screen targets and
//            drags arrive as the key presses the App already handles.
//   Speaker  Silent for now. Power: battery gauge through the ESP32-C5-BSP.
#pragma once

#include <Arduino.h>
#include <TFT_eSPI.h>
#include <vector>

// UI.cpp switches UTF-8 decoding off to print CP437 arrows. TFT_eSPI has the same
// attribute under the same id.
namespace lgfx {
inline namespace v1 {
enum : uint8_t { utf8_switch = UTF8_SWITCH };
}
}  // namespace lgfx

namespace chimera_ws {

constexpr int16_t kScale    = 2;     // logical px -> panel px
constexpr int16_t kLogicalW = 240;   // 480 / kScale
constexpr int16_t kLogicalH = 160;   // 320 / kScale

class DisplayShim {
 public:
  void setRotation(uint8_t) {}
  void setTextSize(uint8_t) {}
  void setTextColor(uint16_t, uint16_t) {}
  int16_t width() const { return kLogicalW; }
  int16_t height() const { return kLogicalH; }
  void fillScreen(uint16_t color);
  void setCursor(int16_t x, int16_t y);
  size_t print(const char* s);
  void setBrightness(uint8_t level);   // 0..255 -> backlight PWM on the I/O expander
};

class KeyboardShim {
 public:
  struct KeysState {
    std::vector<char> word;
    bool enter = false;
    bool del = false;
  };
  // One synthetic key press is visible for exactly one update() cycle.
  bool isChange() const { return fresh_; }
  bool isPressed() const { return fresh_; }
  KeysState& keysState() { return state_; }

  void latch(char key);   // board layer: present this key until the next update()
  void clear() { fresh_ = false; state_ = KeysState(); }

 private:
  KeysState state_;
  bool fresh_ = false;
};

class SpeakerShim {
 public:
  void setVolume(uint8_t) {}
  void tone(float, uint32_t) {}
  void stop() {}
};

class PowerShim {
 public:
  int getBatteryLevel();     // 0..100, or -1 with no cell / no gauge
  int isCharging();          // 1 while charging
  int16_t getBatteryVoltage();   // mV
  int32_t getBatteryCurrent() { return 0; }   // not measured on this board
};

struct Config {};

class CardputerShim {
 public:
  DisplayShim Display;
  KeyboardShim Keyboard;
  SpeakerShim Speaker;
  PowerShim Power;

  void begin(const Config&, bool enableKeyboard = true);
  void update();   // polls touch and latches at most one synthetic key
};

struct M5Shim {
  Config config() const { return Config(); }
};

}  // namespace chimera_ws

using Keyboard_Class = chimera_ws::KeyboardShim;

extern chimera_ws::CardputerShim M5Cardputer;
static const chimera_ws::M5Shim M5;

// The subset of M5Canvas the UI uses. Coordinates and text sizes are logical.
class M5Canvas {
 public:
  M5Canvas();

  void setPsram(bool) {}
  void setColorDepth(uint8_t) {}
  bool createSprite(int16_t w, int16_t h);
  int16_t width() const { return w_; }
  int16_t height() const { return h_; }

  void fillSprite(uint16_t color);
  void fillRect(int16_t x, int16_t y, int16_t w, int16_t h, uint16_t color);
  void drawRect(int16_t x, int16_t y, int16_t w, int16_t h, uint16_t color);
  void fillRoundRect(int16_t x, int16_t y, int16_t w, int16_t h, int16_t r, uint16_t color);
  void drawRoundRect(int16_t x, int16_t y, int16_t w, int16_t h, int16_t r, uint16_t color);

  void setTextSize(uint8_t size);
  void setTextColor(uint16_t fg, uint16_t bg);
  void setCursor(int16_t x, int16_t y);
  template <typename T>
  size_t print(const T& value) { return spr_.print(value); }
  void setAttribute(uint8_t id, uint8_t value) { spr_.setAttribute(id, value); }

  void setClipRect(int16_t x, int16_t y, int16_t w, int16_t h);
  void clearClipRect();

  void pushSprite(chimera_ws::DisplayShim* display, int16_t x, int16_t y);

 private:
  TFT_eSprite spr_;
  int16_t w_ = 0, h_ = 0;
  uint32_t* rowHash_ = nullptr;   // one hash per panel row, from the last push
};
