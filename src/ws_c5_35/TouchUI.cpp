// SPDX-License-Identifier: GPL-3.0-or-later

#if defined(CHIMERA_TOUCH_UI)

#include "TouchUI.h"

#include <stdlib.h>

namespace touchui {
namespace {

struct Target {
  int16_t x, y, w, h;
  char key;      // key press, when row < 0
  int16_t row;   // row to open, when >= 0
};
constexpr size_t kMaxTargets = 24;
Target g_targets[kMaxTargets];
size_t g_targetCount = 0;

struct {
  bool active = false;
  int16_t top = 0, bottom = 0, rowH = 1;
  size_t count = 0;
} g_list;

struct {
  bool active = false;
  int16_t top = 0, bottom = 0, lineH = 1;
} g_lines;

constexpr uint8_t kScreens = 32;
uint8_t g_screen = 0;
int16_t g_scroll[kScreens] = {0};   // list scroll position, per screen

constexpr size_t kKeyQueue = 16;
char g_keys[kKeyQueue];
size_t g_keyHead = 0, g_keyCount = 0;
int g_rowTap = -1;

// Gesture state. A touch is a tap until it moves kDragStart px vertically inside
// a scrollable area; from then on it scrolls and never taps.
enum class Area : uint8_t { None, List, Lines };
constexpr int16_t kDragStart = 5;
bool g_down = false, g_drag = false;
Area g_area = Area::None;
int16_t g_x0 = 0, g_y0 = 0, g_lastY = 0, g_lineAcc = 0;

void pushKey(char k) {
  if (g_keyCount == kKeyQueue) return;
  g_keys[(g_keyHead + g_keyCount) % kKeyQueue] = k;
  ++g_keyCount;
}

void addTarget(int16_t x, int16_t y, int16_t w, int16_t h, char key, int16_t row) {
  if (g_targetCount == kMaxTargets) return;
  g_targets[g_targetCount++] = {x, y, w, h, key, row};
}

void tap(int16_t x, int16_t y) {
  // Later targets are drawn on top, so they win.
  for (size_t i = g_targetCount; i-- > 0;) {
    const Target& t = g_targets[i];
    if (x < t.x || y < t.y || x >= t.x + t.w || y >= t.y + t.h) continue;
    if (t.row >= 0) g_rowTap = t.row;
    else pushKey(t.key);
    return;
  }
  if (g_list.active && y >= g_list.top && y < g_list.bottom) {
    const int32_t row = ((int32_t)y - g_list.top + g_scroll[g_screen]) / g_list.rowH;
    if (row >= 0 && (size_t)row < g_list.count) g_rowTap = (int)row;
  }
}

}  // namespace

void frameBegin(uint8_t screen) {
  g_targetCount = 0;
  g_list.active = false;
  g_lines.active = false;
  g_screen = screen % kScreens;
}

void addKey(int16_t x, int16_t y, int16_t w, int16_t h, char key) {
  addTarget(x, y, w, h, key, -1);
}

void addRow(int16_t x, int16_t y, int16_t w, int16_t h, int row) {
  addTarget(x, y, w, h, 0, (int16_t)row);
}

int16_t list(int16_t top, int16_t bottom, int16_t rowH, size_t count) {
  if (rowH < 1) rowH = 1;
  g_list.active = true;
  g_list.top = top;
  g_list.bottom = bottom;
  g_list.rowH = rowH;
  g_list.count = count;
  int32_t maxScroll = (int32_t)count * rowH - (bottom - top);
  if (maxScroll < 0) maxScroll = 0;
  int16_t& s = g_scroll[g_screen];
  if (s > maxScroll) s = (int16_t)maxScroll;
  if (s < 0) s = 0;
  return s;
}

void lines(int16_t top, int16_t bottom, int16_t lineH) {
  g_lines.active = true;
  g_lines.top = top;
  g_lines.bottom = bottom;
  g_lines.lineH = lineH < 1 ? 1 : lineH;
}

bool takeRowTap(int& row) {
  if (g_rowTap < 0) return false;
  row = g_rowTap;
  g_rowTap = -1;
  return true;
}

char takeKey() {
  if (g_keyCount == 0) return 0;
  const char k = g_keys[g_keyHead];
  g_keyHead = (g_keyHead + 1) % kKeyQueue;
  --g_keyCount;
  return k;
}

void feed(bool down, int16_t x, int16_t y) {
  if (down && !g_down) {
    g_down = true;
    g_drag = false;
    g_x0 = x;
    g_y0 = g_lastY = y;
    g_lineAcc = 0;
    if (g_list.active && y >= g_list.top && y < g_list.bottom) g_area = Area::List;
    else if (g_lines.active && y >= g_lines.top && y < g_lines.bottom) g_area = Area::Lines;
    else g_area = Area::None;
    return;
  }
  if (down) {
    if (!g_drag && g_area != Area::None && abs(y - g_y0) >= kDragStart) g_drag = true;
    if (g_drag) {
      const int16_t dy = y - g_lastY;
      g_lastY = y;
      if (g_area == Area::List) {
        // Content follows the finger; list() clamps the far end next frame.
        int32_t s = (int32_t)g_scroll[g_screen] - dy;
        if (s < 0) s = 0;
        if (s > INT16_MAX) s = INT16_MAX;
        g_scroll[g_screen] = (int16_t)s;
      } else if (g_lines.active) {
        g_lineAcc += dy;
        while (g_lineAcc <= -g_lines.lineH) { pushKey('.'); g_lineAcc += g_lines.lineH; }
        while (g_lineAcc >= g_lines.lineH)  { pushKey(';'); g_lineAcc -= g_lines.lineH; }
      }
    }
    return;
  }
  if (g_down) {
    g_down = false;
    if (!g_drag) tap(g_x0, g_y0);
  }
}

}  // namespace touchui

#endif  // CHIMERA_TOUCH_UI
