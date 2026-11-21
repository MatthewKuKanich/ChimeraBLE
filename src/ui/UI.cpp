// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#include "UI.h"

#include <math.h>
#include <string.h>
#include <vector>

#include "clone.h"
#include "connection.h"
#include "fingerprint.h"
#include "gatt.h"
#include "hid_parser.h"
#include "mitm.h"
#include "scanner.h"
#include "uuid_db.h"

// Touch front-end (boards with a touch panel and no keyboard). The renderer
// declares what can be tapped or dragged each frame; see TouchUI.h.
#if defined(CHIMERA_TOUCH_UI)
#include "TouchUI.h"
#define TOUCH_ROW(x, y, w, h, i) touchui::addRow((x), (y), (w), (h), (int)(i))
#define TOUCH_LINES(top, bottom, lineH) touchui::lines((top), (bottom), (lineH))
#else
#define TOUCH_ROW(x, y, w, h, i) ((void)0)
#define TOUCH_LINES(top, bottom, lineH) ((void)0)
#endif

// CP437 arrow glyphs, matching the Cardputer's orange key legends:
//   ; = up (0x18)   . = down (0x19)   / = right (0x1A)   , = left (0x1B)
#define A_UP "\x18"
#define A_DN "\x19"
#define A_RT "\x1A"
#define A_LF "\x1B"

// ChimeraBLE palette - cool dark theme with deep-violet banners (the mythic /
// chimera head) and the orange selection. Banner is the only color that differs
// from the original; everything else is the original cool palette.
namespace {
constexpr uint16_t kBg        = 0x0821;   // cool near-black
constexpr uint16_t kPanel     = 0x1063;   // dark slate (list rows)
constexpr uint16_t kPanelAlt  = 0x18A5;   // lighter slate (alt rows)
constexpr uint16_t kHeader    = 0x4015;   // deep violet banner (header + footer)
constexpr uint16_t kText      = 0xFFFF;   // white
constexpr uint16_t kTextDim   = 0xBDF7;   // light gray
constexpr uint16_t kSelect    = 0xFD20;   // orange selection (kept)
constexpr uint16_t kSelectTxt = 0x0000;   // black text on selection
constexpr uint16_t kAccent    = 0x07FF;   // cyan (tags, service lines)
constexpr uint16_t kBarFill   = 0x07E0;   // green
constexpr uint16_t kBarTrack  = 0x2104;   // empty bar track
// Shown on the About screen (Settings -> About). Bump on each tagged release.
constexpr const char* kAboutVersion = "v1.0.1";

#if defined(CHIMERA_TOUCH_UI)
constexpr int16_t kTouchBarH = 24;   // bottom button bar

// On-screen keyboard state. The shift and page keys are handled by the renderer
// and never reach the App.
constexpr char kKeyPage = 1, kKeyShift = 2;
bool g_kbShown = false;     // the frame on screen is the keyboard
bool g_kbSymbols = false;   // digits/punctuation page
bool g_kbCaps = false;
String g_kbSig;             // what the keyboard frame on screen shows

// Start any frame that is not the keyboard.
void touchFrame(uint8_t id) {
  g_kbShown = false;
  touchui::frameBegin(id);
}

// The one action a screen offers beyond tapping its rows (the keyboard build
// shows these as footer key hints). Returns false when there is none.
bool touchAction(const MenuView& menu, const char*& label, char& key) {
  switch (menu.screen) {
    case MenuScreen::Main:
      label = "Command line";
      key = '\'';
      return true;
    case MenuScreen::Gatt:
      label = gatt::hasCache() ? "Clone" : "Dump";
      key = '/';
      return gatt::hasCache() || connection::isConnected();
    case MenuScreen::DumpView:
      label = "Delete";
      key = 'x';
      return true;
    case MenuScreen::Sentry:
      // Rules follow the three fixed actions; a tapped rule is the selection.
      label = "Delete rule";
      key = 'x';
      return menu.selectedIndex >= 3;
    default:
      return false;
  }
}
#endif
}  // namespace

void UI::begin() {
  auto cfg = M5.config();
  M5Cardputer.begin(cfg, true);
  auto& d = M5Cardputer.Display;
  d.setRotation(1);
  d.setTextSize(1);
  d.setTextColor(kText, kBg);

  canvas_.setPsram(false);   // StampS3 has no PSRAM - keep the sprite in DRAM
  canvas_.setColorDepth(16);
  if (d.width() > 0 && d.height() > 0) {
    canvasReady_ = canvas_.createSprite(d.width(), d.height());
  }
  if (canvasReady_) {
    canvas_.setTextSize(1);
    canvas_.setTextColor(kText, kBg);
  } else {
    d.fillScreen(kBg);
    d.setCursor(4, 4);
    d.print("canvas init failed");
  }
}

void UI::draw(const MenuView& menu, const String& inputBuffer,
              const String* logLines, size_t logHead, size_t logCount) {
  if (!canvasReady_) return;
  const uint32_t now = millis();
  if (now - lastDrawMs_ < kDrawIntervalMs) return;
  lastDrawMs_ = now;

  const int16_t w = canvas_.width();
  const int16_t h = canvas_.height();

#if defined(CHIMERA_TOUCH_UI)
  // No key-hint footer on a touch screen: a screen with an action gets a button
  // bar, the rest use the full height. hc is the height handed to the screen
  // code, chosen so its "h - 18" footer arithmetic ends at the bar (or the edge).
  if (menu.commandMode) {
    drawTouchKeyboard("Command", inputBuffer + "_", false);
    return;
  }
  touchFrame((uint8_t)menu.screen);
  const char* barLabel = nullptr;
  char barKey = 0;
  const bool hasBar = touchAction(menu, barLabel, barKey);
  const int16_t hc = h + 18 - (hasBar ? kTouchBarH : 0);
#else
  const int16_t hc = h;
#endif

  canvas_.fillSprite(kBg);
  canvas_.fillRect(0, 0, w, 20, kHeader);
#if !defined(CHIMERA_TOUCH_UI)
  canvas_.fillRect(0, h - 18, w, 18, kHeader);
#endif

  drawHeader(menu, w);

  switch (menu.screen) {
    case MenuScreen::Main:         drawMenuList(menu, w, hc); break;
    case MenuScreen::ReconMenu:    drawMenuList(menu, w, hc); break;
    case MenuScreen::AdvMenu:      drawMenuList(menu, w, hc); break;
    case MenuScreen::Devices:      drawDevices(menu, w, hc); break;
    case MenuScreen::DeviceDetail: drawDeviceDetail(menu, w, hc); break;
    case MenuScreen::Gatt:         drawGatt(menu, w, hc); break;
    case MenuScreen::HidStream:    drawHidStream(w, hc); break;
    case MenuScreen::Foxhunt:      drawFoxhunt(menu, w, hc); break;
    case MenuScreen::Clone:        drawClone(menu, w, hc); break;
    case MenuScreen::Dumps:        drawDumps(menu, w, hc); break;
    case MenuScreen::DumpView:     drawDumpView(menu, w, hc); break;
    case MenuScreen::Settings:     drawSettings(menu, w, hc); break;
    case MenuScreen::Honeypot:     drawHoneypot(menu, w, hc); break;
    case MenuScreen::Sentry:       drawSentryList(menu, w, hc); break;
    case MenuScreen::SentryPick:   drawSentryList(menu, w, hc); break;
    case MenuScreen::StreamSelect: drawSentryList(menu, w, hc); break;
    case MenuScreen::SentryType:   drawMenuList(menu, w, hc); break;
    case MenuScreen::Alert:        drawAlert(menu, w, hc); break;
    case MenuScreen::About:        drawAbout(menu, w, hc); break;
    case MenuScreen::Logs:         drawLogs(logLines, logHead, logCount, menu.scrollOffset, w, hc); break;
  }

#if defined(CHIMERA_TOUCH_UI)
  canvas_.clearClipRect();
  if (hasBar) {
    canvas_.fillRect(0, h - kTouchBarH, w, kTouchBarH, kHeader);
    drawTouchButton(2, barLabel, barKey, true);
  }
#else
  drawFooter(menu, inputBuffer, w, h);
#endif
  canvas_.pushSprite(&M5Cardputer.Display, 0, 0);
}

#if defined(CHIMERA_TOUCH_UI)
void UI::drawTouchButton(int slot, const char* label, char key, bool primary) {
  const int16_t w = canvas_.width(), h = canvas_.height();
  const int16_t bw = (slot == 2) ? (w - 12) : (w - 18) / 2;
  const int16_t bx = (slot == 1) ? (w - 6 - bw) : 6;
  const int16_t by = h - kTouchBarH + 3, bh = kTouchBarH - 6;
  const uint16_t fill = primary ? kSelect : kPanel;
  canvas_.fillRoundRect(bx, by, bw, bh, 5, fill);
  canvas_.setTextSize(1);
  canvas_.setTextColor(primary ? kSelectTxt : kText, fill);
  canvas_.setCursor(bx + (bw - (int16_t)strlen(label) * 6) / 2, by + (bh - 8) / 2);
  canvas_.print(label);
  // The whole bar half is the target, not just the drawn button.
  const int16_t tx = (slot == 1) ? (w / 2) : 0;
  const int16_t tw = (slot == 2) ? w : (w / 2);
  touchui::addKey(tx, h - kTouchBarH, tw, kTouchBarH, key);
}
#endif

#if defined(CHIMERA_TOUCH_UI)
void UI::drawTouchKeyboard(const char* title, const String& text, bool numeric) {
  if (!canvasReady_) return;
  if (!g_kbShown) { g_kbSymbols = numeric; g_kbCaps = false; }
  const char local = touchui::takeLocal();
  if (local == kKeyPage) g_kbSymbols = !g_kbSymbols;
  else if (local == kKeyShift) g_kbCaps = !g_kbCaps;

  // Prompts are redrawn every loop: skip the work (and keep the frame's key
  // targets) while nothing on it has changed.
  const String sig = String(title) + "\n" + text + (g_kbSymbols ? "S" : "L") + (g_kbCaps ? "C" : "c");
  if (g_kbShown && sig == g_kbSig) return;
  g_kbSig = sig;
  touchui::frameBegin(0xFD);
  g_kbShown = true;

  const int16_t w = canvas_.width();
  canvas_.fillSprite(kBg);
  canvas_.fillRect(0, 0, w, 20, kHeader);
  canvas_.setTextSize(1);
  canvas_.setTextColor(kText, kHeader);
  canvas_.setCursor(6, 6);
  canvas_.print(trimToWidth(String(title), maxCharsForWidth(w - 12, 1)));

  // What has been typed, large; its tail stays in view when it outgrows the box.
  canvas_.fillRoundRect(4, 24, w - 8, 26, 4, kPanel);
  const size_t maxChars = maxCharsForWidth(w - 20, 2);
  const String shown = text.length() > maxChars ? text.substring(text.length() - maxChars) : text;
  canvas_.setTextSize(2);
  canvas_.setTextColor(kText, kPanel);
  canvas_.setCursor(10, 29);
  canvas_.print(shown);

  // Ten 24-px keys across; the second row is inset half a key, the third sits
  // between Shift and Backspace.
  static const char* const kLetters[3] = {"qwertyuiop", "asdfghjkl", "zxcvbnm"};
  static const char* const kSymbols[3] = {"1234567890", "-_:./=+*#", "()!?@',"};
  const char* const* rows = g_kbSymbols ? kSymbols : kLetters;
  const int16_t top = 56, rowH = 26, keyW = 24;

  auto key = [&](int16_t x, int16_t y, int16_t kw, const char* label, char code,
                 uint16_t fill, uint8_t size) {
    canvas_.fillRoundRect(x + 1, y + 1, kw - 2, rowH - 2, 3, fill);
    canvas_.setTextSize(size);
    canvas_.setTextColor(fill == kSelect ? kSelectTxt : kText, fill);
    const int16_t tw = (int16_t)strlen(label) * 6 * size;
    canvas_.setCursor(x + (kw - tw) / 2, y + (rowH - 8 * size) / 2);
    canvas_.print(label);
    touchui::addKey(x, y, kw, rowH, code, true);
  };

  static const int16_t kRowX[3] = {0, 12, 36};
  for (int r = 0; r < 3; ++r) {
    int16_t x = kRowX[r];
    const int16_t y = top + r * rowH;
    for (const char* p = rows[r]; *p; ++p) {
      char c = *p;
      if (!g_kbSymbols && g_kbCaps) c = (char)toupper((unsigned char)c);
      const char label[2] = {c, 0};
      key(x, y, keyW, label, c, kPanelAlt, 2);
      x += keyW;
    }
  }
  const int16_t y3 = top + 2 * rowH, y4 = top + 3 * rowH;
  if (!g_kbSymbols) key(0, y3, 36, "shift", kKeyShift, g_kbCaps ? kSelect : kPanel, 1);
  key(204, y3, 36, "<-", touchui::kBackspace, kPanel, 1);
  key(0, y4, 36, g_kbSymbols ? "abc" : "123", kKeyPage, kPanel, 1);
  key(36, y4, 96, "space", ' ', kPanelAlt, 1);
  key(132, y4, 54, "Cancel", touchui::kCancel, kPanel, 1);
  key(186, y4, 54, "OK", touchui::kEnter, kSelect, 1);

  canvas_.setTextSize(1);
  canvas_.pushSprite(&M5Cardputer.Display, 0, 0);
  lastDrawMs_ = millis();
}
#endif

UI::ListSpan UI::listSpan(const MenuView& menu, size_t count, int rows, int16_t startY,
                          int16_t rowH, int16_t h) {
  ListSpan s;
#if defined(CHIMERA_TOUCH_UI)
  // Drag-scrolled: rows slide under a clip rectangle, so a partly visible row at
  // either end is simply cut off.
  (void)menu;
  (void)rows;
  const int16_t bottom = h - 18;
  const int16_t scroll = touchui::list(startY, bottom, rowH, count);
  s.start = (size_t)(scroll / rowH);
  s.y0 = (int16_t)(startY - scroll % rowH);
  s.end = min(count, s.start + (size_t)((bottom - startY) / rowH) + 2);
  canvas_.setClipRect(0, startY, canvas_.width(), bottom - startY);
#else
  (void)h;
  const size_t cur = (size_t)max(menu.selectedIndex, 0);
  s.start = (cur / (size_t)rows) * (size_t)rows;
  s.end = min(count, s.start + (size_t)rows);
  s.y0 = startY;
#endif
  return s;
}

void UI::message(const char* title, const char* sub, uint8_t subSize, const char* hint) {
  if (!canvasReady_) return;
  if (subSize < 1) subSize = 1;
  const int16_t w = canvas_.width(), h = canvas_.height();
#if defined(CHIMERA_TOUCH_UI)
  // The App words its prompts for a keyboard ("...   Enter=yes  any=no", hint
  // "ESC = stop"). On a touch screen those become buttons: a prompt that names
  // Enter gets Cancel / OK, a wait that names ESC gets Stop, and anything else
  // is dismissed by a tap anywhere. A prompt whose Enter is not a yes/no
  // ("Enter=save", "Enter=ok") is text entry and gets the on-screen keyboard.
  const bool asks = (sub && strstr(sub, "Enter")) || (hint && strstr(hint, "Enter"));
  const bool stoppable = !asks && hint && strstr(hint, "ESC");
  const bool yesNo = (sub && strstr(sub, "Enter=yes")) || (hint && strstr(hint, "Enter=yes"));
  // A passkey prompt ("Enter=ok") is digits only: the keyboard opens on numbers.
  const bool numeric = (sub && strstr(sub, "Enter=ok")) || (hint && strstr(hint, "Enter=ok"));
  String touchSub;
  if (sub) {
    touchSub = sub;
    const int cut = touchSub.indexOf("   Enter");
    if (cut >= 0) touchSub.remove(cut);
    sub = touchSub.c_str();
  }
  if (asks && !yesNo) {
    drawTouchKeyboard(title, touchSub, numeric);
    return;
  }
  touchFrame(0xFF);
  if (asks || stoppable) hint = nullptr;
#endif
  canvas_.fillSprite(kBg);

  // Box grows to fit whichever line is wider (title @ size 2, sub @ subSize,
  // hint @ size 1), clamped to the screen - so a size-2 MAC still fits.
  const int16_t subCharW = 6 * subSize, subCharH = 8 * subSize;
  int16_t needTitle = (int16_t)strlen(title) * 12;
  int16_t needSub   = sub ? (int16_t)strlen(sub) * subCharW : 0;
  int16_t needHint  = hint ? (int16_t)strlen(hint) * 6 : 0;
  int16_t bw = max(max(needTitle, needSub), needHint) + 24;
  if (bw < w - 36) bw = w - 36;
  if (bw > w - 8)  bw = w - 8;
  int16_t bh = sub ? (int16_t)(28 + subCharH + 12) : 40;
  if (hint) bh += 12;
  int16_t bx = (w - bw) / 2, by = (h - bh) / 2;

  canvas_.fillRoundRect(bx, by, bw, bh, 8, kPanel);
  canvas_.drawRoundRect(bx, by, bw, bh, 8, kAccent);
  canvas_.setTextSize(2);
  canvas_.setTextColor(kText, kPanel);
  int16_t tx = bx + (bw - needTitle) / 2; if (tx < bx + 6) tx = bx + 6;
  canvas_.setCursor(tx, by + 8);
  canvas_.print(title);
  if (sub) {
    canvas_.setTextSize(subSize);
    canvas_.setTextColor(kTextDim, kPanel);
    String s = trimToWidth(String(sub), maxCharsForWidth(bw - 12, subSize));
    int16_t sw = (int16_t)s.length() * subCharW;
    int16_t sx = bx + (bw - sw) / 2; if (sx < bx + 6) sx = bx + 6;
    canvas_.setCursor(sx, by + 30);
    canvas_.print(s);
  }
  if (hint) {
    canvas_.setTextSize(1);
    canvas_.setTextColor(kTextDim, kPanel);
    int16_t hw = (int16_t)strlen(hint) * 6;
    int16_t hx = bx + (bw - hw) / 2; if (hx < bx + 6) hx = bx + 6;
    canvas_.setCursor(hx, by + bh - 12);
    canvas_.print(hint);
  }
  canvas_.setTextSize(1);   // restore default for subsequent draws
#if defined(CHIMERA_TOUCH_UI)
  if (asks) {
    canvas_.fillRect(0, h - kTouchBarH, w, kTouchBarH, kHeader);
    drawTouchButton(0, "Cancel", touchui::kBackspace, false);
    drawTouchButton(1, "OK", touchui::kEnter, true);
  } else if (stoppable) {
    canvas_.fillRect(0, h - kTouchBarH, w, kTouchBarH, kHeader);
    drawTouchButton(2, "Stop", '`', false);
  } else {
    touchui::addKey(0, 0, w, h, touchui::kBackspace);
  }
#endif
  canvas_.pushSprite(&M5Cardputer.Display, 0, 0);
  lastDrawMs_ = millis();
}

void UI::drawBattery(int16_t x, int16_t y, int level, bool charging) {
  const int16_t bw = 18, bh = 10;
  uint16_t lvlCol = (level < 0)  ? kTextDim
                  : (level > 50) ? 0x07E0      // green
                  : (level > 20) ? 0xFFE0      // yellow
                                 : 0xF800;     // red
  uint16_t border = charging ? kAccent : lvlCol;   // cyan border while charging
  canvas_.drawRect(x, y, bw, bh, border);
  canvas_.fillRect(x + bw, y + 3, 2, 4, border);   // nub
  if (level >= 0) {
    int fillw = (bw - 2) * level / 100;
    if (fillw > 0) canvas_.fillRect(x + 1, y + 1, fillw, bh - 2, lvlCol);
  }
}

void UI::drawHeader(const MenuView& menu, int16_t w) {
  // Battery gauge pinned to the far right.
  const int16_t batX = w - 24;
  drawBattery(batX, 5, menu.batLevel, menu.batCharging);

  // Compact status tag, right-aligned just left of the gauge.
  String tag;
  if (mitm::active())                tag = "MITM";
  else if (clone::isAdvertising())   tag = "ADV";
  else if (scanner::foxhuntActive()) tag = "FOX";
  else if (scanner::isScanning())    tag = "SCAN";
  else if (connection::isConnected())tag = "CONN";
  else                               tag = String(scanner::results().size()) + "d";
  uint16_t tagCol = (tag == "MITM" || tag == "CONN" || tag == "ADV") ? kAccent : kTextDim;
  int16_t tagX = batX - 6 - (int16_t)tag.length() * 6;
  canvas_.setTextSize(1);
  canvas_.setTextColor(tagCol, kHeader);
  canvas_.setCursor(tagX, 6);
  canvas_.print(tag);

  // Title fills the remaining left space.
  int16_t titleX = 6;
#if defined(CHIMERA_TOUCH_UI)
  // Back button (the keyboard build's left-arrow key) on every screen but the top one.
  if (menu.screen != MenuScreen::Main) {
    canvas_.fillRoundRect(3, 2, 22, 16, 4, kPanel);
    canvas_.setTextColor(kText, kPanel);
    canvas_.setCursor(11, 6);
    canvas_.print("<");
    touchui::addKey(0, 0, 32, 22, ',');
    titleX = 31;
  }
#endif
  canvas_.setTextColor(kText, kHeader);
  canvas_.setCursor(titleX, 6);
  size_t titleChars = maxCharsForWidth(tagX - titleX - 6, 1);
  canvas_.print(trimToWidth(String(menu.title), titleChars));
}

void UI::drawFooter(const MenuView& menu, const String& inputBuffer, int16_t w, int16_t h) {
  canvas_.setTextSize(1);
  if (menu.commandMode) {
    const size_t maxChars = maxCharsForWidth(w - 40, 1);
    String shown = inputBuffer;
    if (shown.length() > maxChars && maxChars > 0) shown = shown.substring(shown.length() - maxChars);
    canvas_.setTextColor(kSelect, kHeader);
    canvas_.setCursor(6, h - 13);
    canvas_.print("CMD> " + shown + "_");
    return;
  }
  const char* hint;
  switch (menu.screen) {
    case MenuScreen::Logs:      hint = A_UP " older  " A_DN " newer  " A_LF " back"; break;
    case MenuScreen::Foxhunt:   hint = A_LF " back   a audio   ' cmd"; break;
    case MenuScreen::Gatt:      hint = gatt::hasCache()
                                    ? A_RT " clone  " A_UP A_DN " scroll  " A_LF " back"
                                    : A_RT " dump  " A_UP A_DN " scroll  " A_LF " back"; break;
    case MenuScreen::HidStream: hint = A_LF " back stops stream  ' cmd"; break;
    case MenuScreen::Clone:     hint = A_UP A_DN " sel  " A_RT " do  " A_LF " back  ' cmd"; break;
    case MenuScreen::Dumps:     hint = A_UP A_DN " sel  " A_RT " view  x del  " A_LF " back"; break;
    case MenuScreen::DumpView:  hint = A_UP A_DN " scroll  x delete  " A_LF " back"; break;
    case MenuScreen::Settings:  hint = A_UP A_DN " sel  " A_RT " change/do  " A_LF " back"; break;
    case MenuScreen::Honeypot:  hint = A_UP A_DN " scroll   " A_LF " back"; break;
    case MenuScreen::Sentry:    hint = A_UP A_DN " sel  " A_RT " do  x del  " A_LF " back"; break;
    case MenuScreen::SentryPick:hint = A_UP A_DN " sel  " A_RT " track  " A_LF " back"; break;
    case MenuScreen::SentryType:hint = A_UP A_DN " sel  " A_RT " pick  " A_LF " back"; break;
    case MenuScreen::StreamSelect:hint = A_UP A_DN " sel  " A_RT " toggle/start  " A_LF " back"; break;
    case MenuScreen::Alert:     hint = A_UP A_DN " sel  " A_RT " do  " A_LF " back"; break;
    case MenuScreen::About:     hint = A_LF " back"; break;
    default:                    hint = A_UP A_DN " move  " A_RT " open  " A_LF " back  ' cmd"; break;
  }
  printHint(6, h - 13, trimToWidth(hint, maxCharsForWidth(w - 8, 1)), kTextDim, kHeader);
}

void UI::printHint(int16_t x, int16_t y, const String& s, uint16_t fg, uint16_t bg) {
  // UTF8 off so bytes 0x18-0x1B render as CP437 arrow glyphs instead of being
  // skipped as control chars; restore UTF8 afterward (device names use it).
  canvas_.setAttribute(lgfx::v1::utf8_switch, 0);
  canvas_.setTextColor(fg, bg);
  canvas_.setTextSize(1);
  canvas_.setCursor(x, y);
  canvas_.print(s);
  canvas_.setAttribute(lgfx::v1::utf8_switch, 1);
}

void UI::drawMenuList(const MenuView& menu, int16_t w, int16_t h) {
  if (!menu.items || menu.itemCount == 0) return;
  constexpr int rows = 4;
  const int16_t rowH = 22;
  const int16_t startY = 24;
  const ListSpan span = listSpan(menu, menu.itemCount, rows, startY, rowH, h);

  for (size_t i = span.start; i < span.end; ++i) {
    const int16_t y = span.y0 + (int16_t)(i - span.start) * rowH;
    const bool sel = (int)i == menu.selectedIndex;
    canvas_.fillRoundRect(6, y, w - 12, rowH - 4, 5, sel ? kSelect : kPanel);
    canvas_.setTextSize(1);
    canvas_.setTextColor(sel ? kSelectTxt : kText, sel ? kSelect : kPanel);
    canvas_.setCursor(12, y + 6);
    canvas_.print(trimToWidth(String(menu.items[i]), maxCharsForWidth(w - 28, 1)));
  }
}

void UI::drawDevices(const MenuView& menu, int16_t w, int16_t h) {
  const auto& devs = scanner::results();
  if (devs.empty()) {
    canvas_.setTextColor(kTextDim, kBg);
    canvas_.setCursor(10, 40);
    canvas_.print(scanner::isScanning() ? "scanning..." : "no devices - Scan first");
    return;
  }
  constexpr int rows = 5;
  const int16_t rowH = 19;
  const int16_t startY = 23;
  const ListSpan span = listSpan(menu, devs.size(), rows, startY, rowH, h);

  for (size_t i = span.start; i < span.end; ++i) {
    const auto& r = devs[i];
    const int16_t y = span.y0 + (int16_t)(i - span.start) * rowH;
    const bool sel = (int)i == menu.selectedIndex;
    canvas_.fillRoundRect(6, y, w - 12, rowH - 3, 4, sel ? kSelect : kPanel);

    String label = r.name.empty()
        ? ("~" + String(fingerprint::identify(r.addr, r.addr_type, r.adv_payload).c_str()))
        : String(r.name.c_str());

    // Color the RSSI by signal strength (green=near, yellow=mid, red=far). The
    // device name stays in the normal/selected color for readability.
    uint16_t rssiCol = (r.rssi >= -65) ? 0x07E0 : (r.rssi >= -80) ? 0xFFE0 : 0xF800;
    canvas_.setTextSize(1);
    char rbuf[6];
    snprintf(rbuf, sizeof(rbuf), "%4d", r.rssi);
    canvas_.setTextColor(sel ? kSelectTxt : rssiCol, sel ? kSelect : kPanel);
    canvas_.setCursor(10, y + 5);
    canvas_.print(rbuf);
    canvas_.setTextColor(sel ? kSelectTxt : kText, sel ? kSelect : kPanel);
    canvas_.setCursor(10 + 5 * 6, y + 5);   // after the 4-char rssi + space
    canvas_.print(trimToWidth(label, maxCharsForWidth(w - 24 - 5 * 6, 1)));
  }
}

void UI::drawDeviceDetail(const MenuView& menu, int16_t w, int16_t h) {
  const auto* r = scanner::findByIndex(menu.selectedDevice);
  int16_t y = 24;
  canvas_.setTextSize(1);
  if (r) {
    canvas_.setTextColor(kAccent, kBg);
    canvas_.setCursor(8, y); canvas_.print(r->addr.c_str()); y += 11;
    canvas_.setTextColor(kText, kBg);
    canvas_.setCursor(8, y);
    canvas_.print(trimToWidth(String("name: ") + (r->name.empty() ? "(none)" : r->name.c_str()),
                              maxCharsForWidth(w - 16, 1))); y += 11;
    canvas_.setCursor(8, y);
    canvas_.print(String("rssi: ") + r->rssi + " dBm"); y += 11;
    canvas_.setTextColor(kTextDim, kBg);
    String guess = fingerprint::identify(r->addr, r->addr_type, r->adv_payload).c_str();
    canvas_.setCursor(8, y);
    canvas_.print(trimToWidth(guess, maxCharsForWidth(w - 16, 1))); y += 13;
  }
  // action buttons
  if (menu.items) {
    for (size_t i = 0; i < menu.itemCount; ++i) {
      const bool sel = (int)i == menu.selectedIndex;
      canvas_.fillRoundRect(6, y, w - 12, 16, 4, sel ? kSelect : kPanelAlt);
      TOUCH_ROW(0, y - 1, w, 18, i);
      canvas_.setTextColor(sel ? kSelectTxt : kText, sel ? kSelect : kPanelAlt);
      canvas_.setCursor(12, y + 4);
      canvas_.print(menu.items[i]);
      y += 18;
    }
  }
}

static String gattUuidShort(const NimBLEUUID& u, const char* (*named)(uint16_t)) {
  if (u.bitSize() == 16) {
    const uint8_t* b = u.getValue();
    uint16_t v = (uint16_t)(b[0] | (b[1] << 8));
    const char* n = named ? named(v) : nullptr;
    char buf[44];
    if (n) snprintf(buf, sizeof(buf), "%04X %s", v, n);
    else   snprintf(buf, sizeof(buf), "0x%04X", v);
    return String(buf);
  }
  return String(u.toString().c_str());
}

void UI::drawGatt(const MenuView& menu, int16_t w, int16_t h) {
  if (!gatt::hasCache()) {
    // printHint renders CP437 arrow glyphs (UTF8 off) so A_RT shows the -> key.
#if defined(CHIMERA_TOUCH_UI)
    printHint(10, 40, connection::isConnected() ? "tap Dump to read this device"
#else
    printHint(10, 40, connection::isConnected() ? "press " A_RT " to dump this device"
#endif
                                                : "not connected - connect first",
              kTextDim, kBg);
    return;
  }
  // Build a flat, scrollable line list: a header line per service, then one per
  // characteristic. Each entry carries its indent + color via a small tag.
  struct Line { String text; bool isSvc; };
  std::vector<Line> lines;
  char pbuf[8];
  for (const auto& svc : gatt::cache()) {
    lines.push_back({String("SVC ") + gattUuidShort(svc.uuid, uuid_db::serviceName), true});
    for (const auto& c : svc.chars) {
      String l = String("0x") + String(c.handle, HEX) + " [" +
                 gatt::propsString(c.props, pbuf, sizeof(pbuf)) + "] " +
                 gattUuidShort(c.uuid, uuid_db::charName);
      // Show a decoded value inline when we have one (battery %, name, etc.).
      if (c.value_cached && !c.value.empty()) {
        std::string dec = gatt::describeValue(c.uuid, c.value.data(), c.value.size());
        if (!dec.empty()) l += String(" =") + dec.c_str();
      }
      lines.push_back({l, false});
    }
  }

  const int16_t top = 23, bottom = h - 20, lineH = 11;
  const int visible = (bottom - top) / lineH;
  TOUCH_LINES(top, bottom, lineH);
  const int total = (int)lines.size();
  const int maxStart = max(0, total - visible);
  int start = menu.scrollOffset;
  if (start > maxStart) start = maxStart;
  if (start < 0) start = 0;

  int16_t y = top;
  for (int i = start; i < total && i < start + visible; ++i) {
    canvas_.setTextColor(lines[i].isSvc ? kAccent : kText, kBg);
    canvas_.setCursor(lines[i].isSvc ? 6 : 12, y);
    canvas_.print(trimToWidth(lines[i].text, maxCharsForWidth(w - (lines[i].isSvc ? 14 : 20), 1)));
    y += lineH;
  }
  // scroll position indicator
  if (total > visible) {
    canvas_.setTextColor(kTextDim, kHeader);
    String pos = String(start + 1) + "-" + String(min(total, start + visible)) + "/" + total;
    canvas_.setCursor(w - 6 * (int)pos.length() - 30, 6);   // left of the battery gauge
    canvas_.print(pos);
  }
}

void UI::drawHidStream(int16_t w, int16_t h) {
  if (!hid_parser::streamActive()) {
    canvas_.setTextColor(kTextDim, kBg);
    canvas_.setCursor(10, 38);
    canvas_.print("not streaming");
    canvas_.setCursor(10, 52);
    canvas_.print("connect + dump a device first");
    return;
  }
  canvas_.setTextColor(kTextDim, kBg);
  canvas_.setCursor(8, 22);
  canvas_.print("live notifications:");

  // One decoded notification per line, newest at the bottom (scrolling log).
  const int total = (int)hid_parser::streamLineCount();
  canvas_.setTextSize(2);
  const size_t maxChars = maxCharsForWidth(w - 14, 2);
  const int16_t top = 38, bottom = h - 20, lineH = 18;
  const int visible = (bottom - top) / lineH;
  const int start = (total > visible) ? (total - visible) : 0;
  int16_t y = top;
  for (int i = start; i < total; ++i) {
    canvas_.setTextColor(kText, kBg);
    canvas_.setCursor(8, y);
    canvas_.print(trimToWidth(String(hid_parser::streamLine(i).c_str()), maxChars));
    y += lineH;
  }
  canvas_.setTextSize(1);
  if (total == 0) {
    canvas_.setTextColor(kTextDim, kBg);
    canvas_.setCursor(8, top);
    canvas_.print("(waiting for notifications...)");
  }
}

void UI::drawClone(const MenuView& menu, int16_t w, int16_t h) {
  // status line: loaded profile + advertising state
  canvas_.setTextSize(1);
  canvas_.setTextColor(kAccent, kBg);
  canvas_.setCursor(8, 23);
  String st;
  if (clone::hasLoaded())
    st = String("loaded: ") + clone::loadedName().c_str() + " (" + clone::loadedServiceCount() + " svc)";
  else if (gatt::hasCache())
    st = "dump ready - Save it below";
  else
    st = "no dump - connect+dump to save";
  if (clone::isAdvertising()) st += " [ADV]";
  canvas_.print(trimToWidth(st, maxCharsForWidth(w - 14, 1)));

  // combined list: fixed actions, then saved profile names
  const int actions = menu.cloneActions;
  const int nameCount = menu.cloneNames ? (int)menu.cloneNames->size() : 0;
  const int total = actions + nameCount;

  const int16_t top = 36, rowH = 15;
  const int visible = max(1, (h - 20 - top) / rowH);
  const int sel = menu.selectedIndex;
  const ListSpan span = listSpan(menu, (size_t)total, visible, top, rowH, h);

  int16_t y = span.y0;
  for (int i = (int)span.start; i < (int)span.end; ++i) {
    const bool isSel = i == sel;
    canvas_.fillRoundRect(6, y, w - 12, rowH - 2, 4, isSel ? kSelect : kPanel);
    canvas_.setTextColor(isSel ? kSelectTxt : kText, isSel ? kSelect : kPanel);
    canvas_.setCursor(11, y + 4);
    String label = (i < actions) ? String(menu.items[i])
                                 : (String("load: ") + (*menu.cloneNames)[i - actions].c_str());
    canvas_.print(trimToWidth(label, maxCharsForWidth(w - 24, 1)));
    y += rowH;
  }
  if (total == actions) {
    canvas_.setTextColor(kTextDim, kBg);
    canvas_.setCursor(8, y + 2);
    canvas_.print("(no saved profiles)");
  }
}

void UI::drawDumps(const MenuView& menu, int16_t w, int16_t h) {
  const auto* files = menu.dumpFiles;
  if (!files || files->empty()) {
    canvas_.setTextColor(kTextDim, kBg);
    canvas_.setCursor(10, 40);
    canvas_.print("no saved dumps");
    return;
  }
  constexpr int rows = 5;
  const int16_t rowH = 19, startY = 23;
  const ListSpan span = listSpan(menu, files->size(), rows, startY, rowH, h);
  for (size_t i = span.start; i < span.end; ++i) {
    const int16_t y = span.y0 + (int16_t)(i - span.start) * rowH;
    const bool sel = (int)i == menu.selectedIndex;
    canvas_.fillRoundRect(6, y, w - 12, rowH - 3, 4, sel ? kSelect : kPanel);
    canvas_.setTextSize(1);
    canvas_.setTextColor(sel ? kSelectTxt : kText, sel ? kSelect : kPanel);
    canvas_.setCursor(10, y + 5);
    canvas_.print(trimToWidth((*files)[i], maxCharsForWidth(w - 24, 1)));
  }
}

void UI::drawSettings(const MenuView& menu, int16_t w, int16_t h) {
  const auto* items = menu.settingsLabels;
  if (!items || items->empty()) return;
  constexpr int rows = 5;
  const int16_t rowH = 20, startY = 24;
  const ListSpan span = listSpan(menu, items->size(), rows, startY, rowH, h);
  for (size_t i = span.start; i < span.end; ++i) {
    const int16_t y = span.y0 + (int16_t)(i - span.start) * rowH;
    const bool sel = (int)i == menu.selectedIndex;
    canvas_.fillRoundRect(6, y, w - 12, rowH - 4, 5, sel ? kSelect : kPanel);
    canvas_.setTextSize(1);
    canvas_.setTextColor(sel ? kSelectTxt : kText, sel ? kSelect : kPanel);
    canvas_.setCursor(12, y + 5);
    canvas_.print(trimToWidth((*items)[i], maxCharsForWidth(w - 80, 1)));
    // little volume bar on the Volume row (it's row 0)
    if (i == 0) {
      const int16_t bx = w - 64, by = y + 4, bw = 52, bh = rowH - 12;
      canvas_.drawRect(bx, by, bw, bh, sel ? kSelectTxt : kTextDim);
      int fw = (bw - 2) * menu.volume / 255;
      if (fw > 0) canvas_.fillRect(bx + 1, by + 1, fw, bh - 2, sel ? kSelectTxt : kBarFill);
    }
  }
}

void UI::drawHoneypot(const MenuView& menu, int16_t w, int16_t h) {
  canvas_.setTextSize(1);

  const auto* lines = menu.honeypotLines;
  const bool haveLines = lines && !lines->empty();
  const bool armed = clone::isAdvertising() || mitm::active();

  // Nothing advertising + no proxy + no host + no history = a dead end: a host
  // can never connect because nothing is exposed. Explain how to arm the honeypot
  // instead of showing a "waiting for host..." that will never resolve. Clears
  // itself once a clone is advertising / a MITM proxy is up / a host connects.
  if (!armed && !menu.honeypotConnected && !haveLines) {
    canvas_.setTextColor(kSelect, kBg);
    canvas_.setCursor(6, 26);
    canvas_.print("Not advertising");
    canvas_.setTextColor(kTextDim, kBg);
    static const char* kHelp[] = {
      "Nothing is advertising, so no host",
      "can connect here yet.",
      "Adversarial -> Clone: save a dump,",
      "load it, then 'Advertise loaded'.",
      "(A MITM proxy also feeds this.)",
    };
    int16_t y = 44;
    for (const char* s : kHelp) {
      canvas_.setCursor(6, y);
      canvas_.print(trimToWidth(String(s), maxCharsForWidth(w - 12, 1)));
      y += 12;
    }
    return;
  }

  // status line: connection + logging state
  canvas_.setTextColor(menu.honeypotConnected ? kBarFill : kTextDim, kBg);
  canvas_.setCursor(6, 23);
  String stat = menu.honeypotConnected ? "HOST CONNECTED" : "waiting for host...";
  if (menu.honeypotLogging) stat += "  [REC]";
  canvas_.print(trimToWidth(stat, maxCharsForWidth(w - 12, 1)));

  if (!haveLines) {
    canvas_.setTextColor(kTextDim, kBg);
    canvas_.setCursor(6, 40);
    canvas_.print("(no events yet)");
    return;
  }
  const int16_t top = 34, bottom = h - 20, lineH = 10;
  const int visible = (bottom - top) / lineH;
  TOUCH_LINES(top, bottom, lineH);
  const int total = (int)lines->size();
  const int maxStart = max(0, total - visible);
  // scrollOffset counts back from the newest (0 = newest), like Logs.
  int start = maxStart - menu.scrollOffset;
  if (start < 0) start = 0;
  if (start > maxStart) start = maxStart;

  int16_t y = top;
  for (int i = start; i < total && i < start + visible; ++i) {
    canvas_.setTextColor(kText, kBg);
    canvas_.setCursor(6, y);
    canvas_.print(trimToWidth((*lines)[i], maxCharsForWidth(w - 12, 1)));
    y += lineH;
  }
}

// Generic paged row list from menu.sentryRows (used by Sentry + SentryPick).
// Rows already carry any markers ([*]/[ ]) and labels.
void UI::drawSentryList(const MenuView& menu, int16_t w, int16_t h) {
  const auto* rows = menu.sentryRows;
  if (!rows || rows->empty()) {
    canvas_.setTextColor(kTextDim, kBg);
    canvas_.setCursor(10, 40);
    const char* msg = menu.screen == MenuScreen::SentryPick   ? "no matchable attributes"
                    : menu.screen == MenuScreen::StreamSelect ? "connect + dump a device first"
                                                              : "no rules - add one";
    canvas_.print(msg);
    return;
  }
  constexpr int visRows = 5;
  const int16_t rowH = 19, startY = 23;
  const ListSpan span = listSpan(menu, rows->size(), visRows, startY, rowH, h);
  for (size_t i = span.start; i < span.end; ++i) {
    const int16_t y = span.y0 + (int16_t)(i - span.start) * rowH;
    const bool sel = (int)i == menu.selectedIndex;
    canvas_.fillRoundRect(6, y, w - 12, rowH - 3, 4, sel ? kSelect : kPanel);
    canvas_.setTextSize(1);
    canvas_.setTextColor(sel ? kSelectTxt : kText, sel ? kSelect : kPanel);
    canvas_.setCursor(10, y + 5);
    canvas_.print(trimToWidth((*rows)[i], maxCharsForWidth(w - 24, 1)));
  }
}

void UI::drawAlert(const MenuView& menu, int16_t w, int16_t h) {
  // Banner-style match readout, then the action options.
  canvas_.setTextSize(2);
  canvas_.setTextColor(kSelect, kBg);
  canvas_.setCursor(8, 24);
  canvas_.print("! MATCH");

  canvas_.setTextSize(1);
  canvas_.setTextColor(kText, kBg);
  canvas_.setCursor(8, 44);
  canvas_.print(trimToWidth(String(menu.alertLabel), maxCharsForWidth(w - 16, 1)));
  canvas_.setTextColor(kAccent, kBg);
  canvas_.setCursor(8, 56);
  canvas_.print(trimToWidth(String(menu.alertReason), maxCharsForWidth(w - 16, 1)));
  canvas_.setTextColor(kTextDim, kBg);
  canvas_.setCursor(8, 68);
  canvas_.print(trimToWidth(String(menu.alertInfo), maxCharsForWidth(w - 16, 1)));

  static const char* kOpts[] = {"Connect", "Foxhunt", "Dismiss"};
  const int16_t boxW = (w - 24) / 3;
  for (int i = 0; i < 3; ++i) {
    const bool sel = i == menu.selectedIndex;
    const int16_t x = 6 + i * (boxW + 3), y = h - 36;
    canvas_.fillRoundRect(x, y, boxW, 14, 4, sel ? kSelect : kPanel);
    TOUCH_ROW(x - 1, y - 6, boxW + 3, 26, i);
    canvas_.setTextColor(sel ? kSelectTxt : kText, sel ? kSelect : kPanel);
    int16_t tw = (int16_t)strlen(kOpts[i]) * 6;
    canvas_.setCursor(x + (boxW - tw) / 2, y + 4);
    canvas_.print(kOpts[i]);
  }
}

void UI::drawAbout(const MenuView& menu, int16_t w, int16_t h) {
  (void)menu;
  (void)h;
  // App title, large + accent, centered.
  canvas_.setTextSize(2);
  canvas_.setTextColor(kAccent, kBg);
  const char* name = "ChimeraBLE";
  canvas_.setCursor((w - (int16_t)strlen(name) * 12) / 2, 26);
  canvas_.print(name);

  // Version, dim, centered under the title.
  canvas_.setTextSize(1);
  canvas_.setTextColor(kTextDim, kBg);
  canvas_.setCursor((w - (int16_t)strlen(kAboutVersion) * 6) / 2, 46);
  canvas_.print(kAboutVersion);

  // Tagline.
  canvas_.setTextColor(kText, kBg);
  const char* tag = "BLE security & RE tool";
  canvas_.setCursor((w - (int16_t)strlen(tag) * 6) / 2, 60);
  canvas_.print(tag);

  // Author.
  const char* author = "by Matthew Kukanich";
  canvas_.setCursor((w - (int16_t)strlen(author) * 6) / 2, 78);
  canvas_.print(author);

  // GitHub (accent), trimmed to width for safety.
  canvas_.setTextColor(kAccent, kBg);
  String gh = trimToWidth(String("github.com/MatthewKuKanich/ChimeraBLE"),
                          maxCharsForWidth(w - 8, 1));
  canvas_.setCursor((w - (int16_t)gh.length() * 6) / 2, 92);
  canvas_.print(gh);

  // License + copyright, dim.
  canvas_.setTextColor(kTextDim, kBg);
  const char* lic = "GPL-3.0-or-later   (c) 2026";
  canvas_.setCursor((w - (int16_t)strlen(lic) * 6) / 2, 106);
  canvas_.print(lic);

  canvas_.setTextSize(1);
}

void UI::drawSplash() {
  if (!canvasReady_) return;
  const int16_t w = canvas_.width();
  canvas_.fillSprite(kBg);

  // Big title (accent), centered.
  canvas_.setTextSize(3);
  canvas_.setTextColor(kAccent, kBg);
  const char* name = "ChimeraBLE";
  canvas_.setCursor((w - (int16_t)strlen(name) * 18) / 2, 32);
  canvas_.print(name);

  // Version.
  canvas_.setTextSize(1);
  canvas_.setTextColor(kTextDim, kBg);
  canvas_.setCursor((w - (int16_t)strlen(kAboutVersion) * 6) / 2, 64);
  canvas_.print(kAboutVersion);

  // Author.
  canvas_.setTextColor(kText, kBg);
  canvas_.setTextSize(2);
  const char* author = "Matthew KuKanich";
  canvas_.setCursor((w - (int16_t)strlen(author) * 12) / 2, 86);
  canvas_.print(author);

  // GitHub (accent), trimmed to width for safety.
  canvas_.setTextSize(1);
  canvas_.setTextColor(kAccent, kBg);
  String gh = trimToWidth(String("github.com/MatthewKuKanich/ChimeraBLE"),
                          maxCharsForWidth(w - 8, 1));
  canvas_.setCursor((w - (int16_t)gh.length() * 6) / 2, 112);
  canvas_.print(gh);

  canvas_.setTextSize(1);
  canvas_.pushSprite(&M5Cardputer.Display, 0, 0);
  lastDrawMs_ = millis();
}

void UI::drawCharging(int level, bool charging, int16_t mv, int32_t ma) {
  if (!canvasReady_) return;
  const int16_t w = canvas_.width(), h = canvas_.height();
#if defined(CHIMERA_TOUCH_UI)
  touchFrame(0xFE);
  touchui::addKey(0, 0, w, h, touchui::kBackspace);
#endif

  // Pure black, no banners - fewest lit pixels. Gentle slow drift (anti burn-in).
  canvas_.fillSprite(0x0000);
  const int16_t ox = (int16_t)((millis() / 30000) % 7) - 3;
  const int16_t oy = (int16_t)((millis() / 41000) % 5) - 2;

  // Big percentage (green while charging, white on battery).
  canvas_.setTextSize(4);
  canvas_.setTextColor(charging ? 0x07E0 : 0xFFFF, 0x0000);
  char pct[8];
  snprintf(pct, sizeof(pct), "%ld%%", (long)(level < 0 ? 0 : level));
  int16_t pw = (int16_t)strlen(pct) * 24;
  canvas_.setCursor((w - pw) / 2 + ox, 30 + oy);
  canvas_.print(pct);

  // Charging state.
  canvas_.setTextSize(2);
  canvas_.setTextColor(charging ? 0x07E0 : 0x8410, 0x0000);
  const char* st = charging ? "CHARGING" : "on battery";
  canvas_.setCursor((w - (int16_t)strlen(st) * 12) / 2 + ox, 74 + oy);
  canvas_.print(st);

  // Voltage / current detail (dim, small).
  canvas_.setTextSize(1);
  canvas_.setTextColor(0x630C, 0x0000);
  char det[40];
  if (mv > 0) snprintf(det, sizeof(det), "%d.%03d V   %ld mA", mv / 1000, mv % 1000, (long)ma);
  else        snprintf(det, sizeof(det), "%ld mA", (long)ma);
  canvas_.setCursor((w - (int16_t)strlen(det) * 6) / 2 + ox, 98 + oy);
  canvas_.print(det);

  canvas_.setTextColor(0x4208, 0x0000);
  const char* hint = "charging mode - press any key to exit";
  canvas_.setCursor((w - (int16_t)strlen(hint) * 6) / 2 + ox, h - 12 + oy);
  canvas_.print(hint);

  canvas_.pushSprite(&M5Cardputer.Display, 0, 0);
  lastDrawMs_ = millis();
}

void UI::drawDumpView(const MenuView& menu, int16_t w, int16_t h) {
  const auto* lines = menu.dumpViewLines;
  // filename as the first body line (header is too cramped now with the gauge)
  canvas_.setTextColor(kAccent, kBg);
  canvas_.setCursor(6, 23);
  canvas_.print(trimToWidth(String(menu.dumpViewName), maxCharsForWidth(w - 12, 1)));

  if (!lines || lines->empty()) {
    canvas_.setTextColor(kTextDim, kBg);
    canvas_.setCursor(10, 40);
    canvas_.print("(empty)");
    return;
  }
  const int16_t top = 34, bottom = h - 20, lineH = 10;   // 34 leaves room for the filename line
  const int visible = (bottom - top) / lineH;
  TOUCH_LINES(top, bottom, lineH);
  const int total = (int)lines->size();
  const int maxStart = max(0, total - visible);
  int start = menu.scrollOffset;
  if (start > maxStart) start = maxStart;
  if (start < 0) start = 0;

  int16_t y = top;
  canvas_.setTextSize(1);
  for (int i = start; i < total && i < start + visible; ++i) {
    canvas_.setTextColor(kText, kBg);
    canvas_.setCursor(6, y);
    canvas_.print(trimToWidth((*lines)[i], maxCharsForWidth(w - 12, 1)));
    y += lineH;
  }
  if (total > visible) {
    canvas_.setTextColor(kTextDim, kHeader);
    String pos = String(start + 1) + "-" + String(min(total, start + visible)) + "/" + total;
    canvas_.setCursor(w - 6 * (int)pos.length() - 30, 6);   // left of the battery gauge
    canvas_.print(pos);
  }
}

void UI::drawFoxhunt(const MenuView& menu, int16_t w, int16_t h) {
  const int rssi = scanner::foxhuntLastRssi();
  const int peak = scanner::foxhuntPeakRssi();
  const bool stale = scanner::foxhuntSinceSeenMs() > 4000;

  // Blended power/dBm fraction (matches the serial bar feel).
  constexpr int hi = -20, lo = -95;
  float fdb = (float)(rssi - lo) / (float)(hi - lo);
  float fpw = (powf(10.f, rssi / 10.f) - powf(10.f, lo / 10.f)) /
              (powf(10.f, hi / 10.f) - powf(10.f, lo / 10.f));
  float frac = 0.5f * fpw + 0.5f * fdb;
  if (rssi <= -127) frac = 0;
  if (frac < 0) frac = 0; if (frac > 1) frac = 1;

  String tgt = scanner::foxhuntName().empty()
      ? String(scanner::foxhuntTarget().c_str())
      : String(scanner::foxhuntName().c_str());
  canvas_.setTextSize(1);
  canvas_.setTextColor(kTextDim, kBg);
  canvas_.setCursor(8, 24);
  canvas_.print(trimToWidth(tgt, maxCharsForWidth(w - 16, 1)));

  // big dBm number
  canvas_.setTextSize(3);
  canvas_.setTextColor(stale ? kTextDim : kText, kBg);
  canvas_.setCursor(8, 38);
  canvas_.print(rssi <= -127 ? String("--") : (String(rssi) + ""));
  canvas_.setTextSize(1);
  canvas_.setCursor(108, 50);
  canvas_.print("dBm");

  // audio (Geiger) state, top-right of the content area
  canvas_.setTextColor(menu.audioOn ? kBarFill : kTextDim, kBg);
  canvas_.setCursor(w - 56, 24);
  canvas_.print(menu.audioOn ? "audio ON" : "audio off");

  // bar
  const int16_t bx = 8, by = 74, bw = w - 16, bh = 18;
  canvas_.fillRoundRect(bx, by, bw, bh, 4, kBarTrack);
  int16_t fill = (int16_t)(frac * (bw - 4));
  if (fill > 0) canvas_.fillRoundRect(bx + 2, by + 2, fill, bh - 4, 3, stale ? kTextDim : kBarFill);

  canvas_.setTextColor(kTextDim, kBg);
  canvas_.setCursor(8, 98);
  String foot = String("peak ") + (peak <= -127 ? String("--") : String(peak)) +
                "  n=" + scanner::foxhuntCount();
  if (stale) foot += "  NO SIG";
  canvas_.print(trimToWidth(foot, maxCharsForWidth(w - 16, 1)));
}

void UI::drawLogs(const String* logLines, size_t logHead, size_t logCount, int scrollOffset,
                  int16_t w, int16_t h) {
  const int16_t top = 24;
  const int16_t bottom = h - 20;
  const int16_t lineH = 10;
  const int maxLines = (bottom - top) / lineH;
  TOUCH_LINES(top, bottom, lineH);
  if (maxLines <= 0 || logCount == 0) {
    canvas_.setTextColor(kTextDim, kBg);
    canvas_.setCursor(10, 40);
    canvas_.print("no logs yet");
    return;
  }
  const size_t visible = (size_t)maxLines;
  const size_t maxStart = (logCount > visible) ? (logCount - visible) : 0;
  size_t start = maxStart;
  if (scrollOffset > 0) {
    const size_t off = (size_t)scrollOffset;
    start = (off < maxStart) ? (maxStart - off) : 0;
  }
  const size_t end = min(logCount, start + visible);

  int16_t y = top;
  canvas_.setTextSize(1);
  for (size_t i = start; i < end; ++i) {
    const size_t ring = (logHead + i) % kLogCapacity;
    canvas_.setTextColor(kText, kBg);
    canvas_.setCursor(6, y);
    canvas_.print(trimToWidth(logLines[ring], maxCharsForWidth(w - 12, 1)));
    y += lineH;
  }
}

String UI::trimToWidth(const String& text, size_t maxChars) const {
  if (text.length() <= maxChars) return text;
  if (maxChars <= 3) return text.substring(0, maxChars);
  return text.substring(0, maxChars - 3) + "...";
}

size_t UI::maxCharsForWidth(int16_t pixelWidth, uint8_t textSize) const {
  if (pixelWidth <= 0 || textSize == 0) return 1;
  const int16_t cw = (int16_t)(6 * textSize);
  return (size_t)max<int16_t>(1, pixelWidth / cw);
}
