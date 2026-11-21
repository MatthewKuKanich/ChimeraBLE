// SPDX-License-Identifier: GPL-3.0-or-later
//
// Touch input for the on-device UI (CHIMERA_TOUCH_UI builds).
//
// The renderer declares, every frame, what can be touched; the board layer
// feeds raw touch samples; gestures come out as the events the App already
// understands:
//
//   tap on a key target   -> that key press (Enter, Backspace or a character)
//   tap on a row          -> takeRowTap(): the App selects and opens that row
//   drag on a list        -> the list scrolls (position kept per screen)
//   drag on a text area   -> up/down key presses, one per line dragged
//
// All coordinates are logical canvas pixels.
#pragma once

#include <stddef.h>
#include <stdint.h>

namespace touchui {

constexpr char kEnter = '\n';
constexpr char kBackspace = '\b';

// Start a frame: forget the previous frame's targets. `screen` names the scroll
// position that list() uses (one remembered position per screen).
void frameBegin(uint8_t screen);

// A tap inside the rectangle presses `key`.
void addKey(int16_t x, int16_t y, int16_t w, int16_t h, char key);

// A tap inside the rectangle opens row `row`.
void addRow(int16_t x, int16_t y, int16_t w, int16_t h, int row);

// A list of `count` rows of height `rowH` shown between top and bottom. Drag to
// scroll, tap a row to open it. Returns the scroll position in pixels, clamped
// to the list's length.
int16_t list(int16_t top, int16_t bottom, int16_t rowH, size_t count);

// A text area scrolled a line at a time by the App: a drag presses the up (';')
// or down ('.') key once per `lineH` moved.
void lines(int16_t top, int16_t bottom, int16_t lineH);

// True once per tapped row.
bool takeRowTap(int& row);

// Board layer: one touch sample per poll (down = finger on the glass).
void feed(bool down, int16_t x, int16_t y);

// Board layer: next queued key press, or 0.
char takeKey();

}  // namespace touchui
