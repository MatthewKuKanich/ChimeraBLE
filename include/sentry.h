// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#pragma once

#include <Arduino.h>
#include <string>
#include <vector>

#include "scanner.h"

namespace fs { class FS; }   // forward-decl so includers don't need <FS.h>

// Sentry - passive detection / alert watchlist.
//
// Holds a list of rules describing devices to watch for. A continuous (repeated)
// scan checks every advertisement against the enabled rules; the UI alerts on a
// match. Matching uses ONLY what's in the advertisement (no connection), so the
// supported attributes are MAC, OUI, manufacturer Company ID, advertised Service
// UUID, and local Name. (GATT characteristics aren't advertised, so they can't
// be matched passively - Service UUID is the advertised stand-in.)
//
// Rules persist as JSON on the storage backend (SD if present, else LittleFS),
// mirroring clone's pattern.
namespace sentry {

enum class MatchType : uint8_t { Mac, Oui, Company, Service, Name };

struct Rule {
  std::string label;
  MatchType   type = MatchType::Mac;
  std::vector<std::string> values;   // normalized tokens; matches if ANY matches
  bool        enabled = true;
};

// Storage backend (defaults to LittleFS; the app points it at SD when present).
// Call before load().
void setStorage(fs::FS* fs, const char* dir);

bool load();   // read rules from <dir>/sentry.json (ok if absent)
bool save();   // write rules

const std::vector<Rule>& rules();
bool   addRule(const Rule& r);          // append + save
bool   removeRule(size_t i);            // erase + save
bool   setEnabled(size_t i, bool on);   // toggle + save
size_t enabledCount();

const char* typeName(MatchType t);      // "MAC" / "OUI" / "Company" / "Service" / "Name"

// Matching: does any ENABLED rule match this advertisement?
struct Hit { int ruleIndex = -1; std::string reason; };
bool check(const scanner::Result& r, Hit& out);

// "Add from scan": the matchable attributes present in a scanned device, each
// ready to become a one-value rule. display is a human label for the picker.
struct Attr { MatchType type; std::string value; std::string display; };
std::vector<Attr> attributesOf(const scanner::Result& r);

// Build a rule from manual text entry: split value(s) on space/comma, normalize
// per type, and synthesize a default label. Returns false if no usable value.
bool makeRule(MatchType t, const std::string& rawValues, Rule& out);

}
