// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#include "sentry.h"

#include <ArduinoJson.h>
#include <LittleFS.h>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "uuid_db.h"

namespace sentry {

namespace {

constexpr const char* kDir = "/sentry";

fs::FS*     g_fs  = &LittleFS;
std::string g_dir = kDir;
std::vector<Rule> g_rules;

std::string pathFor() { return g_dir + "/sentry.json"; }

// ---- small string helpers ----

std::string lower(const std::string& s) {
  std::string o = s;
  for (auto& c : o) c = (char)tolower((unsigned char)c);
  return o;
}

std::vector<std::string> splitTokens(const std::string& s) {
  std::vector<std::string> out;
  std::string cur;
  for (char c : s) {
    if (c == ' ' || c == ',' || c == ';' || c == '\t') {
      if (!cur.empty()) { out.push_back(cur); cur.clear(); }
    } else {
      cur += c;
    }
  }
  if (!cur.empty()) out.push_back(cur);
  return out;
}

template <typename T>
std::vector<T> uniq(const std::vector<T>& in) {
  std::vector<T> out;
  for (const auto& v : in) {
    bool seen = false;
    for (const auto& o : out) if (o == v) { seen = true; break; }
    if (!seen) out.push_back(v);
  }
  return out;
}

// 16 little-endian bytes -> canonical lowercase UUID string.
std::string uuid128le(const uint8_t* b) {
  char s[37];
  snprintf(s, sizeof(s),
           "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
           b[15], b[14], b[13], b[12], b[11], b[10], b[9], b[8],
           b[7], b[6], b[5], b[4], b[3], b[2], b[1], b[0]);
  return s;
}

// Walk AD records, collecting manufacturer Company IDs (0xFF) and Service UUIDs
// (0x02/03 16-bit, 0x04/05 32-bit, 0x06/07 128-bit). Either out-ptr may be null.
void scanAd(const std::vector<uint8_t>& b,
            std::vector<std::string>* companies,
            std::vector<std::string>* services) {
  size_t i = 0;
  while (i + 1 < b.size()) {
    uint8_t len = b[i];
    if (len == 0) break;
    if (i + 1 + len > b.size()) break;   // truncated record
    uint8_t type = b[i + 1];
    const uint8_t* d = &b[i + 2];
    uint8_t dlen = len - 1;
    char buf[40];
    switch (type) {
      case 0xFF:
        if (companies && dlen >= 2) {
          snprintf(buf, sizeof(buf), "%04X", (unsigned)(d[0] | (d[1] << 8)));
          companies->push_back(buf);
        }
        break;
      case 0x02: case 0x03:
        if (services)
          for (uint8_t k = 0; k + 1 < dlen; k += 2) {
            snprintf(buf, sizeof(buf), "%04x", (unsigned)(d[k] | (d[k + 1] << 8)));
            services->push_back(buf);
          }
        break;
      case 0x04: case 0x05:
        if (services)
          for (uint8_t k = 0; k + 3 < dlen; k += 4) {
            snprintf(buf, sizeof(buf), "%08lx",
                     (unsigned long)(d[k] | (d[k + 1] << 8) | (d[k + 2] << 16) |
                                     ((uint32_t)d[k + 3] << 24)));
            services->push_back(buf);
          }
        break;
      case 0x06: case 0x07:
        if (services)
          for (uint8_t k = 0; k + 15 < dlen; k += 16) services->push_back(uuid128le(&d[k]));
        break;
      default: break;
    }
    i += 1 + len;
  }
}

bool inList(const std::vector<std::string>& vals, const std::string& x) {
  for (const auto& v : vals) if (v == x) return true;
  return false;
}

// Normalize a user/scan token to the stored form for its match type.
std::string normalize(MatchType t, const std::string& raw) {
  std::string s = raw;
  switch (t) {
    case MatchType::Mac:
    case MatchType::Oui: {
      std::string hex;
      for (char c : s) if (isxdigit((unsigned char)c)) hex += (char)tolower((unsigned char)c);
      size_t want = (t == MatchType::Oui) ? 6 : 12;
      if (hex.size() < want) return "";
      hex = hex.substr(0, want);
      std::string out;
      for (size_t i = 0; i < hex.size(); i += 2) {
        if (i) out += ':';
        out += hex.substr(i, 2);
      }
      return out;
    }
    case MatchType::Company: {
      if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) s = s.substr(2);
      char* end = nullptr;
      long v = strtol(s.c_str(), &end, 16);
      if (end == s.c_str() || v < 0 || v > 0xFFFF) return "";
      char b[8]; snprintf(b, sizeof(b), "%04X", (unsigned)v);
      return b;
    }
    case MatchType::Service: {
      if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) s = s.substr(2);
      s = lower(s);
      bool hasDash = s.find('-') != std::string::npos;
      if (hasDash) return s;                    // 128-bit UUID as typed
      char* end = nullptr;
      unsigned long v = strtoul(s.c_str(), &end, 16);
      if (end == s.c_str()) return "";
      char b[12];
      snprintf(b, sizeof(b), (s.size() <= 4) ? "%04lx" : "%08lx", v);
      return b;
    }
    case MatchType::Name: {
      while (!s.empty() && isspace((unsigned char)s.front())) s.erase(s.begin());
      while (!s.empty() && isspace((unsigned char)s.back())) s.pop_back();
      return s;
    }
  }
  return "";
}

const char* typeKey(MatchType t) {
  switch (t) {
    case MatchType::Mac:     return "mac";
    case MatchType::Oui:     return "oui";
    case MatchType::Company: return "company";
    case MatchType::Service: return "service";
    case MatchType::Name:    return "name";
  }
  return "mac";
}

MatchType typeFromKey(const char* k) {
  if (!k) return MatchType::Mac;
  if (!strcmp(k, "oui"))     return MatchType::Oui;
  if (!strcmp(k, "company")) return MatchType::Company;
  if (!strcmp(k, "service")) return MatchType::Service;
  if (!strcmp(k, "name"))    return MatchType::Name;
  return MatchType::Mac;
}

}  // namespace

void setStorage(fs::FS* fs, const char* dir) {
  if (!fs) return;
  g_fs  = fs;
  g_dir = (dir && *dir) ? dir : kDir;
  if (!g_fs->exists(g_dir.c_str())) g_fs->mkdir(g_dir.c_str());
}

const char* typeName(MatchType t) {
  switch (t) {
    case MatchType::Mac:     return "MAC";
    case MatchType::Oui:     return "OUI";
    case MatchType::Company: return "Company";
    case MatchType::Service: return "Service";
    case MatchType::Name:    return "Name";
  }
  return "?";
}

const std::vector<Rule>& rules() { return g_rules; }
size_t enabledCount() {
  size_t n = 0;
  for (const auto& r : g_rules) if (r.enabled) n++;
  return n;
}

bool load() {
  g_rules.clear();
  std::string path = pathFor();
  if (!g_fs->exists(path.c_str())) return true;   // none yet is fine
  File f = g_fs->open(path.c_str(), "r");
  if (!f) return false;
  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, f);
  f.close();
  if (err) { Serial.printf("[sentry] parse error: %s\n", err.c_str()); return false; }
  for (JsonObject jr : doc["rules"].as<JsonArray>()) {
    Rule r;
    r.label   = (const char*)(jr["label"] | "");
    r.type    = typeFromKey(jr["type"] | "mac");
    r.enabled = jr["enabled"] | true;
    for (JsonVariant v : jr["values"].as<JsonArray>()) r.values.push_back((const char*)(v | ""));
    if (!r.values.empty()) g_rules.push_back(std::move(r));
  }
  Serial.printf("[sentry] loaded %u rules\n", (unsigned)g_rules.size());
  return true;
}

bool save() {
  JsonDocument doc;
  JsonArray jrules = doc["rules"].to<JsonArray>();
  for (const auto& r : g_rules) {
    JsonObject jr = jrules.add<JsonObject>();
    jr["label"]   = r.label;
    jr["type"]    = typeKey(r.type);
    jr["enabled"] = r.enabled;
    JsonArray jv = jr["values"].to<JsonArray>();
    for (const auto& v : r.values) jv.add(v);
  }
  std::string path = pathFor();
  File f = g_fs->open(path.c_str(), "w");
  if (!f) { Serial.printf("[sentry] cannot write %s\n", path.c_str()); return false; }
  serializeJsonPretty(doc, f);
  f.close();
  return true;
}

bool addRule(const Rule& r) {
  if (r.values.empty()) return false;
  g_rules.push_back(r);
  return save();
}

bool removeRule(size_t i) {
  if (i >= g_rules.size()) return false;
  g_rules.erase(g_rules.begin() + i);
  return save();
}

bool setEnabled(size_t i, bool on) {
  if (i >= g_rules.size()) return false;
  g_rules[i].enabled = on;
  return save();
}

bool check(const scanner::Result& r, Hit& out) {
  if (g_rules.empty()) return false;
  std::string mac = lower(r.addr);
  std::string oui = mac.size() >= 8 ? mac.substr(0, 8) : mac;
  std::string nameLower = lower(r.name);
  std::vector<std::string> companies, services;
  bool parsed = false;

  for (size_t i = 0; i < g_rules.size(); ++i) {
    const Rule& rule = g_rules[i];
    if (!rule.enabled || rule.values.empty()) continue;
    bool hit = false;
    std::string reason;
    switch (rule.type) {
      case MatchType::Mac:
        if (inList(rule.values, mac)) { hit = true; reason = "MAC " + mac; }
        break;
      case MatchType::Oui:
        if (r.addr_type == 0 && inList(rule.values, oui)) { hit = true; reason = "OUI " + oui; }
        break;
      case MatchType::Company:
        if (!parsed) { scanAd(r.adv_payload, &companies, &services);
                       scanAd(r.scan_response, &companies, &services); parsed = true; }
        for (const auto& c : companies)
          if (inList(rule.values, c)) { hit = true; reason = "Company 0x" + c; break; }
        break;
      case MatchType::Service:
        if (!parsed) { scanAd(r.adv_payload, &companies, &services);
                       scanAd(r.scan_response, &companies, &services); parsed = true; }
        for (const auto& s : services)
          if (inList(rule.values, s)) { hit = true; reason = "Service 0x" + s; break; }
        break;
      case MatchType::Name:
        for (const auto& v : rule.values)
          if (!v.empty() && nameLower.find(lower(v)) != std::string::npos) {
            hit = true; reason = "Name ~ " + v; break;
          }
        break;
    }
    if (hit) { out.ruleIndex = (int)i; out.reason = reason; return true; }
  }
  return false;
}

std::vector<Attr> attributesOf(const scanner::Result& r) {
  std::vector<Attr> out;
  std::string mac = lower(r.addr);
  out.push_back({MatchType::Mac, mac, "MAC " + mac});
  if (r.addr_type == 0 && mac.size() >= 8)
    out.push_back({MatchType::Oui, mac.substr(0, 8), "OUI " + mac.substr(0, 8)});

  std::vector<std::string> companies, services;
  scanAd(r.adv_payload, &companies, &services);
  scanAd(r.scan_response, &companies, &services);

  for (const auto& c : uniq(companies)) {
    std::string disp = "Company 0x" + c;
    const char* nm = uuid_db::companyName((uint16_t)strtol(c.c_str(), nullptr, 16));
    if (nm) disp += std::string(" (") + nm + ")";
    out.push_back({MatchType::Company, c, disp});
  }
  for (const auto& s : uniq(services)) {
    std::string disp = (s.size() <= 4) ? "Service 0x" + s : "Service " + s;
    if (s.size() == 4) {
      const char* nm = uuid_db::serviceName((uint16_t)strtol(s.c_str(), nullptr, 16));
      if (nm) disp += std::string(" (") + nm + ")";
    }
    out.push_back({MatchType::Service, s, disp});
  }
  if (!r.name.empty()) out.push_back({MatchType::Name, r.name, "Name '" + r.name + "'"});
  return out;
}

bool makeRule(MatchType t, const std::string& rawValues, Rule& out) {
  Rule r;
  r.type = t;
  r.enabled = true;
  for (const auto& tok : splitTokens(rawValues)) {
    std::string n = normalize(t, tok);
    if (!n.empty() && !inList(r.values, n)) r.values.push_back(n);
  }
  if (r.values.empty()) return false;
  r.label = std::string(typeName(t)) + " " + r.values[0];
  if (r.values.size() > 1) r.label += " +" + std::to_string(r.values.size() - 1);
  out = std::move(r);
  return true;
}

}  // namespace sentry
