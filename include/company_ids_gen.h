// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Matthew Kukanich

#pragma once
#include <stdint.h>

// Auto-generated from the Bluetooth SIG company identifiers
// (NordicSemiconductor/bluetooth-numbers-database company_ids.json).
// Sorted by code ascending for binary search. Do not edit by hand.

struct CompanyId { uint16_t code; const char* name; };
extern const CompanyId COMPANY_IDS[];
extern const unsigned COMPANY_IDS_COUNT;
