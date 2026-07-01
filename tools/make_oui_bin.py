#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Matthew Kukanich
"""
Generate oui.bin - the sorted, seek-searchable IEEE OUI (MA-L /24) -> vendor
database read at runtime by src/oui_db.cpp.

Source of truth: Wireshark's `manuf` registry (tab-separated, derived from the
official IEEE registries). Only MA-L /24 assignments are kept (the 3-byte OUI
prefixes); the longer MA-M /28 and MA-S /36 blocks are skipped - BLE vendor
attribution works at the /24 level.

Usage:
    tools/make_oui_bin.py [manuf_path] [-o oui.bin]

  manuf_path   path to a Wireshark `manuf` file. If omitted, it is downloaded
               from https://www.wireshark.org/download/automated/data/manuf
  -o           output path (default: data/oui.bin)

Then put the result in the /ChimeraBLE folder on the SD card (Cardputer) and/or
in data/ for the serial CLI builds' LittleFS image (`pio run -t uploadfs`).

--------------------------------------------------------------------------------
ON-DISK FORMAT  (all integers little-endian)
--------------------------------------------------------------------------------
  offset 0 : magic   "OUI2"                      4 bytes
  offset 4 : count   uint32                      4 bytes  (number of OUI records)
  offset 8 : index   count * record, sorted ascending by oui24:
                 oui[3]   the 24-bit OUI as bytes [b0,b1,b2] little-endian,
                          i.e. value = b0 | b1<<8 | b2<<16, where for OUI
                          AA:BB:CC the value is 0xAABBCC
                 off[3]   uint24 little-endian byte offset of the vendor name
                          within the names blob
             -> a record is 6 bytes, so record i is at file offset 8 + i*6,
                enabling a pure binary search with seek()+read(6).
  names blob : starts at offset 8 + count*6; concatenated NUL-terminated UTF-8
               vendor strings. De-duplicated: identical names are stored once and
               multiple index records point at the same offset.
--------------------------------------------------------------------------------
"""

import os
import struct
import sys
import urllib.request

MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"


def load_manuf(path):
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()
    print(f"[oui] downloading manuf from {MANUF_URL} ...", file=sys.stderr)
    with urllib.request.urlopen(MANUF_URL) as r:
        return r.read().decode("utf-8", "replace").splitlines()


def parse_ouis(lines):
    """Return {oui24:int -> vendor:str} for MA-L /24 entries only."""
    out = {}
    for line in lines:
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        cols = line.split("\t")
        if len(cols) < 2:
            continue
        prefix = cols[0].strip()
        # Skip MA-M / MA-S blocks (e.g. "8C:1F:64:00:00:00/28") - /24 only.
        if "/" in prefix:
            continue
        hexes = prefix.split(":")
        if len(hexes) != 3:
            continue
        try:
            b = [int(h, 16) for h in hexes]
        except ValueError:
            continue
        oui24 = (b[0] << 16) | (b[1] << 8) | b[2]
        # Prefer the long name (col 2) when present, else the short name (col 1).
        name = (cols[2].strip() if len(cols) >= 3 and cols[2].strip() else cols[1].strip())
        if name:
            out[oui24] = name
    return out


def build(ouis):
    """Pack {oui24 -> name} into the OUI2 binary blob (bytes)."""
    # De-duplicate names into a single blob; remember each name's offset.
    names = bytearray()
    name_off = {}

    def offset_of(name):
        if name not in name_off:
            name_off[name] = len(names)
            names.extend(name.encode("utf-8"))
            names.append(0)  # NUL terminator
        return name_off[name]

    items = sorted(ouis.items())  # ascending by oui24 -> binary-searchable index
    index = bytearray()
    for oui24, name in items:
        off = offset_of(name)
        if off > 0xFFFFFF:
            raise SystemExit("[oui] names blob exceeds 16 MB (uint24 offset overflow)")
        index += struct.pack("<I", oui24)[:3]   # oui[3] LE
        index += struct.pack("<I", off)[:3]      # off[3] LE

    out = bytearray()
    out += b"OUI2"
    out += struct.pack("<I", len(items))
    out += index
    out += names
    return out, len(items), len(names)


def main(argv):
    manuf_path = None
    out_path = os.path.join(os.path.dirname(__file__), "..", "data", "oui.bin")
    i = 0
    args = argv[1:]
    while i < len(args):
        if args[i] == "-o" and i + 1 < len(args):
            out_path = args[i + 1]
            i += 2
        else:
            manuf_path = args[i]
            i += 1

    lines = load_manuf(manuf_path)
    ouis = parse_ouis(lines)
    if not ouis:
        raise SystemExit("[oui] no /24 OUIs parsed - is this a Wireshark manuf file?")
    blob, count, names_len = build(ouis)

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(blob)
    print(f"[oui] wrote {out_path}: {count} OUIs, "
          f"{len(blob)} bytes ({8 + count*6} index + {names_len} names)")


if __name__ == "__main__":
    main(sys.argv)
