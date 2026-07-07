#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Matthew Kukanich
#
# Build every ChimeraBLE release binary into dist/:
#
#   ChimeraBLE_cardputer_merged.bin      full 0x0 image  (M5Stack Cardputer ADV / S3)
#   ChimeraBLE_cardputer_M5Launcher.bin  app-only image  (sideload via the M5 Launcher)
#   ChimeraBLE_esp32dev_merged.bin       full 0x0 image  (ESP32 WROOM)
#   ChimeraBLE_xiao_esp32c5_merged.bin   full 0x0 image  (Seeed XIAO ESP32-C5)
#   oui.bin                              OUI vendor DB    (copy to the Cardputer SD card)
#
# The merged images bundle bootloader + partition table + app + a LittleFS image
# that already contains the OUI database, so they flash in one shot at offset 0x0.
# The serial boards read the OUI DB from that embedded LittleFS; the Cardputer app
# reads it from the SD card, so oui.bin ships standalone too.
#
# Usage:   tools/build_release.sh
# Refresh the OUI DB (re-download Wireshark's manuf):  OUI_REFRESH=1 tools/build_release.sh
#
# Requires network access the first time (to fetch the OUI source) unless
# data/oui.bin already exists.
set -euo pipefail

PROJ="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJ"
DIST="$PROJ/dist"
mkdir -p "$DIST"

PIO="${PIO:-$(command -v pio || echo "$HOME/.local/bin/pio")}"
[ -x "$PIO" ] || { echo "[release] pio not found (set PIO=/path/to/pio)"; exit 1; }

# 1) OUI database. Reused if present so we don't re-download every run; delete
#    data/oui.bin or pass OUI_REFRESH=1 to rebuild it. Must exist before the merged
#    builds so `buildfs` can pack it into each LittleFS image.
if [ "${OUI_REFRESH:-0}" = "1" ] || [ ! -f data/oui.bin ]; then
  echo "[release] generating data/oui.bin (downloads Wireshark manuf) ..."
  python3 tools/make_oui_bin.py
else
  echo "[release] reusing existing data/oui.bin (OUI_REFRESH=1 to refresh)"
fi
cp -f data/oui.bin "$DIST/oui.bin"

# 2) Merged 0x0 images for each board. make_merged_bin.sh runs `pio run` +
#    `pio run -t buildfs`, then esptool merge-bin, writing <env>_merged.bin.
for env in cardputer esp32dev xiao_esp32c5; do
  echo "[release] building merged image: $env ..."
  bash tools/make_merged_bin.sh "$env"
  mv -f "${env}_merged.bin" "$DIST/ChimeraBLE_${env}_merged.bin"
done

# 3) Cardputer app-only image for the M5 Launcher. Reuse the app that step 2 just
#    built for the cardputer env (no extra compile).
cp -f .pio/build/cardputer/firmware.bin "$DIST/ChimeraBLE_cardputer_M5Launcher.bin"

echo ""
echo "[release] done. Release assets in dist/:"
ls -lh "$DIST/ChimeraBLE_cardputer_merged.bin" \
       "$DIST/ChimeraBLE_cardputer_M5Launcher.bin" \
       "$DIST/ChimeraBLE_esp32dev_merged.bin" \
       "$DIST/ChimeraBLE_xiao_esp32c5_merged.bin" \
       "$DIST/oui.bin"
