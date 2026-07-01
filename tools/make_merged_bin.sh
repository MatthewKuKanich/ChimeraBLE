#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Matthew Kukanich
# Build a single merged firmware image (bootloader + partition table + boot_app0
# + app + the LittleFS partition that holds the OUI database) flashable at 0x0.
# Handy for sharing: one file, one flash command, no separate uploadfs step.
#
# Usage:  tools/make_merged_bin.sh [env]      (default env: cardputer)
# Flash:  esptool --chip <chip> write-flash 0x0 <env>_merged.bin
#         (or drop the file at offset 0x0 in any web flasher)
set -euo pipefail

ENV="${1:-cardputer}"
PROJ="$(cd "$(dirname "$0")/.." && pwd)"
# Tool locations. Auto-detected with sensible fallbacks; override any of them via
# the environment if your PlatformIO install differs, e.g.:
#   PIO=/path/to/pio ESPTOOL_PYTHON=/path/to/python tools/make_merged_bin.sh
PIO="${PIO:-$(command -v pio || echo "$HOME/.local/bin/pio")}"
ESPTOOL_PY="${ESPTOOL_PY:-$HOME/.platformio/packages/tool-esptoolpy/esptool.py}"
# esptool needs a Python that has 'intelhex'. A pipx-installed PlatformIO keeps it
# in the pipx venv; a standard install uses ~/.platformio/penv. Try both, then
# fall back to system python3.
if [ -z "${ESPTOOL_PYTHON:-}" ]; then
  for p in "$HOME/.local/pipx/venvs/platformio/bin/python" \
           "$HOME/.platformio/penv/bin/python" \
           "$(command -v python3)"; do
    [ -x "$p" ] && ESPTOOL_PYTHON="$p" && break
  done
fi
[ -x "$PIO" ]         || { echo "[merge] pio not found (set PIO=/path/to/pio)"; exit 1; }
[ -f "$ESPTOOL_PY" ]  || { echo "[merge] esptool.py not found at $ESPTOOL_PY (set ESPTOOL_PY=...)"; exit 1; }
[ -x "$ESPTOOL_PYTHON" ] || { echo "[merge] no usable python for esptool (set ESPTOOL_PYTHON=...)"; exit 1; }
BUILD="$PROJ/.pio/build/$ENV"
BOOT_APP0="$HOME/.platformio/packages/framework-arduinoespressif32/tools/partitions/boot_app0.bin"

# Per-board: chip, bootloader offset (varies by silicon), LittleFS/fs offset.
case "$ENV" in
  esp32dev)      CHIP=esp32;   BOOT_OFF=0x1000; FS_OFF=0x290000 ;;
  xiao_esp32c5)  CHIP=esp32c5; BOOT_OFF=0x2000; FS_OFF=0x290000 ;;
  cardputer)     CHIP=esp32s3; BOOT_OFF=0x0;    FS_OFF=0x670000 ;;
  *) echo "unknown env '$ENV' (esp32dev | xiao_esp32c5 | cardputer)"; exit 1 ;;
esac

echo "[merge] building firmware + filesystem image for $ENV ..."
"$PIO" run -e "$ENV" >/dev/null
"$PIO" run -e "$ENV" -t buildfs >/dev/null

OUT="$PROJ/${ENV}_merged.bin"
echo "[merge] merging (chip=$CHIP, bootloader@$BOOT_OFF, fs@$FS_OFF) ..."
# --flash-mode/freq/size keep: preserve the bootloader header exactly as built
# (re-encoding it is what made an earlier merged image fail to boot).
"$ESPTOOL_PYTHON" "$ESPTOOL_PY" --chip "$CHIP" merge-bin -o "$OUT" \
  --flash-mode keep --flash-freq keep --flash-size keep \
  "$BOOT_OFF"  "$BUILD/bootloader.bin" \
  0x8000       "$BUILD/partitions.bin" \
  0xe000       "$BOOT_APP0" \
  0x10000      "$BUILD/firmware.bin" \
  "$FS_OFF"    "$BUILD/littlefs.bin"

echo "[merge] wrote $OUT ($(du -h "$OUT" | cut -f1))"
echo "[merge] flash with: esptool --chip $CHIP write-flash 0x0 $(basename "$OUT")"
