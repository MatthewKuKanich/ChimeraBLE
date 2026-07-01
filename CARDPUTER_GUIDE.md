# ChimeraBLE - Cardputer Quick Guide

A handheld, multi-headed BLE security tool. Scan for Bluetooth LE devices,
inspect them, clone them, sniff HID, direction-find, and proxy traffic. Named
for the chimera: one tool that speaks BLE as Host, Peripheral, and MITM (both at
once).

> **SD card.** Insert a microSD card. ChimeraBLE keeps everything it writes in a
> single `/ChimeraBLE` folder on the card (clone profiles, Sentry rules, device
> dumps, and honeypot/MITM logs) so it never litters the card's root. The folder
> is created automatically on first launch; you can also make `/ChimeraBLE`
> yourself beforehand. For MAC-vendor names, put `oui.bin` inside it (so
> `/ChimeraBLE/oui.bin`) - optional; without it, vendor names are just disabled.
> The card is required when running ChimeraBLE sideloaded from the M5 launcher.

---

## Controls

The Cardputer has no real arrow keys, so navigation uses the marked keys:

| Key | Action |
|---|---|
| `;` | Up - move selection up / scroll up |
| `.` | Down - move selection down / scroll down |
| `,` | Left - back / go up a screen |
| `/` | Right - open / select / confirm |
| `Enter` | Select / confirm (same as Right) |
| `Del` / `Backspace` | Back (or delete a character in Command mode) |
| `'` | Open the Command line (type a CLI command) |
| `` ` `` (top-left) | ESC: opens the action menu on Main (see below); also cancels a hanging "Connecting..." popup |

> Tip: most screens show key hints along the bottom.

---

## Main menu

Move with up/down, open with Right/Enter, and back out one level with Left/Del.
The menu has five entries: **Scan**, two categories, **Sentry**, and
**Settings**.

### Scan

Start a BLE scan. While **Scan** is highlighted you can **type a number**
(seconds) to set the scan duration, then press Right/Enter to start. Found
devices stream in live, sorted by signal strength (RSSI), and you land on the
Devices list.

### Recon & Analysis

Passive inspection tools (the "Host" head):

- **Devices** - the list of devices from the last scan. Shows the name (or a
  best-guess for unnamed devices) plus a color-coded RSSI. The highlight stays
  pinned to a device as the list re-sorts during a live scan, so it won't slide
  onto a neighbor. Select one to open its actions:
  - **Connect** - connect, then dump on the GATT screen. Pairs only if the
    device requests it (toggle **Settings -> Auto-pair** to force it). Press
    ESC to abort if the "Connecting..." popup hangs.
  - **Foxhunt / Track** - signal-strength hunt for this device.
  - **MITM proxy** - man-in-the-middle this device.
- **GATT** - services and characteristics of the connected (or last-dumped)
  device, decoded where known. Scroll with up/down. Right/Enter **dumps** the
  device the first time; once a dump exists, Right/Enter **saves it as a clone
  profile** (type a name, then optionally advertise - see Clone). To re-dump,
  use the Command line (`'` then `dump`).
- **Live Stream** - live decode of notifications from a connected + dumped
  device, one per line: HID keyboards (keystrokes), Heart Rate ("HR 72 bpm",
  updates live), Battery, or any other notify characteristic (raw hex). Opening
  it first shows a picker - toggle which notifications you want with Enter, then
  choose "Start streaming". Connect + dump first.
- **Saved Dumps** - browse device dumps saved to the microSD card. Select one to
  view it; press `x` to delete (asks to confirm).

### Adversarial

Active tools (the "Peripheral" + "MITM" heads):

- **Clone** - save the current dump as a clone profile, then advertise as that
  device.
  - **Save current dump...** - type a name and press Enter to save the profile.
    (Connect + dump a device first; with no dump it tells you.)
  - **Advertise loaded** - broadcast as the loaded profile (reboots to spoof the
    target MAC).
  - **Stop advertising** - stop broadcasting.
  - Saved profiles are listed below the actions; select one to load it. The list
    auto-refreshes after a save.

  After a save (from here or from the GATT screen), a prompt offers to advertise
  the new clone immediately: Right/Enter loads it and starts advertising (reboots
  to spoof the MAC); any other key skips.
- **BLE Honeypot** - live view of what a host does when it connects to your clone
  (or MITM proxy): subscribes, reads, writes, and relayed traffic. Also logged
  to the microSD card in real time. Opens automatically when a host connects. If
  nothing is advertising yet, it tells you to clone + advertise a device first.
- **MITM proxy** - jumps to a "MITM: pick target" device list. Selecting a
  device connects + pairs + dumps it, then reboots into proxy mode (see the MITM
  proxy section below).

### Sentry

Detection / alert mode. Keep a watchlist of devices to look for; when watching
is on, the device scans continuously and alerts (sound + popup) on a match. See
the Sentry section below.

### Settings

Volume / brightness / scan time, plus state-dependent actions, About, and Logs.
See the Settings section below.

---

## Settings

| Setting | What it does |
|---|---|
| Volume | Cycle speaker volume (also used by Foxhunt audio). |
| Brightness | Cycle screen brightness. |
| Scan time | Cycle the default scan duration. |
| Auto-pair | On/off. OFF (default) connects without forcing pairing, like nRF Connect - best for most devices (some sensors drop a central that pairs uninvited). Turn ON only if a device needs pairing to expose its data and won't ask for it itself. |
| Logs | Open the scrollable activity log. |
| Charging mode | Dim to a battery-only readout + low-power state for charging (see below). Press any key to exit. |
| About | App version, author, and project link. |
| Disconnect | (only if connected) drop the current link. |
| Stop advertising | (only if advertising a clone) stop it. |
| Stop MITM proxy | (only if a proxy is live) stop it. |
| Clear all bonds | Forget all saved pairings. |

---

## Charging mode

The Cardputer only charges while it's powered on, so this mode lets you leave it
charging with minimal waste and no screen burn-in. **Settings -> Charging mode**
shows a big battery readout (level %, charging/on-battery, voltage, current) on
a near-black, heavily-dimmed screen, and while active it:

- dims the backlight to near-off (the biggest power draw),
- drops the CPU clock to 80 MHz,
- stops scanning / foxhunt / Sentry watching and silences the speaker,
- redraws slowly and gently drifts the text to avoid burn-in.

Press any key to exit - brightness and full speed are restored.

---

## Sentry (detection / alert)

Watch for specific devices and get alerted when one shows up nearby.

The Sentry screen lists three actions, then your saved rules:

- **Start/Stop watching** - toggle detection mode on/off.
- **Add from scan** - pick a scanned device, then pick which of its attributes to
  track (MAC / OUI / Company ID / Service UUID / Name).
- **Add manually** - pick a match type, then type the value(s). Multiple values
  (space- or comma-separated) match if any matches - e.g. one "Smart Glasses"
  rule with company IDs `01AB 058E 0D53 03C2`.
- **Rules** - each shows `[*]` enabled / `[ ]` disabled. Right/Enter toggles a
  rule on/off; `x` deletes it.

Match types (all read from the advertisement - no connection needed):

| Type | Matches |
|---|---|
| MAC | Exact device address. |
| OUI | Vendor prefix (first 3 bytes; public addresses only). |
| Company | Manufacturer SIG company ID (e.g. `0x01AB` Meta). |
| Service | Advertised service UUID (e.g. `0x1812` HID). Individual GATT characteristics aren't advertised, so they can't be matched passively - the advertised Service UUID is the stand-in. |
| Name | Case-insensitive substring of the local name. |

When watching is on, the device scans continuously. On a match it plays an alert
tone and opens a MATCH screen showing the rule, the reason, and the device, with
three choices:

- **Connect** - connect to it (then dump on the GATT screen).
- **Foxhunt** - track its signal to home in on it.
- **Dismiss** - ignore this device for the rest of the session.

A matched device won't re-alert for ~2 minutes (Dismiss = ignore until you
stop/restart watching). Rules persist on the SD card (or flash if no card).

---

## Foxhunt / Track

Direction-finding: a big live RSSI readout for one device - walk around and
watch the number rise as you get closer.

| Key | Action |
|---|---|
| `a` | Toggle Geiger-counter audio (faster clicks = stronger signal). Audio is OFF by default. |
| `;` / `.` | When audio is on, raise / lower the volume. |
| `,` (Left) | Back (stops the hunt). |

---

## Pairing / passkeys

If a device needs a passkey, a popup appears:

- **Numeric Comparison** - a 6-digit code shows; confirm it matches the other
  device (auto-accepted on the Cardputer side).
- **Passkey Entry** - type the 6 digits shown on the other device, then Enter.

---

## ESC menu (Main screen, `` ` `` key)

| Key | Action |
|---|---|
| `Enter` | Disconnect the current device (if connected). |
| `c` | Forget all bonds. |
| any | Cancel. |

---

## MITM proxy

*Advanced / experimental - known limitations.*

Sits between a target device and a host, forwarding traffic and logging it. From
**Devices -> a device -> MITM proxy**:

1. It connects + pairs + dumps the target, then reboots into proxy mode.
2. After reboot it advertises as a clone of the target and reconnects to the real
   target. The header shows a "MITM" tag.
3. Connect your host (e.g. a laptop) to the clone; traffic relays both ways and
   shows in BLE Honeypot.

Stop it from **Settings -> Stop MITM proxy**.

---

## Typical first test

1. **Main -> Scan** (type a duration if you like) -> Right/Enter.
2. On the Devices list, pick a device -> **Connect**.
3. Open **Recon & Analysis -> GATT** and press Right to dump it.
4. For a BLE keyboard or heart-rate strap, try **Recon & Analysis -> Live
   Stream**.
5. To clone: **Adversarial -> Clone -> Save current dump...**, name it, then
   **Advertise loaded**. (The Cardputer reboots to set the cloned parameters,
   then starts advertising.)
6. To proxy: **Adversarial -> MITM proxy**, pick the target. It connects, pairs,
   dumps, and reboots into proxy mode; connect a host and watch BLE Honeypot.
