# ChimeraBLE

A multi-headed BLE security & reverse-engineering tool for the ESP32 - named for
the chimera because it's one beast made of many parts, and because it speaks BLE
in all three roles: **Host** (central - scan, connect, enumerate, decode),
**Peripheral** (clone/emulate a device), and **MITM** (both at once - proxy
between a real device and its host). Enumerate a full GATT tree, read/write/
subscribe to characteristics, decode advertising data, parse HID report maps,
clone a device, direction-find it, or sit in the middle and log the traffic -
from a serial command line or the on-device Cardputer UI.

Built on [NimBLE-Arduino](https://github.com/h2zero/NimBLE-Arduino) 2.x.

> ⚠️ **Responsible use.** ChimeraBLE is a dual-use security research tool: it can
> impersonate/clone devices, man-in-the-middle connections, run a honeypot, and
> sniff HID/notification traffic. Use it **only** on devices you own or are
> explicitly authorized to test. You are responsible for complying with all
> applicable laws. Provided with **no warranty** (see LICENSE).

### Supported boards

| Env | Board | MCU | Front-end |
|---|---|---|---|
| `esp32dev` | ESP32 WROOM | classic Xtensa dual-core | serial CLI |
| `xiao_esp32c5` | Seeed Studio XIAO ESP32-C5 | RISC-V single-core | serial CLI |
| `cardputer` | M5Stack Cardputer ADV | ESP32-S3 (Stamp-S3A) | on-device M5 UI |

All targets use the [pioarduino](https://github.com/pioarduino/platform-espressif32)
platform (Arduino-ESP32 3.x / ESP-IDF 5.5) and **share the same BLE engine**
(`scanner`, `connection`, `gatt`, `adv_parser`, `uuid_db`, `hid_parser`, `oui_db`,
`fingerprint`, `clone`). `build_src_filter` swaps only the front-end: the serial
targets use `main.cpp` + `cli.cpp`; the Cardputer uses [`src/ui/`](src/ui/) (an
M5 menu UI in `App`/`UI`) and runs the engine natively on its own S3 radio - no
companion device. The XIAO ESP32-C5 board def lives in
[`boards/seeed_xiao_esp32c5.json`](boards/seeed_xiao_esp32c5.json).

---

## Build & flash

```sh
cd ChimeraBLE

# build both targets
pio run

# pick a target
pio run -e esp32dev
pio run -e xiao_esp32c5

# flash + monitor a specific target
pio run -e xiao_esp32c5 -t upload
pio device monitor -e xiao_esp32c5    # serial console @ 115200

# one-time: flash the OUI vendor database to the device filesystem (LittleFS).
# Needed for OUI-based vendor identification; also (re)formats LittleFS, so do
# this BEFORE saving clone profiles you want to keep.
pio run -e xiao_esp32c5 -t uploadfs
```

After flashing, open the monitor. You'll get a `ble>` prompt (it changes to
`ble-connected>` while a device is connected). Type `help` for the command list,
or just start with `scan`.

### Cardputer ADV (on-device UI)

```sh
pio run -e cardputer -t upload      # flash firmware
pio run -e cardputer -t uploadfs    # one-time: OUI DB onto LittleFS
```

No serial console needed - the UI is on the screen. Keyboard navigation:

| Key | Action |
|---|---|
| `;` / `.` | move selection up / down (scroll in Logs) |
| `/` or Enter | open / activate |
| `,` or Del | back (stops a fox hunt) |
| `'` | command mode - type any CLI command (e.g. `secure mitm iocap=display_yesno`, `clone save x`) and Enter |

Screens: **Main** → Scan / Devices / GATT / Command / Logs. **Devices** lists
scan results (RSSI + name or `~fingerprint`); select one for **Device Detail**
(Connect+dump, or Foxhunt). **Foxhunt** shows a live signal bar. Anything the
serial CLI can do is reachable from command mode, since both share the same
dispatch (`cli::execute`).

---

## Quick start

```
ble> scan 10                 # scan 10 seconds
ble> list                    # see what was found
ble> info 3                  # inspect device #3's advertising data
ble> connect 3               # connect to it
ble> secure                  # encrypt/bond (needed for many characteristics)
ble> dump                    # enumerate everything + auto-parse HID if present
ble> sub 0x002d              # subscribe to a notify characteristic
   ... press buttons / trigger the device, watch notifications stream ...
ble> disconnect
```

---

## Command reference

### Scanning & discovery

| Command | What it does |
|---|---|
| `scan [secs]` | Active scan for nearby devices (default 10s). Results are deduped by MAC. |
| `stop` | Stop an in-progress scan early. |
| `list` | Show the last scan's results, **sorted by signal strength (strongest/nearest first)** with indices renumbered 0..N to match: index, MAC, RSSI, adv byte count, and **name + fingerprint guess**. No-name devices show `~guess` (e.g. `~Apple (Nearby)`, `~BTHome sensor`). Named devices show `name \| guess` when the guess adds something (e.g. `Vertuo_DV6_… \| company 0x…`), since many self-reported names are cryptic. RPA/random addresses are tagged `[RPA]`/`[rand]`. |
| `info <idx>` | Full advertising payload for a device, hex + decoded AD records (flags, UUID lists, name, Tx power, appearance, service data, manufacturer data with Apple/Microsoft/Google sub-decoding), plus a **fingerprint** section: best-guess identity, address type (public / random-static / RPA), and every identifying signal broken out. |
| `foxhunt <idx\|mac>` | **RF direction finding.** Continuously tracks one device's RSSI and streams a live signal-strength bar - walk around and watch it climb as you get closer. Shows current dBm, a bar, the peak seen, and a closer/farther trend. `stop` to end. |

**Device fingerprinting (no connection needed):** lots of BLE devices advertise
no name - beacons, trackers, sensors, phones in privacy mode. The tool guesses
what they are from the advertising data, in priority order:

1. **Service-data protocol UUIDs** - Eddystone, Google Fast Pair, BTHome,
   Exposure Notification, Xiaomi/MiBeacon, Tile, etc. (strongest signal).
2. **Manufacturer company ID** → vendor name, with Apple Continuity sub-type
   (iBeacon / Nearby / Handoff / AirPods / FindMy …).
3. **Recognizable custom services** (e.g. Nordic UART).
4. **SIG service UUIDs** → device class (HID input device, Heart Rate monitor,
   Fitness machine, Environmental sensor …).
5. **Appearance** → device category.
6. **OUI vendor** (public addresses only) → IEEE-assigned product brand, e.g.
   `fc:b9:7e` → GE Appliances, `0c:95:05` → Chamberlain Group. This complements
   the company ID: the company ID is the *SIG member* (often the chip/parent -
   `0x0929` is Qingdao Haier), while the OUI is the *IEEE product brand* (GE
   Appliances). Requires the OUI database on the filesystem (`uploadfs`).
7. **Address type** - public, random-static, or resolvable-private (RPA, the
   rotating privacy address most phones/watches use). Shown as `[RPA]` in `list`.

The full Bluetooth SIG company-identifier list (~4,000 entries) is embedded in
flash; the IEEE OUI table (~39,000 entries) lives as a binary on LittleFS and is
binary-searched at runtime. Both are generated from authoritative sources (the
SIG/Nordic numbers DB and Wireshark's `manuf`). RPA-clustering across MAC
rotations (fingerprint hashing) is intentionally not implemented.

### Connection

| Command | What it does |
|---|---|
| `connect <idx\|mac>` | Connect to a device by its scan index or MAC (`aa:bb:cc:dd:ee:ff`). Auto-requests a 247-byte MTU to speed up reads. |
| `disconnect` | Drop the current link and clear the cached GATT tree. |
| `mtu <bytes>` | Manually request an ATT MTU (23-517). |
| `status` | Show current link state, encryption/bond status, scan state, and whether a GATT tree is cached. |

### Security & bonding

| Command | What it does |
|---|---|
| `secure` | Request encryption / bonding on the current link with the active security config. |
| `secure show` | Print the current security config without initiating pairing. |
| `secure <flags>` | Update the security config, then secure. Flags can be combined. |
| `secure auto {on\|off}` | Auto-initiate pairing immediately after every `connect`. Needed for HID peripherals (keyboards, remotes) that lead with a security request and drop the link if pairing doesn't start in time. |
| `bonds` | List bonded devices stored in NVS. |
| `forget <mac>` | Delete one stored bond. |
| `forget all` | Delete all stored bonds. |

**Security flags** (for `secure <flags>`):

| Flag | Meaning |
|---|---|
| `bond` / `nobond` | Store the pairing keys (default `bond`). |
| `mitm` / `nomitm` | Require man-in-the-middle protection / authenticated pairing (default `nomitm`). |
| `lesc` / `legacy` | LE Secure Connections vs legacy pairing (default `lesc`). |
| `iocap=none` | No input/output - "Just Works" pairing (default). |
| `iocap=display` | Display only. |
| `iocap=display_yesno` | Display + yes/no - enables Numeric Comparison. |
| `iocap=keyboard` | Keyboard only - passkey entry. |
| `iocap=keyboard_display` | Keyboard + display. |

Example: `secure nobond mitm iocap=display_yesno`

> **Note:** Bonding to the ESP32 may evict a device's existing bond to its real
> host (e.g. pairing a remote to the ESP32 can unpair it from its TV). If a
> device refuses to pair because of a stale bond on the ESP32, clear it with
> `forget <mac>` and try again.

**Connecting to HID devices (keyboards, remotes, controllers):** these require
an encrypted link and send a security request the instant you connect. Two things
matter - pairing must start immediately, and it usually must be **authenticated
(MITM)**, not Just Works:

```
secure mitm iocap=display_yesno    # authenticated pairing (Numeric Comparison)
secure auto on                     # pair immediately on connect
connect <idx>
```

If the device uses **Numeric Comparison** (a passkey appears on both the device
and, say, your Mac when you pair normally), the ESP32 prints the 6-digit value
and auto-accepts - confirm the matching prompt on the device:

```
[sec] >>> NUMERIC COMPARISON  passkey = 481516 <<<
```

If the device uses **Passkey Entry** (it displays a code you must type), the tool
prompts you - read the code off the device and run:

```
passkey 481516
```

`secure auto on` alone (Just Works, `iocap=none`) is enough for devices that
accept unauthenticated pairing, but many HID peripherals reject it with HCI
**0x205 Authentication Failure**.

**Automatic MITM upgrade:** you usually don't have to do this by hand. If a
`connect` drops with 0x205/0x206 while MITM/auto-secure were off, the tool
automatically enables `mitm iocap=display_yesno` + `secure auto on` and retries
the connection **once**:

```
connect 40
[link] disconnected reason=0x205 (Authentication Failure ...)
[sec] pairing was rejected - auto-enabling MITM numeric comparison ... and retrying once
[link] connecting to 80:e1:26:...
[sec] >>> NUMERIC COMPARISON  passkey = 481516 <<<
[sec] auth complete  encrypted=1  bonded=1
```

It only upgrades once per connect attempt, and only if those settings weren't
already on - so a persistent 0x205 *after* the upgrade points instead at a
**stale bond**: `forget all` on the ESP32 and unpair the ESP32 on the target,
then retry. Disconnect reasons are decoded inline (`0x206` = key missing,
`0x208` = timeout, `0x213` = remote terminated, etc.).

> The ATT MTU is negotiated lazily on the first GATT operation rather than during
> connect, so it doesn't race a device-led pairing handshake. You'll see
> `[mtu] negotiated MTU = N` when you `dump`, not at connect time.

### GATT operations

All characteristic-targeting commands accept either a **handle** (hex `0x002a`
or decimal `42`) or a **UUID** via the `uuid:` prefix (`uuid:2A19` for a 16-bit
SIG UUID, or `uuid:6e400001-b5a3-f393-e0a9-e50e24dcca9e` for a full 128-bit
UUID). Handles are unique per connection; a UUID lookup returns the first match.

| Command | What it does |
|---|---|
| `dump` | Enumerate all services, characteristics, and descriptors; read every readable value; resolve SIG UUIDs to friendly names. Auto-runs the HID parser if a HID service (0x1812) is present. |
| `read <h\|uuid:U>` | One-shot read of a characteristic. |
| `write <h\|uuid:U> <hex>` | Write with response. Hex accepts `01:02:03`, `01-02-03`, `01 02 03`, or `010203`. |
| `writenr <h\|uuid:U> <hex>` | Write without response. |
| `sub <h\|uuid:U>` | Subscribe to notifications/indications. Each event streams live with a timestamp, source UUID, and payload. |
| `unsub <h\|uuid:U>` | Unsubscribe. |
| `subs` | List currently active subscriptions. |

### Decoders

| Command | What it does |
|---|---|
| `hid` | Find the HID service (0x1812), read the Report Map (0x2A4B), and parse it per USB HID 1.11: a decoded item tree (Usage Page/Usage names, collections, Input/Output/Feature flags) plus a per-Report-ID byte-layout cheatsheet for interpreting live notifications. Requires a prior `dump`. |
| `hid stream` | Subscribe to the device's HID Input report characteristics and decode notifications live. **Keyboard** reports become key names (e.g. `LShift+A`, `Enter`); other report types print as raw bytes. Press keys on the device and watch them stream over serial. Requires a connected device with a prior `dump`. |
| `hid stream off` | Stop the live stream and unsubscribe. |

### Cloning (peripheral emulation)

Capture a connected device's attribute table + advertising data into a profile,
then re-expose the ESP32 as a BLE peripheral that mirrors it. See
[Cloning a device](#cloning-a-device) below for the workflow and limitations.

| Command | What it does |
|---|---|
| `clone save <name>` | Serialize the dumped device's GATT tree (services, characteristics, properties, values, descriptors) + captured adv payload to `/clones/<name>.json` on LittleFS. Works from the `dump` snapshot, so it still succeeds after the device drops the link - just `connect` + `dump` at some point first. |
| `clone list` | List saved profiles. |
| `clone load <name>` | Load a profile into memory. |
| `clone info` | Show the loaded profile's structure. |
| `clone advertise` | Bring up a `NimBLEServer` mirroring the loaded profile and start advertising (replays the captured adv payload). Drops any active central link first. |
| `clone stop` | Stop advertising. |
| `clone delete <name>` | Delete a saved profile. |

### Output mode

| Command | What it does |
|---|---|
| `json on` | Switch to JSON-line output: one JSON object per event. Suppresses the `ble>` prompt for clean piping. |
| `json off` | Back to human-readable output. |
| `json` | Show the current mode. |

### Misc

| Command | What it does |
|---|---|
| `help` | Print the built-in command list. |

---

## JSON mode

With `json on`, machine-parseable events are emitted one JSON object per line.
Interactive output (help, errors, `status`, security config) stays human-readable.

Event types:

```json
{"ev":"scan_end","t":12340,"count":7}
{"ev":"device","t":12345,"idx":0,"mac":"aa:bb:cc:dd:ee:ff","addr_type":1,"rssi":-58,"name":"AR","adv":"02 01 06 03 02 12 18"}
{"ev":"svc","t":12500,"uuid":"0x180F","start":"0x002A","end":"0x002C"}
{"ev":"chr","t":12501,"svc":"0x180F","uuid":"0x2A19","handle":"0x002B","props":"R--N--","value":"64"}
{"ev":"dsc","t":12502,"chr_handle":"0x002B","uuid":"0x2902","handle":"0x002C","value":"01 00"}
{"ev":"dump_end","t":12550}
{"ev":"read","t":12600,"uuid":"0x2A19","handle":"0x002B","value":"63"}
{"ev":"notify","t":12700,"svc":"0x1812","uuid":"0x2A4D","handle":"0x002D","bytes":"02 01 00 00"}
```

The `props` string is a 6-char field: `R` read, `W` write, `w` write-no-response,
`N` notify, `I` indicate, `B` broadcast (`-` where absent).

Example - diff two devices' GATT trees:

```sh
jq -c 'select(.ev=="chr") | {svc, uuid, props}' deviceA.jsonl | sort > A.txt
jq -c 'select(.ev=="chr") | {svc, uuid, props}' deviceB.jsonl | sort > B.txt
diff A.txt B.txt
```

---

## Typical workflows

**Reverse-engineer an unknown peripheral**
```
scan 15 → list → info <idx> → connect <idx> → secure → dump
```
The dump resolves known UUIDs, reads all values, and shows the full attribute
table. Subscribe to notify characteristics and exercise the device to capture
its live protocol.

**Decode an HID device (remote, keyboard, controller)**
```
connect <idx> → secure → dump → hid
```
`hid` turns the raw Report Map into report layouts so you can interpret the
bytes that arrive on each `notify`.

**Watch keystrokes from a BLE keyboard live**
```
connect <idx> → (auto-secures) → dump → hid stream
```
Now press keys on the keyboard - they decode in real time:
```
[hid] stream active on 1 characteristic(s) - press keys on the device
[hid kbd] H
[hid kbd] I
[hid kbd] LShift+1
[hid kbd] Enter
```
`hid stream off` to stop. Non-keyboard input reports (consumer/media, mouse)
print as raw bytes - cross-reference them against the `hid` report layout.

**Capture for offline analysis**
```
json on → connect <idx> → secure → dump → sub <handle>
```
Pipe the serial stream to a file and process with `jq`.

**Find a device physically (fox hunt)**
```
scan → list → foxhunt <idx>
```
Continuously tracks that one device's RSSI with a live bar; move around and the
bar climbs as you close in. Peak-hold smooths fast advertisers; a "no signal"
note appears if it drops out of range. `stop` to end.
```
[fox] hunting 80:e1:26:76:6c:46 (Flipper) - move around, stronger = closer. Type 'stop' to end.
[fox]  -71 dBm  [########            ]  peak -71  ...
[fox]  -63 dBm  [##########          ]  peak -63  closer
[fox]  -55 dBm  [############        ]  peak -55  closer
```

---

## Cloning a device

Mirror a real device as a BLE peripheral for impersonation testing or to replay
a captured device to a host:

```
scan → connect <idx> → secure → dump      # capture the attribute table (snapshot)
clone save myremote                        # serialize to /clones/myremote.json
clone advertise myremote                   # spoofs the target MAC (reboots once), then advertises
   ... device reboots, comes back advertising as the target ...
   ... point a host/phone at it ...
clone stop
```

**How it works:** `dump` reads every characteristic/descriptor value into an
in-memory snapshot. `clone save` serializes that snapshot - plus the captured
advertising payload - to JSON on LittleFS. Because it works from the snapshot
rather than live reads, **`clone save` still works after the target drops the
link** (many devices, e.g. Sonos, close an idle BLE connection seconds after the
dump finishes). `clone advertise` rebuilds the tree on a `NimBLEServer`, sets
each characteristic's properties and stored value, and replays the advertising
bytes verbatim.

> The GATT snapshot persists across disconnect and is only cleared when you
> connect to the **next** device. So `connect → dump → (link drops) → clone save`
> works fine. Live `read`/`write`/`sub`/`hid` against a dropped link will report
> "not connected" rather than acting on stale data - reconnect to use them.

**MAC spoofing (automatic reboot):** the BT controller latches its public
address at init, so to advertise under the target's MAC the firmware sets it
*before* the stack starts. `clone advertise` detects the address mismatch,
writes the profile name to `/clones/.active`, and reboots; on the next boot the
MAC is applied and advertising resumes automatically. You'll see:

```
clone advertise sonos
[clone] rebooting to advertise under target MAC b8:e9:37:xx:xx:xx ...
   ... device reboots ...
[clone] boot: set BT MAC = b8:e9:37:xx:xx:xx (ok)
[clone] resuming advertise after MAC-spoof reboot
[clone] advertising as 'sonos' on MAC B8:E9:37:XX:XX:XX - 5 services, 18 characteristics
[clone] target MAC b8:e9:37:xx:xx:xx (matched)
```

A normal power cycle (no `clone advertise` pending) boots with the real ESP32
MAC in standard scan/connect mode - the `.active` trigger is one-shot.

**Other limitations to be aware of:**

- **Security:** cloned characteristics use open access (no encryption). A host
  that expects an encrypted/bonded link to the original may behave differently.
- **GAP/GATT services:** the GAP (0x1800) and GATT (0x1801) services and the
  CCCD descriptor (0x2902) are owned by the NimBLE stack and can't be recreated
  as app services (a duplicate 0x1800 would be malformed). The target's **Device
  Name (0x2A00)** and **Appearance (0x2A01)** *are* replicated - they're pushed
  into the stack's GAP service, so a host that connects and reads them sees the
  target's identity. What does **not** carry over: the exact 0x1800 handle
  numbers and config-only characteristics like Preferred Connection Parameters
  (0x2A04) and Central Address Resolution (0x2AA6), which follow the stack's
  build rather than the target's layout.
- **One profile per boot:** NimBLE can't cleanly rebuild a GATT table at
  runtime. `clone advertise` builds the server once; `clone stop` only stops
  advertising. Advertising a *different* profile reboots automatically (needed
  for the MAC change anyway).

---

## Prebuilt firmware

Prebuilt binaries are attached to the GitHub **Releases** page (not committed to
the tree): the Cardputer `ChimeraBLE.bin` (sideload via the M5 launcher, or a
merged `0x0` image), and the OUI vendor database `oui.bin`.

- **Cardputer:** copy `oui.bin` into the **`/ChimeraBLE/` folder on the microSD
  card** (i.e. `/ChimeraBLE/oui.bin`) for MAC-vendor names (optional - everything
  else works without it). ChimeraBLE keeps all its files in that one folder and
  creates it on first launch, or you can make it yourself and drop `oui.bin` in.
  See [`CARDPUTER_GUIDE.md`](CARDPUTER_GUIDE.md).
- **Serial boards (esp32dev / xiao_esp32c5):** the OUI DB lives on LittleFS -
  generate it with `python tools/make_oui_bin.py` (writes `data/oui.bin`), then
  `pio run -e <env> -t uploadfs`.

---

## Credits

ChimeraBLE builds on excellent open-source work:

- [NimBLE-Arduino](https://github.com/h2zero/NimBLE-Arduino) - BLE stack (Apache-2.0)
- [ArduinoJson](https://arduinojson.org/) - JSON (MIT)
- [M5Cardputer / M5Unified / M5GFX](https://github.com/m5stack) - Cardputer HAL + graphics (MIT)
- [pioarduino](https://github.com/pioarduino/platform-espressif32) - Arduino-ESP32 platform (Apache-2.0)

Bundled data:

- **OUI vendor database** (`data/oui.bin`, generated by
  [`tools/make_oui_bin.py`](tools/make_oui_bin.py)) is derived from
  [Wireshark's `manuf`](https://www.wireshark.org/) registry, which is licensed
  **GPL-2.0-or-later** - one reason ChimeraBLE is GPL-licensed (compatible).
- **Bluetooth company identifiers** (`src/company_ids_gen.cpp`) are generated from
  the Bluetooth SIG assigned numbers via Nordic's
  [bluetooth-numbers-database](https://github.com/NordicSemiconductor/bluetooth-numbers-database).

---

## License

Copyright (C) 2026 Matthew Kukanich.

ChimeraBLE is free software licensed under the **GNU General Public License v3.0
or later (GPL-3.0-or-later)** - see [`LICENSE`](LICENSE). You may use, study,
modify, and redistribute it, but any distributed derivative (including firmware
that incorporates this code) must also be released under the GPL and retain this
copyright and attribution. Provided **without warranty** to the extent permitted
by law.
