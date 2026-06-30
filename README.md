# FocusShield

A self-control app for Android that blocks gambling and adult content at
the network level, with tamper-resistance designed so it can't just be
switched off in a moment of weakness.

## What's actually built here

- **`FilterVpnService`** — local-only `VpnService`. Filters DNS against a
  bundled blocklist. No remote server, no third party ever sees your
  traffic, no subscription cost.
- **`BlocklistRepository`** — loads `assets/blocklist_gambling.txt` and
  `assets/blocklist_adult.txt`, plus a keyword-heuristic layer that catches
  new/mirror domains not yet in the static list.
- **`FocusShieldAdminReceiver`** — applies Device Owner policy
  restrictions (blocking VPN reconfiguration, app uninstall, safe boot,
  factory reset, and ADB debugging) so the protections sit at the OS
  level, not just inside the app.
- **`AppGuardAccessibilityService`** — secondary layer that catches
  gambling apps installed directly (not just browser-based access).
- **`CooldownManager` / `DisableRequestActivity`** — a mandatory 72-hour
  wait (configurable) before the app can be disabled, with an optional
  trusted-contact PIN. This is the actual self-control mechanism; the
  technical blocking is meaningless without it.

## What's NOT finished

`FilterVpnService.handlePacket()` is a stub. Parsing raw IP/UDP packets to
extract and rewrite DNS queries correctly is the single hardest part of
this project and needs real testing on-device — I'd strongly recommend
adapting the packet-parsing logic from an existing open-source project
rather than writing it from scratch, since DNS-over-VPN parsing has a lot
of edge cases (TCP fallback, DNS-over-HTTPS bypass attempts, IPv6, etc).
Two solid references: **dns66** and **AdAway**'s VPN-based blocker — both
are open-source (GPLv3) Android ad/DNS blockers you can read for the
packet-loop implementation.

`promptForTrustedPin()` in `DisableRequestActivity` is a hook with no UI —
build out a PIN entry dialog there if you want that extra layer.

## One-time setup: Device Owner provisioning

This is what makes the lockdown restrictions actually stick (vs. being
removable from Settings). It requires ADB and, in most cases, a factory
reset first since Android won't grant Device Owner on a device that
already has a Google account configured.

1. Factory reset the device (Settings > System > Reset, or during first
   setup skip adding any Google account).
2. Enable Developer Options and USB debugging.
3. Build and install the app via Android Studio, **but do not open it
   yet** / do not add a Google account yet if starting from reset.
4. From a computer with ADB:
   ```
   adb shell dpm set-device-owner com.focusshield.app/.admin.FocusShieldAdminReceiver
   ```
5. Open the app, tap "Enable Protection," grant the VPN permission
   prompt. The Device Owner restrictions are applied automatically in
   `FocusShieldAdminReceiver.onEnabled()`.
6. Add your Google account back and Play Store will work normally — only
   VPN config, uninstall, and safe-boot are restricted.

## Updating the blocklist (free, no API)

Pull a fresh copy from Steven Black's unified hosts project
(https://github.com/StevenBlack/hosts, MIT licensed) — the "gambling" and
"porn" category variants — strip the leading `0.0.0.0 ` from each line,
and replace `assets/blocklist_gambling.txt` / `assets/blocklist_adult.txt`.
No code changes needed.

## Build

Standard Android Studio project. Open the `FocusShield/` folder directly,
let Gradle sync, build & run on a device (API 26+).
