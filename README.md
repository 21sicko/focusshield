# FocusShield

A self-control app for Android that blocks gambling and adult content at
the network level, with tamper-resistance designed so it can't just be
switched off in a moment of weakness.

## What's built and functional

- **`FilterVpnService` + `DnsPacketProcessor` + `DnsMessage`** — a real,
  working local DNS filter. The VPN routes *only* the virtual DNS server
  address through the tun interface (not all traffic), so it doesn't need
  to act as a full traffic proxy. It parses real IPv4/UDP/DNS packets,
  checks the queried hostname against the blocklist, and either:
  - returns a synthesized NXDOMAIN response immediately for blocked
    domains, or
  - forwards the query to a real upstream resolver (Cloudflare 1.1.1.1 by
    default, change `UPSTREAM_DNS` in `FilterVpnService` if you prefer
    another) via a `protect()`-ed socket and relays the response back.
- **`BlocklistRepository`** — loads bundled blocklist assets plus a
  keyword-heuristic layer for new/mirror domains.
- **`FocusShieldAdminReceiver`** — Device Owner policy lockdown (blocks
  VPN reconfiguration, uninstall, safe boot, factory reset, ADB
  debugging).
- **`AppGuardAccessibilityService`** — catches gambling apps installed
  directly, not just browser access.
- **`CooldownManager` + `DisableRequestActivity` + `PinDialogHelper`** —
  72-hour mandatory wait before disabling, plus an optional
  trusted-contact PIN (set it from the main screen — "Set
  Trusted-Contact PIN" — and give the PIN to someone other than
  yourself; verification is required at disable time).

## Known, honest limitations

- **IPv4/UDP DNS only.** IPv6 and DNS-over-TCP (the fallback for
  responses over 512 bytes) aren't handled. Most ordinary DNS traffic on
  a phone is IPv4/UDP, but this isn't exhaustive.
- **DNS-over-HTTPS/TLS bypasses this.** Any DNS-based blocker (including
  commercial ones) only sees plain port-53 traffic. If an app or browser
  uses its own built-in DoH resolver, the query never touches this
  filter. Closing that gap fully requires a different layer (blocking
  known DoH provider endpoints by IP/SNI), which isn't implemented here.
- **UDP checksum is left at 0** in synthesized/relayed packets, which is
  valid for IPv4 (checksum is optional there) but means it's skipped
  rather than computed — fine functionally, just worth knowing.

## Build it — phone only, no laptop needed

This project now includes `.github/workflows/build.yml`, which tells
GitHub's free build servers to compile the APK for you. You never need
Android Studio or a desktop computer — just a phone, a browser, and a
free GitHub account. Here's the full path:

**1. Install Termux** (a terminal app for Android — get it from F-Droid
at https://f-droid.org/packages/com.termux/, not the outdated Play Store
version).

**2. In Termux, set up storage access and basic tools:**
```
termux-setup-storage
pkg install git unzip -y
```

**3. Get the project files onto the phone and unzip them:**
Save `FocusShield.zip` (from this chat) to your phone's Downloads folder,
then in Termux:
```
cd ~/storage/downloads
unzip FocusShield.zip
cd FocusShield
```

**4. Create a free GitHub account** at github.com (mobile browser is
fine), then create a new **empty** repository (no README/license) —
call it `focusshield`.

**5. Create a GitHub Personal Access Token** (so Termux can push code):
GitHub → your profile photo → Settings → Developer settings → Personal
access tokens → Tokens (classic) → Generate new token → check the "repo"
scope → Generate → **copy the token somewhere safe, it's shown only
once.**

**6. Push the project from Termux:**
```
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://YOUR_USERNAME:YOUR_TOKEN@github.com/YOUR_USERNAME/focusshield.git
git push -u origin main
```
(Replace `YOUR_USERNAME` and `YOUR_TOKEN` with your actual GitHub
username and the token from step 5.)

**7. Watch the build run:** open your repo in the browser → **Actions**
tab. The push automatically triggers "Build FocusShield APK." It takes a
few minutes. A green check means it succeeded.

**8. Download the APK:** still on the Actions tab, click the completed
run → scroll to **Artifacts** → tap `FocusShield-debug-apk` to download
a zip containing `app-debug.apk` straight to your phone.

**9. Install it:** open your Downloads/file manager app, unzip that
artifact zip if needed, then tap `app-debug.apk`. Android will prompt to
allow installs from whatever app you used to open it — allow it, then
tap Install.

If the build fails, tap into the failed step in the Actions log — it'll
usually be a clear Gradle/compile error you can read right there on your
phone and fix by editing the file in GitHub's mobile web editor (tap the
file → pencil icon → edit → commit), which re-triggers the build
automatically.

## One-time setup: Device Owner provisioning (tamper-resistance)

This part still requires ADB, which needs a computer — Android doesn't
expose an on-device way to grant Device Owner status. **Without this
step, the app still works as a DNS blocker**, it just won't be protected
against being disabled/uninstalled at the OS level (no factory-reset
block, no "can't remove the app" lock). If you only have a phone and no
access to any computer at all, even briefly (library, friend's, internet
café), you can skip this and rely on the cooldown + trusted-contact PIN
inside the app as your tamper-resistance instead.

If you do get access to a computer at some point:
1. Factory reset the device (Settings → System → Reset), or do this on a
   freshly reset phone before adding any Google account.
2. Enable Developer Options + USB debugging on the phone.
3. Install `app-debug.apk` (already built from step 9 above, or rebuild) —
   **don't open it yet**.
4. From the computer, with the phone connected via USB and ADB
   installed:
   ```
   adb shell dpm set-device-owner com.focusshield.app/.admin.FocusShieldAdminReceiver
   ```
   If this fails with "not allowed," it usually means a Google account
   already exists on the device — remove all accounts (Settings →
   Accounts) and retry, or do a fresh factory reset.
5. Open the app, tap "Enable Protection," grant the VPN permission
   prompt that appears.
6. Add your Google account back — Play Store works normally from here;
   only VPN reconfiguration, uninstall, safe boot, and ADB debugging are
   restricted.

## Updating the blocklist (free, no API)

Pull a fresh copy from Steven Black's unified hosts project
(https://github.com/StevenBlack/hosts, MIT licensed) — the "gambling"
and "porn" category variants — strip the leading `0.0.0.0 ` from each
line, and replace `assets/blocklist_gambling.txt` /
`assets/blocklist_adult.txt`. No code changes needed.
