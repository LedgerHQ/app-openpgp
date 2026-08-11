# OpenPGP Backup — Web UI

A browser-based tool to **backup and restore** the data of the Ledger OpenPGP App.
Everything runs locally in your browser; the backup file never leaves your machine.

Built with **Vite + React 18** and Ledger's **lumen** design system
(`@ledgerhq/lumen-ui-react`, Tailwind CSS).

## Why WebHID (and not WebUSB)

The OpenPGP app exposes a USB **CCID** (smartcard) interface used by GPG, plus
the standard Ledger **generic HID** APDU interface. WebUSB would collide with
CCID on the same USB endpoint (`0x83`), so it is disabled in the app firmware.

Instead this UI uses [`@ledgerhq/hw-transport-webhid`](https://www.npmjs.com/package/@ledgerhq/hw-transport-webhid),
which talks to the **generic HID** interface (vendor id `0x2c97`, usage page
`0xFFA0`) — the exact same channel the Python backup tool (`pytools/backup.py`)
already uses. No firmware change is required.

## Requirements

- A **Chromium-based browser** (Chrome, Edge, Brave). WebHID is not available
  in Firefox or Safari.
- The OpenPGP app **open** on a connected Ledger device.
- **No other client holding the device.** gpg/scdaemon and this page share the
  USB device; a running scdaemon can break the WebHID connection ("Bad
  interface"). Release it first with `gpgconf --kill scdaemon` (or `pkill
  scdaemon`).

## After a restore or factory reset

The web UI talks to the device over **HID**, gpg over **CCID**. The app only
signals a "card changed" to the CCID side when it (re)starts, so after a
**restore** or a **factory reset** you must, before using gpg:

1. **Restart the OpenPGP app** on the device (quit to the dashboard, reopen it).
2. Reload scdaemon: `gpgconf --kill scdaemon`.

Otherwise gpg keeps seeing the old card state. (A factory reset also resets the
PINs to their defaults: `123456` / `12345678`.)

## Develop

This project uses **pnpm** (provisioned by corepack from the `packageManager`
field — run `corepack enable` once if needed):

```sh
pnpm install
pnpm dev        # Vite dev server on http://localhost:5173 (opens the browser)
pnpm mock       # same, but opens at /?mock — see below
pnpm build      # production bundle in dist/
```

Local testing of the device interaction requires a **physical device**:
Speculos exposes APDUs over TCP, not WebHID.

### Preview without a device (`?mock`)

Append `?mock` to the URL (or run `pnpm mock`) to jump straight to the
*connected* screen — Backup / Restore / Factory reset / Disconnect, with a
placeholder AID — so the layout and dialogs can be reviewed without a Ledger.
It is **dev-only**: `import.meta.env.DEV` gates it, so production builds ignore
the flag. Submitting an action still fails (no device), but every screen and
dialog renders.

### Tests

The pure-logic units (APDU framing / command chaining, TLV decoding) are
covered by **Vitest** and run without a device:

```sh
pnpm test        # run once (CI)
pnpm test:watch  # watch mode
```

Device interaction itself is not unit-tested.

## Deployment

Built as a static site and co-hosted on the project's existing GitHub Pages
site: the `Generate GitHub Pages` workflow (`.github/workflows/pages.yml`)
builds this app and copies `dist/` into `doc/html/build/wui/`, so it is served
at **`https://ledgerhq.github.io/app-openpgp/wui/`** and linked from the docs
landing page. The Vite `base` is `./` (relative asset paths), so the build
works at that sub-path without a custom domain. A dedicated domain (e.g.
`openpgp.ledger.com`) could be added later via a `CNAME`.

## Known issues

- **The app can occasionally crash during key regeneration.** Regenerating the
  three keys from the seed runs heavy, variable-time operations on the device
  (RSA prime search + key-pair generation); the OpenPGP app sometimes drops its
  USB interface mid-operation. It is intermittent and **not fixable from this client**.
  The keys are almost always regenerated successfully anyway.
  Restart the OpenPGP app, reconnect, and verify the fingerprints.
  The page detects this disconnect and shows a dedicated message.
