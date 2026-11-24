# Changelog

Each release's bullet lines become the "What's new" list in the app's update dialog
(`packaging/latest-json.py` → `site/releases/latest.json`). Keep them short.

## 1.1.0 — 2026-11-24

- Files tab (Ctrl Shift E): browse the server; copy, cut, paste, rename, create and delete files and folders there.
- Upload and download over SCP on the same SSH connection: pick files or a folder, drag files in from the desktop, or paste files copied in Explorer.
- Update checker: SecureWire tells you when a new version is out, downloads it, checks its SHA-256 and installs it.

## 1.0.0 — 2026-11-16

- First release: terminal, live system, services, firewall, security and log panels over one SSH connection.
- Command palette, server actions with confirmation, tunnels, ~/.ssh/config import and jump hosts.
