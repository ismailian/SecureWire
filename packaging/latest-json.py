#!/usr/bin/env python3
"""Write the update feed (site/releases/latest.json) for a release.

    python3 packaging/latest-json.py 1.1.0 dist/ > latest.json

Reads the packages in dist/ (sizes, SHA-256) and the release's notes from
CHANGELOG.md (the bullet lines under "## <version>"). The URLs point at the
GitHub release assets, so publish the release before deploying this file to
the website: the app downloads from those URLs as soon as the site has it.
"""
import hashlib
import json
import pathlib
import sys

REPO = "https://github.com/ismailian/SecureWire"
# latest.json asset key -> package file name pattern (see release.yml)
ASSETS = {
    "windows-x86_64": "securewire-v{v}-windows-x86_64-setup.exe",
    "linux-x86_64": "securewire-v{v}-linux-x86_64.AppImage",
    "macos-aarch64": "securewire-v{v}-macos-aarch64.dmg",
}


def notes(version: str) -> tuple[str, list[str]]:
    date, out, inside = "", [], False
    for line in pathlib.Path("CHANGELOG.md").read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            head = line[3:].strip()
            inside = head.split()[0].lstrip("v") == version
            if inside and "—" in head:
                date = head.split("—", 1)[1].strip()
            continue
        if inside and line.startswith("- "):
            out.append(line[2:].strip())
    return date, out


def main() -> None:
    version, dist = sys.argv[1], pathlib.Path(sys.argv[2])
    date, changes = notes(version)
    if not changes:
        sys.exit(f"CHANGELOG.md has no bullet lines under '## {version}'")
    assets = {}
    for key, pattern in ASSETS.items():
        name = pattern.format(v=version)
        data = (dist / name).read_bytes()
        assets[key] = {
            "url": f"{REPO}/releases/download/v{version}/{name}",
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }
    feed = {
        "version": version,
        "date": date,
        "notes": changes,
        "page": f"{REPO}/releases/tag/v{version}",
        "assets": assets,
    }
    print(json.dumps(feed, indent=2))


if __name__ == "__main__":
    main()
