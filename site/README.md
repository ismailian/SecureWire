# SecureWire website

Static pages for https://securewire-app.pages.dev/, with no build step and no third-party requests.

| File | What |
|---|---|
| `index.html` | Landing page: features, how it works, security, downloads, FAQ |
| `docs.html` | Getting started guide |
| `404.html` | Not-found page (Cloudflare Pages serves it automatically) |
| `_headers` | Security and cache headers for Cloudflare Pages |
| `releases/latest.json` | **Update feed read by the app on every start** (D-037): version, date, notes, and per platform the direct GitHub download URL, SHA-256 and size |
| `assets/` | `site.css`, `site.js`, `icons.svg` (icon sprite), `img/` screenshots, `fonts/` JetBrains Mono (OFL) |

## Deploy on Cloudflare Pages

Connect the GitHub repo, then use:
- Framework preset: **None**
- Build command: *(empty)*
- Build output directory: **`site`**

Or deploy by hand with Wrangler: `npx wrangler pages deploy site --project-name securewire-app`.

## Preview locally

```bash
python -m http.server -d site 8080
```

## On a new release

1. Write the release's bullets under `## X.Y.Z — date` in `CHANGELOG.md` (they become "What's new" in the app's update dialog).
2. Tag and push; the Release workflow builds a **draft** release and a `latest.json` (attached to the draft and as the `latest-json` artifact).
3. **Publish the release first**, then copy that `latest.json` to `site/releases/latest.json` and deploy the site. Installed copies of SecureWire see the update on their next start, so never deploy the feed while the release is still a draft (its URLs would 404).
4. Download links on the pages point at `releases/download/vX.Y.Z/<file>`. Search for the old version in `index.html` (links, sizes, the hero badge, JSON-LD) and `docs.html` (the `.deb` name), and replace it.

The app checks `https://securewire-app.pages.dev/releases/latest.json` (asset keys `windows-x86_64` → Inno Setup installer, `linux-x86_64` → AppImage, `macos-aarch64` → .dmg). Changing the domain means changing `LATEST_URL` in `crates/app/src/update.rs` and shipping a release before the old address goes away.

## Screenshots

Taken from the real app with `securewire --demo` (release build, 1920×1051 window), cropped, and converted to WebP. Everything in them is sample data from the demo host (documentation IP ranges such as 203.0.113.0/24).
