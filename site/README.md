# SecureWire website

Static pages for https://securewire-app.pages.dev/, with no build step and no third-party requests.

| File | What |
|---|---|
| `index.html` | Landing page: features, how it works, security, downloads, FAQ |
| `docs.html` | Getting started guide |
| `404.html` | Not-found page (Cloudflare Pages serves it automatically) |
| `_headers` | Security and cache headers for Cloudflare Pages |
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

Download links point at `releases/download/vX.Y.Z/<file>`. Search for the old version in `index.html` (links, sizes, the hero badge, JSON-LD) and `docs.html` (the `.deb` name), and replace it.

## Screenshots

Taken from the real app with `securewire --demo` (release build, 1920×1051 window), cropped, and converted to WebP. Everything in them is sample data from the demo host (documentation IP ranges such as 203.0.113.0/24).
