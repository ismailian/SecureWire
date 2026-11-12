# SecureWire — Design

Everything about how SecureWire looks, behaves, and talks to servers, before (and alongside) the code.

| File | What it is |
|---|---|
| [`prototype/index.html`](prototype/index.html) | Clickable UI mock. Open in a browser. Fake live data, working splitters, dialogs, palette, mock terminal. |
| [`ui-spec.md`](ui-spec.md) | Layout, every panel and section, dialogs, states, keyboard map. **Authoritative over the prototype.** |
| [`design-tokens.md`](design-tokens.md) | Colors, typography, spacing, egui `Visuals` mapping. |
| [`collector-protocol.md`](collector-protocol.md) | Single-connection channel plan, collector framing + control commands, sections, log channels, actions. |
| [`decisions.md`](decisions.md) | Decision log (D-001 …) for UI and architecture choices. |

## Trying the prototype
- `Ctrl K` palette · `Ctrl B` / `Ctrl Alt B` / `Ctrl J` toggle panels · drag the 1 px dividers to resize.
- Click the **Live** switch in Services, the **+** next to it, and the sliders icon in the Logs toolbar for the configuration dialogs.
- Click into the terminal and type `help`, `free -h`, or `systemctl restart redis-server` (watch the Services panel).

The prototype loads Inter, JetBrains Mono and Phosphor icons from public CDNs; offline it falls back to system fonts and missing icons.

## Workflow
1. UI change → update `ui-spec.md` (and tokens if needed) → update the prototype if the change is visual → implement.
2. Protocol change → update `collector-protocol.md` first, bump the `HELLO` protocol version if the frame format changes.
3. Non-obvious choice → add a `D-0xx` entry to `decisions.md`.
