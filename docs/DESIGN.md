# SecureMesh dashboard design system

The dashboard is a local engineering/security console. It applies the deliberate palette, typography and composition principles in [Alan West's design article](https://dev.to/alanwest/how-to-fix-the-ai-generated-look-in-your-frontend-1ahh); it does not reproduce the article's example design.

## Visual vocabulary

| Token | Value | Purpose |
| --- | --- | --- |
| ink | `#161818` | Header, navigation, chart and form inset |
| canvas | `#1d2020` | Main working surface |
| surface | `#252828` | Selected navigation and notices |
| line | `#3b4040` | Structural borders |
| text | `#eeeae0` | Warm off-white primary text |
| muted | `#adb1aa` | Readable supporting text |
| accent | `#d0b77e` | Restrained brass: actions, focus and chart |
| success | `#9cbd9e` | Genuine active/authenticated/executed states |
| danger | `#e7a3a0` | Revocation, blocked messages and actual failure |

Segoe UI with Helvetica Neue/Arial fallbacks carries interface text. Cascadia Code with Consolas/Liberation Mono fallbacks identifies device/session/command IDs, fingerprints, timestamps, sequences and protocol events. Local system fonts require no external requests. Labels use selective uppercase; headings and body copy use sentence case. Numeric totals use tabular figures.

Spacing follows 4, 8, 12, 16, 24, 32 and 36-pixel steps. Radius is zero for structural regions and tables, three pixels for controls/dialogs, and circular only for tiny status dots. There are no shadows, gradients, floating metric cards or glow effects. Thin borders divide shared surfaces.

## Layout and components

A charcoal identity header and narrow numbered navigation frame the working canvas. A shared metric ledger leads overview; a real temperature timeline occupies the next band. An asymmetric registry/audit split makes operational state and security decisions visible together. Tables carry density; each major region has a heading, supporting context and an empty state. Device detail uses identity/session definitions above telemetry, commands and events. Command center places a restrained form beside its audit history.

All states include text; color supplements the label. Authentication, registration and simulator state remain distinct. Administrative session invalidation is ACCEPTED, not a blocked message. Unknown security event codes are INFO, not invented attacks. Missing ACKs are shown as awaiting acknowledgement. Expired commands retain the explicit warning that execution may have occurred.

Charts use actual samples, measured times and auto-scaled temperature axes. Multiple devices have labeled series with different dash patterns. A single reading is a point; no synthetic time series is inserted. Tables supply exact numeric values and keyboard-accessible device links.

Buttons, filters and forms use semantic HTML and visible brass focus outlines. Tables have captions and column headers. Native modal dialogs provide focus containment, Escape/cancel behavior and confirmation for commands, revocation and rotation. A skip link reaches the operational view. Responsive layouts collapse regions while retaining horizontally scrollable dense tables. Reduced-motion preferences disable transitions.

## Actual API mapping and implementation plan

The initial inspection found no frontend framework, no streaming transport, dict/list FastAPI responses, and list-history limits of 100. The smallest maintainable frontend is native ES modules, served on the existing origin. No frontend build server, CDN, framework or authentication facade is introduced.

| View/action | API | Response mapping |
| --- | --- | --- |
| Overview | `GET /api/dashboard` | Exact lifetime totals; health; bounded recent telemetry; registry and events |
| Registry | `GET /api/dashboard` | Public device identity/state, per-device counts, live session and latest reading |
| Device detail | `GET /api/dashboard?device_id=...` | Identity/session/latest reading plus device-scoped recent histories |
| Telemetry | `GET /api/dashboard` | Telemetry payload measurements, timestamp, device_state and envelope sequence |
| Command history | `GET /api/dashboard` | Command ID/type/target/times/status and validated acknowledgement |
| Submit command | Existing `POST /api/devices/{id}/commands` | Existing strict command_type/parameters schema; persisted command metadata |
| Revoke | Existing `POST /api/devices/{id}/revoke` | Device REVOKED; subsequent snapshot updates state/session |
| Rotate | Existing `POST /api/devices/{id}/sessions/rotate` | Rotation requested; subsequent snapshot reflects reauthentication |
| Security events | `GET /api/dashboard` | Backend event metadata with explicit decision/severity/reason projection |

Existing `/health`, `/api/devices`, `/api/telemetry`, `/api/commands`, `/api/sessions` and `/api/security-events` remain available unchanged. One new read-only projection is needed because counts cannot be computed from truncated histories. It reads one SQLite transaction, uses explicit public device fields, retains original session metadata-only schemas, and does not serialize live cryptographic objects. Histories default to 200 and are capped at 500. Filters on the telemetry/security/history views operate on the labeled recent window, not the entire archive. Device detail requests its own history so quieter devices are not lost in global traffic.

Data fetching is a single non-overlapping five-second snapshot request. Hidden tabs pause; failures back off to 30 seconds; requests time out after 10 seconds; stale scope responses are discarded. Mutation completion requests an immediate refresh, then normal refresh resumes. Forms retain drafts and focus as data changes. No WebSocket/SSE is justified for this local desktop scope.

Implementation order: inspect/map APIs; add read-only projection; build tokens/layout and view modules; connect existing mutations with confirmations; test projection/browser behavior and real devices; inspect desktop/mobile screenshots; run all regression checks.

## Trust boundary

The dashboard inherits the trusted-localhost assumption. There is no administrator login, and browser controls do not replace backend authorization. Keep FastAPI bound to loopback. Browser requests are same-origin; no credentials, private keys, CA private key, session keys or shared secrets are exposed. Backend strings are escaped before HTML rendering. A restrictive page Content Security Policy blocks external scripts, framing and object embedding. The existing cryptographic protocol and command authorization are unchanged.
