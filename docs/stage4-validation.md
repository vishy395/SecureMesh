# Stage 4 validation

Validated on 2026-10-03 with Python 3.12.2, Windows, Microsoft Edge (headless Playwright) and the project-local Mosquitto executable.

## Implemented scope

All six requested views are implemented: overview, device registry, device detail, telemetry, command center and security events. They use real backend data, empty/loading/error states, five-second snapshots, preserved command drafts/focus, keyboard navigation and confirmations. Desktop and mobile layouts were inspected as rendered in a real browser.

The frontend uses native ES modules and local CSS, served by FastAPI at `/`. No framework, Node build step, CDN or external font is required. The palette is charcoal, warm off-white and restrained brass, with green/red reserved for actual state. Shared structural borders, a metric ledger, asymmetric registry/audit regions and dense tables replace floating rounded cards.

## Actual API integration

Existing Stage 3 GET and POST endpoints were inspected before implementation and remain available. Commands, revocation and rotation use their existing endpoints and policies. One read-only `GET /api/dashboard` projection was added for exact lifetime counts, current registry/session state, certificate validity dates, latest per-device readings and consistent bounded histories. It reads one SQLite transaction; optional device_id scopes histories, and limit defaults to 200 with a maximum of 500. History filters are explicitly scoped to that recent window.

No database schema, cryptographic protocol, handshake, envelope, session security, transport, command authorization or device execution code was changed. Private keys, CA private keys, session keys, shared secrets and broker credentials never enter the dashboard projection or frontend. Event classification distinguishes explicit BLOCKED, ACCEPTED, FAILED and INFO backend decisions; administrative revocation is not counted as a blocked message.

## Changed files

- `securemesh/server/main.py`: snapshot route, same-origin static serving, dashboard security headers and Stage 4 health metadata.
- `securemesh/server/dashboard.py`: read-only public projection and explicit event presentation.
- `securemesh/web/index.html`, `styles.css`: semantic console shell and project-specific visual tokens.
- `securemesh/web/api.js`, `store.js`, `format.js`, `app.js`: API requests, refresh lifecycle, safe formatting and layout/action orchestration.
- `securemesh/web/components/ui.js`, `chart.js`: shared accessible tables/statuses/empty states and actual-sample telemetry plotting.
- `securemesh/web/views/overview.js`, `device.js`, `telemetry.js`, `commands.js`, `security.js`: domain-specific views; registry is organized with overview.
- `pyproject.toml`: Playwright test-only dependency and static package-data inclusion.
- `tests/integration/test_dashboard_api.py`: 10 projection/integration cases.
- `tests/frontend/conftest.py`, `test_dashboard.py`, `test_live_dashboard.py`: real-browser fixtures and 11 browser tests.
- `docs/DESIGN.md`: visual system, actual API/view mapping, implementation plan and trust boundary.
- `README.md`: launch, test, browser prerequisite and local-operator instructions.
- `docs/stage4-validation.md`: this report.

## Test results

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
git diff --check
```

**202 passed, zero failed, zero skipped**, in 63.10 seconds. This includes all 181 existing Stage 1–3 tests, 10 new dashboard backend cases and 11 real-browser cases. `pip check`: **No broken requirements found.** `git diff --check`: clean. The existing Starlette TestClient/httpx deprecation warning remains. No frontend lint/type-check configuration exists; all frontend modules are parsed and executed in the browser tests.

Projection tests verify totals beyond truncated history limits, correct revoked/expired session counts, scoped histories, explicit event decisions, public identity fields, static serving and path-traversal rejection. Browser tests cover all empty views, keyboard navigation, real revocation/cancel, event filtering, data mapping, HTML escaping, initial/stale backend failures, missing devices, mobile width, discarded late responses, preserved form draft/focus and single-sample plotting.

## Live browser demonstration

The live test starts isolated real Mosquitto and FastAPI processes, provisions temporary identities for device-01/device-02/device-03 and launches all three real simulators. The rendered dashboard shows all devices and actual telemetry. Through the UI it submits START, CHANGE_THRESHOLD, STOP, UPDATE_CONFIG and RESTART, confirms each operation and waits for authenticated EXECUTED acknowledgements. Command cancellation is also checked before publication. Restart establishes a new device-01 session.

Through device detail it revokes device-02, verifies inactive session history and disabled command actions, and displays administrative revocation plus rejected communication in the security view. device-01/device-03 remain authenticated. The projection contains no sensitive cryptographic fields. All test processes are stopped during cleanup, and existing workspace registrations are untouched.

Desktop and mobile screenshots were captured and inspected at:

- `runtime/stage4-review/overview-desktop.png`
- `runtime/stage4-review/commands-desktop.png`
- `runtime/stage4-review/revoked-device.png`
- `runtime/stage4-review/security-desktop.png`
- `runtime/stage4-review/overview-revoked.png`
- `runtime/stage4-review/overview-mobile.png`

These local review artifacts are ignored by Git and regenerated by the live browser test. Review confirmed structured hierarchy, readable operational typography, actual metrics, visible security decisions, consistent spacing, restrained borders/radii and no generic purple/blue gradient/card treatment. UTF-8 symbol rendering, accessible navigation names and small-screen chart axes were corrected during review.

## Reproduction and limitations

Follow the broker/server/three-device launch commands in [README](../README.md#stage-4-control-center-dashboard), then open http://127.0.0.1:8000/. No separate dashboard process is required.

For an isolated live demonstration:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/frontend/test_live_dashboard.py -v -s
```

Browser tests use installed Edge/Chrome, SECUREMESH_BROWSER_EXE, or Playwright Chromium. Install the project's test extras; when no supported installed browser is available, run `python -m playwright install chromium`. Mosquitto is discovered at the project-local path or via SECUREMESH_MOSQUITTO_EXE/PATH.

The dashboard retains trusted-localhost access with no administrator login. Keep the server on loopback. Updates are snapshots, not instantaneous streaming; hidden tabs pause and failed requests back off. Histories/filters are bounded, while overview counts are exact database totals. Existing Stage 3 ACK uncertainty, deduplication and revocation limitations still apply. The dashboard exposes those states without weakening backend security.

No attack simulator or Stage 5 work was implemented.
