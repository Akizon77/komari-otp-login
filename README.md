# Komari One-time Code Login

This plugin adds a one-time-code sign-in button to Komari's login screen. Selecting it opens a dialog styled with Komari's current Radix Dialog classes. The user must enter the configured Komari username before the plugin sends an eight-character uppercase letter-and-number code through Komari's notification channels.

## Install

1. Configure and test at least one notification channel in Komari.
2. Compress the contents of this directory so that `komari-plugin.json` is at the ZIP root.
3. Upload and enable the ZIP from **Admin > Plugins**. Approve the requested route, HTML injection, Node runtime, and system RPC permissions.
4. (Optional) Adjust code lifetime and rate-limit thresholds in **Admin > Plugins > Configuration**.

## Security behavior

- The generated eight-character code is stored only as a SHA-256 digest with a random salt.
- **Single active code at a time**: only one verification code exists in memory at any instant. Concurrent send requests are serialized, and issuing a new code immediately replaces and invalidates any prior active code.
- **Single notification per code**: each generated code verifies that Komari notifications are enabled with a configured channel (`admin:getSettings`), dispatches `admin:sendNotification` at most once, and is never retried for the same code.
- A code is scoped to the requesting IP address and username (compared in constant time), expires after the configured lifetime (default: 3 minutes), and is invalidated immediately upon verification or after exceeding the per-code failed attempt limit (default: 5).
- **Global and per-IP rate limiting**: both `/send` and `/verify` enforce rolling-window global and per-IP rate limits before username lookup or code verification, with bounded IP tracking memory.
- **Request & session hardening**: endpoints enforce `Content-Type: application/json`, reject `Sec-Fetch-Site: cross-site` requests, sanitize and bound `User-Agent` values, and issue `HttpOnly; SameSite=Lax` (plus `Secure` over HTTPS) sessions.
- Successful verification creates a normal Komari session with a 30-day lifetime and sends a login-success notification.

> **Deployment notes**:
> - Per-IP rate limiting and IP scoping rely on your reverse proxy overwriting `X-Forwarded-For` / `X-Real-IP` / `X-Forwarded-Proto` when Komari is exposed publicly.
> - One-time code login signs in directly via the configured Komari notification channel without prompting for TOTP 2FA; treat notification channel access and Komari audit logs as sensitive.

## Configuration

All settings can be configured in **Admin > Plugins** via the plugin manifest (`komari-plugin.json`):

| Key | Default | Range | Description |
| --- | --- | --- | --- |
| `code_ttl_seconds` | `180` | `30–3600` | Active code lifetime in seconds |
| `resend_cooldown_seconds` | `60` | `5–3600` | Minimum interval between issuing new codes |
| `max_code_attempts` | `5` | `1–100` | Failed verification tries before invalidating the active code |
| `global_send_window_seconds` | `900` | `10–86400` | Global rolling window for `/send` requests |
| `global_send_max_requests` | `10` | `1–1000` | Maximum total `/send` requests across all IPs in the global window |
| `global_verify_window_seconds` | `900` | `10–86400` | Global rolling window for `/verify` requests |
| `global_verify_max_requests` | `30` | `1–5000` | Maximum total `/verify` requests across all IPs in the global window |
| `ip_send_window_seconds` | `900` | `10–86400` | Per-IP rolling window for `/send` requests |
| `ip_send_max_requests` | `5` | `1–1000` | Maximum `/send` requests per IP in the window |
| `ip_verify_window_seconds` | `900` | `10–86400` | Per-IP rolling window for `/verify` requests |
| `ip_verify_max_requests` | `10` | `1–5000` | Maximum `/verify` requests per IP in the window |

The plugin uses Komari's configured notification routes through `admin:sendNotification`; it does not store notification credentials.
