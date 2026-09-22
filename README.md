# Komari One-time Code Login

This plugin adds a one-time-code sign-in button to Komari's login screen. Selecting it opens a dialog styled with Komari's current Radix Dialog classes. The user must enter the configured Komari username before the plugin sends an eight-character uppercase letter-and-number code through Komari's notification channels. Each code is valid for three minutes.

## Install

1. Configure and test at least one notification channel in Komari.
2. Compress the contents of this directory so that `komari-plugin.json` is at the ZIP root.
3. Upload and enable the ZIP from **Admin > Plugins**. Approve the requested route, HTML injection, Node runtime, and system RPC permissions.

## Security behavior

- The generated eight-character code is stored only as a SHA-256 digest with a random salt.
- A code is scoped to the requesting IP address and username, lasts three minutes, and is invalidated after use.
- Sending another code invalidates every prior active code. Sending is limited to once per minute.
- Five failed verification attempts invalidate the current code.
- Each IP address is limited to ten failed verification attempts in a rolling 15-minute window.
- Successful verification creates a normal Komari session with a 30-day lifetime and sends a login-success notification.

The plugin uses Komari's configured notification routes through `admin:sendNotification`; it does not store notification credentials.
