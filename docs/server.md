# Tucano on a server

Tucano can run on a server you own, such as a VPS or a machine at home. On a server, routines keep running when your computer sleeps, and you use Tucano from a browser, on any computer or phone. The server runs Tucano's core on plain Node and serves the app's own screens to the browser. Nothing goes through a Tucano service: the server is yours, and so are the data and the logins on it.

Status: **new and experimental.** The core, the screens and the agents work in a browser, tested on Linux (Debian 12, Node 24) and macOS. A real agent turn on a server has only been tested with the test engine so far.

## What you need

| | |
|---|---|
| Linux, x64 or ARM64 | Any VPS with 2 GB of RAM or more |
| [Node.js](https://nodejs.org) 24+ | Tucano's database is Node's built-in SQLite |
| At least one harness, installed and signed in | Signed in **on the server**, as the user that runs Tucano (see below) |
| Optional: Docker Engine | For agents' isolated Linux computers |
| Optional: Chromium or Google Chrome | For agents' browsers (`apt install chromium`) |

## Install

As the user that will run Tucano (not root):

```bash
git clone https://github.com/eduwxyz/tucano.git
cd tucano
ELECTRON_SKIP_BINARY_DOWNLOAD=1 npm ci   # the server doesn't need Electron itself
npm run build
npm run server
```

It prints the address to open:

```
Tucano server: http://127.0.0.1:7337/
```

Open that address and enter the token from `~/.tucano-server/server-token` (or from `TUCANO_TOKEN` if configured). Read the file in your private SSH terminal, for example with `cat ~/.tucano-server/server-token`, and paste it into the password field. The form sends it in a POST body, and an HttpOnly, SameSite=Lax cookie keeps the browser signed in. Do not put tokens in URLs: old `?token=` links are rejected and the server no longer prints the token. Existing cookies for the default generated token keep working.

To sign every browser out, delete `server-token` and restart Tucano, or change `TUCANO_TOKEN` and restart if using that override. Never enable request-body or cookie logging at a reverse proxy.

### Signing the harnesses in

Sign each harness in on the server, in a terminal over SSH:

```bash
curl -fsSL https://claude.ai/install.sh | bash && claude auth login   # prints a link and asks for the code
npm install -g @openai/codex
```

Codex is signed in from Tucano's **Settings › Models**, like on a desktop. On a server, the **Sign in** button can't open a terminal, so it shows the command to run in your SSH session.

## Reaching it

By default the server only listens on the server itself (`127.0.0.1`), because anyone who has the token controls your agents. Pick one of these ways to reach it:

- **SSH tunnel**, the simplest: run `ssh -L 7337:127.0.0.1:7337 you@your-server`, then open the printed link on your computer.
- **Tailscale** (or another private network): set `TUCANO_HOST` to the server's Tailscale address, then open `http://<that address>:7337/` from any of your devices, including your phone.
- **A reverse proxy with HTTPS** (Caddy, nginx) on a domain of yours: keep Tucano on `127.0.0.1` and point the proxy at it. Turn off response buffering for `/events`, which is a live event stream. For example, with Caddy:

  ```
  tucano.example.com {
    reverse_proxy 127.0.0.1:7337 {
      flush_interval -1
    }
  }
  ```

Never expose port 7337 on a public address without HTTPS. Set `TUCANO_COOKIE_SECURE=1` when serving through HTTPS so browsers never send the authentication cookie over plain HTTP. Leave it off for a plain HTTP loopback SSH tunnel.

The browser's `Origin` must match the request's scheme, host and port on `/login`, `/events` and `/rpc`. If an HTTPS proxy rewrites `Host`, list its public origin in `TUCANO_ORIGINS`, for example `https://tucano.example.com`. Command-line requests without `Origin` still require authentication.

Forwarded headers are ignored by default, including through SSH tunnels. To use a reverse proxy **on the same machine**, set `TUCANO_TRUST_PROXY=1` and keep the listener private. Only loopback peers are then trusted: `X-Forwarded-Proto: https` marks cookies Secure, and the last entry in `X-Forwarded-For`, if it is a valid IP, identifies the client for failed-login limits. The proxy must overwrite or append the real peer IP, and overwrite the protocol header. Do not enable this for direct clients or SSH tunnels, which can supply these headers themselves. Non-loopback proxies need the explicit cookie/origin settings and share the socket-address rate limit.

Ten wrong token attempts from an address in ten minutes cause new authentication attempts to return `429` with `Retry-After`. Visits without credentials do not count. Invalid cookies are expired. During the wait, all authentication from that address is blocked, including valid cookies: clients sharing an address or SSH tunnel share the limit. The limit is in memory and resets on restart; use a long random token and your proxy's own limits too.

## Keeping it running

Run Tucano as a systemd service, under your own user. Save this as `/etc/systemd/system/tucano.service` and change the user and the path:

```ini
[Unit]
Description=Tucano
After=network-online.target

[Service]
User=you
WorkingDirectory=/home/you/tucano
ExecStart=/usr/bin/npm run server
Restart=on-failure
Environment=TUCANO_PORT=7337

[Install]
WantedBy=multi-user.target
```

Then run `sudo systemctl enable --now tucano`. The logs, including the address but never the token, are in `journalctl -u tucano`.

To update Tucano, run `git pull && npm ci && npm run build && sudo systemctl restart tucano`.

## Settings

| Variable | Default | |
|---|---|---|
| `TUCANO_DATA` | `~/.tucano-server` | Where everything is kept: database, memory, agents' files, the key and the token |
| `TUCANO_HOST` | `127.0.0.1` | The address to listen on |
| `TUCANO_PORT` | `7337` | |
| `TUCANO_TOKEN` | a random token, kept in `server-token` | Set it to use a long random token of your own |
| `TUCANO_COOKIE_SECURE` | unset | `1` requires HTTPS for authentication cookies; also tells the Origin check the external scheme is HTTPS |
| `TUCANO_ORIGINS` | unset | Additional HTTP(S) origins, comma separated, for a proxy that rewrites Host |
| `TUCANO_TRUST_PROXY` | unset | `1` trusts forwarded client IP/protocol headers only from loopback peers; see the restrictions above |

## How it differs from the desktop app

- **Connectors that sign in with OAuth** (an **Authorize in the browser** button): Tucano opens the authorization page in your browser. When you allow access, the page ends on an address starting with `http://127.0.0.1` that doesn't load, because that address is the server's own. Copy the whole address from the address bar and paste it into Tucano.
- **Secrets** (connector keys, Telegram, GitHub) are encrypted with AES-256-GCM. The key is in `server.key` in the data folder, and only your user can read that file. A desktop app keeps that key in the system's keychain instead. Back the key up together with the data folder: the secrets can't be read without it.
- **Notifications:** connect Telegram (**Settings › Phone and GitHub**) to get approvals, questions and results on your phone. The browser doesn't pop up notifications.
- **Agents' browsers** need Chromium or Chrome on the server, and run without a window. **Take over** doesn't open a window there: the live picture of the browser in the panel becomes the browser. Click on it, type, paste and scroll, then click **Hand back**. This is how you sign in to a site for an agent.
- **Pages agents serve** (a dashboard, an API) listen on the server's own `127.0.0.1`. Agents take their screenshots with the server's Chrome. When Tucano listens on a private address (Tailscale or a home network), it also passes each running page through on the same port at that address, so the preview panel and **Open** work from your computer. That doesn't happen on a public address, because those pages have no token. Over an SSH tunnel, forward the page's port too (`-L 5173:127.0.0.1:5173`).
- **Choosing a folder** asks for its path on the server, since the browser can't browse the server's disk.
- **No self-update.** Update with `git pull` (see above).
- **One Tucano per data folder.** Don't run the desktop app and the server on the same data folder at the same time.
