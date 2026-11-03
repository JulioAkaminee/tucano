# Running your agents on a server, from the Mac app

The Mac app can use a Tucano server (see [server.md](server.md)) as if it were its own: the agents, their conversations, memory and logins live on the server, run while your Mac sleeps, and you use them from a window of the app.

```
Mac app ──ssh tunnel──▶ your server (127.0.0.1:7337)
   │                         │ Tucano's core, agents, data
   └─ a window with the server's own screens
```

## Set it up

**1. On the server**, as the user that will run Tucano (not root), on Linux x64 or ARM64 with systemd:

```sh
curl -fsSL https://github.com/eduwxyz/tucano/releases/latest/download/install-server.sh | sh -s -- --label "My Mac" --host vps.example.com
```

It installs the server (with a Node 24 of its own if the system has none, checked against a SHA-256), runs it as a systemd user service that listens on `127.0.0.1` only, adds the `tucano-server` command, and prints a one-time pairing code and a `tucano://pair?…` link. The link names this machine's SSH address and its SSH host key.

To keep it running after you log out of SSH and across reboots, run once `sudo loginctl enable-linger $USER`; the script says so when it is needed.

**2. On the Mac**, in the Tucano app: **Settings → Servers**, paste the link, **Continue**, check the address, **Add**. The app opens an SSH tunnel, trades the code for a token of its own, and opens a window with the server's screens. Opening it again later is one click on **Open**.

The Mac's `ssh` has to be able to log in to the server as that user with a key (or an agent): the app never asks for a password. Try `ssh you@vps.example.com` in Terminal first if it says it can't.

No link? In **Settings → Servers** choose **No link? Type it in**, and give the address (`you@vps.example.com`) and the code from `tucano-server pair`. The app then shows the SSH key the server presents: compare it with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server before you accept it.

The first time, the server shows its own introduction, like a new Tucano does: pick your name, sign the harnesses in on the server ([server.md](server.md#signing-the-harnesses-in)), and add agents there. A server and your Mac keep separate agents and conversations.

## How it is kept safe

- **The server opens no port.** The tunnel ends on its loopback. Nothing listens on a public address, so there is nothing to scan or to guess at.
- **The server is who you confirmed.** The link carries the server's SSH host key, or the app shows it for you to compare. The app keeps that key in a `known_hosts` of its own and runs `ssh` with strict checking on it, ignoring `~/.ssh/known_hosts` and your ssh config's connection sharing and agent forwarding. A reinstalled server, or someone in between, shows another key and is refused.
- **The link is not trusted.** It can come from a chat or a web page, and it becomes an `ssh` command, so a link that could make `ssh` read an option, or carries more than a name, an address and a code, is refused whole (`src/shared/pairlink.ts`). A link opened from outside only fills the form in: nothing connects until you press **Add**.
- **The token stays out of sight.** It goes in the system's keychain, never in the page, an address or a cookie. The server's window adds it as a header to requests to the server's own address, and to nothing else; a link in a page goes to your browser, not into the window.
- **Revoking works.** `tucano-server revoke <id>` (or `--all`) on the server cuts a Mac off: the open window says so, and the list says **pair again** until you do.
- **A wrong code costs the server's patience, not yours.** After 10 wrong tries the server answers 429 for 10 minutes ([pairing.md](pairing.md)).

## More than one server

Add as many as you like. Each has its own tunnel on its own local port, its own token and its own window, and what a server's page saves stays with that server. **Disconnect** ends a tunnel and closes its window; **Remove** also forgets the token and the SSH key (unless another server is at the same address). The tunnel starts when you open a server and again when the Mac wakes or the network changes.

## If something fails

| The app says | Do |
|---|---|
| The server didn't accept this Mac's SSH key | `ssh-copy-id you@vps.example.com`, and check that `ssh you@vps.example.com` works in Terminal |
| The server's SSH key is not the one you confirmed | If you reinstalled the server, **Remove** it and add it again. If you didn't, don't: someone may be between you and the server |
| Connected, but Tucano isn't answering on port 7337 | On the server: `systemctl --user status tucano` and `journalctl --user -u tucano` |
| The server didn't take that code | A code works once and for 5 minutes. Make another: `tucano-server pair --label "My Mac" --ssh you@vps.example.com` |
| The server no longer accepts this Mac | It was revoked there. **Remove** it and pair again |
| That server's SSH doesn't allow port forwarding | `AllowTcpForwarding yes` in the server's `sshd_config` |

## Without the app

`tucano-server pair --ssh you@vps.example.com` also prints an `ssh -N -L …` command and an address for a browser: open the tunnel yourself and use the server from any browser ([server.md](server.md#reaching-it)).
