# Pairing devices with the server

The server doesn't hand its own token to every browser. Each device is **paired**: it trades a
one-time code for a token of its own, so you can see who is signed in and take one device's access
away without touching the others.

## Pair a device

On the machine the server runs on:

```sh
node out/main/server.js pair --label "My Mac"
```

It prints a code like `K7QM-2XPD-9TWH` and a link, `http://127.0.0.1:7337/?pair=K7QM-2XPD-9TWH`.

- The code works **once**, for **one device**, for **5 minutes**.
- Open the link in the browser (through your SSH tunnel, Tailscale address or proxy: use the address
  you reach the server at). The browser trades the code for its own token, kept in a cookie, and the
  address bar goes back to `/`.
- The device's token lasts **30 days from its last use**. Using it renews it.
- The server keeps only a hash of the code and of each token, in `pairing.json` in the data directory
  (readable only by the server's user).

## See and revoke

```sh
node out/main/server.js devices            # id, label, paired, last seen
node out/main/server.js revoke <id|label>  # one device
node out/main/server.js revoke --all       # every device, and the codes not used yet
```

A revoked device is refused on its next request, and a page it already has open is cut within half a
minute.

## The server's own token

`…/?token=…` (the link the server prints at start) and `Authorization: Bearer <token>` still work, for
scripts and for what you set up before pairing. Signing in with the token now gives the browser a
device token of its own too, so the server's own token no longer sits in a cookie for a year. A cookie
made before pairing still works until you replace it; to cut those, set a new `TUCANO_TOKEN` (or
delete `server-token` in the data directory and restart).

## Wrong codes

A wrong code counts like a wrong token: 10 in 10 minutes from one address, then a wait (see
`guard.ts`). With 12 characters from a 32-character set a code has 60 bits, and it dies in 5
minutes.
