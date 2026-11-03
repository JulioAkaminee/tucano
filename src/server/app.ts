// The server's HTTP side: who may come in, and what each request gets. It lives apart from index.ts, which boots
// the core and listens, so a test can run it on a port of its own with a stand-in for the core (test/app.test.ts).
// Every request needs a token: the server's own, or the one a paired device was given (pairing.ts).
import { createHash, timingSafeEqual } from 'node:crypto'
import { existsSync, readFileSync, statSync } from 'node:fs'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { extname, join, normalize, sep } from 'node:path'
import { clearedCookie, clientKey, cookieValue, decodePart, parseJson, sameOrigin, sessionCookie, Strikes } from './guard'
import { cookieName, type Pairing, pairRequest, SESSION_MS } from './pairing'

// One connection of a page to the core. What the core sends goes to the `write` it was opened with; what the page
// sends goes to `send`. `start` hands the connection to the core, once the page has been told its id.
export type Link = { send(data: unknown): void; close(): void }
export type Core = {
  open(write: (msg: unknown) => void): Link & { id: string; start(): void }
  find(id: string): Link | undefined
}

export type AppOptions = {
  pairing: Pairing
  token: string // the server's own
  serverId: string
  dataDir: string
  page: string // where the built screens are
  index: () => string // the page's HTML, with the policy and bridge script for a browser
  web: string // the bridge script (tucano-web.js)
  core: Core
  origins?: readonly string[] // TUCANO_ORIGINS
  cookieSecure?: boolean // TUCANO_COOKIE_SECURE
  strikes?: Strikes
  beatMs?: number // how often an open event stream checks its device again
  rpcMax?: number // the largest request the page may send up
}

const TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.woff2': 'font/woff2',
  '.mp3': 'audio/mpeg',
  '.wav': 'audio/wav',
  '.pdf': 'application/pdf',
  '.txt': 'text/plain; charset=utf-8',
  '.md': 'text/plain; charset=utf-8',
  '.csv': 'text/csv; charset=utf-8'
}

const JSON_BODY = { 'content-type': 'application/json', 'cache-control': 'no-store' }

// What is sent is read first: once writeHead has run the headers count as sent, and a failure after it could no
// longer be answered with an error, only with an empty page.
function file(res: ServerResponse, path: string, headers: Record<string, string> = {}): void {
  if (!existsSync(path) || !statSync(path).isFile()) return void res.writeHead(404).end('not found')
  const data = readFileSync(path)
  res.writeHead(200, { 'content-type': TYPES[extname(path).toLowerCase()] ?? 'application/octet-stream', ...headers }).end(data)
}

function body(req: IncomingMessage, max: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0
    req.on('data', (c: Buffer) => {
      size += c.length
      if (size > max) return reject(new Error('too large'))
      chunks.push(c)
    })
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

// A bug while handling one request answers that request and goes no further.
function fail(res: ServerResponse): void {
  if (!res.headersSent) res.writeHead(500)
  res.end()
}

// Compared by digest, so a token of another length or with other characters is only a wrong one.
const digest = (s: string): Buffer => createHash('sha256').update(s).digest()

export function createApp(o: AppOptions): (req: IncomingMessage, res: ServerResponse) => void {
  const { pairing, core, dataDir, page } = o
  const COOKIE = cookieName(o.serverId)
  const origins = o.origins ?? []
  const strikes = o.strikes ?? new Strikes()
  const beatMs = o.beatMs ?? 25_000
  const rpcMax = o.rpcMax ?? 64 * 1024 * 1024

  const tokenDigest = digest(o.token)
  const sameToken = (t: string | undefined): boolean => !!t && timingSafeEqual(digest(t), tokenDigest)
  // The server's own token (a script's Authorization: Bearer, or the ?token= link) or a paired device's.
  const allowed = (t: string | undefined): boolean => sameToken(t) || !!pairing.check(t)

  function route(req: IncomingMessage, res: ServerResponse, url: URL): void {
    const who = clientKey(req.socket.remoteAddress, req.headers['x-forwarded-for'])
    const secure = o.cookieSecure === true || req.headers['x-forwarded-proto'] === 'https'

    const cookie = cookieValue(req.headers.cookie, COOKIE)
    const bearer = /^Bearer (\S+)$/i.exec(req.headers.authorization ?? '')?.[1]
    const sent = [cookie, bearer]
    // A paired device's token is 256 random bits: there is nothing to guess, so the wait below never turns one
    // away. Through an SSH tunnel every client reaches the server from 127.0.0.1, and one wrong code typed ten
    // times would otherwise lock out the app that is already paired. The server's own token is not like that
    // (TUCANO_TOKEN can be short), so a wait does turn it away.
    const device = sent.find((t) => !!pairing.check(t))

    // Wrong tokens and codes, counted by who sent them: 10 in 10 minutes, then a wait (guard.ts).
    const wait = strikes.retryAfter(who)
    if (wait && device === undefined) {
      return void res
        .writeHead(429, { 'content-type': 'text/plain; charset=utf-8', 'retry-after': String(wait) })
        .end('Tucano: too many wrong tokens, try again later.\nTucano: tokens errados demais, tente de novo mais tarde.')
    }

    // The app (or a script) trades a pairing code for its token by POST and keeps the token itself: it is sent
    // back in the body, with no cookie to pick out of a Set-Cookie header. A wrong code counts like a wrong token;
    // a body that isn't a request for one isn't a guess.
    if (url.pathname === '/pair' && req.method === 'POST') {
      if (!sameOrigin(req.headers.origin, req.headers.host, origins)) return void res.writeHead(403).end()
      body(req, 4096)
        .then(
          (text) => {
            const ask = pairRequest(text)
            if (!ask) return void res.writeHead(400).end()
            const issued = pairing.redeem(ask.code, ask.label)
            if (!issued) {
              strikes.fail(who)
              return void res.writeHead(401, JSON_BODY).end(JSON.stringify({ error: 'wrong or expired code' }))
            }
            strikes.clear(who)
            res
              .writeHead(200, JSON_BODY)
              .end(JSON.stringify({ server: o.serverId, token: issued.token, device: issued.device, days: SESSION_MS / 86_400_000 }))
          },
          () => res.writeHead(413).end()
        )
        .catch(() => fail(res))
      return
    }

    // A browser signs in with a pairing code (…/?pair=CODE, made by `pair` on this machine) or with the
    // server's own token (…/?token=…). Either is traded for a token of the browser's own, kept in a
    // cookie, good for 30 days from its last use and revocable: the server's own token never sits in
    // the cookie. Then the code or token is dropped from the address bar. Lax, not Strict: the link is
    // often clicked from elsewhere (a chat), and a Strict cookie wouldn't ride the redirect that follows.
    // Lax still keeps it off other sites' POSTs to /rpc.
    const code = url.searchParams.get('pair') ?? undefined
    const given = url.searchParams.get('token') ?? undefined
    const signedIn = (code !== undefined ? pairing.redeem(code) : undefined) ?? (sameToken(given) ? pairing.enroll('browser') : undefined)
    if (signedIn) {
      strikes.clear(who)
      return void res
        .writeHead(302, {
          // The shared name from before pairing is dropped too: that cookie held the server's own token.
          'set-cookie': [sessionCookie(COOKIE, signedIn.token, SESSION_MS / 1000, secure), clearedCookie('tucano', secure)],
          location: '/'
        })
        .end()
    }

    // Whichever proves who is asking, kept to prove it again on a stream that stays open.
    const proof = device ?? sent.find(sameToken)
    if (proof === undefined) {
      // Opening the address with no token at all isn't a guess, and doesn't count.
      if (code !== undefined || given !== undefined || cookie !== undefined || bearer !== undefined) strikes.fail(who)
      // A cookie that opens nothing any more (revoked, expired) is taken back, so a page left open stops sending
      // it, and stops being counted against its owner with every request.
      const stale = cookie === undefined ? {} : { 'set-cookie': clearedCookie(COOKIE, secure) }
      return void res
        .writeHead(401, { 'content-type': 'text/plain; charset=utf-8', ...stale })
        .end('Tucano: open the link the server printed (…/?token=…), or pair with a code (…/?pair=CODE).\nTucano: abra o link que o servidor mostrou (…/?token=…) ou pareie com um código (…/?pair=CÓDIGO).')
    }

    if ((url.pathname === '/events' || url.pathname === '/rpc') && !sameOrigin(req.headers.origin, req.headers.host, origins)) {
      return void res.writeHead(403).end()
    }

    if (url.pathname === '/events') {
      const link = core.open((msg) => res.write(`data: ${JSON.stringify(msg)}\n\n`))
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', 'x-accel-buffering': 'no' })
      res.write(`event: hello\ndata: ${link.id}\n\n`)
      // On each beat, the device is checked again: one revoked since is cut off here.
      const beat = setInterval(() => (allowed(proof) ? res.write(': \n\n') : res.end()), beatMs)
      link.start()
      req.on('close', () => {
        clearInterval(beat)
        link.close()
      })
      return
    }

    if (url.pathname === '/rpc' && req.method === 'POST') {
      const link = core.find(url.searchParams.get('c') ?? '')
      if (!link) return void res.writeHead(410).end()
      body(req, rpcMax)
        .then(
          (text) => {
            const msg = parseJson(text)
            if (!msg) return void res.writeHead(400).end()
            link.send(msg.value)
            res.writeHead(204).end()
          },
          () => res.writeHead(413).end()
        )
        .catch(() => fail(res))
      return
    }

    // What the agents showed in the chat, sandboxed as on the desktop.
    const art = /^\/artifact\/([0-9a-f-]{36})\/([^/]+)$/.exec(url.pathname)
    if (art) {
      const dir = join(dataDir, 'artifacts', art[1]!)
      const name = decodePart(art[2]!)
      if (name === undefined) return void res.writeHead(400).end()
      const path = normalize(join(dir, name))
      if (!path.startsWith(dir + sep)) return void res.writeHead(404).end()
      return file(res, path, { 'content-security-policy': 'sandbox allow-scripts allow-popups' })
    }

    if (url.pathname === '/tucano-web.js') return void res.writeHead(200, { 'content-type': TYPES['.js']! }).end(o.web)
    if (url.pathname === '/' || url.pathname === '/index.html') {
      const html = o.index()
      return void res.writeHead(200, { 'content-type': TYPES['.html']!, 'cache-control': 'no-cache' }).end(html)
    }
    const rel = decodePart(url.pathname)
    if (rel === undefined) return void res.writeHead(400).end()
    const path = normalize(join(page, rel))
    if (!path.startsWith(page + sep)) return void res.writeHead(404).end()
    file(res, path)
  }

  return (req, res) => {
    const url = new URL(req.url ?? '/', 'http://x')
    res.setHeader('x-content-type-options', 'nosniff')
    res.setHeader('referrer-policy', 'no-referrer')
    try {
      route(req, res, url)
    } catch {
      fail(res)
    }
  }
}
