// Tucano as a server: the core on plain Node (a VPS, a home server), and the
// app's own screens in a browser. Where the desktop app's main process hosts the
// core and the window, this does: it stands in for Electron's parentPort, keeps
// the secrets with a key of its own, and serves the page plus a bridge to the
// core (events down an event stream, requests up by POST). Every request needs
// the server's token.
//
//   node out/main/server.js        (TUCANO_DATA, TUCANO_HOST, TUCANO_PORT, TUCANO_TOKEN)
import { randomBytes, randomUUID } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { homedir } from 'node:os'
import { extname, join, normalize, sep } from 'node:path'
import { pathToFileURL } from 'node:url'
import { Forwarder, isPrivate } from './forward'
import { vault } from './vault'
import { clientKey, cookie, cookieToken, decodePart, parseOrigins, parseRpc, sameOrigin, sameToken, Strikes, trustedProxy } from './guard'

const dataDir = process.env['TUCANO_DATA'] || join(homedir(), '.tucano-server')
const host = process.env['TUCANO_HOST'] || '127.0.0.1'
const port = Number(process.env['TUCANO_PORT'] || 7337)
const page = join(import.meta.dirname, '..', 'renderer')
mkdirSync(dataDir, { recursive: true, mode: 0o700 })

// A file only this user reads, made once: the server's key or token.
function kept(name: string, make: () => string): string {
  const file = join(dataDir, name)
  if (!existsSync(file)) writeFileSync(file, make(), { mode: 0o600 })
  chmodSync(file, 0o600)
  return readFileSync(file, 'utf8').trim()
}
const token = process.env['TUCANO_TOKEN'] || kept('server-token', () => randomBytes(24).toString('base64url'))
// The secrets (Telegram, GitHub, connector keys) are sealed with this key; on a
// desktop it's the system's keychain, which a server doesn't have.
const key = Buffer.from(kept('server.key', () => randomBytes(32).toString('base64')), 'base64')

const { seal, open } = vault(key)

// Electron's MessagePortMain and parentPort, as far as the core uses them.
class Port extends EventEmitter {
  constructor(readonly postMessage: (msg: unknown) => void) {
    super()
  }
  start(): void {}
  close(): void {
    this.emit('close')
  }
}

type CoreRequest = { type: string; id?: string; op?: string; data?: string }
const parent = new Port((msg) => fromCore(msg as CoreRequest))
const toCore = (data: unknown, ports: Port[] = []): boolean => parent.emit('message', { data, ports })

// What the main process does for the core on a desktop. A server has no screen:
// no notifications (Telegram carries them), nothing to open, no login item.
function fromCore(msg: CoreRequest): void {
  const id = msg.id
  if (msg.type === 'secret') {
    try {
      toCore({ type: 'secret-result', id, data: msg.op === 'encrypt' ? seal(msg.data ?? '') : open(msg.data ?? '') })
    } catch (e) {
      toCore({ type: 'secret-result', id, error: e instanceof Error ? e.message : String(e) })
    }
  } else if (msg.type === 'screenshot') {
    toCore({ type: 'screenshot-result', id, error: 'screenshots need the desktop app' })
  } else if (msg.type === 'browser') {
    // Only when there's no Chrome: the core drives Chrome or Chromium itself when one is installed.
    toCore({ type: 'browser-result', id, error: 'install Google Chrome or Chromium on the server for the agents’ browser' })
  }
}

// The page's connections: each one a port of the core, events down its stream.
const clients = new Map<string, Port>()

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

function file(res: ServerResponse, path: string, headers: Record<string, string> = {}): void {
  if (!existsSync(path) || !statSync(path).isFile()) return void res.writeHead(404).end('not found')
  const data = readFileSync(path) // Read before sending headers: failures must not look like a successful response.
  res.writeHead(200, { 'content-type': TYPES[extname(path).toLowerCase()] ?? 'application/octet-stream', ...headers }).end(data)
}

const strikes = new Strikes()
const origins = parseOrigins(process.env['TUCANO_ORIGINS'])
const cookieSecure = process.env['TUCANO_COOKIE_SECURE'] === '1'
const trustProxy = process.env['TUCANO_TRUST_PROXY'] === '1'

// The pages agents serve (a dashboard, an API) listen on the server's own
// loopback. On a private address (Tailscale, a home network) each running one
// is passed through on the same port at the server's address, so the preview
// panel can show it. Never on a public address: those pages have no token.
const privateHost = isPrivate(host)
const forwarder = new Forwarder(host)
const forwardServices = (ports: Set<number>): void => {
  if (privateHost) forwarder.set(new Set([...ports].filter((p) => p !== port)))
}
const servicePorts = new Map<string, number[]>() // by agent
const loopbackPort = (url?: string): number | undefined => (url ? Number(/^http:\/\/127\.0\.0\.1:(\d+)/.exec(url)?.[1]) || undefined : undefined)
type Computer = { agentId: string; services: { url?: string; running: boolean }[] }
function sawComputers(list: Computer[]): void {
  for (const c of list) servicePorts.set(c.agentId, c.services.filter((s) => s.running).flatMap((s) => loopbackPort(s.url) ?? []))
  forwardServices(new Set([...servicePorts.values()].flat()))
}
// The server's own connection to the core, to follow the services.
const watcher = new Port((msg) => {
  const m = msg as { id?: number; result?: { computers?: Computer[] }; event?: { type: string; computer?: Computer } }
  if (m.id === 1 && m.result?.computers) sawComputers(m.result.computers)
  else if (m.event?.type === 'computer' && m.event.computer) sawComputers([m.event.computer])
})

// The desktop page, told it's in a browser: the bridge script first, and its
// policy letting it frame the agents' pages from this server.
function index(): string {
  return readFileSync(join(page, 'index.html'), 'utf8')
    .replace('frame-src tucano:', `frame-src 'self' tucano:${privateHost ? ` http://${host}:*` : ''}`)
    .replace('<title>', '<meta name="viewport" content="width=device-width, initial-scale=1" />\n    <script src="./tucano-web.js"></script>\n    <title>')
}

function body(req: IncomingMessage, limit = 64 * 1024 * 1024): Promise<string> {
  return new Promise((resolve, reject) => {
    let chunks: Buffer[] = []
    let size = 0
    req.on('data', (c: Buffer) => {
      size += c.length
      if (size > limit) {
        chunks = []
        reject(new Error('too large'))
        return // Drain the request without retaining further bytes.
      }
      chunks.push(c)
    })
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
    req.on('aborted', () => reject(new Error('aborted')))
  })
}

// The token goes in a POST body, never a URL, redirect or server log. No scripts or external resources.
const LOGIN = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Tucano</title><h1>Tucano</h1>
<p>Enter the token from the server-token file or TUCANO_TOKEN setting. / Digite o token do arquivo server-token ou da configuração TUCANO_TOKEN.</p>
<form method="post" action="/login"><label>Token <input name="token" type="password" autocomplete="current-password" required></label>
<button type="submit">Sign in / Entrar</button></form></html>`

function fail(res: ServerResponse): void {
  if (res.headersSent) res.destroy()
  else res.writeHead(500).end()
}

async function route(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
  const secure = cookieSecure || (trustedProxy(req.socket.remoteAddress, trustProxy) && req.headers['x-forwarded-proto'] === 'https')
  // Check before authentication so a foreign page cannot consume login attempts or set a cookie.
  if (['/login', '/events', '/rpc'].includes(url.pathname) && !sameOrigin(req.headers.origin, req.headers.host, secure, origins)) {
    return void res.writeHead(403).end()
  }
  if (url.searchParams.has('token')) return void res.writeHead(400).end('Use the sign-in form at /. / Use o formulário de entrada em /.')

  const who = clientKey(req.socket.remoteAddress, req.headers['x-forwarded-for'], trustProxy)
  const limited = (): boolean => {
    const wait = strikes.retryAfter(who)
    if (!wait) return false
    res.writeHead(429, { 'retry-after': String(wait) }).end('Too many wrong tokens. Try again later. / Tokens errados demais. Tente mais tarde.')
    return true
  }
  if (limited()) return
  const saved = cookieToken(req.headers.cookie)
  const signedIn = sameToken(saved, token)
  if (saved !== undefined && !signedIn) res.setHeader('set-cookie', cookie('', secure))

  if (url.pathname === '/login') {
    if (req.method !== 'POST') return void res.writeHead(405, { allow: 'POST' }).end()
    if (req.headers['content-type']?.split(';')[0]?.trim() !== 'application/x-www-form-urlencoded') return void res.writeHead(415).end()
    let text: string
    try { text = await body(req, 4096) } catch { return void res.writeHead(413).end() }
    // Several bodies may arrive together; check again before trying each token.
    if (limited()) return
    const given = new URLSearchParams(text).get('token') ?? ''
    if (!sameToken(given, token)) {
      strikes.fail(who)
      return void res.writeHead(401, { 'content-type': TYPES['.html']!, 'content-security-policy': "default-src 'none'; form-action 'self'; frame-ancestors 'none'" }).end(LOGIN)
    }
    strikes.clear(who)
    return void res.writeHead(303, { 'set-cookie': cookie(token, secure), location: '/' }).end()
  }
  if (!signedIn) {
    // A plain visit is not a guess. A stale cookie is expired so it will only count once in a browser.
    if (saved !== undefined) strikes.fail(who)
    return void res.writeHead(401, { 'content-type': TYPES['.html']!, 'content-security-policy': "default-src 'none'; form-action 'self'; frame-ancestors 'none'" }).end(LOGIN)
  }

  if (url.pathname === '/events') {
    const c = new Port((msg) => res.write(`data: ${JSON.stringify(msg)}\n\n`))
    const id = randomUUID()
    clients.set(id, c)
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', 'x-accel-buffering': 'no' })
    res.write(`event: hello\ndata: ${id}\n\n`)
    const beat = setInterval(() => res.write(': \n\n'), 25_000)
    toCore(null, [c])
    req.on('close', () => {
      clearInterval(beat)
      clients.delete(id)
      c.close()
    })
    return
  }

  if (url.pathname === '/rpc' && req.method === 'POST') {
    const c = clients.get(url.searchParams.get('c') ?? '')
    if (!c) return void res.writeHead(410).end()
    let text: string
    try { text = await body(req) } catch { return void res.writeHead(413).end() }
    const msg = parseRpc(text)
    if (!msg) return void res.writeHead(400).end()
    c.emit('message', { data: msg })
    res.writeHead(204).end()
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

  if (url.pathname === '/tucano-web.js') return void res.writeHead(200, { 'content-type': TYPES['.js']! }).end(WEB)
  if (url.pathname === '/' || url.pathname === '/index.html') return void res.writeHead(200, { 'content-type': TYPES['.html']!, 'cache-control': 'no-cache' }).end(index())
  const name = decodePart(url.pathname)
  if (name === undefined) return void res.writeHead(400).end()
  const path = normalize(join(page, name))
  if (!path.startsWith(page + sep)) return void res.writeHead(404).end()
  file(res, path)
}

const server = createServer((req, res) => {
  res.setHeader('x-content-type-options', 'nosniff')
  res.setHeader('referrer-policy', 'no-referrer')
  res.setHeader('cache-control', 'no-store')
  let url: URL
  try {
    const target = req.url ?? '/'
    if (!target.startsWith('/') || target.startsWith('//')) throw new Error('invalid target')
    url = new URL(target, 'http://localhost')
  } catch {
    return void res.writeHead(400).end()
  }
  void route(req, res, url).catch(() => fail(res))
})

// window.tucano for a browser: the core's port comes from the event stream and
// the requests go up by POST; what only the desktop does is left out quietly.
const WEB = `(() => {
  window.__TUCANO_WEB__ = true
  let client = null
  const connect = () => {
    const ch = new MessageChannel()
    const es = new EventSource('./events')
    let opened = false
    es.addEventListener('hello', (e) => {
      if (opened) return location.reload() // a new connection after a drop: start fresh
      opened = true
      client = e.data
      window.postMessage('core:port', '*', [ch.port1])
    })
    es.onmessage = (e) => ch.port2.postMessage(JSON.parse(e.data))
    ch.port2.onmessage = async (m) => {
      const id = m.data.id
      try {
        const r = await fetch('./rpc?c=' + encodeURIComponent(client), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(m.data) })
        if (r.status === 204) return // The core's reply still arrives on the event stream.
        const retry = r.headers.get('retry-after')
        const error = 'Falha na solicitação (HTTP ' + r.status + '). / Request failed (HTTP ' + r.status + ').' + (retry ? ' Retry-After: ' + retry + '.' : '')
        ch.port2.postMessage({ id, error })
        if (r.status === 410) location.reload()
      } catch {
        // A failed POST may already have reached the core. Settle it, but never replay it.
        ch.port2.postMessage({ id, error: 'Não foi possível concluir a solicitação ao servidor. / Could not complete the request to the server.' })
      }
    }
  }
  window.tucano = {
    connect,
    pickFolder: async () => {
      const p = prompt('Pasta no servidor (caminho completo) / Folder on the server (full path):')
      return p && p.trim() ? p.trim() : null
    },
    onNavigate: () => {},
    viewing: () => {},
    updateState: async () => ({ version: '', status: 'off' }),
    onUpdate: () => {},
    checkUpdates: () => {},
    installUpdate: () => {}
  }
})()
`

process.env['TUCANO_DATA'] = dataDir
process.env['TUCANO_PACKAGED'] = '1'
process.env['TUCANO_SERVER'] = '1'
;(process as unknown as { parentPort: Port }).parentPort = parent
await import(pathToFileURL(join(import.meta.dirname, 'core.js')).href)
toCore(null, [watcher])
watcher.emit('message', { data: { id: 1, method: 'snapshot' } })

server.listen(port, host, () => {
  const shown = host === '0.0.0.0' || host === '::' ? 'localhost' : host
  const listening = server.address()
  console.log(`Tucano server: http://${shown.includes(':') ? `[${shown}]` : shown}:${typeof listening === 'object' && listening ? listening.port : port}/`)
  console.log(process.env['TUCANO_TOKEN'] ? 'Sign in with the token configured in TUCANO_TOKEN.' : `Sign in with the token in ${join(dataDir, 'server-token')}.`)
  console.log(`Data: ${dataDir}`)
  if (host === '127.0.0.1') console.log('Listening on this machine only: reach it through an SSH tunnel, Tailscale or a reverse proxy with HTTPS (docs/server.md).')
})
