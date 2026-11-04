// Exercise the built HTTP boundary and real core on isolated data and loopback ports.
// npm run build && npm run test:server
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { request } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, test } from 'node:test'
import { fileURLToPath } from 'node:url'

const entry = fileURLToPath(new URL('../out/main/server.js', import.meta.url))
const servers = []
const streams = []
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

async function stop(server) {
  if (server.child.exitCode === null && server.child.signalCode === null) {
    const exit = once(server.child, 'exit')
    server.child.kill()
    await exit
  }
}

after(async () => {
  for (const stream of streams) stream.close()
  await Promise.all(servers.map(async ({ child, dir }) => {
    await stop({ child })
    rmSync(dir, { recursive: true, force: true })
  }))
})

async function start(extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'tucano-hardening-'))
  const child = spawn(process.execPath, [entry], {
    env: { ...process.env, HOME: dir, USERPROFILE: dir, TUCANO_DATA: dir, TUCANO_HOST: '127.0.0.1', TUCANO_PORT: '0', TUCANO_TOKEN: '', TUCANO_FAKE_ENGINES: '1', TUCANO_SEED: '0', TUCANO_TRUST_PROXY: '', TUCANO_COOKIE_SECURE: '', TUCANO_ORIGINS: '', ...extra },
    stdio: ['ignore', 'pipe', 'pipe']
  })
  let log = ''
  child.stdout.on('data', (chunk) => { log += chunk })
  child.stderr.on('data', (chunk) => { log += chunk })
  const server = { child, dir, log: () => log, port: 0, token: '' }
  servers.push(server)
  for (let i = 0; i < 600; i++) {
    assert.equal(child.exitCode, null, 'server exited before listening')
    const port = /Tucano server: http:\/\/127\.0\.0\.1:(\d+)\//.exec(log)?.[1]
    if (port) {
      server.port = Number(port)
      server.token = extra.TUCANO_TOKEN || readFileSync(join(dir, 'server-token'), 'utf8').trim()
      return server
    }
    await sleep(50)
  }
  throw new Error(`server did not listen within 30 seconds: ${log}`)
}

function http(server, { method = 'GET', path = '/', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port: server.port, method, path, headers }, (res) => {
      const chunks = []
      res.on('data', (chunk) => chunks.push(chunk))
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8') }))
      res.on('error', reject)
    })
    req.setTimeout(10_000, () => req.destroy(new Error('request timed out')))
    req.on('error', reject)
    req.end(body)
  })
}
const login = (server, token = server.token, headers = {}) => http(server, { method: 'POST', path: '/login', headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers }, body: new URLSearchParams({ token }).toString() })
const auth = (server) => ({ cookie: `tucano=${encodeURIComponent(server.token)}` })
const cookie = (res) => res.headers['set-cookie']?.[0] ?? ''

function events(server, headers = auth(server)) {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port: server.port, path: '/events', headers }, (res) => {
      if (res.statusCode !== 200) { res.resume(); reject(new Error(`events returned ${res.statusCode}`)); return }
      let seen = ''
      const stream = { seen: () => seen, id: '', close: () => req.destroy() }
      streams.push(stream)
      res.on('data', (chunk) => {
        seen += chunk
        const id = /event: hello\ndata: (\S+)/.exec(seen)?.[1]
        if (id && !stream.id) { stream.id = id; resolve(stream) }
      })
    })
    req.on('error', reject)
    req.end()
  })
}

test('built server authentication and request boundaries', { timeout: 90_000 }, async (t) => {
  const server = await start()
  const origin = `http://127.0.0.1:${server.port}`
  await t.test('startup and unauthenticated responses contain no token', async () => {
    assert.ok(!server.log().includes(server.token))
    assert.ok(!server.log().includes('?token='))
    const res = await http(server)
    assert.equal(res.status, 401)
    assert.equal(cookie(res), '')
    assert.equal(res.headers['cache-control'], 'no-store')
    assert.equal(res.headers['referrer-policy'], 'no-referrer')
    assert.equal(res.headers['x-content-type-options'], 'nosniff')
    assert.match(res.text, /method="post" action="\/login"/)
    assert.ok(!res.text.includes(server.token))
  })
  await t.test('query tokens never authenticate or appear in responses', async () => {
    const res = await http(server, { path: `/?token=${server.token}` })
    assert.equal(res.status, 400)
    assert.equal(cookie(res), '')
    assert.ok(!res.text.includes(server.token))
  })
  await t.test('login rejects cross-origin, invalid content and oversized bodies', async () => {
    for (const bad of ['https://evil.example', 'null', origin.replace('http:', 'https:')]) assert.equal((await login(server, server.token, { origin: bad })).status, 403)
    assert.equal((await http(server, { path: '/login' })).status, 405)
    assert.equal((await http(server, { method: 'POST', path: '/login', body: '{}' })).status, 415)
    assert.equal((await login(server, 'x'.repeat(5000))).status, 413)
    assert.equal((await login(server, 'é'.repeat(server.token.length))).status, 401)
    assert.equal((await login(server, 'incorrect')).status, 401)
  })
  await t.test('POST signs in without leaking token to URL, ignores untrusted forwarded proto', async () => {
    const res = await login(server, server.token, { origin, 'x-forwarded-proto': 'https' })
    assert.equal(res.status, 303)
    assert.equal(res.headers.location, '/')
    assert.match(cookie(res), /HttpOnly; SameSite=Lax; Path=\/; Max-Age=31536000$/)
    assert.ok(!res.text.includes(server.token))
    const page = await http(server, { headers: { cookie: cookie(res).split(';')[0] } })
    assert.equal(page.status, 200)
    assert.match(page.text, /tucano-web.js/)
  })
  await t.test('invalid request targets and paths are contained', async () => {
    for (const path of ['http://[', 'http://example.com:invalid/', '//[', '/%E0%A4%A', '/%00', '/artifact/00000000-0000-0000-0000-000000000000/%E0%A4%A']) assert.equal((await http(server, { path, headers: auth(server) })).status, 400, path)
    for (const path of ['/assets', '/../../../etc/passwd', '/%2e%2e/%2e%2e/etc/passwd', '/artifact/00000000-0000-0000-0000-000000000000/..%2f..%2fserver-token']) assert.equal((await http(server, { path, headers: auth(server) })).status, 404, path)
    assert.equal((await http(server, { headers: auth(server) })).status, 200)
  })
  await t.test('SSE and RPC reject foreign origins and malformed messages, then complete a real snapshot', async () => {
    for (const path of ['/events', '/rpc']) for (const bad of ['https://evil.example', 'null', origin.replace('http:', 'https:')]) assert.equal((await http(server, { path, headers: { ...auth(server), origin: bad } })).status, 403)
    const stream = await events(server, { ...auth(server), origin })
    const rpc = (body, id = stream.id) => http(server, { method: 'POST', path: `/rpc?c=${id}`, headers: { ...auth(server), origin }, body })
    for (const bad of ['{', 'null', 'false', '[]', '{}', '{"id":1,"method":42}', '{"id":1,"method":"constructor"}']) assert.equal((await rpc(bad)).status, 400, bad)
    assert.equal((await rpc('{"id":1,"method":"snapshot"}', 'missing')).status, 410)
    assert.equal((await rpc(Buffer.alloc(64 * 1024 * 1024 + 1, 'x'))).status, 413)
    await new Promise((resolve) => {
      const aborted = request({ host: '127.0.0.1', port: server.port, method: 'POST', path: `/rpc?c=${stream.id}`, headers: { ...auth(server), 'content-length': '100' } })
      aborted.on('error', () => {})
      aborted.on('close', resolve)
      aborted.write('{')
      setTimeout(() => aborted.destroy(), 25)
    })
    assert.equal((await rpc('{"id":42,"method":"snapshot"}')).status, 204)
    for (let i = 0; i < 200 && !stream.seen().includes('"id":42'); i++) await sleep(25)
    assert.match(stream.seen(), /"id":42,"result":/)
    stream.close()
  })
  await t.test('stale cookies expire, plain visits do not count, forwarded IPs cannot evade limits', async () => {
    const stale = await http(server, { headers: { cookie: 'tucano=invalid' } })
    assert.equal(stale.status, 401)
    assert.match(cookie(stale), /Max-Age=0/)
    await login(server) // Start a new failure window.
    for (let i = 0; i < 12; i++) assert.equal((await http(server)).status, 401)
    for (let i = 0; i < 10; i++) assert.equal((await login(server, 'wrong', { 'x-forwarded-for': `203.0.113.${i}` })).status, 401)
    const limited = await login(server)
    assert.equal(limited.status, 429)
    assert.ok(Number(limited.headers['retry-after']) > 0)
    assert.equal((await http(server, { headers: auth(server) })).status, 429, 'cookie guesses cannot bypass the limit')
    assert.ok(!server.log().includes(server.token))
  })
  await stop(server)
})

test('explicit loopback proxy trust and Secure cookies', { timeout: 60_000 }, async () => {
  const server = await start({ TUCANO_TRUST_PROXY: '1', TUCANO_ORIGINS: 'https://tucano.example' })
  const proxy = { 'x-forwarded-proto': 'https', origin: 'https://tucano.example' }
  assert.match(cookie(await login(server, server.token, proxy)), /; Secure$/)
  const invalid = await http(server, { headers: { ...proxy, cookie: 'tucano=wrong' } })
  assert.match(cookie(invalid), /Max-Age=0; Secure$/)
  for (let i = 0; i < 10; i++) assert.equal((await login(server, 'wrong', { ...proxy, 'x-forwarded-for': '198.51.100.1, 203.0.113.1' })).status, 401)
  assert.equal((await login(server, server.token, { ...proxy, 'x-forwarded-for': '198.51.100.2, 203.0.113.1' })).status, 429)
  assert.equal((await login(server, server.token, { ...proxy, 'x-forwarded-for': '203.0.113.2' })).status, 303)
  await stop(server)
  const explicit = await start({ TUCANO_COOKIE_SECURE: '1', TUCANO_TOKEN: 'synthetic-test-token-only' })
  assert.match(cookie(await login(explicit)), /; Secure$/)
  assert.ok(!explicit.log().includes(explicit.token))
  await stop(explicit)
})
