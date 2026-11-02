import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { cli } from '../src/server/cli'
import { CODE_TTL_MS, Pairing, SESSION_MS, cleanLabel, normalizeCode } from '../src/server/pairing'

const MINUTE = 60_000
const DAY = 24 * 60 * MINUTE

let dir: string
let t: number
const file = (): string => join(dir, 'pairing.json')
const open = (): Pairing => new Pairing(file(), () => t)

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'tucano-pair-'))
  t = 1_700_000_000_000
})
afterEach(() => rmSync(dir, { recursive: true, force: true }))

describe('a pairing code', () => {
  it('is twelve characters, in groups of four, none easy to misread', () => {
    const { code, expires } = open().invite('Mac')
    expect(code).toMatch(/^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/)
    expect(expires).toBe(t + CODE_TTL_MS)
  })

  it('is different every time', () => {
    const p = open()
    const codes = new Set(Array.from({ length: 15 }, () => p.invite().code))
    expect(codes.size).toBe(15)
  })

  it('trades once for a token, and not twice', () => {
    const p = open()
    const { code } = p.invite('Mac')
    const got = p.redeem(code)
    expect(got?.token).toMatch(/^tk_/)
    expect(got?.device.label).toBe('Mac')
    expect(p.redeem(code)).toBeUndefined()
  })

  it('is read however it was typed', () => {
    const p = open()
    expect(normalizeCode(' abcd-efgh jklm ')).toBe('ABCDEFGHJKLM')
    const { code } = p.invite()
    expect(p.redeem(code.toLowerCase().replace(/-/g, ' '))).toBeDefined()
  })

  it('works up to five minutes and not after', () => {
    const p = open()
    const early = p.invite().code
    const late = p.invite().code
    t += CODE_TTL_MS - 1
    expect(p.redeem(early)).toBeDefined()
    t += 2
    expect(p.redeem(late)).toBeUndefined()
  })

  it('is not used up by a wrong one', () => {
    const p = open()
    const { code } = p.invite()
    for (const bad of ['', 'short', 'AAAA-AAAA-AAAA', 'AAAA-AAAA-AAAA-AAAA']) expect(p.redeem(bad)).toBeUndefined()
    expect(p.redeem(code)).toBeDefined()
  })

  it('names the device as the owner did, or else as the device does', () => {
    const p = open()
    expect(p.redeem(p.invite().code, '  Julio’s iPad  ')?.device.label).toBe('Julio’s iPad')
    expect(p.redeem(p.invite('My Mac').code, 'something else')?.device.label).toBe('My Mac')
    expect(p.redeem(p.invite().code)?.device.label).toBe('device')
  })

  it('keeps twenty waiting at most, the oldest give way', () => {
    const p = open()
    const codes = Array.from({ length: 25 }, () => p.invite().code)
    expect(p.redeem(codes[0]!)).toBeUndefined()
    expect(p.redeem(codes[24]!)).toBeDefined()
  })
})

describe('a paired device', () => {
  it('gets in with its token and nobody else does', () => {
    const p = open()
    const { token, device } = p.enroll('Mac')
    expect(p.check(token)?.id).toBe(device.id)
    for (const bad of ['tk_nope', '', undefined, 'x'.repeat(500)]) expect(p.check(bad)).toBeUndefined()
  })

  it('is kept as hashes: neither the code nor the token is in the file', () => {
    const p = open()
    const { code } = p.invite('Mac')
    expect(readFileSync(file(), 'utf8')).not.toContain(normalizeCode(code))
    const { token } = p.redeem(code)!
    const text = readFileSync(file(), 'utf8')
    expect(text).not.toContain(token)
    expect(text).not.toContain(normalizeCode(code))
  })

  it('is in a file only this user reads', () => {
    open().invite()
    if (process.platform !== 'win32') expect(statSync(file()).mode & 0o777).toBe(0o600)
  })

  it('is seen at once by another process, the commands next to the server', () => {
    const server = open()
    const commands = open()
    const { code } = commands.invite('Mac')
    const { token } = server.redeem(code)!
    expect(commands.list().map((d) => d.label)).toEqual(['Mac'])
    expect(commands.revokeAll()).toBe(1)
    expect(server.check(token)).toBeUndefined()
  })

  it('is listed without its hash', () => {
    const p = open()
    p.enroll('Mac')
    expect(JSON.stringify(p.list())).not.toContain('hash')
  })

  it('pairs nobody from a file that is garbage, and recovers', () => {
    const p = open()
    const { token } = p.enroll('Mac')
    writeFileSync(file(), '{nope')
    expect(p.check(token)).toBeUndefined()
    expect(p.list()).toEqual([])
    expect(p.invite().code).toBeDefined()
  })

  it('keeps a hundred at most, the longest unused give way', () => {
    const p = open()
    const first = p.enroll('first')
    for (let i = 0; i < 100; i++) {
      t += 1000
      p.enroll(`d${i}`)
    }
    expect(p.list()).toHaveLength(100)
    expect(p.check(first.token)).toBeUndefined()
  })
})

describe('how long a session lasts', () => {
  it('goes on while it is used and ends thirty days after the last use', () => {
    const p = open()
    const { token } = p.enroll('Mac')
    t += 29 * DAY
    expect(p.check(token)).toBeDefined()
    t += 29 * DAY
    expect(p.check(token)).toBeDefined()
    t += SESSION_MS + 1
    expect(p.check(token)).toBeUndefined()
    expect(p.list()).toEqual([])
  })

  it('does not renew on every request, only once an hour has gone', () => {
    const p = open()
    const { token, device } = p.enroll('Mac')
    t += 10 * MINUTE
    p.check(token)
    expect(p.list()[0]?.seen).toBe(device.seen)
    t += 51 * MINUTE
    p.check(token)
    expect(p.list()[0]?.seen).toBe(t)
  })
})

describe('taking access away', () => {
  it('by id or by label, one device at a time', () => {
    const p = open()
    const mac = p.enroll('Mac')
    const phone = p.enroll('Phone')
    expect(p.revoke(mac.device.id)).toBe(1)
    expect(p.check(mac.token)).toBeUndefined()
    expect(p.check(phone.token)).toBeDefined()
    expect(p.revoke('nobody')).toBe(0)
    expect(p.revoke(' PHONE ')).toBe(1)
    expect(p.check(phone.token)).toBeUndefined()
  })

  it('all of them, and the codes not used yet', () => {
    const p = open()
    p.enroll('Mac')
    const { code } = p.invite()
    expect(p.revokeAll()).toBe(1)
    expect(p.redeem(code)).toBeUndefined()
  })
})

describe('a label', () => {
  it('is trimmed, free of control characters, short, and never empty', () => {
    expect(cleanLabel('  My Mac  ', 'x')).toBe('My Mac')
    expect(cleanLabel('a\nb', 'x')).toBe('a b')
    expect(cleanLabel('a'.repeat(100), 'x')).toHaveLength(60)
    expect(cleanLabel('   ', 'x')).toBe('x')
    expect(cleanLabel(42, 'x')).toBe('x')
  })
})

describe('the commands on the server machine', () => {
  const base = 'http://127.0.0.1:7337'
  const run = (args: string[], p = open()): { code: number | undefined; out: string } => {
    const lines: string[] = []
    const code = cli(args, p, base, (l) => lines.push(l))
    return { code, out: lines.join('\n') }
  }

  it('leave the server to start when there is no command, or only flags', () => {
    expect(run([]).code).toBeUndefined()
    expect(run(['--port', '1']).code).toBeUndefined()
  })

  it('pair prints a code and the link that signs a browser in', () => {
    const p = open()
    const { code, out } = run(['pair', '--label', 'My Mac'], p)
    expect(code).toBe(0)
    const given = /[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}/.exec(out)?.[0]
    expect(given).toBeDefined()
    expect(out).toContain(`${base}/?pair=${given}`)
    expect(p.redeem(given!)?.device.label).toBe('My Mac')
  })

  it('pair takes --label=Name as well', () => {
    const p = open()
    const given = /[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}/.exec(run(['pair', '--label=Phone'], p).out)?.[0]
    expect(p.redeem(given!)?.device.label).toBe('Phone')
  })

  it('devices says who is paired, or that nobody is', () => {
    const p = open()
    expect(run(['devices'], p).out).toContain('No paired devices')
    const { device } = p.enroll('My Mac')
    const { code, out } = run(['devices'], p)
    expect(code).toBe(0)
    expect(out).toContain(device.id)
    expect(out).toContain('My Mac')
  })

  it('revoke takes one device, or all, and says when there is none to take', () => {
    const p = open()
    const { device, token } = p.enroll('My Mac')
    expect(run(['revoke', 'nobody'], p).code).toBe(1)
    expect(run(['revoke'], p).code).toBe(2)
    expect(run(['revoke', device.id], p).code).toBe(0)
    expect(p.check(token)).toBeUndefined()
    p.enroll('Other')
    expect(run(['revoke', '--all'], p).out).toContain('Revoked 1 device.')
  })

  it('answer help, and refuse what they do not know', () => {
    expect(run(['help']).code).toBe(0)
    const bad = run(['pari'])
    expect(bad.code).toBe(2)
    expect(bad.out).toContain('Unknown command: pari')
  })
})
