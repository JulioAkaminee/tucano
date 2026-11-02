// Pairing: how a browser or the Mac app gets in without ever holding the server's own token.
// `pair` makes a one-time code (12 characters, 5 minutes). Trading it gives the device a token of
// its own, good for 30 days from its last use, kept here only as a hash and revocable one by one.
// The state is one small file in the data dir, read again on every call, so the commands on this
// machine and the running server see each other's changes at once.

import { createHash, randomBytes, randomInt } from 'node:crypto'
import { chmodSync, readFileSync, renameSync, writeFileSync } from 'node:fs'

export const CODE_TTL_MS = 5 * 60_000
export const SESSION_MS = 30 * 24 * 60 * 60_000
const RENEW_AFTER_MS = 60 * 60_000 // a session renews with use, but the file isn't rewritten on every request
const MAX_PENDING = 20
const MAX_DEVICES = 100
const CODE_LENGTH = 12
// No 0, O, 1 or I: a code is often read out, or typed from a screen.
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'

export type Device = { id: string; label: string; created: number; seen: number }
export type Issued = { token: string; device: Device }
type Stored = Device & { hash: string }
type Pending = { hash: string; label: string; expires: number }
type State = { devices: Stored[]; pending: Pending[] }

// Codes and tokens are random and long, so a plain hash is enough to keep them out of the file.
const sha = (s: string): string => createHash('sha256').update(s).digest('hex')

const strip = ({ id, label, created, seen }: Stored): Device => ({ id, label, created, seen })

// What was typed is read in any case, with or without the dashes or spaces.
export const normalizeCode = (code: string): string => code.toUpperCase().replace(/[^A-Z0-9]/g, '')

export function cleanLabel(label: unknown, fallback: string): string {
  const s = typeof label === 'string' ? label.replace(/\p{Cc}/gu, ' ').trim().slice(0, 60) : ''
  return s || fallback
}

export class Pairing {
  constructor(
    private readonly file: string,
    private readonly now: () => number = Date.now
  ) {}

  private load(): State {
    let raw: { devices?: unknown; pending?: unknown } = {}
    try {
      raw = JSON.parse(readFileSync(this.file, 'utf8')) ?? {}
    } catch {
      // None yet, or unreadable: nobody is paired, which is the safe way to fail.
    }
    const t = this.now()
    const devices = (Array.isArray(raw.devices) ? raw.devices : []) as Stored[]
    const pending = (Array.isArray(raw.pending) ? raw.pending : []) as Pending[]
    return {
      // A session that went 30 days unused, and a code that ran out, are gone.
      devices: devices.filter((d) => typeof d?.hash === 'string' && t - d.seen <= SESSION_MS),
      pending: pending.filter((p) => typeof p?.hash === 'string' && p.expires > t)
    }
  }

  private save(s: State): void {
    const tmp = `${this.file}.${process.pid}.tmp`
    writeFileSync(tmp, JSON.stringify(s), { mode: 0o600 })
    renameSync(tmp, this.file)
    chmodSync(this.file, 0o600)
  }

  private make(s: State, label: string): Issued {
    const t = this.now()
    const token = `tk_${randomBytes(32).toString('base64url')}`
    const device: Stored = { id: randomBytes(4).toString('hex'), label, created: t, seen: t, hash: sha(token) }
    s.devices = [...s.devices, device].sort((a, b) => b.seen - a.seen).slice(0, MAX_DEVICES)
    return { token, device: strip(device) }
  }

  // A one-time code for one device. The label is the owner's name for it ("My Mac").
  invite(label?: string): { code: string; expires: number } {
    const s = this.load()
    const raw = Array.from({ length: CODE_LENGTH }, () => ALPHABET.charAt(randomInt(ALPHABET.length))).join('')
    const expires = this.now() + CODE_TTL_MS
    s.pending = [...s.pending, { hash: sha(raw), label: cleanLabel(label, ''), expires }].slice(-MAX_PENDING)
    this.save(s)
    return { code: `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8)}`, expires }
  }

  // The code for the device's own token, once. A wrong, used or expired code answers nothing.
  redeem(code: string, label?: string): Issued | undefined {
    const norm = normalizeCode(code)
    if (norm.length !== CODE_LENGTH) return undefined
    const s = this.load()
    const h = sha(norm)
    const at = s.pending.findIndex((p) => p.hash === h)
    const found = s.pending[at]
    if (!found) return undefined
    s.pending = s.pending.filter((_, i) => i !== at)
    const issued = this.make(s, found.label || cleanLabel(label, 'device'))
    this.save(s)
    return issued
  }

  // A device the owner already vouched for with the server's own token.
  enroll(label: string): Issued {
    const s = this.load()
    const issued = this.make(s, cleanLabel(label, 'device'))
    this.save(s)
    return issued
  }

  // Whose token this is, if it is one. Using it renews the session.
  check(token: string | undefined): Device | undefined {
    if (!token || token.length > 200) return undefined
    const s = this.load()
    const h = sha(token)
    const d = s.devices.find((x) => x.hash === h)
    if (!d) return undefined
    const t = this.now()
    if (t - d.seen > RENEW_AFTER_MS) {
      d.seen = t
      this.save(s)
    }
    return strip(d)
  }

  list(): Device[] {
    return this.load()
      .devices.map(strip)
      .sort((a, b) => a.created - b.created)
  }

  // By id or by label (any case). How many lost their access.
  revoke(which: string): number {
    const s = this.load()
    const w = which.trim().toLowerCase()
    const keep = s.devices.filter((d) => d.id !== w && d.label.toLowerCase() !== w)
    const n = s.devices.length - keep.length
    if (n) {
      s.devices = keep
      this.save(s)
    }
    return n
  }

  // Every device, and the codes not used yet.
  revokeAll(): number {
    const s = this.load()
    const n = s.devices.length
    this.save({ devices: [], pending: [] })
    return n
  }
}
