// The servers this Mac is paired with, in one file in the app's data folder. The token each one gave the Mac is
// sealed with the system's keychain before it is written (the same safeStorage that keeps the app's other secrets),
// so the file alone opens nothing. It goes nowhere else: the page never sees it.
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import type { Reach } from '../../shared/pairlink'

export type Stored = {
  id: string
  name: string
  reach: Reach
  remotePort: number
  localPort?: number // the Mac's end of the tunnel, kept so the page's address (and what it saved there) stays the same
  token: string // sealed
  paired: number
  lastOpened?: number
}

export type Vault = { seal(text: string): string; open(sealed: string): string }

type Disk = { v: 1; servers: Stored[] }

const sane = (s: unknown): s is Stored => {
  if (!s || typeof s !== 'object') return false
  const o = s as Record<string, unknown>
  const r = o['reach'] as { via?: unknown } | undefined
  return (
    typeof o['id'] === 'string' && /^[0-9a-f]{6,64}$/.test(o['id']) &&
    typeof o['name'] === 'string' &&
    (r?.via === 'ssh' || r?.via === 'url') &&
    Number.isInteger(o['remotePort']) &&
    typeof o['token'] === 'string' &&
    typeof o['paired'] === 'number'
  )
}

export class ServerStore {
  private servers: Stored[] = []

  constructor(
    private readonly file: string,
    private readonly vault: Vault
  ) {
    this.servers = this.read()
  }

  private read(): Stored[] {
    if (!existsSync(this.file)) return []
    try {
      const disk = JSON.parse(readFileSync(this.file, 'utf8')) as Partial<Disk>
      if (disk.v !== 1 || !Array.isArray(disk.servers)) throw new Error('not a list of servers')
      return disk.servers.filter(sane)
    } catch {
      // A file that can't be read is set aside, not overwritten: the person may want it back.
      try {
        renameSync(this.file, `${this.file}.unreadable-${Date.now()}`)
      } catch {
        /* nothing more to do */
      }
      return []
    }
  }

  private write(): void {
    mkdirSync(dirname(this.file), { recursive: true, mode: 0o700 })
    const tmp = `${this.file}.tmp`
    writeFileSync(tmp, JSON.stringify({ v: 1, servers: this.servers } satisfies Disk, null, 2), { mode: 0o600 })
    renameSync(tmp, this.file)
    chmodSync(this.file, 0o600)
  }

  list(): Stored[] {
    return this.servers.map((s) => ({ ...s }))
  }

  get(id: string): Stored | undefined {
    const s = this.servers.find((x) => x.id === id)
    return s && { ...s }
  }

  // The token itself, only for whoever is about to use it.
  token(id: string): string | undefined {
    const s = this.servers.find((x) => x.id === id)
    if (!s) return undefined
    try {
      return this.vault.open(s.token)
    } catch {
      return undefined
    }
  }

  // Pairing again with a server already here (a new code, after a revoke) replaces its entry.
  put(entry: Omit<Stored, 'token'> & { token: string }): void {
    const sealed = this.vault.seal(entry.token)
    const next: Stored = { ...entry, token: sealed }
    const i = this.servers.findIndex((x) => x.id === entry.id)
    if (i < 0) this.servers.push(next)
    else this.servers[i] = next
    this.write()
  }

  update(id: string, patch: Partial<Pick<Stored, 'name' | 'localPort' | 'lastOpened'>>): void {
    const s = this.servers.find((x) => x.id === id)
    if (!s) return
    Object.assign(s, patch)
    this.write()
  }

  remove(id: string): void {
    const n = this.servers.length
    this.servers = this.servers.filter((x) => x.id !== id)
    if (this.servers.length !== n) this.write()
  }
}
