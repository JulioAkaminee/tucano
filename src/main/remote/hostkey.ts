// The first time the app reaches a server over SSH, the person is shown the server's host key (its fingerprint) and
// says it is the right one, or the link they pasted already carries it. From then on the app trusts that key and
// no other: it keeps its own known_hosts file, apart from the one in ~/.ssh, and ssh runs with strict checking on
// it. A server reinstalled, or someone in between, shows another key, and the connection is refused.
import { createHash } from 'node:crypto'
import { execFile } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

export type HostKey = { type: string; key: string; fingerprint: string }

// What `ssh-keygen -lf` prints: SHA256 of the key's wire form, in base64 with no padding.
export function fingerprintOf(key: string): string {
  return `SHA256:${createHash('sha256').update(Buffer.from(key, 'base64')).digest('base64').replace(/=+$/, '')}`
}

// Best first. A server has more than one; ed25519 is the one everybody checks.
const TYPES = ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'ssh-rsa']

// ssh-keyscan's output: "# comments", and "host type key" lines.
export function parseKeyscan(output: string): HostKey[] {
  const keys: HostKey[] = []
  for (const line of output.split('\n')) {
    if (!line || line.startsWith('#')) continue
    const [, type, key] = line.trim().split(/\s+/)
    if (!type || !key || !TYPES.includes(type) || !/^[A-Za-z0-9+/]+={0,2}$/.test(key)) continue
    keys.push({ type, key, fingerprint: fingerprintOf(key) })
  }
  return keys.sort((a, b) => TYPES.indexOf(a.type) - TYPES.indexOf(b.type))
}

// How known_hosts names a server: the bare host on port 22, [host]:port on any other.
export const patternOf = (host: string, port: number): string => (port === 22 ? host : `[${host}]:${port}`)

// What ssh is told to expect, so a server that also has other keys can't be met with one never confirmed.
export const algorithmsOf = (type: string): string => (type === 'ssh-rsa' ? 'rsa-sha2-512,rsa-sha2-256,ssh-rsa' : type)

type Run = (cmd: string, args: string[]) => Promise<string>
const run: Run = (cmd, args) =>
  new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout: 20_000, windowsHide: true, maxBuffer: 1 << 20 }, (err, stdout) => (err ? reject(err) : resolve(stdout)))
  })

// Asks the server for its keys (nothing is trusted yet: this is only to show and to compare).
export async function scan(host: string, port: number, exec: Run = run): Promise<HostKey> {
  let out: string
  try {
    out = await exec('ssh-keyscan', ['-T', '10', '-p', String(port), '-t', 'ed25519,ecdsa,rsa', '--', host])
  } catch (e) {
    const missing = (e as NodeJS.ErrnoException).code === 'ENOENT'
    throw new Error(missing ? 'ssh-keyscan isn’t installed on this computer' : `couldn’t reach ${host} on port ${port}`)
  }
  const [best] = parseKeyscan(out)
  if (!best) throw new Error(`${host} on port ${port} didn’t show an SSH key: is SSH running there?`)
  return best
}

// The app's own known_hosts: one line for each server the person confirmed.
export class KnownHosts {
  constructor(readonly file: string) {}

  private lines(): string[] {
    return existsSync(this.file) ? readFileSync(this.file, 'utf8').split('\n').filter(Boolean) : []
  }

  // The key trusted for this server, if one was confirmed.
  trusted(host: string, port: number): { type: string; key: string } | undefined {
    const [, type, key] = this.lines().find((l) => l.startsWith(`${patternOf(host, port)} `))?.split(/\s+/) ?? []
    return type && key ? { type, key } : undefined
  }

  // Trusts this key for this server and no other (a key confirmed before is replaced: the person did it on purpose).
  pin(host: string, port: number, key: Pick<HostKey, 'type' | 'key'>): void {
    const at = patternOf(host, port)
    const kept = this.lines().filter((l) => !l.startsWith(`${at} `))
    mkdirSync(dirname(this.file), { recursive: true, mode: 0o700 })
    const tmp = `${this.file}.tmp`
    writeFileSync(tmp, `${[...kept, `${at} ${key.type} ${key.key}`].join('\n')}\n`, { mode: 0o600 })
    renameSync(tmp, this.file)
    chmodSync(this.file, 0o600)
  }

  forget(host: string, port: number): void {
    const at = patternOf(host, port)
    const kept = this.lines().filter((l) => !l.startsWith(`${at} `))
    if (kept.length === this.lines().length) return
    writeFileSync(this.file, kept.length ? `${kept.join('\n')}\n` : '', { mode: 0o600 })
  }
}
