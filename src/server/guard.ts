// Checks for the HTTP boundary. Keep them independent of the running core.
import { timingSafeEqual } from 'node:crypto'
import { isIP } from 'node:net'

export function sameToken(given: string | undefined, token: string): boolean {
  if (!given) return false
  const a = Buffer.from(given)
  const b = Buffer.from(token)
  return a.length === b.length && timingSafeEqual(a, b)
}

export function decodePart(part: string): string | undefined {
  try {
    const value = decodeURIComponent(part)
    return value.includes('\0') ? undefined : value
  } catch {
    return undefined
  }
}

export function parseRpc(text: string): { id: number; method: string; params?: unknown } | undefined {
  try {
    const value = JSON.parse(text)
    if (!value || Array.isArray(value) || !Number.isSafeInteger(value.id) || typeof value.method !== 'string' || !value.method.trim()) return undefined
    // The core dispatches through an object: inherited Object methods are not RPCs.
    if (Object.hasOwn(Object.prototype, value.method)) return undefined
    return value
  } catch {
    return undefined
  }
}

function originOf(value: string): string | undefined {
  try {
    const url = new URL(value)
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) return undefined
    return url.origin
  } catch {
    return undefined
  }
}

export function parseOrigins(list: string | undefined): string[] {
  return (list ?? '').split(',').flatMap((s) => originOf(s.trim()) ?? [])
}

export function sameOrigin(origin: string | undefined, host: string | undefined, secure: boolean, allowed: readonly string[] = []): boolean {
  // Command-line clients need no Origin, but still need the token.
  if (origin === undefined) return true
  const from = originOf(origin)
  if (!from) return false
  return allowed.includes(from) || (!!host && from === originOf(`${secure ? 'https' : 'http'}://${host}`))
}

export function trustedProxy(remote: string | undefined, enabled: boolean): boolean {
  return enabled && !!remote && (remote === '::1' || /^127\./.test(remote) || remote.startsWith('::ffff:127.'))
}

export function clientKey(remote: string | undefined, forwarded: string | string[] | undefined, trust: boolean): string {
  if (trustedProxy(remote, trust)) {
    // The nearest proxy must append/overwrite this header. Earlier entries are client-controlled.
    const last = (Array.isArray(forwarded) ? forwarded.join(',') : forwarded)?.split(',').at(-1)?.trim()
    if (last && isIP(last)) return last
  }
  return remote ?? 'unknown'
}

export function cookieToken(header: string | undefined): string | undefined {
  const value = /(?:^|;\s*)tucano=([^;]*)/.exec(header ?? '')?.[1]
  return value === undefined ? undefined : (decodePart(value) ?? '')
}

export function cookie(value: string, secure: boolean): string {
  return `tucano=${encodeURIComponent(value)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${value ? 31536000 : 0}${secure ? '; Secure' : ''}`
}

// Only failed authentication attempts count. Both addresses and timestamps are bounded.
export class Strikes {
  private readonly hits = new Map<string, number[]>()
  constructor(private readonly limit = 10, private readonly windowMs = 10 * 60_000, private readonly now: () => number = Date.now) {}

  private recent(key: string): number[] {
    const list = (this.hits.get(key) ?? []).filter((t) => t > this.now() - this.windowMs)
    if (list.length) this.hits.set(key, list)
    else this.hits.delete(key)
    return list
  }

  retryAfter(key: string): number {
    const list = this.recent(key)
    return list.length < this.limit ? 0 : Math.max(1, Math.ceil((list[0]! + this.windowMs - this.now()) / 1000))
  }

  fail(key: string): void {
    const list = this.recent(key)
    if (list.length < this.limit) list.push(this.now())
    this.hits.set(key, list)
    if (this.hits.size > 10_000) this.hits.delete(this.hits.keys().next().value!)
  }

  clear(key: string): void { this.hits.delete(key) }
}
