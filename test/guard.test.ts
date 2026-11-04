import { describe, expect, it } from 'vitest'
import { clientKey, cookie, cookieToken, decodePart, parseOrigins, parseRpc, sameOrigin, sameToken, Strikes, trustedProxy } from '../src/server/guard'

describe('untrusted request input', () => {
  it('compares token bytes without throwing on different UTF-8 lengths', () => {
    expect(sameToken('secret', 'secret')).toBe(true)
    for (const value of [undefined, '', 'wrong', 'éééééé', 'secreT']) expect(sameToken(value, 'secret')).toBe(false)
  })
  it('rejects broken percent escapes and NULs', () => {
    expect(decodePart('hello%20%C3%A7')).toBe('hello ç')
    for (const value of ['%', '%E0%A4%A', '%00', 'a\0b']) expect(decodePart(value)).toBeUndefined()
  })
  it('accepts only RPC envelopes with a safe numeric id and a method', () => {
    expect(parseRpc('{"id":1,"method":"snapshot"}')).toEqual({ id: 1, method: 'snapshot' })
    expect(parseRpc('{"id":2,"method":"sendMessage","params":{"text":"hello"}}')?.params).toEqual({ text: 'hello' })
    for (const text of ['', '{', 'null', 'false', '1', '"a"', '[]', '{}', '{"id":"1","method":"snapshot"}', '{"id":1.5,"method":"snapshot"}', '{"id":1e100,"method":"snapshot"}', '{"id":1,"method":null}', '{"id":1,"method":" "}', '{"id":1,"method":"constructor"}', '{"id":1,"method":"__proto__"}']) expect(parseRpc(text)).toBeUndefined()
  })
})

describe('Origin', () => {
  it('compares the complete HTTP origin, including scheme and port', () => {
    expect(sameOrigin(undefined, undefined, false)).toBe(true)
    expect(sameOrigin('http://LOCALHOST:7337', 'localhost:7337', false)).toBe(true)
    expect(sameOrigin('https://tucano.example', 'tucano.example:443', true)).toBe(true)
    expect(sameOrigin('http://[::1]:7337', '[::1]:7337', false)).toBe(true)
    for (const origin of ['null', 'https://localhost:7337', 'http://localhost:7338', 'http://evil.example', 'http://localhost:7337/path', 'http://user@localhost:7337', 'http://localhost:7337?x', 'http://localhost:7337#x', 'file:///']) expect(sameOrigin(origin, 'localhost:7337', false)).toBe(false)
    expect(sameOrigin('http://localhost:7337', undefined, false)).toBe(false)
    expect(sameOrigin('http://localhost', 'evil.example@localhost', false)).toBe(false)
  })
  it('accepts only the explicit external origins configured for a proxy', () => {
    const origins = parseOrigins(' https://tucano.example/, ,nope,file:///,https://other.example/path,http://local:7337')
    expect(origins).toEqual(['https://tucano.example', 'http://local:7337'])
    expect(parseOrigins(undefined)).toEqual([])
    expect(sameOrigin('https://tucano.example', '127.0.0.1:7337', true, origins)).toBe(true)
    expect(sameOrigin('http://tucano.example', '127.0.0.1:7337', true, origins)).toBe(false)
  })
})

describe('proxy trust and cookies', () => {
  it('ignores forwarded headers unless a loopback proxy is explicitly trusted', () => {
    expect(clientKey('127.0.0.1', '203.0.113.1', false)).toBe('127.0.0.1')
    expect(clientKey('203.0.113.2', '203.0.113.1', true)).toBe('203.0.113.2')
    expect(clientKey('::1', '198.51.100.1, 203.0.113.1', true)).toBe('203.0.113.1')
    expect(clientKey('::ffff:127.0.0.1', ['198.51.100.1', '203.0.113.1'], true)).toBe('203.0.113.1')
    for (const forwarded of [undefined, '', 'arbitrary', '203.0.113.1, invalid']) expect(clientKey('127.0.0.1', forwarded, true)).toBe('127.0.0.1')
    expect(clientKey(undefined, undefined, true)).toBe('unknown')
    expect(trustedProxy('::1', false)).toBe(false)
    expect(trustedProxy('192.168.1.1', true)).toBe(false)
  })
  it('encodes cookies safely, expires them with the same attributes, and reads old ASCII cookies', () => {
    expect(cookie('a; é', true)).toBe('tucano=a%3B%20%C3%A9; HttpOnly; SameSite=Lax; Path=/; Max-Age=31536000; Secure')
    expect(cookie('', true)).toBe('tucano=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0; Secure')
    expect(cookie('secret', false)).not.toContain('Secure')
    expect(cookieToken('other=x; tucano=a%3B%20%C3%A9')).toBe('a; é')
    expect(cookieToken('tucano=secret')).toBe('secret')
    expect(cookieToken('tucano=%')).toBe('')
    expect(cookieToken('other=secret')).toBeUndefined()
  })
})

describe('failed authentication limits', () => {
  it('waits until the oldest strike expires without extending a lockout', () => {
    let time = 1_000_000
    const strikes = new Strikes(2, 60_000, () => time)
    strikes.fail('a')
    time += 10_000
    strikes.fail('a')
    expect(strikes.retryAfter('a')).toBe(50)
    for (let i = 0; i < 20_000; i++) strikes.fail('a')
    time += 50_000
    expect(strikes.retryAfter('a')).toBe(0)
    strikes.fail('a')
    expect(strikes.retryAfter('a')).toBe(10)
  })
  it('separates clients and clears strikes after sign-in', () => {
    const strikes = new Strikes(1)
    strikes.fail('a')
    expect(strikes.retryAfter('a')).toBeGreaterThan(0)
    expect(strikes.retryAfter('b')).toBe(0)
    strikes.clear('a')
    expect(strikes.retryAfter('a')).toBe(0)
  })
  it('bounds the number of client entries', () => {
    const strikes = new Strikes(1)
    for (let i = 0; i <= 10_000; i++) strikes.fail(String(i))
    expect(strikes.retryAfter('0')).toBe(0)
    expect(strikes.retryAfter('10000')).toBeGreaterThan(0)
  })
})
