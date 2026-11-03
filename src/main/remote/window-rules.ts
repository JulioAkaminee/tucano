// What window.ts decides without needing Electron, so it can be tested: where a server's window may go, what its
// session is called, and what its title says.
import { L } from '../../shared/lang'
import type { ServerState } from '../../shared/servers'

// The server's window stays on the server's own origin (the address the tunnel gives, or the URL as paired).
// Anything else, even a link inside the page, is for the browser.
export function navigationAllowed(url: string, origin: string): boolean {
  try {
    return new URL(url).origin === new URL(origin).origin
  } catch {
    return false
  }
}

// One session per server, kept: a server's page keeps what it saved (its theme, what it was last looking at), and
// no server's page can see another's, even when both are at 127.0.0.1 on different ports.
export const sessionName = (id: string): string => `persist:tucano-server-${id.replace(/[^0-9a-f]/g, '')}`

export function titleOf(name: string, state: ServerState): string {
  const clean = name.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 80)
  if (state === 'online') return `${clean} · Tucano`
  if (state === 'connecting') return `${clean} · ${L('conectando…', 'connecting…')}`
  return `${clean} · ${L('sem conexão', 'offline')}`
}
