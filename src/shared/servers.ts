// The servers the Mac app can run its agents on, as the page sees them. The token a server gave this Mac never
// gets here: it stays in the main process (src/main/remote), sealed in the system's keychain.
import type { PairLink, Reach } from './pairlink'

export { fingerprintOk } from './pairlink'

export type ServerState = 'offline' | 'connecting' | 'online'

export type ServerInfo = {
  id: string // the server's own id: what it names its cookie after, and what tells two servers apart
  name: string
  reach: Reach
  remotePort: number
  state: ServerState
  error?: string // why it is offline, in words for the person
  paired: number // when this Mac was paired with it
  lastOpened?: number
}

// The key an SSH server shows, as the person compares it: SHA256:… is what `ssh-keygen -lf` prints for it.
export type HostKeyInfo = { type: string; fingerprint: string }

export type AddRequest = {
  link: PairLink
  // The fingerprint the person confirmed, or the one the link itself carried. The key the server shows has to be
  // exactly this one: it is what makes the first connection safe.
  fingerprint?: string
}

export type AddResult = { ok: true; server: ServerInfo } | { ok: false; error: string }
