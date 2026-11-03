// Where the app meets the servers it can run on: what the page may ask of src/main/remote, and the `tucano://pair`
// link that starts adding one. The page is trusted with nothing here: a link is parsed again, an id is checked,
// the token is never sent to it, and a link from outside (a click on a web page can open one) only fills in a form:
// nothing connects until the person says so.
import { ipcMain, powerMonitor, safeStorage, type BrowserWindow } from 'electron'
import { hostname } from 'node:os'
import { join } from 'node:path'
import { L } from '../../shared/lang'
import { fingerprintOk, parsePairLink } from '../../shared/pairlink'
import type { AddResult, HostKeyInfo, ServerInfo } from '../../shared/servers'
import { KnownHosts } from './hostkey'
import { Remote } from './remote'
import { ServerStore, type Vault } from './servers'
import { ServerWindows } from './window'

const MAX_LINK = 2048

// The system's own vault (the Keychain on a Mac): the same one the app's other secrets are sealed with.
const vault: Vault = {
  seal(text) {
    if (!safeStorage.isEncryptionAvailable()) throw new Error(L('O cofre do sistema não está disponível.', "The system's vault isn't available."))
    if (process.platform === 'linux' && ['basic_text', 'unknown'].includes(safeStorage.getSelectedStorageBackend()))
      throw new Error(L('Este Linux não tem um chaveiro aberto (GNOME Keyring ou KWallet), e o Tucano não guarda o acesso a um servidor sem cifrar.', "This Linux has no keyring open (GNOME Keyring or KWallet), and Tucano doesn't keep the way into a server unencrypted."))
    return safeStorage.encryptString(text).toString('base64')
  },
  open: (sealed) => safeStorage.decryptString(Buffer.from(sealed, 'base64'))
}

const text = (v: unknown): string | undefined => (typeof v === 'string' && v.length <= MAX_LINK ? v : undefined)
const idOf = (v: unknown): string | undefined => (typeof v === 'string' && /^[0-9a-f]{6,64}$/.test(v) ? v : undefined)
const refuse = (error: string): { ok: false; error: string } => ({ ok: false, error })

export type RemoteHooks = {
  dataDir: () => string
  mainWindow: () => BrowserWindow | null
  showWindow: () => void
}

export function setupRemote(hooks: RemoteHooks): { dispose(): void; pairLink(url: string): void } {
  const windows = new ServerWindows((id) => remote.markRevoked(id))
  const remote = new Remote({
    store: new ServerStore(join(hooks.dataDir(), 'servers.json'), vault),
    hosts: new KnownHosts(join(hooks.dataDir(), 'servers-known-hosts')),
    windows,
    name: () => hostname().replace(/\.local$/, '') || 'Mac'
  })

  const send = (channel: string, payload: unknown): void => {
    const win = hooks.mainWindow()
    if (win && !win.isDestroyed()) win.webContents.send(channel, payload)
  }
  remote.on('change', (list: ServerInfo[]) => send('servers:changed', list))

  ipcMain.handle('servers:list', (): ServerInfo[] => remote.list())

  // The key the server shows, for the person to compare.
  ipcMain.handle('servers:hostkey', async (_e, link: unknown): Promise<{ ok: true; key: HostKeyInfo } | { ok: false; error: string }> => {
    const t = text(link)
    const parsed = t === undefined ? undefined : parsePairLink(t)
    if (!parsed?.ok) return refuse(parsed ? parsed.error : 'not a Tucano link')
    try {
      return { ok: true, key: await remote.hostKey(parsed.link.reach) }
    } catch (e) {
      return refuse(e instanceof Error ? e.message : String(e))
    }
  })

  ipcMain.handle('servers:add', async (_e, link: unknown, fingerprint: unknown): Promise<AddResult> => {
    const t = text(link)
    const parsed = t === undefined ? undefined : parsePairLink(t)
    if (!parsed?.ok) return refuse(parsed ? parsed.error : 'not a Tucano link')
    // The link's own fingerprint is what the server is held to; one the person confirmed has to be the same.
    if (fingerprint !== undefined && fingerprint !== null && !fingerprintOk(fingerprint)) return refuse('not a key fingerprint')
    if (parsed.link.fp && typeof fingerprint === 'string' && fingerprint !== parsed.link.fp) return refuse('the fingerprint is not the one in the link')
    const confirmed = parsed.link.fp ?? (typeof fingerprint === 'string' ? fingerprint : undefined)
    return remote.add({ link: parsed.link, ...(confirmed ? { fingerprint: confirmed } : {}) })
  })

  ipcMain.handle('servers:open', async (_e, id: unknown) => {
    const i = idOf(id)
    return i ? remote.open(i) : refuse('not a server')
  })
  ipcMain.on('servers:disconnect', (_e, id: unknown) => {
    const i = idOf(id)
    if (i) remote.disconnect(i)
  })
  ipcMain.on('servers:remove', (_e, id: unknown) => {
    const i = idOf(id)
    if (i) remote.remove(i)
  })

  // A pairing link the app was opened with, or that was clicked, waits here until the page asks for it.
  let waiting: string | undefined
  ipcMain.handle('servers:pending-link', () => {
    const t = waiting
    waiting = undefined
    return t
  })
  const pairLink = (url: string): void => {
    if (text(url) === undefined || !url.startsWith('tucano://pair')) return
    waiting = url
    hooks.showWindow()
    const win = hooks.mainWindow()
    if (win && !win.isDestroyed() && !win.webContents.isLoading()) {
      send('servers:pair-link', url)
      waiting = undefined
    }
  }

  // The Mac wakes, or its network changes: the tunnels try again at once instead of waiting out their pauses.
  powerMonitor.on('resume', () => remote.wake())
  powerMonitor.on('unlock-screen', () => remote.wake())

  return {
    dispose: () => {
      remote.dispose()
      windows.closeAll()
    },
    pairLink
  }
}
