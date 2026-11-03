// The window onto a server's screens: the same page the server gives a browser, in a window of its own. Nothing of
// the app's own is in it (no preload, no bridge to the core on this Mac), because what runs there is the server's.
//
// It is signed in without the token ever being in an address or a cookie: this window's own session adds the
// token to what goes to the server's origin, as an `Authorization` header. A page that came from anywhere else
// never gets it, and a token the server has revoked shows as a message, not as a page that quietly fails.
import { BrowserWindow, nativeTheme, session, shell } from 'electron'
import { L } from '../../shared/lang'
import type { ServerState } from '../../shared/servers'
import { navigationAllowed, sessionName, titleOf } from './window-rules'
import type { Windows } from './remote'

type Open = { id: string; name: string; origin: string; token: string }

const page = (title: string, text: string): string =>
  `data:text/html;charset=utf-8,${encodeURIComponent(
    `<!doctype html><meta charset="utf-8"><title>${title}</title><style>body{font:15px -apple-system,system-ui,sans-serif;display:grid;place-items:center;height:100vh;margin:0;color:#444;background:#f3f0ea}@media(prefers-color-scheme:dark){body{color:#ccc;background:#121110}}main{max-width:30em;padding:2em;text-align:center}h1{font-size:1.2em}</style><main><h1>${title}</h1><p>${text}</p></main>`
  )}`

const escape = (s: string): string => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`)

export class ServerWindows implements Windows {
  private wins = new Map<string, { win: BrowserWindow; name: string; origin: string; state: ServerState }>()

  constructor(private readonly onRevoked: (id: string) => void) {}

  open(s: Open): void {
    const known = this.wins.get(s.id)
    this.sign(s)
    if (known && !known.win.isDestroyed()) {
      const moved = known.origin !== s.origin
      known.origin = s.origin
      known.name = s.name
      if (known.win.isMinimized()) known.win.restore()
      known.win.show()
      known.win.focus()
      if (moved) void known.win.loadURL(`${s.origin}/`)
      return
    }
    const win = new BrowserWindow({
      width: 1280,
      height: 820,
      minWidth: 900,
      minHeight: 600,
      show: false,
      title: titleOf(s.name, 'connecting'),
      titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
      autoHideMenuBar: process.platform !== 'darwin',
      trafficLightPosition: { x: 16, y: 18 },
      backgroundColor: nativeTheme.shouldUseDarkColors ? '#121110' : '#f3f0ea',
      webPreferences: {
        sandbox: true,
        contextIsolation: true,
        nodeIntegration: false,
        webviewTag: false,
        session: session.fromPartition(sessionName(s.id))
      }
    })
    const entry = { win, name: s.name, origin: s.origin, state: 'connecting' as ServerState }
    this.wins.set(s.id, entry)
    win.once('ready-to-show', () => win.show())
    win.on('closed', () => {
      if (this.wins.get(s.id)?.win === win) this.wins.delete(s.id)
    })
    // A link in the server's page goes to the browser; a page of another origin never loads in here.
    win.webContents.setWindowOpenHandler(({ url }) => {
      if (/^https?:\/\//.test(url)) void shell.openExternal(url)
      return { action: 'deny' }
    })
    win.webContents.on('will-navigate', (event, url) => {
      if (navigationAllowed(url, entry.origin)) return
      event.preventDefault()
      if (/^https?:\/\//.test(url)) void shell.openExternal(url)
    })
    // The server said no to the token: it was revoked there (tucano-server revoke), or the server was set up again.
    win.webContents.on('did-navigate', (_e, url, code) => {
      if (code !== 401 || !navigationAllowed(url, entry.origin)) return
      this.onRevoked(s.id)
      void win.loadURL(
        page(
          escape(L('Este Mac não está mais pareado', 'This Mac is no longer paired')),
          escape(L('O servidor não aceita mais o acesso deste Mac. Em Configurações › Servidores, remova o servidor e pareie de novo com um código novo (tucano-server pair).', 'The server no longer accepts this Mac. In Settings › Servers, remove the server and pair again with a new code (tucano-server pair).'))
        )
      )
    })
    win.webContents.on('did-fail-load', (_e, code, _text, url, isMainFrame) => {
      if (!isMainFrame || code === -3 || !navigationAllowed(url, entry.origin)) return // -3: a navigation that was cut short
      void win.loadURL(page(escape(L('Sem conexão com o servidor', 'No connection to the server')), escape(L('O Tucano tenta de novo sozinho. Esta janela volta quando a conexão voltar.', 'Tucano keeps trying. This window comes back when the connection does.'))))
    })
    void win.loadURL(`${s.origin}/`)
  }

  // Adds the token to what goes to this origin, and to nothing else; the page asks for nothing it wasn't given.
  private sign(s: Open): void {
    const ses = session.fromPartition(sessionName(s.id))
    ses.webRequest.onBeforeSendHeaders({ urls: [`${s.origin}/*`] }, (details, done) => {
      done({ requestHeaders: { ...details.requestHeaders, Authorization: `Bearer ${s.token}` } })
    })
    ses.setPermissionRequestHandler((_wc, permission, done) => done(permission === 'clipboard-sanitized-write'))
    ses.setPermissionCheckHandler((_wc, permission) => permission === 'clipboard-sanitized-write')
  }

  // The line's state is in the title: the page is the server's, and doesn't know about the tunnel.
  state(id: string, state: ServerState): void {
    const w = this.wins.get(id)
    if (!w || w.win.isDestroyed()) return
    w.state = state
    w.win.setTitle(titleOf(w.name, state))
    // Back up after a drop: the message the window was showing gives way to the page.
    if (state === 'online' && !w.win.webContents.getURL().startsWith(w.origin)) void w.win.loadURL(`${w.origin}/`)
  }

  close(id: string): void {
    const w = this.wins.get(id)
    this.wins.delete(id)
    if (w && !w.win.isDestroyed()) w.win.close()
  }

  closeAll(): void {
    for (const id of [...this.wins.keys()]) this.close(id)
  }
}
