import { requestUrl, RequestUrlParam } from 'obsidian'
import { IJiraIssueAccountSettings, IMcpOAuthState } from '../interfaces/settingsInterfaces'

// Atlassian Rovo MCP server, used purely as a transport for issue lookups and JQL searches.
export const MCP_URL = 'https://mcp.atlassian.com/v2/mcp'
// The org's domain allowlist rejects the obsidian:// scheme, so the redirect goes to a temporary localhost listener.
export const MCP_CALLBACK_PORT = 27183
export const MCP_REDIRECT_URI = `http://localhost:${MCP_CALLBACK_PORT}/callback`
const SIGN_IN_TIMEOUT_MS = 5 * 60 * 1000
const MCP_PROTOCOL_VERSION = '2025-06-18'
const MCP_SCOPES = 'read:me read:account offline_access read:jira:agent-interface search:jira:agent-interface'
// Refresh slightly before the real expiry so an in-flight request does not fail.
const EXPIRY_MARGIN_MS = 60 * 1000

interface IAuthServerMetadata {
    authorization_endpoint: string
    token_endpoint: string
    registration_endpoint: string
}

interface IPendingSignIn {
    state: string
    verifier: string
    account: IJiraIssueAccountSettings
    onDone: (error?: Error) => void
    close: () => void
}

let authServerMetadata: IAuthServerMetadata = null
let pendingSignIn: IPendingSignIn = null
// MCP sessions and in-flight refreshes are keyed by the account object.
const sessions = new WeakMap<IJiraIssueAccountSettings, string>()
const refreshes = new WeakMap<IJiraIssueAccountSettings, Promise<void>>()
// Set by the plugin so refreshed tokens are persisted to data.json.
let persistSettings: () => Promise<void> = async () => { /* replaced in setPersistCallback */ }
let nextRpcId = 1

export function setPersistCallback(callback: () => Promise<void>) {
    persistSettings = callback
}

export function isSignedIn(account: IJiraIssueAccountSettings): boolean {
    return !!account.oauth?.refreshToken
}

function base64Url(bytes: Uint8Array): string {
    let s = ''
    bytes.forEach(b => s += String.fromCharCode(b))
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function randomString(byteLength: number): string {
    return base64Url(crypto.getRandomValues(new Uint8Array(byteLength)))
}

async function sha256Challenge(verifier: string): Promise<string> {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
    return base64Url(new Uint8Array(digest))
}

async function postJson(url: string, body: unknown, headers: Record<string, string> = {}): Promise<{ status: number, headers: Record<string, string>, text: string }> {
    const param: RequestUrlParam = {
        url,
        method: 'POST',
        contentType: 'application/json',
        headers: { Accept: 'application/json, text/event-stream', ...headers },
        body: JSON.stringify(body),
        throw: false,
    }
    const response = await requestUrl(param)
    return { status: response.status, headers: response.headers, text: response.text }
}

async function postForm(url: string, form: Record<string, string>): Promise<any> {
    const response = await requestUrl({
        url,
        method: 'POST',
        contentType: 'application/x-www-form-urlencoded',
        body: new URLSearchParams(form).toString(),
        throw: false,
    })
    if (response.status !== 200) {
        throw new Error(`OAuth token request failed (HTTP ${response.status}): ${response.json?.error_description || response.json?.error || response.text}`)
    }
    return response.json
}

// Follows the MCP authorization spec: protected resource metadata -> authorization server metadata.
async function discoverAuthServer(): Promise<IAuthServerMetadata> {
    if (authServerMetadata) return authServerMetadata
    const origin = new URL(MCP_URL)
    const resourceMetadata = (await requestUrl(`${origin.origin}/.well-known/oauth-protected-resource${origin.pathname}`)).json
    const issuer: string = resourceMetadata.authorization_servers[0]
    const issuerUrl = new URL(issuer)
    const metadata = (await requestUrl(`${issuerUrl.origin}/.well-known/oauth-authorization-server${issuerUrl.pathname}`)).json
    authServerMetadata = metadata
    return metadata
}

async function ensureClientId(account: IJiraIssueAccountSettings, metadata: IAuthServerMetadata): Promise<string> {
    // A client registered for another redirect URI cannot be reused.
    if (account.oauth?.clientId && account.oauth.redirectUri === MCP_REDIRECT_URI) {
        return account.oauth.clientId
    }
    const response = await postJson(metadata.registration_endpoint, {
        client_name: 'Obsidian Jira Issue',
        redirect_uris: [MCP_REDIRECT_URI],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
    })
    if (response.status !== 200 && response.status !== 201) {
        throw new Error(`Client registration failed (HTTP ${response.status})`)
    }
    const clientId = JSON.parse(response.text).client_id as string
    account.oauth = { clientId, redirectUri: MCP_REDIRECT_URI }
    return clientId
}

/** Opens the browser for the OAuth consent. `onDone` is called once the callback was handled. */
export async function startSignIn(account: IJiraIssueAccountSettings, onDone: (error?: Error) => void): Promise<void> {
    const metadata = await discoverAuthServer()
    const clientId = await ensureClientId(account, metadata)
    const verifier = randomString(48)
    const state = randomString(16)
    const close = await listenForCallback()
    pendingSignIn?.close()
    pendingSignIn = { state, verifier, account, onDone, close }
    const url = new URL(metadata.authorization_endpoint)
    url.search = new URLSearchParams({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: MCP_REDIRECT_URI,
        scope: MCP_SCOPES,
        state,
        code_challenge: await sha256Challenge(verifier),
        code_challenge_method: 'S256',
        resource: MCP_URL,
        audience: 'api.atlassian.com',
        prompt: 'consent',
    }).toString()
    window.open(url.toString())
}

// Starts a one-shot listener for the OAuth redirect. Desktop only (needs Node `http`).
function listenForCallback(): Promise<() => void> {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const http = require('http')
    return new Promise((resolve, reject) => {
        const server = http.createServer((req: any, res: any) => {
            const url = new URL(req.url, MCP_REDIRECT_URI)
            if (url.pathname !== '/callback') {
                res.writeHead(404).end()
                return
            }
            res.writeHead(200, { 'Content-Type': 'text/html' })
            res.end('<html><body>Signed in. You can close this tab and return to Obsidian.</body></html>')
            handleSignInCallback(Object.fromEntries(url.searchParams))
        })
        const timer = setTimeout(() => close(), SIGN_IN_TIMEOUT_MS)
        const close = () => {
            clearTimeout(timer)
            server.close()
            if (pendingSignIn?.close === close) {
                pendingSignIn.onDone(new Error('Sign in timed out'))
                pendingSignIn = null
            }
        }
        server.once('error', (e: Error) => { clearTimeout(timer); reject(new Error(`Cannot listen on port ${MCP_CALLBACK_PORT}: ${e.message}`)) })
        server.listen(MCP_CALLBACK_PORT, '127.0.0.1', () => resolve(close))
    })
}

function storeTokens(account: IJiraIssueAccountSettings, tokens: any) {
    account.oauth.accessToken = tokens.access_token
    // Refresh token rotation: keep the old one if the server did not issue a new one.
    account.oauth.refreshToken = tokens.refresh_token || account.oauth.refreshToken
    account.oauth.expiresAt = Date.now() + (tokens.expires_in || 3600) * 1000
}

/** Handler for `obsidian://jira-mcp-callback`. */
export async function handleSignInCallback(params: Record<string, string>): Promise<void> {
    const pending = pendingSignIn
    if (!pending) return
    pendingSignIn = null
    pending.close()
    try {
        if (params.error) throw new Error(`${params.error}: ${params.error_description || ''}`)
        if (params.state !== pending.state) throw new Error('OAuth state mismatch')
        const metadata = await discoverAuthServer()
        const tokens = await postForm(metadata.token_endpoint, {
            grant_type: 'authorization_code',
            code: params.code,
            redirect_uri: MCP_REDIRECT_URI,
            client_id: pending.account.oauth.clientId,
            code_verifier: pending.verifier,
            resource: MCP_URL,
        })
        storeTokens(pending.account, tokens)
        sessions.delete(pending.account)
        await persistSettings()
        pending.onDone()
    } catch (e) {
        pending.onDone(e as Error)
    }
}

export async function signOut(account: IJiraIssueAccountSettings): Promise<void> {
    account.oauth = undefined
    sessions.delete(account)
    await persistSettings()
}

async function refreshAccessToken(account: IJiraIssueAccountSettings): Promise<void> {
    const inFlight = refreshes.get(account)
    if (inFlight) return inFlight
    const refresh = (async () => {
        const metadata = await discoverAuthServer()
        try {
            const tokens = await postForm(metadata.token_endpoint, {
                grant_type: 'refresh_token',
                refresh_token: account.oauth.refreshToken,
                client_id: account.oauth.clientId,
                resource: MCP_URL,
            })
            storeTokens(account, tokens)
            await persistSettings()
        } catch (e) {
            throw new Error(`Rovo MCP session expired, sign in again from the plugin settings. (${(e as Error).message})`)
        }
    })()
    refreshes.set(account, refresh)
    try {
        await refresh
    } finally {
        refreshes.delete(account)
    }
}

async function getAccessToken(account: IJiraIssueAccountSettings): Promise<string> {
    if (!isSignedIn(account)) {
        throw new Error('Not signed in to Rovo MCP: open the plugin settings and use "Sign in".')
    }
    if (!account.oauth.accessToken || (account.oauth.expiresAt || 0) - EXPIRY_MARGIN_MS < Date.now()) {
        await refreshAccessToken(account)
    }
    return account.oauth.accessToken
}

// Streamable HTTP replies are either a JSON body or an SSE stream carrying the JSON-RPC response.
function parseRpcResponse(text: string, contentType: string, id: number): any {
    if (contentType?.includes('text/event-stream')) {
        for (const event of text.split(/\r?\n\r?\n/)) {
            const data = event.split(/\r?\n/).filter(l => l.startsWith('data:')).map(l => l.slice(5).trimStart()).join('\n')
            if (!data) continue
            const message = JSON.parse(data)
            if (message.id === id) return message
        }
        throw new Error('MCP: no response in event stream')
    }
    return JSON.parse(text)
}

async function rpc(account: IJiraIssueAccountSettings, method: string, params: unknown, options: { notification?: boolean, retry?: boolean } = {}): Promise<any> {
    const token = await getAccessToken(account)
    const headers: Record<string, string> = {
        Authorization: `Bearer ${token}`,
        'MCP-Protocol-Version': MCP_PROTOCOL_VERSION,
    }
    const session = sessions.get(account)
    if (session) headers['Mcp-Session-Id'] = session
    const id = nextRpcId++
    const body = options.notification ? { jsonrpc: '2.0', method, params } : { jsonrpc: '2.0', id, method, params }
    const response = await postJson(MCP_URL, body, headers)

    if (response.status === 401 && options.retry !== false) {
        account.oauth.expiresAt = 0
        return rpc(account, method, params, { ...options, retry: false })
    }
    if (response.status === 404 && session && options.retry !== false) {
        // Session expired on the server side.
        sessions.delete(account)
        return rpc(account, method, params, { ...options, retry: false })
    }
    if (response.status >= 400) {
        throw new Error(`Rovo MCP HTTP ${response.status}: ${response.text.slice(0, 200)}`)
    }
    const sessionId = response.headers['mcp-session-id']
    if (sessionId) sessions.set(account, sessionId)
    if (options.notification) return null
    const message = parseRpcResponse(response.text, response.headers['content-type'], id)
    if (message.error) throw new Error(`Rovo MCP error: ${message.error.message}`)
    return message.result
}

async function ensureSession(account: IJiraIssueAccountSettings): Promise<void> {
    if (sessions.has(account)) return
    await rpc(account, 'initialize', {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: 'obsidian-jira-issue', version: '1' },
    })
    await rpc(account, 'notifications/initialized', {}, { notification: true })
}

/** Calls an MCP tool and returns its JSON payload. */
export async function callTool(account: IJiraIssueAccountSettings, name: string, args: Record<string, unknown>): Promise<any> {
    await ensureSession(account)
    const result = await rpc(account, 'tools/call', { name, arguments: args })
    const text: string = result.content?.filter((c: any) => c.type === 'text').map((c: any) => c.text).join('') ?? ''
    if (result.isError) throw new Error(`Rovo MCP tool ${name} failed: ${text.slice(0, 300)}`)
    if (result.structuredContent) return result.structuredContent
    try {
        return JSON.parse(text)
    } catch {
        throw new Error(`Rovo MCP tool ${name} returned non-JSON content: ${text.slice(0, 200)}`)
    }
}
