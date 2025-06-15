import { Hono } from 'hono'
import pug from 'pug'
import { join } from 'path'

import { getOAuthClient, createClientMetadata, getCurrentKeys, sessionStore } from './oauth-client'
import type { Config } from './types'
import { createHmac, timingSafeEqual } from 'crypto'
import { OAuthSession } from '@atproto/oauth-client-node'
import { Agent } from '@atproto/api'
import { TID } from '@atproto/common-web'
import { Database } from 'bun:sqlite'

const config: Config = {
    // Prefer environment variables, fallback to defaults for local development
    domain: (Bun.env.DOMAIN ?? 'https://dev.nekomimi.pet') as `https://${string}`,
    clientName: Bun.env.CLIENT_NAME ?? 'PDS-View'
}

const app = new Hono()
const client = await getOAuthClient(config);

const templatePath = join(process.cwd(), 'views', 'index.pug')
const template = pug.compileFile(templatePath)

const COOKIE_NAME = 'bsid'

const appDb = new Database('oauth.db');
appDb.exec(`CREATE TABLE IF NOT EXISTS app_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);

function getCookieSecret(): string {
    const row = appDb.prepare('SELECT value FROM app_config WHERE key = ?').get('cookie_secret') as { value: string } | undefined;
    if (row) return row.value;
    const newSecret = crypto.randomUUID().replace(/-/g, '');
    appDb.prepare('INSERT INTO app_config (key,value) VALUES (?,?)').run('cookie_secret', newSecret);
    return newSecret;
}

const COOKIE_SECRET = getCookieSecret();

const base64urlEncode = (buf: Buffer | Uint8Array) => Buffer.from(buf).toString('base64url')
const base64urlDecode = (str: string) => Buffer.from(str, 'base64url')

const sign = (msg: string) => createHmac('sha256', COOKIE_SECRET).update(msg).digest('base64url')

const createSignedToken = (sub: string) => {
    const payload = base64urlEncode(Buffer.from(JSON.stringify({ sub })))
    const sig = sign(payload)
    return `${payload}.${sig}`
}

const verifySignedToken = (token: string): string | null => {
    const parts = token.split('.')
    if (parts.length !== 2) return null
    const [payloadB64, sig] = parts as [string, string]
    if (!sig) return null
    const expected = sign(payloadB64)
    // constant-time compare
    if (sig.length !== expected.length) return null
    try {
        if (!timingSafeEqual(Buffer.from(sig, 'base64url'), Buffer.from(expected, 'base64url'))) return null
    } catch { return null }
    try {
        const json = JSON.parse(base64urlDecode(payloadB64).toString('utf8'))
        if (typeof json.sub === 'string') return json.sub
    } catch { /* ignore */ }
    return null
}

const serializeCookie = (name: string, value: string, opts: { maxAge?: number } = {}) => {
    const parts = [`${name}=${value}`]
    parts.push('HttpOnly', 'Secure', 'SameSite=Lax', 'Path=/')
    if (opts.maxAge) parts.push(`Max-Age=${opts.maxAge}`)
    return parts.join('; ')
}
const deleteCookie = (name: string) => `${name}=; HttpOnly; Secure; SameSite=Lax; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT`

const parseCookies = (cookieHeader?: string | null) => {
    const cookies: Record<string, string> = {}
    if (!cookieHeader) return cookies
    for (const pair of cookieHeader.split(';')) {
        const [k, ...vals] = pair.trim().split('=')
        if (!k) continue
        cookies[k] = decodeURIComponent(vals.join('=') || '')
    }
    return cookies
}

app.get('/', (c) => {
    const html = template({
        title: 'OAuth Backend',
        domain: config.domain,
        clientName: config.clientName
    })
    return c.html(html)
});

app.get('/client-metadata.json', (c) => {
    return c.json(createClientMetadata(config))
});

app.get('/jwks.json', (c) => {
    const keys = getCurrentKeys();
    if (!keys.length) {
        return c.json({ keys: [] });
    }
    return c.json({
        keys: keys.map(k => {
            const jwk = (k as any).publicJwk ?? k;
            const { d: _d, k: _k, ...pub } = jwk;
            return pub;
        })
    })
});

app.post('/api/auth/signin', async (c) => {
    try {
        const { handle } = await c.req.json<{ handle: string }>()
        const state = crypto.randomUUID()
        const url = await client.authorize(handle, { state })
        return c.json({ url })
    } catch (err) {
        console.error('Signin error', err)
        return c.json({ error: 'Authentication failed' }, 400)
    }
});

app.get('/api/auth/callback', async (c) => {
    try {
        const params = new URL(c.req.url).searchParams
        const result = await client.callback(params)
        if (!result?.session) {
            return c.json({ error: 'Authentication failed' }, 400)
        }
        const token = createSignedToken(result.session.sub)
        const cookie = serializeCookie(COOKIE_NAME, token, { maxAge: 60 * 60 * 24 * 7 })
        const res = c.redirect(config.domain, 302)
        res.headers.set('Set-Cookie', cookie)
        return res
    } catch (err) {
        console.error('Callback error', err)
        return c.json({ error: 'Authentication failed' }, 400)
    }
});

app.get('/api/auth/status', async (c) => {
    try {
        const cookies = parseCookies(c.req.header('Cookie'))
        const token = cookies[COOKIE_NAME]
        const sub = token ? verifySignedToken(token) : null
        if (!sub) return c.json({ authenticated: false })

        let oauthSession: OAuthSession | undefined;
        try {
            oauthSession = await client.restore(sub, 'auto');
        } catch (_) {
        }

        if (!oauthSession) {
            const stored = await sessionStore.get(sub)
            if (!stored) {
                const res = c.json({ authenticated: false })
                res.headers.set('Set-Cookie', deleteCookie(COOKIE_NAME))
                return res
            }
            return c.json({ authenticated: true, user: { sub } })
        }

        return c.json({ authenticated: true, user: { sub, pds: oauthSession.serverMetadata.issuer } })
    } catch (err) {
        console.error('Status check error', err)
        return c.json({ authenticated: false })
    }
});

app.post('/api/auth/logout', async (c) => {
    try {
        const cookies = parseCookies(c.req.header('Cookie'))
        const token = cookies[COOKIE_NAME]
        const sub = token ? verifySignedToken(token) : null
        if (sub) {
            await sessionStore.del(sub)
        }
        const res = c.json({ success: true })
        res.headers.set('Set-Cookie', deleteCookie(COOKIE_NAME))
        return res
    } catch (err) {
        console.error('Logout error', err)
        return c.json({ error: 'Logout failed' }, 500)
    }
});

app.get('/plonk/getPlonks', async (c) => {
    const cookies = parseCookies(c.req.header('Cookie'));
    const token = cookies[COOKIE_NAME];
    const sub = token ? verifySignedToken(token) : null;
    if (!sub) return c.json({ error: 'Authentication failed' }, 400);
    
    const session = await client.restore(sub, 'auto');
    const agent = new Agent(session);

    const { data } = await agent.com.atproto.repo.listRecords({
        repo: sub,
        collection: 'li.plonk.paste',
    });

    return c.json(data);
});

app.post('/plonk/post', async (c) => {
    try {
        const cookies = parseCookies(c.req.header('Cookie'))
        const token = cookies[COOKIE_NAME]
        const sub = token ? verifySignedToken(token) : null
        if (!sub) return c.json({ error: 'Authentication failed' }, 401)

        const body = await c.req.json<{ title?: string; lang?: string; code: string }>()
        const rkey = TID.nextStr()
        const shortUrl = Math.random().toString(36).slice(2, Math.floor(Math.random() * 8) + 3)
        const record = {
            $type: 'li.plonk.paste',
            code: body.code,
            lang: body.lang || 'plaintext',
            shortUrl,
            title: body.title || '',
            createdAt: new Date().toISOString(),
        }

        const session = await client.restore(sub, 'auto')
        const agent = new Agent(session)
        await agent.com.atproto.repo.putRecord({
            repo: sub,
            collection: 'li.plonk.paste',
            rkey,
            record,
            validate: false,
        })

        return c.json({ success: true })
    } catch (err) {
        console.error('Post plonk error', err)
        return c.json({ error: 'Post failed' }, 500)
    }
})

export default {
    port: 80,
    fetch: app.fetch
};
