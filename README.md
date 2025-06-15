# A simple OAuth backend example for an AT Proto PDS

Live demo: https://oauth-backend.fly.dev

## Brief explanation of what OAuth is

OAuth 2.0 is a *delegated authentication* framework. Instead of sharing passwords between a client and a resource server, the resource owner (end‑user) grants the client scoped, time‑bounded access by way of a bearer **access‑token**, optionally accompanied by a long‑lived **refresh‑token**. The grant is mediated by an **authorisation server**, which authenticates the user and issues the tokens.

| Role                 | In AT Proto terms                            | Job in the dance                           |
| -------------------- | -------------------------------------------- | ------------------------------------------ |
| Resource Owner       | End‑user with a handle / DID                 | Decides whether to grant the client access |
| Client               | *PDS‑View* backend (**confidential** client) | Requests and later uses tokens             |
| Resource Server      | The user’s PDS (or any repo)                 | Accepts **DPoP‑bound** access‑tokens       |
| Authorisation Server | Same PDS (`/xrpc/com.atproto.oauth.*`)       | Authenticates the user, mints tokens       |

Core ideas:

1. **Redirect‑based consent** - browser bounces to the PDS for a login + *Allow* click.
2. **Scopes** - explicit permission strings (`atproto`, `transition:generic`, …).
3. **Proof‑of‑possession (DPoP)** - every token ties to a per‑session EC key.
4. **Refresh** - short‑lived access‑tokens; background refresh with a refresh‑token.

---

## 1 · Declaring your client - `createClientMetadata()`

The helper builds the JSON document the PDS will fetch to learn how your backend authenticates and where it should redirect the browser.

```ts
export const createClientMetadata = (cfg: {domain: `https://${string}`, clientName: string}): ClientMetadata => ({
  client_id: `${cfg.domain}/client-metadata.json`,   // unique ID + fetch location
  client_name: cfg.clientName,
  redirect_uris: [ `${cfg.domain}/api/auth/callback` ],
  token_endpoint_auth_method: 'private_key_jwt',     // we sign a JWT with ES256
  token_endpoint_auth_signing_alg: 'ES256',
  dpop_bound_access_tokens: true,                    // sender‑constrained tokens
  scope: 'atproto transition:generic',
  jwks_uri: `${cfg.domain}/jwks.json`,
  grant_types: [ 'authorization_code', 'refresh_token' ],
  response_types: [ 'code' ],
  application_type: 'web',
  subject_type: 'public',
  authorization_signed_response_alg: 'ES256'
});
```

*Why it matters* - the `private_key_jwt` method lets a **confidential** client prove its identity without a shared secret; it signs a short‑lived JWT with one of the ES256 keys published at `/jwks.json`.

---

## 2 · Ephemeral data stores - `stateStore` & `sessionStore`

| Table / KV key   | Contains                                                                                   | Lifetime                                              | Swappable for                                |
| ---------------- | ------------------------------------------------------------------------------------------ | ----------------------------------------------------- | -------------------------------------------- |
| `oauth_states`   | The *login attempt*: `<state, code_verifier, DPoP key, issuer>`                            | Minutes - removed after `/callback`                   | Cloudflare KV / Redis / DynamoDB / R2 Object |
| `oauth_sessions` | The *long‑lived session*: refresh‑token, access‑token expiry, session DPoP key, last nonce | Days -> weeks - SDK auto‑updates row on silent refresh | Same services - any consistent KV suffices   |

SQLite is used in the sample because it is zero‑dependency and file‑backed; swap the `set/get/del` calls for your provider's SDK to keep the backend *stateless* (ideal for serverless deployments).

---

## 3 · Key material - JSON Web Keys (JWKs) & rotation

The backend needs a *client‑authentication* key‑set to sign `client_assertion` JWTs.  `ensureKeys()` guarantees **three** ES256 keys exist:

```text
key1 (key‑pair) <- oldest, prunable after no sessions reference it
key2 (key‑pair)
key3 (key‑pair) <- newest; used for new logins & token refresh
```

* **Public parts** are exposed at `/jwks.json`; the PDS uses them to verify your JWT signatures.
* **Private parts** are saved in `oauth_keys` so the service survives restarts.
* **Rotation** strategy: periodically add a fresh key -> start using it -> delete the oldest once it's idle.
* **Serverless note** - when running on Cloudflare Workers, Lambda, etc., load the *private* keys from an encrypted secret store or environment variable, never from the code bundle.

---

## 4 · Complete helper module - `oauth-client.ts`

```ts
// oauth-client.ts  -  all helper glue for a confidential AT Proto OAuth client

import { NodeOAuthClient, type ClientMetadata } from "@atproto/oauth-client-node";
import { Database } from "bun:sqlite";
import { JoseKey } from "@atproto/jwk-jose";

// ────────────────────────────────────────────────────────────
// 1. Persistence layer - SQLite for the demo
// ────────────────────────────────────────────────────────────
const db = new Database("oauth.db");

// Keeps one row per in-flight login request (state → blob)
db.exec(`
    CREATE TABLE IF NOT EXISTS oauth_states (
        key TEXT PRIMARY KEY,
        data TEXT NOT NULL,
        created_at INTEGER DEFAULT (strftime('%s', 'now'))
    )
`);

// Keeps one row per user session (DID → Session JSON)
db.exec(`
    CREATE TABLE IF NOT EXISTS oauth_sessions (
        sub TEXT PRIMARY KEY,
        data TEXT NOT NULL,
        updated_at INTEGER DEFAULT (strftime('%s', 'now'))
    )
`);

// Stores the **private** JWKs for client-auth; public parts go to /jwks.json
db.exec(`
    CREATE TABLE IF NOT EXISTS oauth_keys (
        kid TEXT PRIMARY KEY,
        jwk TEXT NOT NULL
    )
`);

// ────────────────────────────────────────────────────────────
// 2. Tiny KV wrappers expected by NodeOAuthClient
// ────────────────────────────────────────────────────────────
const stateStore = {
    async set(key: string, data: any) {
        console.debug('[stateStore] set', key);
        db.prepare(
            "INSERT OR REPLACE INTO oauth_states (key, data) VALUES (?, ?)"
        ).run(key, JSON.stringify(data));
    },
    async get(key: string) {
        console.debug('[stateStore] get', key);
        const row = db.prepare(
            "SELECT data FROM oauth_states WHERE key = ?"
        ).get(key) as { data: string } | undefined;
        return row ? JSON.parse(row.data) : undefined;
    },
    async del(key: string) {
        console.debug('[stateStore] del', key);
        db.prepare("DELETE FROM oauth_states WHERE key = ?").run(key);
    }
};

const sessionStore = {
    async set(sub: string, data: any) {
        console.debug('[sessionStore] set', sub);
        db.prepare(
            "INSERT OR REPLACE INTO oauth_sessions (sub, data) VALUES (?, ?)"
        ).run(sub, JSON.stringify(data));
    },
    async get(sub: string) {
        console.debug('[sessionStore] get', sub);
        const row = db.prepare(
            "SELECT data FROM oauth_sessions WHERE sub = ?"
        ).get(sub) as { data: string } | undefined;
        return row ? JSON.parse(row.data) : undefined;
    },
    async del(sub: string) {
        console.debug('[sessionStore] del', sub);
        db.prepare("DELETE FROM oauth_sessions WHERE sub = ?").run(sub);
    }
};

export { sessionStore };

// ────────────────────────────────────────────────────────────
// 3. Client-metadata helper - served at /client-metadata.json
// ────────────────────────────────────────────────────────────
export const createClientMetadata = (
    cfg: { domain: `https://${string}`, clientName: string }
): ClientMetadata => ({
    client_id:              `${cfg.domain}/client-metadata.json`,
    client_name:            cfg.clientName,
    client_uri:             cfg.domain,

    logo_uri:               `${cfg.domain}/logo.png`,
    tos_uri:                `${cfg.domain}/tos`,
    policy_uri:             `${cfg.domain}/policy`,

    redirect_uris:          [ `${cfg.domain}/api/auth/callback` ],
    grant_types:            ["authorization_code", "refresh_token"],
    response_types:         ["code"],
    application_type:       "web",

    token_endpoint_auth_method:        "private_key_jwt",
    token_endpoint_auth_signing_alg:   "ES256",

    scope:                  "atproto transition:generic",
    dpop_bound_access_tokens: true,

    jwks_uri:               `${cfg.domain}/jwks.json`,
    subject_type:           "public",
    authorization_signed_response_alg: "ES256"
});

// ────────────────────────────────────────────────────────────
// 4. Key management - generate / persist 3 ES256 keys
// ────────────────────────────────────────────────────────────

// Persist a fresh private JWK row
const persistKey = (key: JoseKey) => {
    const priv = key.privateJwk;
    if (!priv) return;                    // public-only key: ignore
    const kid = key.kid ?? crypto.randomUUID();
    db.prepare(
        "INSERT OR REPLACE INTO oauth_keys (kid, jwk) VALUES (?, ?)"
    ).run(kid, JSON.stringify(priv));
};

// Read keys back on boot
const loadPersistedKeys = async (): Promise<JoseKey[]> => {
    const rows = db.prepare(
        "SELECT kid, jwk FROM oauth_keys ORDER BY kid"
    ).all() as { kid: string; jwk: string }[];

    const keys: JoseKey[] = [];
    for (const { jwk } of rows) {
        try {
            const obj  = JSON.parse(jwk);
            const key  = await JoseKey.fromImportable(obj as any, (obj as any).kid);
            keys.push(key);
        } catch (err) {
            console.error('Could not parse stored JWK', err);
        }
    }
    return keys;
};

// Guarantee we always have key1, key2, key3 on disk
const ensureKeys = async (): Promise<JoseKey[]> => {
    let keys = await loadPersistedKeys();
    const needed: string[] = [];

    for (let i = 1; i <= 3; i++) {
        const kid = `key${i}`;
        if (!keys.some(k => k.kid === kid)) needed.push(kid);
    }

    // Generate any missing keys
    for (const kid of needed) {
        const newKey = await JoseKey.generate(['ES256'], kid);
        persistKey(newKey);
        keys.push(newKey);
    }

    // Order makes "latest" easy to find
    keys.sort((a, b) => (a.kid ?? '').localeCompare(b.kid ?? ''));
    return keys;
};

// ────────────────────────────────────────────────────────────
// 5. Exposed helpers used by the rest of the app
// ────────────────────────────────────────────────────────────
let currentKeys: JoseKey[] = [];

export const getCurrentKeys = () => currentKeys;

// Build / cache a fully-wired NodeOAuthClient instance
export const getOAuthClient = async (
    cfg: { domain: `https://${string}`, clientName: string }
) => {
    if (currentKeys.length === 0) {
        currentKeys = await ensureKeys();
    }

    return new NodeOAuthClient({
        clientMetadata: createClientMetadata(cfg),
        keyset:         currentKeys,
        stateStore,
        sessionStore
    });
};
```

---

## 5 · Next steps (out of scope for this primer)

* **Key storage in serverless** - use Secrets Manager / CF Secrets and decrypt at boot.
* **Distributed locks** - if multiple instances may refresh tokens concurrently, add a Redis Redlock.
* **Cleanup jobs** - cron delete expired `oauth_states` and stale `oauth_sessions`; rotate out old `key*` rows.

---

## 6 · Auth route handlers (`index.ts`)

### 6.1 Why Hono?

* **Tiny & fast.** Hono is a 3-4 kB router whose API matches Express-style middleware, yet compiles to a single function that runs on Node, Bun **or** edge runtimes (Cloudflare Workers, Vercel Edge, etc.).
* **Serverless-friendly.** Because each handler is just `fetch(Request)→Response`, you can lift this file into a fully-stateless deployment later; nothing in the code ties you to Bun/SQLite except the stores we wired earlier (which you may swap for KV).

---

### 6.2 Session cookies - recap

We **sign** the cookie instead of encrypting it, so the browser can only present it; it can't fabricate or tamper with it:

```
payload = base64url( {"sub": "<did>"} )
cookie   = payload + "." + HMAC-SHA256(COOKIE_SECRET, payload)
```

**If an attacker steals it**: they can act inside *our* backend until the cookie expires or the DB row is deleted, but they still never receive the PDS refresh-token itself.
**What they *cannot* do is just claim a DID at will.**  The backend always recomputes the HMAC with its private `COOKIE_SECRET`:

```txt
expected = HMAC-SHA-256(COOKIE_SECRET, payload)
```

If the signature on the incoming cookie doesn't match that exact value-because the attacker fabricated a new payload with a different `sub`, `verifySignedToken()` rejects it in constant time.
So possession of the *string* `did:plc:…` is worthless without the corresponding, server-issued cookie.

---

### 6.3 `POST /api/auth/signin`

```ts
app.post('/api/auth/signin', async (c) => {
  const { handle } = await c.req.json();   // ⓵ user typed e.g. "ana.bsky.social"
  const state = crypto.randomUUID();       // ⓶ anti-CSRF + stateStore key
  const url   = await client.authorize(handle, { state });
  return c.json({ url });                  // ⓷ front-end JS will `window.location = url`
});
```

| Step | What happens under the hood (NodeOAuthClient)                                             |
| ---- | ----------------------------------------------------------------------------------------- |
| ⓵    | Resolves **handle → DID → PDS URL**.                                                      |
| ⓶    | Generates PKCE code\_verifier, a fresh DPoP key-pair, stores both in `stateStore[state]`. |
| ⓷    | Returns the *browser-facing* authorize URL (already uploaded via PAR).                    |

---

### 6.4 `GET /api/auth/callback`

```ts
app.get('/api/auth/callback', async (c) => {
  const params  = new URL(c.req.url).searchParams;   // ?code & state
  const result  = await client.callback(params);     // ① exchanges code for tokens
  if (!result.session) return c.json({ error: 'Authentication failed' }, 400);

  const token   = createSignedToken(result.session.sub);             // ② sign DID
  const cookie  = serializeCookie(COOKIE_NAME, token, { maxAge: 604800 /*7d*/ });

  const res = c.redirect(config.domain, 302);       // ③ bounce back to SPA
  res.headers.set('Set-Cookie', cookie);
  return res;
});
```

| # | Callback details                                                                                                                                                                                                                                                                                          |
| - | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ① | *client.callback()* pulls the `state` blob, verifies it, sends the token request with:<br>• PKCE `code_verifier`<br>• DPoP header signed with the **session** key<br>• `client_assertion` JWT signed with the **client** ES256 key.<br>It then writes the full `OAuthSession` JSON into `oauth_sessions`. |
| ② | We create an **HMAC cookie** that carries only the user’s DID.                                                                                                                                                                                                                                            |
| ③ | The browser returns to `/`, now holding `bsid=<signed DID>`.                                                                                                                                                                                                                                              |

---

### 6.5 `GET /api/auth/status`

```ts
app.get('/api/auth/status', async (c) => {
  const sub = verifySignedToken(parseCookies(c.req.header('Cookie'))[COOKIE_NAME]);
  if (!sub) return c.json({ authenticated: false });

  // ① Try fast-path: does an active session exist?
  let oauthSession: OAuthSession|undefined;
  try { oauthSession = await client.restore(sub, 'auto'); } catch {}

  // ② If restore failed, fall back to the DB row (token may be expired)
  if (!oauthSession) {
    const stored = await sessionStore.get(sub);
    if (!stored) {                       // row missing → force logout
      const res = c.json({ authenticated: false });
      res.headers.set('Set-Cookie', deleteCookie(COOKIE_NAME));
      return res;
    }
    return c.json({ authenticated: true, user: { sub } });
  }

  // ③ Happy path
  return c.json({
    authenticated: true,
    user: { sub, pds: oauthSession.serverMetadata.issuer }
  });
});
```

* **`restore(sub,'auto')`** loads the JSON row, silently refreshes if the access-token is close to expiry, and re-persists the new blob-so the front end never notices.
* If the row vanished (admin revocation, DB GC), we wipe the cookie so the browser re-logs in.

---

### 6.6 `POST /api/auth/logout`

Same pattern: verify cookie → delete `oauth_sessions` row → delete browser cookie.
After that, even if the browser sends the old cookie, `status` will 401 because the row is gone.

---

### 6.7 Where the routes fit in the bigger picture

```
/api/auth/signin   ──┐  (browser kicks off)
// redirect --> PDS  │
/api/auth/callback  ─┘  (server stores session, sets cookie)

          repeat while cookie valid
/api/auth/status    →  “am I still logged in?”
     ↑                      ↓ (silent token refresh)
/api/auth/logout    ←  kill cookie & DB row
```

Everything else (e.g. your `/bsky/*` routes) just:
1. Read & verify the signed cookie.
2. `client.restore()` to get an `Agent` that already injects the right DPoP & Auth headers.
3. Call AT Proto XRPCs as the user.
---

That's the full tour of the three authentication endpoints.

### 6 · “Plonk” helper routes - quick repo CRUD with a restored OAuth Session

| Route              | HTTP verb | AT Proto XRPC called           | Purpose                                |
| ------------------ | --------- | ------------------------------ | -------------------------------------- |
| `/plonk/getPlonks` | **GET**   | `com.atproto.repo.listRecords` | Read every paste the user has stored.  |
| `/plonk/post`      | **POST**  | `com.atproto.repo.putRecord`   | Append a new paste to the user's repo. |

`plonk` itself is just a **tiny paste-bin lexicon**; one record = one code snippet, simple to show in this tutorial vs bsky lexicons:

```ts
export interface PlonkRecord {
  uri: string;  // at://<did>/<collection>/<rkey>
  cid: string;  // content-hash of the record blob
  value: {
    title:     string;
    lang:      string;   // syntax hint (python, js, …)
    code:      string;   // literal paste
    createdAt: string;   // ISO date-time, server trustable
  };
}
```

#### 6.1  GET `/plonk/getPlonks`

```ts
const token = parseCookies(c.req.header('Cookie'))[COOKIE_NAME];
const sub   = token ? verifySignedToken(token) : null;
if (!sub) return c.json({ error: 'Authentication failed' }, 400);

const session = await client.restore(sub, 'auto');   // ↖ pulls refresh-token row
const agent   = new Agent(session);                  // ↖ injects DPoP + Bearer

const { data } = await agent.com.atproto.repo.listRecords({
  repo: sub,
  collection: 'li.plonk.paste',
});
return c.json(data);             // { records:[ PlonkRecord… ], cursor? }
```

* **Auth check** - the same signed-cookie pattern: if the HMAC is wrong or the row is gone we immediately 400.
* **`client.restore()`** silently refreshes the access-token if it's near expiry, so this call is safe even when the user left the tab open all night.
* **XRPC call** - `listRecords` is a paginated, server-side filter that returns every record in the collection (plus a cursor if the user has >500 pastes).

#### 6.2  POST `/plonk/post`

```ts
const body  = await c.req.json();           // { title, lang, code }
const rkey  = TID.nextStr();                // sortable, collision-proof
const short = Math.random().toString(36).slice(2, 2 + Math.random()*6|0);

const record = {
  $type: 'li.plonk.paste',  // the lexicon type-id
  title: body.title || '',
  lang:  body.lang  || 'plaintext',
  code:  body.code,         // required
  shortUrl: short,          // fun preview slug
  createdAt: new Date().toISOString(),
};

await agent.com.atproto.repo.putRecord({
  repo: sub,
  collection: 'li.plonk.paste',
  rkey,                      // user-side primary key
  record,
  validate: false,           // we trust ourselves; skip schema round-trip
});
return c.json({ success: true });
```

* **Why `TID.nextStr()`?** - TID is the “time-sortable identifier” helper from `@atproto/common-web`. Using it for `rkey` ensures old and new pastes sort chronologically without a separate index.
* `putRecord` stores the blob and returns its **CID**; we ignore it here because the client-side refresh (`loadPlonks`) will immediately fetch the up-to-date list.

---

**Key takeaway**
Both routes demonstrate the *confidential-client pattern* in practice:

1. Browser never sends OAuth tokens - just the signed DID cookie.
2. Backend verifies → restores session → instantiates an `Agent`.
3. All AT Proto I/O goes through the `Agent`, which attaches the latest **DPoP-bound** access-token for that user.

Once you understand this skeleton you can swap `li.plonk.paste` for any Bluesky/AT-Proto collection (posts, likes, follows, etc.) with virtually identical code.

## 7 · Minimal front-end (Pug + vanilla JS)

The page is a single server-rendered Pug template plus \~150 lines of browser JavaScript.
Everything interesting happens in four small functions; the browser never has to know what an *access-token* is, it just relies on the signed **`bsid`** cookie the backend set during `/api/auth/callback`.

---

### 7.1 Markup skeleton (Pug)

| Block                                                   | Purpose                                                                                                                             |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| **`input#handle` + `button#loginButton`**               | Collect the user's Bluesky handle and kick off `/api/auth/signin`.                                                                  |
| **`p#sessionInfo`**                                     | Shows "Not logged in" or "Logged in as: did\:plc:…".                                                                                |
| **`section#plonkSection`** *(initially `display:none`)* | Hidden until authentication succeeds. Contains:<br>• a mini "create new plonk" form<br>• `div#plonkList` where pastes are rendered. |

> *Why Pug?* - readable indentation, no build step

---

### 7.2 Login button handler

```js
document.getElementById('loginButton').addEventListener('click', async () => {
  const handle = document.getElementById('handle').value.trim();
  const res    = await fetch('/api/auth/signin', {
                   method:'POST', headers:{'Content-Type':'application/json'},
                   body:JSON.stringify({ handle })
                 });
  const { url } = await res.json();       // ① authorisation URL
  window.location.href = url;             // ② browser → PDS
});
```

1. Calls the **signin** route we dissected in § 6.3; gets back the pre-built authorisation URL.
2. Navigates there; the user logs in, hits *Allow*, the PDS sends the browser to `/api/auth/callback`.
   → The backend stores the session and sets the **HMAC cookie**.

---

### 7.3 `checkStatus()` - run on every page load

```js
const res = await fetch('/api/auth/status');     // cookie auto-sent (SameSite=Lax)
const data = await res.json();

if (data.authenticated) {
  sessionInfo.textContent  = `Logged in as: ${data.user.sub}`;
  plonkSection.style.display = 'block';
  await loadPlonks();                            // pull user’s pastes
} else {
  sessionInfo.textContent  = 'Not logged in';
  plonkSection.style.display = 'none';
}
```

* The browser never touches `document.cookie`; `fetch()` includes it automatically because the request is **same-site** and the cookie is marked `SameSite=Lax`.
* If the cookie was missing or expired, `/api/auth/status` returns `{authenticated:false}` and the UI stays in “please log in” mode.

---

### 7.4 Listing plonks - `loadPlonks()`

```js
const res   = await fetch('/plonk/getPlonks');   // again, cookie goes along
const data  = await res.json();                  // { records:[ … ] }
```

* On the server side we call `agent.com.atproto.repo.listRecords()` with the
  restored OAuth session.
* The loop renders each *plonk* into a simple card (`<pre>` with the code blob).

---

### 7.5 Posting a new plonk

```js
const body = { title, lang, code };
await fetch('/plonk/post', {
  method:'POST', headers:{'Content-Type':'application/json'},
  body: JSON.stringify(body)
});
```

The backend flow:

1. Verify cookie → extract `sub`.
2. `client.restore(sub,'auto')` → live OAuth session.
3. `agent.com.atproto.repo.putRecord()` writes a record with `$type: 'li.plonk.paste'`.

`TID.nextStr()` produces a lexicographically sortable rkey; the UI reloads the list so the new paste appears instantly.

---

### 7.6 Why no extra headers / tokens in JS?

* **Bearer vs. session** - the browser never sees `access_token` or `refresh_token`; security logic stays server-side.
* **Same-site cookie** - every `fetch('/api/…')` automatically carries the signed `bsid`.
* **Stateless front-end** - you could host this HTML on a CDN and it would still work, because the only stateful bits live in the backend’s SQLite/KV and in the cookie.

---


With this, the tutorial now shows the full round-trip:

```
handle → /api/auth/signin → PDS               ─┐
                ← cookie   /api/auth/callback ─┘
frontend fetches /api/auth/status  (*cookie*) → authenticated
frontend fetches /plonk/*          (*cookie*) → Agent acts on repo
```

All without the browser ever touching raw OAuth tokens or an app password.
