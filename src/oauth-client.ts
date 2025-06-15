import { NodeOAuthClient, type ClientMetadata } from "@atproto/oauth-client-node";
import { Database } from "bun:sqlite";
import { JoseKey } from "@atproto/jwk-jose";

const db = new Database("oauth.db");

db.exec(`
    CREATE TABLE IF NOT EXISTS oauth_states (
        key TEXT PRIMARY KEY,
        data TEXT NOT NULL,
        created_at INTEGER DEFAULT (strftime('%s', 'now'))
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS oauth_sessions (
        sub TEXT PRIMARY KEY,
        data TEXT NOT NULL,
        updated_at INTEGER DEFAULT (strftime('%s', 'now'))
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS oauth_keys (
        kid TEXT PRIMARY KEY,
        jwk TEXT NOT NULL
    )
`);

const stateStore = {
    async set(key: string, data: any) {
        console.debug('[stateStore] set', key)
        db.prepare("INSERT OR REPLACE INTO oauth_states (key, data) VALUES (?, ?)").run(key, JSON.stringify(data));
    },
    async get(key: string) {
        console.debug('[stateStore] get', key)
        const result = db.prepare("SELECT data FROM oauth_states WHERE key = ?").get(key) as { data: string } | undefined;
        return result ? JSON.parse(result.data) : undefined;
    },
    async del(key: string) {
        console.debug('[stateStore] del', key)
        db.prepare("DELETE FROM oauth_states WHERE key = ?").run(key);
    }
};

const sessionStore = {
    async set(sub: string, data: any) {
        console.debug('[sessionStore] set', sub)
        db.prepare("INSERT OR REPLACE INTO oauth_sessions (sub, data) VALUES (?, ?)").run(sub, JSON.stringify(data));
    },
    async get(sub: string) {
        console.debug('[sessionStore] get', sub)
        const result = db.prepare("SELECT data FROM oauth_sessions WHERE sub = ?").get(sub) as { data: string } | undefined;
        return result ? JSON.parse(result.data) : undefined;
    },
    async del(sub: string) {
        console.debug('[sessionStore] del', sub)
        db.prepare("DELETE FROM oauth_sessions WHERE sub = ?").run(sub);
    }
};

export { sessionStore };

export const createClientMetadata = (config: { domain: `https://${string}`, clientName: string }): ClientMetadata => ({
    client_id: `${config.domain}/client-metadata.json`,
    client_name: config.clientName,
    client_uri: config.domain,
    logo_uri: `${config.domain}/logo.png`,
    tos_uri: `${config.domain}/tos`,
    policy_uri: `${config.domain}/policy`,
    redirect_uris: [`${config.domain}/api/auth/callback`],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    application_type: 'web',
    token_endpoint_auth_method: 'private_key_jwt',
    token_endpoint_auth_signing_alg: "ES256",
    scope: "atproto transition:generic",
    dpop_bound_access_tokens: true,
    jwks_uri: `${config.domain}/jwks.json`,
    subject_type: 'public',
    authorization_signed_response_alg: 'ES256'
});

const persistKey = (key: JoseKey) => {
    const priv = key.privateJwk;
    if (!priv) return;
    const kid = key.kid ?? crypto.randomUUID();
    db.prepare("INSERT OR REPLACE INTO oauth_keys (kid, jwk) VALUES (?, ?)").run(kid, JSON.stringify(priv));
};

const loadPersistedKeys = async (): Promise<JoseKey[]> => {
    const rows = db.prepare("SELECT kid, jwk FROM oauth_keys ORDER BY kid").all() as { kid: string; jwk: string }[];
    const keys: JoseKey[] = [];
    for (const { jwk } of rows) {
        try {
            const obj = JSON.parse(jwk);
            const key = await JoseKey.fromImportable(obj as any, (obj as any).kid);
            keys.push(key);
        } catch (err) {
            console.error('Could not parse stored JWK', err);
        }
    }
    return keys;
};

const ensureKeys = async (): Promise<JoseKey[]> => {
    let keys = await loadPersistedKeys();
    const needed: string[] = [];
    for (let i = 1; i <= 3; i++) {
        const kid = `key${i}`;
        if (!keys.some(k => k.kid === kid)) needed.push(kid);
    }
    for (const kid of needed) {
        const newKey = await JoseKey.generate(['ES256'], kid);
        persistKey(newKey);
        keys.push(newKey);
    }
    keys.sort((a, b) => (a.kid ?? '').localeCompare(b.kid ?? ''));
    return keys;
};

let currentKeys: JoseKey[] = [];

export const getCurrentKeys = () => currentKeys;

export const getOAuthClient = async (config: { domain: `https://${string}`, clientName: string }) => {
    if (currentKeys.length === 0) {
        currentKeys = await ensureKeys();
    }

    return new NodeOAuthClient({
        clientMetadata: createClientMetadata(config),
        keyset: currentKeys,
        stateStore,
        sessionStore
    });
};