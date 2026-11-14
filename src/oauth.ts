/** OAuth resource server backed by an external RFC 7662 authorization server. */
export interface OAuthConfig {
    resource: string;
    issuer: string;
    introspectionUrl: string;
    clientId: string;
    clientSecret: string;
}

export const READ_SCOPE = 'remnawave:read';

function httpsUrl(value: string | undefined, key: string): string {
    if (!value) throw new Error(key + ' is required in OAuth mode');
    let url: URL;
    try {
        url = new URL(value);
    } catch {
        throw new Error(key + ' must be an HTTPS URL');
    }
    if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search)
        throw new Error(key + ' must be an HTTPS URL without credentials, query or fragment');
    return url.href;
}

export function loadOAuthConfig(env = process.env): OAuthConfig {
    const resource = httpsUrl(env.REMNAWAVE_OAUTH_RESOURCE, 'REMNAWAVE_OAUTH_RESOURCE');
    if (new URL(resource).pathname !== '/mcp')
        throw new Error('REMNAWAVE_OAUTH_RESOURCE must end in /mcp');
    // Preserve the issuer identifier exactly as registered, including a trailing slash if present.
    httpsUrl(env.REMNAWAVE_OAUTH_ISSUER, 'REMNAWAVE_OAUTH_ISSUER');
    const introspectionUrl = httpsUrl(env.REMNAWAVE_OAUTH_INTROSPECTION_URL, 'REMNAWAVE_OAUTH_INTROSPECTION_URL');
    const clientId = env.REMNAWAVE_OAUTH_CLIENT_ID;
    const clientSecret = env.REMNAWAVE_OAUTH_CLIENT_SECRET;
    if (!clientId || !clientSecret)
        throw new Error('REMNAWAVE_OAUTH_CLIENT_ID and REMNAWAVE_OAUTH_CLIENT_SECRET are required in OAuth mode');
    return { resource, issuer: env.REMNAWAVE_OAUTH_ISSUER!, introspectionUrl, clientId, clientSecret };
}

export function resourceMetadata(cfg: OAuthConfig) {
    return { resource: cfg.resource, authorization_servers: [cfg.issuer], scopes_supported: [READ_SCOPE], bearer_methods_supported: ['header'] };
}

export function challenge(cfg: OAuthConfig, error?: 'invalid_token' | 'insufficient_scope'): string {
    return 'Bearer resource_metadata="' + new URL('/.well-known/oauth-protected-resource/mcp', cfg.resource).href +
        '", scope="' + READ_SCOPE + '"' + (error ? ', error="' + error + '"' : '');
}

export type AuthResult =
    | { ok: true; principal: string }
    | { ok: false; status: 401 | 403 | 503 };

const invalid = { ok: false, status: 401 } as const;
const unavailable = { ok: false, status: 503 } as const;

function formEncode(s: string): string {
    return new URLSearchParams({ v: s }).toString().slice(2);
}

/** No cached positive decisions: expiration, revocation and scopes are checked on every request. */
export async function verifyOAuthToken(
    cfg: OAuthConfig,
    token: string,
    fetcher: typeof fetch = fetch,
): Promise<AuthResult> {
    try {
        const basic = Buffer.from(formEncode(cfg.clientId) + ':' + formEncode(cfg.clientSecret)).toString('base64');
        const response = await fetcher(cfg.introspectionUrl, {
            method: 'POST',
            headers: { Authorization: 'Basic ' + basic, Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ token, token_type_hint: 'access_token' }),
            redirect: 'error',
            signal: AbortSignal.timeout(5000),
        });
        if (!response.ok) return unavailable;
        const value: unknown = await response.json();
        if (!value || typeof value !== 'object' || Array.isArray(value)) return invalid;
        const data = value as Record<string, unknown>;
        const now = Date.now() / 1000;
        if (data.active !== true || data.iss !== cfg.issuer ||
            !(data.aud === cfg.resource || (Array.isArray(data.aud) && data.aud.includes(cfg.resource))) ||
            typeof data.exp !== 'number' || !Number.isFinite(data.exp) || data.exp <= now ||
            (data.nbf !== undefined && (typeof data.nbf !== 'number' || !Number.isFinite(data.nbf) || data.nbf > now)) ||
            typeof data.sub !== 'string' || !data.sub || typeof data.client_id !== 'string' || !data.client_id ||
            typeof data.token_type !== 'string' || data.token_type.toLowerCase() !== 'bearer')
            return invalid;
        if (typeof data.scope !== 'string' || !data.scope.split(' ').includes(READ_SCOPE))
            return { ok: false, status: 403 };
        // Stable across token refresh, but never across a different subject or OAuth client.
        return { ok: true, principal: JSON.stringify([data.iss, data.sub, data.client_id]) };
    } catch {
        // Do not expose tokens, provider response bodies or credentials to the MCP client.
        return unavailable;
    }
}
