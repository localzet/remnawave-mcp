import test from 'node:test';
import assert from 'node:assert/strict';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { createHttpServer, loadHttpConfig } from '../dist/http.js';
import { challenge, loadOAuthConfig, verifyOAuthToken } from '../dist/oauth.js';

const config = {
    resource: 'https://mcp.example.com/mcp', issuer: 'https://auth.example.com/',
    introspectionUrl: 'https://auth.example.com/introspect', clientId: 'client', clientSecret: 'secret',
};

const claims = (over = {}) => ({
    active: true, iss: config.issuer, aud: [config.resource],
    sub: 'alice', client_id: 'assistant', token_type: 'Bearer',
    exp: Math.floor(Date.now() / 1000) + 600, scope: 'remnawave:read',
    ...over,
});

const reply = (value) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });

test('OAuth configuration requires HTTPS and forbids static fallback', () => {
    const env = {
        REMNAWAVE_HTTP_AUTH: 'oauth', REMNAWAVE_OAUTH_RESOURCE: config.resource,
        REMNAWAVE_OAUTH_ISSUER: config.issuer, REMNAWAVE_OAUTH_INTROSPECTION_URL: config.introspectionUrl,
        REMNAWAVE_OAUTH_CLIENT_ID: config.clientId, REMNAWAVE_OAUTH_CLIENT_SECRET: config.clientSecret,
    };
    assert.deepEqual(loadHttpConfig(env), { host: '127.0.0.1', port: 3001, oauth: config });
    assert.throws(() => loadHttpConfig({ ...env, REMNAWAVE_HTTP_TOKEN: 'fallback' }), /Unset REMNAWAVE_HTTP_TOKEN/);
    assert.throws(() => loadOAuthConfig({ ...env, REMNAWAVE_OAUTH_INTROSPECTION_URL: 'http://auth.example.com' }), /HTTPS/);
    assert.throws(() => loadOAuthConfig({ ...env, REMNAWAVE_OAUTH_CLIENT_SECRET: '' }), /CLIENT_SECRET/);
    assert.match(challenge(config), /resource_metadata="https:\/\/mcp.example.com\/\.well-known\/oauth-protected-resource\/mcp"/);
});

test('introspection verifies resource, issuer, lifetime, token type and scope', async () => {
    const verify = (value) => verifyOAuthToken(config, 'token', async (url, init) => {
        assert.equal(url, config.introspectionUrl);
        assert.equal(init.method, 'POST');
        assert.equal(init.redirect, 'error');
        assert.equal(init.headers.Authorization, 'Basic ' + Buffer.from('client:secret').toString('base64'));
        assert.equal(init.body.get('token'), 'token');
        return reply(value);
    });
    assert.equal((await verify(claims())).ok, true);
    for (const over of [
        { active: false }, { iss: 'https://other.example.com/' }, { aud: 'https://other.example.com' },
        { exp: 0 }, { exp: undefined }, { nbf: Math.floor(Date.now() / 1000) + 600 },
        { token_type: 'refresh_token' }, { sub: '' }, { client_id: undefined },
    ]) assert.deepEqual(await verify(claims(over)), { ok: false, status: 401 });
    assert.deepEqual(await verify(claims({ scope: 'other' })), { ok: false, status: 403 });
    assert.deepEqual(await verifyOAuthToken(config, 'token', async () => { throw new Error('provider unavailable'); }), { ok: false, status: 503 });
});

test('OAuth discovery and HTTP sessions are bound to the authorized subject and client', async (t) => {
    let revoked = false;
    const listener = createHttpServer({ host: '127.0.0.1', port: 0, oauth: config }, () =>
        new Server({ name: 'test', version: '1' }, { capabilities: {} }),
        async (_url, init) => {
            const token = init.body.get('token');
            if (token === 'alice' || token === 'alice-refreshed')
                return reply(claims({ active: !revoked }));
            if (token === 'bob') return reply(claims({ sub: 'bob' }));
            if (token === 'other-client') return reply(claims({ client_id: 'other' }));
            if (token === 'no-scope') return reply(claims({ scope: '' }));
            return reply({ active: false });
        },
    );
    await new Promise((resolve, reject) => {
        listener.once('error', reject);
        listener.listen(0, '127.0.0.1', resolve);
    });
    t.after(async () => {
        listener.closeAllConnections();
        await new Promise((resolve) => listener.close(resolve));
    });
    const base = 'http://127.0.0.1:' + listener.address().port;
    const metadata = await fetch(base + '/.well-known/oauth-protected-resource/mcp');
    assert.equal(metadata.status, 200);
    assert.deepEqual(await metadata.json(), {
        resource: config.resource, authorization_servers: [config.issuer],
        scopes_supported: ['remnawave:read'], bearer_methods_supported: ['header'],
    });
    const init = { jsonrpc: '2.0', id: 1, method: 'initialize', params: {
        protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'test', version: '1' },
    } };
    const post = (token, body, session, protocol) => fetch(base + '/mcp', {
        method: 'POST',
        headers: {
            Accept: 'application/json, text/event-stream', 'Content-Type': 'application/json',
            ...(token ? { Authorization: 'Bearer ' + token } : {}),
            ...(session ? { 'Mcp-Session-Id': session, 'MCP-Protocol-Version': protocol } : {}),
        },
        body: JSON.stringify(body),
    });
    const missing = await post(undefined, init);
    assert.equal(missing.status, 401);
    assert.match(missing.headers.get('www-authenticate'), /resource_metadata=/);
    await missing.text();
    const insufficient = await post('no-scope', init);
    assert.equal(insufficient.status, 403);
    assert.match(insufficient.headers.get('www-authenticate'), /insufficient_scope/);
    await insufficient.text();
    const response = await post('alice', init);
    assert.equal(response.status, 200);
    const sid = response.headers.get('mcp-session-id');
    assert.ok(sid);
    const protocol = (await response.json()).result.protocolVersion;
    const initialized = await post('alice', { jsonrpc: '2.0', method: 'notifications/initialized' }, sid, protocol);
    assert.equal(initialized.status, 202);
    await initialized.text();
    const ping = { jsonrpc: '2.0', id: 2, method: 'ping' };
    for (const token of ['bob', 'other-client']) {
        const denied = await post(token, ping, sid, protocol);
        assert.equal(denied.status, 404);
        await denied.text();
    }
    const refreshed = await post('alice-refreshed', ping, sid, protocol);
    assert.equal(refreshed.status, 200);
    await refreshed.text();
    revoked = true;
    const denied = await post('alice-refreshed', ping, sid, protocol);
    assert.equal(denied.status, 401);
    await denied.text();
});
