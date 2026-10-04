import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { createApp } from './server.ts';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const ownerKey = 'test-only-owner-credential-000000000000000';
const issuer = 'https://connector.example';
const callback = 'https://gemini.example/oauth/callback';
const verifier = 'v'.repeat(64);
const challenge = createHash('sha256').update(verifier).digest('base64url');
async function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'aliaddo-oauth-test-'));
  const file = join(dir, 'oauth.enc');
  let time = Math.floor(Date.now() / 1000);
  const options = { key: ownerKey, token: 'fake-upstream-token', issuer, oauthFile: file, now: () => time,
    fetchImpl: async () => Response.json([]) };
  let server; let base;
  async function start() {
    server = createApp(options).listen(0, '127.0.0.1');
    await new Promise<void>(resolve => server.once('listening', resolve));
    base = `http://127.0.0.1:${server.address().port}`;
  }
  async function stop() { await new Promise<void>(resolve => { server.close(resolve); server.closeAllConnections(); }); }
  await start();
  const request = (path, init = {}) => fetch(base + path, { redirect: 'manual', ...init });
  const form = (path, body, headers = {}) => request(path, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers }, body: new URLSearchParams(body) });
  async function register(override = {}) {
    return request('/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ client_name: '<script>bad()</script>', redirect_uris: [callback], token_endpoint_auth_method: 'none', ...override }) });
  }
  async function authorize(clientId, override = {}) {
    const response = await request('/authorize?' + new URLSearchParams({ client_id: clientId, redirect_uri: callback, response_type: 'code', code_challenge: challenge, code_challenge_method: 'S256', state: 'original-state', resource: issuer + '/mcp', ...override }));
    const html = await response.text();
    return { response, html, cookie: response.headers.get('set-cookie')?.split(';')[0], id: /name="request" value="([A-Za-z0-9_-]+)"/.exec(html)?.[1] };
  }
  const consent = (auth, extra = {}, headers = {}) => form('/consent', { request: auth.id, decision: 'allow', key: ownerKey, ...extra }, { Origin: issuer, Cookie: auth.cookie, ...headers });
  async function grant(client) {
    const auth = await authorize(client.client_id);
    const response = await consent(auth);
    assert.equal(response.status, 303);
    const location = new URL(response.headers.get('location')!);
    assert.equal(location.searchParams.get('state'), 'original-state');
    return location.searchParams.get('code')!;
  }
  const exchange = (client, code, override = {}) => form('/token', { grant_type: 'authorization_code', client_id: client.client_id, code, code_verifier: verifier, redirect_uri: callback, resource: issuer + '/mcp', ...(client.client_secret ? { client_secret: client.client_secret } : {}), ...override });
  return { request, form, register, authorize, consent, grant, exchange, file,
    url: () => new URL(base + '/mcp'), advance: seconds => time += seconds,
    restart: async () => { await stop(); await start(); },
    close: async () => { await stop(); rmSync(dir, { recursive: true, force: true }); } };
}

test('OAuth discovery, consent, PKCE, MCP, expiry, persistence, refresh rotation and revocation', async () => {
  const f = await fixture();
  try {
    const denied = await f.request('/mcp', { method: 'POST' });
    assert.equal(denied.status, 401);
    assert.match(denied.headers.get('www-authenticate')!, /resource_metadata="https:\/\/connector.example\/\.well-known\/oauth-protected-resource\/mcp"/);
    const prm = await (await f.request('/.well-known/oauth-protected-resource/mcp')).json();
    assert.equal(prm.resource, issuer + '/mcp');
    const metadata = await (await f.request('/.well-known/oauth-authorization-server')).json();
    assert.deepEqual(metadata.code_challenge_methods_supported, ['S256']);
    assert.equal(metadata.registration_endpoint, issuer + '/register');
    const registered = await f.register(); assert.equal(registered.status, 201);
    const client = await registered.json();
    const code = await f.grant(client);
    assert.equal((await f.exchange(client, code, { code_verifier: 'x'.repeat(64) })).status, 400);
    assert.equal((await f.exchange(client, code, { redirect_uri: 'https://other.example/' })).status, 400);
    assert.equal((await f.exchange(client, code, { resource: 'https://other.example/' })).status, 400);
    const response = await f.exchange(client, code); assert.equal(response.status, 200);
    const tokens = await response.json();
    assert.equal((await f.exchange(client, code)).status, 400, 'code is one-time');
    const sdkClient = new Client({ name: 'oauth-test', version: '1' });
    await sdkClient.connect(new StreamableHTTPClientTransport(f.url(), { requestInit: { headers: { Authorization: 'Bearer ' + tokens.access_token } } }));
    assert.equal((await sdkClient.listTools()).tools[0].name, 'consultar_facturas');
    assert.equal((await sdkClient.callTool({ name: 'consultar_facturas', arguments: { fecha: '2026-10-04' } })).isError, undefined);
    await sdkClient.close();
    assert.equal(readFileSync(f.file).includes(Buffer.from(tokens.access_token)), false);
    assert.equal(readFileSync(f.file).includes(Buffer.from(callback)), false);
    await f.restart();
    assert.equal((await f.request('/mcp', { headers: { Authorization: 'Bearer ' + tokens.access_token } })).status, 405, 'authenticated after restart');
    f.advance(3601);
    assert.equal((await f.request('/mcp', { headers: { Authorization: 'Bearer ' + tokens.access_token } })).status, 401);
    const refreshedResponse = await f.form('/token', { grant_type: 'refresh_token', client_id: client.client_id, refresh_token: tokens.refresh_token });
    assert.equal(refreshedResponse.status, 200);
    const refreshed = await refreshedResponse.json();
    assert.equal((await f.request('/mcp', { headers: { Authorization: 'Bearer ' + refreshed.access_token } })).status, 405);
    assert.equal((await f.form('/token', { grant_type: 'refresh_token', client_id: client.client_id, refresh_token: tokens.refresh_token })).status, 400);
    assert.equal((await f.request('/mcp', { headers: { Authorization: 'Bearer ' + refreshed.access_token } })).status, 401, 'replay revokes token family');
    const newTokens = await (await f.exchange(client, await f.grant(client))).json();
    assert.equal((await f.form('/revoke', { client_id: client.client_id, token: newTokens.refresh_token })).status, 200);
    assert.equal((await f.request('/mcp', { headers: { Authorization: 'Bearer ' + newTokens.access_token } })).status, 401);
  } finally { await f.close(); }
});

test('OAuth rejects unsafe redirects, missing PKCE, excessive scope, forged consent and wrong owner credentials', async () => {
  const f = await fixture();
  try {
    for (const uri of ['http://other.example/', 'https://user:pass@other.example/', 'https://other.example/#fragment']) assert.equal((await f.register({ redirect_uris: [uri] })).status, 400);
    const geminiRedirects = Array.from({ length: 6 }, (_, i) => `https://gemini.example/oauth/callback/${i}`);
    const multiRedirect = await f.register({ redirect_uris: geminiRedirects, token_endpoint_auth_method: 'client_secret_post' });
    assert.equal(multiRedirect.status, 201, 'Gemini registers six callbacks');
    assert.deepEqual((await multiRedirect.json()).redirect_uris, geminiRedirects);
    assert.equal((await f.register({ redirect_uris: Array(21).fill(callback) })).status, 400);
    const scopedRegistration = await f.register({ scope: '' });
    assert.equal(scopedRegistration.status, 201);
    const client = await scopedRegistration.json();
    assert.equal(client.scope, 'invoices:read');
    assert.equal((await f.authorize(client.client_id, { redirect_uri: 'https://unregistered.example/' })).response.status, 400);
    for (const override of [{ scope: 'invoices:write' }, { resource: 'https://other.example/' }, { code_challenge_method: 'plain' }]) {
      const rejected = await f.authorize(client.client_id, override);
      assert.equal(rejected.response.status, 302);
      assert.match(rejected.response.headers.get('location')!, /error=/);
    }
    const auth = await f.authorize(client.client_id);
    assert.equal(auth.response.status, 200);
    assert.equal(auth.html.includes('<script>bad()'), false);
    assert.match(auth.html, /&lt;script&gt;/);
    assert.match(auth.response.headers.get('content-security-policy')!, /frame-ancestors 'none'/);
    assert.equal(auth.response.headers.get('referrer-policy'), 'strict-origin', 'form posts preserve Origin without disclosing authorization query');
    assert.equal((await f.consent(auth, {}, { Cookie: '' })).status, 403);
    assert.equal((await f.consent(auth, {}, { Origin: 'null' })).status, 403, 'opaque origins still rejected');
    assert.equal((await f.consent(auth, {}, { Origin: 'https://evil.example' })).status, 403);
    assert.equal((await f.consent(auth, { key: 'wrong' })).status, 403);
    const denial = await f.consent(auth, { decision: 'deny', key: '' });
    assert.equal(denial.status, 303); assert.match(denial.headers.get('location')!, /error=access_denied/);
    assert.equal((await f.consent(auth)).status, 403, 'consent cannot be replayed');
    const confidential = await (await f.register({ token_endpoint_auth_method: 'client_secret_post' })).json();
    const code = await f.grant(confidential);
    const wrongSecret = await f.exchange(confidential, code, { client_secret: 'wrong' });
    assert.equal(wrongSecret.status, 400);
    assert.equal((await wrongSecret.json()).error, 'invalid_client');
    assert.equal((await f.exchange(confidential, code)).status, 200);
    const expired = await f.authorize(client.client_id);
    f.advance(601);
    assert.equal((await f.consent(expired)).status, 403);
  } finally { await f.close(); }
});

test('codes and refresh tokens are bound to their client, expire, and owner login is rate limited', async () => {
  const f = await fixture();
  try {
    const first = await (await f.register()).json();
    const second = await (await f.register()).json();
    const code = await f.grant(first);
    assert.equal((await f.exchange(second, code)).status, 400);
    f.advance(121);
    assert.equal((await f.exchange(first, code)).status, 400);
    const tokens = await (await f.exchange(first, await f.grant(first))).json();
    assert.equal((await f.form('/token', { client_id: second.client_id, grant_type: 'refresh_token', refresh_token: tokens.refresh_token })).status, 400);
    f.advance(31 * 86400);
    assert.equal((await f.form('/token', { client_id: first.client_id, grant_type: 'refresh_token', refresh_token: tokens.refresh_token })).status, 400);
    const auth = await f.authorize(first.client_id);
    for (let i = 0; i < 5; i++) assert.equal((await f.consent(auth, { key: 'incorrect' })).status, 403);
    assert.equal((await f.consent(auth)).status, 429);
    assert.throws(() => createApp({ key: 'a-different-owner-key-0000000000000000', token: 'test', issuer, oauthFile: f.file }), /almacen OAuth/);
  } finally { await f.close(); }
});
