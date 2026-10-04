import express from 'express';
import { createHash, createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, renameSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { InvalidGrantError, InvalidTokenError, InvalidScopeError, InvalidRequestError, InvalidClientMetadataError, TooManyRequestsError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type { OAuthServerProvider, AuthorizationParams } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthClientInformationFull, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import { OAuthClientMetadataSchema } from '@modelcontextprotocol/sdk/shared/auth.js';

const scope = 'invoices:read';
const hash = (s: string) => createHash('sha256').update(s).digest('hex');
const random = () => randomBytes(32).toString('base64url');
const equal = (a: string, b: string) => timingSafeEqual(Buffer.from(hash(a)), Buffer.from(hash(b)));
const escape = (s: string) => s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
type Grant = { clientId: string; family: string; expires: number; deadline: number; kind: 'access' | 'refresh'; used?: boolean };
type Saved = { clients: Record<string, OAuthClientInformationFull>; tokens: Record<string, Grant> };
type Pending = { clientId: string; params: AuthorizationParams; expires: number; cookieHash: string };
type Code = Pending & { family: string };

// Single-instance store. Encrypted at rest; an unavailable/corrupt store fails closed.
// For durable Render sessions, OAUTH_STORE_FILE must point to a persistent disk.
export function installOAuth(app: express.Express, { key, issuer, file, now = () => Math.floor(Date.now() / 1000) }:
  { key: string; issuer: string; file: string; now?: () => number }) {
  const base = new URL(issuer);
  if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash || base.pathname !== '/') throw new Error('OAuth requiere un origen HTTPS publico.');
  const resource = new URL('/mcp', base).href;
  const encryptionKey = createHash('sha256').update('aliaddo-oauth-store-v1\0' + key).digest();
  let saved: Saved = { clients: {}, tokens: {} };
  if (existsSync(file)) {
    try {
      const bytes = readFileSync(file);
      const decipher = createDecipheriv('aes-256-gcm', encryptionKey, bytes.subarray(0, 12));
      decipher.setAuthTag(bytes.subarray(12, 28));
      saved = JSON.parse(Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString('utf8'));
      if (!saved.clients || !saved.tokens) throw new Error();
    } catch { throw new Error('No se pudo abrir el almacen OAuth. Restaura su clave o reinicia las autorizaciones con un archivo nuevo.'); }
  }
  const persist = () => {
    for (const [id, token] of Object.entries(saved.tokens)) if (token.expires <= now()) delete saved.tokens[id];
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', encryptionKey, iv);
    const encrypted = Buffer.concat([cipher.update(JSON.stringify(saved), 'utf8'), cipher.final()]);
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
    const temporary = file + '.tmp';
    writeFileSync(temporary, Buffer.concat([iv, cipher.getAuthTag(), encrypted]), { mode: 0o600 });
    renameSync(temporary, file);
  };
  const pending = new Map<string, Pending>();
  const codes = new Map<string, Code>();
  const attempts = new Map<string, { count: number; expires: number }>();
  const sweep = () => {
    for (const collection of [pending, codes, attempts]) for (const [id, entry] of collection) if (entry.expires <= now()) collection.delete(id);
  };
  const checkResource = (requested?: URL) => {
    if (requested && requested.href !== resource) throw new InvalidRequestError('Recurso no admitido.');
  };
  const checkScopes = (scopes?: string[]) => {
    if (scopes?.some(s => s !== scope)) throw new InvalidScopeError('Solo se permite consultar facturas.');
  };
  const revokeFamily = (family: string) => {
    for (const [id, token] of Object.entries(saved.tokens)) if (token.family === family) delete saved.tokens[id];
  };
  const issue = (clientId: string, family: string, deadline: number): OAuthTokens => {
    if (Object.keys(saved.tokens).length > 10000) throw new TooManyRequestsError('Demasiadas sesiones.');
    const access = random(); const refresh = random();
    saved.tokens[hash(access)] = { clientId, family, kind: 'access', expires: Math.min(now() + 3600, deadline), deadline };
    saved.tokens[hash(refresh)] = { clientId, family, kind: 'refresh', expires: deadline, deadline };
    persist();
    return { access_token: access, refresh_token: refresh, token_type: 'Bearer', expires_in: Math.min(3600, deadline - now()), scope };
  };
  const getCode = (client: OAuthClientInformationFull, raw: string) => {
    const entry = codes.get(hash(raw));
    if (!entry || entry.clientId !== client.client_id || entry.expires <= now()) throw new InvalidGrantError('Codigo invalido o vencido.');
    return entry;
  };
  const html = (body: string) => `<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Autorizar Aliaddo</title><body><main><h1>Conectar Aliaddo</h1>${body}</main></body></html>`;
  const provider: OAuthServerProvider = {
    clientsStore: {
      getClient: id => Object.hasOwn(saved.clients, id) ? saved.clients[id] : undefined,
      registerClient: async info => {
        if (Object.keys(saved.clients).length >= 500) throw new TooManyRequestsError('Limite de aplicaciones registradas.');
        if (!info.redirect_uris.length || info.redirect_uris.length > 20 || info.redirect_uris.some(uri => {
          try { const u = new URL(uri); return u.protocol !== 'https:' || !!u.username || !!u.password || !!u.hash || uri.length > 2048; } catch { return true; }
        })) throw new InvalidClientMetadataError('Las direcciones de retorno deben ser HTTPS, sin credenciales ni fragmentos.');
        if (!['none', 'client_secret_post', 'client_secret_basic'].includes(info.token_endpoint_auth_method || 'client_secret_post')) throw new InvalidClientMetadataError('Metodo de cliente no admitido.');
        if (info.grant_types?.some(g => !['authorization_code', 'refresh_token'].includes(g)) || info.response_types?.some(r => r !== 'code')) throw new InvalidClientMetadataError('Solo se admite authorization_code con PKCE.');
        // Registration describes the client, not an authorization grant. Return
        // our supported scope; requested permissions are checked at /authorize.
        const client = { ...info, client_id: random(), client_id_issued_at: now(), scope, grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'] };
        saved.clients[client.client_id] = client;
        persist();
        return client;
      }
    },
    authorize: async (client, params, res) => {
      checkResource(params.resource); checkScopes(params.scopes); sweep();
      if (!/^[A-Za-z0-9_-]{43}$/.test(params.codeChallenge)) throw new InvalidRequestError('PKCE S256 invalido.');
      if (pending.size >= 500) throw new TooManyRequestsError('Hay demasiadas autorizaciones pendientes.');
      const id = random(); const cookie = random();
      pending.set(id, { clientId: client.client_id, params, expires: now() + 600, cookieHash: hash(cookie) });
      res.cookie('__Host-aliaddo_oauth', cookie, { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 600000 });
      res.type('html').send(html(`<p>La aplicacion solicita permiso para <strong>consultar facturas</strong>. No podra crear ni modificar documentos.</p><p>Nombre declarado por la aplicacion: <strong>${escape(client.client_name || 'Sin nombre')}</strong>.</p><p>Volveras a: <code>${escape(params.redirectUri)}</code></p><p>Autoriza solo si acabas de iniciar esta conexion desde Gemini u otra aplicacion de confianza.</p><form method="post" action="/consent"><input type="hidden" name="request" value="${id}"><label>Clave del conector (MCP_ACCESS_KEY de Render)<br><input name="key" type="password" required maxlength="512" autocomplete="off"></label><p>Esta clave se verifica aqui y no se envia a la aplicacion.</p><button type="submit" name="decision" value="allow">Autorizar consulta de facturas</button><button type="submit" name="decision" value="deny" formnovalidate>Cancelar</button></form>`));
    },
    challengeForAuthorizationCode: async (client, code) => getCode(client, code).params.codeChallenge,
    exchangeAuthorizationCode: async (client, raw, _verifier, redirect, requested) => {
      const entry = getCode(client, raw);
      if (redirect !== entry.params.redirectUri) throw new InvalidGrantError('La direccion de retorno no coincide.');
      checkResource(requested);
      codes.delete(hash(raw));
      return issue(client.client_id, entry.family, now() + 30 * 86400);
    },
    exchangeRefreshToken: async (client, raw, scopes, requested) => {
      checkResource(requested); checkScopes(scopes);
      const entry = saved.tokens[hash(raw)];
      if (!entry || entry.kind !== 'refresh' || entry.clientId !== client.client_id || entry.expires <= now()) throw new InvalidGrantError('Sesion invalida o vencida. Vuelve a conectar.');
      if (entry.used) { revokeFamily(entry.family); persist(); throw new InvalidGrantError('Sesion revocada por reutilizacion de credencial.'); }
      entry.used = true;
      return issue(client.client_id, entry.family, entry.deadline);
    },
    verifyAccessToken: async raw => {
      const entry = saved.tokens[hash(raw)];
      if (!entry || entry.kind !== 'access' || entry.expires <= now()) throw new InvalidTokenError('Sesion invalida o vencida.');
      return { token: raw, clientId: entry.clientId, scopes: [scope], expiresAt: entry.expires, resource: new URL(resource) };
    },
    revokeToken: async (client, request) => {
      const entry = saved.tokens[hash(request.token)];
      if (entry?.clientId === client.client_id) { revokeFamily(entry.family); persist(); }
    }
  };
  app.use(['/authorize', '/consent'], (_req, res, next) => {
    // A basic form POST under no-referrer can carry Origin: null. Keep only
    // the origin (never the authorization query) so strict CSRF validation works.
    res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'strict-origin', 'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" });
    next();
  });
  app.post('/consent', express.urlencoded({ extended: false, limit: '4kb' }), (req, res) => {
    sweep();
    const entry = typeof req.body.request === 'string' ? pending.get(req.body.request) : undefined;
    const cookie = /(?:^|;\s*)__Host-aliaddo_oauth=([A-Za-z0-9_-]+)/.exec(req.headers.cookie || '')?.[1] || '';
    if (req.headers.origin !== base.origin || !entry || entry.cookieHash !== hash(cookie)) {
      console.info('OAuth consent rejected', JSON.stringify({ reason: req.headers.origin !== base.origin ? 'origin' : !entry ? 'expired_or_missing_request' : 'browser_cookie' }));
      return res.status(403).type('html').send(html('<p>Solicitud vencida o invalida. Vuelve a iniciar la conexion desde Gemini.</p>'));
    }
    const redirect = new URL(entry.params.redirectUri);
    if (entry.params.state !== undefined) redirect.searchParams.set('state', entry.params.state);
    if (req.body.decision === 'deny') {
      pending.delete(req.body.request); redirect.searchParams.set('error', 'access_denied');
      return res.redirect(303, redirect.href);
    }
    const ip = req.ip || 'unknown';
    if (!attempts.has(ip)) {
      if (attempts.size >= 2000) return res.sendStatus(429);
      attempts.set(ip, { count: 0, expires: now() + 900 });
    }
    const attempt = attempts.get(ip)!;
    if (++attempt.count > 5) return res.status(429).type('html').send(html('<p>Demasiados intentos. Espera 15 minutos.</p>'));
    if (req.body.decision !== 'allow' || typeof req.body.key !== 'string' || !equal(req.body.key, key)) return res.status(403).type('html').send(html('<p>Clave incorrecta. Vuelve atras e introduce MCP_ACCESS_KEY de Render.</p>'));
    if (codes.size >= 500) return res.sendStatus(429);
    const raw = random();
    codes.set(hash(raw), { ...entry, expires: now() + 120, family: random() });
    pending.delete(req.body.request);
    res.clearCookie('__Host-aliaddo_oauth', { secure: true, httpOnly: true, sameSite: 'lax', path: '/' });
    redirect.searchParams.set('code', raw);
    return res.redirect(303, redirect.href);
  });
  app.use('/register', express.json({ limit: '32kb' }), (req, res, next) => {
    res.once('finish', () => {
      const parsed = OAuthClientMetadataSchema.safeParse(req.body);
      const method = req.body?.token_endpoint_auth_method;
      // Never log the body, URLs, client identifiers, secrets or credentials.
      console.info('OAuth registration', JSON.stringify({ status: res.statusCode,
        schema: parsed.success ? 'ok' : 'invalid',
        invalidFields: parsed.success ? [] : parsed.error.issues.map(i => i.path.filter(p => typeof p === 'string' && /^[a-z_]+$/.test(p)).join('.')),
        authMethod: ['none', 'client_secret_post', 'client_secret_basic'].includes(method) ? method : method === undefined ? 'omitted' : 'other',
        scope: req.body?.scope === undefined ? 'omitted' : req.body.scope === '' ? 'empty' : req.body.scope === scope ? 'supported' : 'other',
        redirects: Array.isArray(req.body?.redirect_uris) ? req.body.redirect_uris.length : 'invalid' }));
    });
    next();
  });
  app.use(mcpAuthRouter({ provider, issuerUrl: base, resourceServerUrl: new URL(resource), scopesSupported: [scope], resourceName: 'Aliaddo Caldas - consulta de facturas', clientRegistrationOptions: { clientSecretExpirySeconds: 0 } }));
  return requireBearerAuth({ verifier: provider, requiredScopes: [scope], expectedResource: resource, resourceMetadataUrl: new URL('/.well-known/oauth-protected-resource/mcp', base).href });
}
