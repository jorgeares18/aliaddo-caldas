import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from './server.ts';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const key = 'test-only-connector-key-000000000000000';
async function start(options = {}) {
  const server = createApp({ key, token: 'test-only-aliaddo-token', ...options }).listen(0, '127.0.0.1');
  await new Promise<void>(resolve => server.once('listening', resolve));
  const address = server.address() as { port: number };
  return { url: new URL(`http://127.0.0.1:${address.port}/mcp`), close: () => new Promise<void>(resolve => { server.close(() => resolve()); server.closeAllConnections(); }) };
}
test('requires configured secrets and correct authorization', async () => {
  for (const [options, headers, status] of [[{ token: '' }, {}, 503], [{}, {}, 401], [{}, { Authorization: 'Bearer wrong' }, 401], [{}, { Authorization: 'Bearer ' + key, Origin: 'https://untrusted.example' }, 403]] as const) {
    const running = await start(options);
    try { assert.equal((await fetch(running.url, { method: 'POST', headers })).status, status); }
    finally { await running.close(); }
  }
});
test('real MCP client discovers and calls read-only tool; pagination and errors', async () => {
  let mode = 'ok'; let calls = 0;
  const running = await start({ fetchImpl: async (url, options) => {
    calls++;
    assert.equal(url.origin, 'https://app.aliaddo.net');
    assert.equal(url.pathname, '/v1/invoices');
    assert.equal(url.searchParams.get('date'), '2026-10-03');
    assert.equal(options.method, 'GET');
    assert.equal(options.redirect, 'error');
    assert.equal(options.headers.Authorization, 'Bearer test-only-aliaddo-token');
    if (mode === '401') return new Response('{}', { status: 401 });
    if (mode === 'error') throw new Error('secret-should-not-appear');
    if (mode === 'shape') return Response.json({ invoices: [] });
    if (url.searchParams.get('page') === '2') return Response.json([]);
    return Response.json([{ id: 'invoice-1', date: mode === 'date' ? '2026-10-02' : '2026-10-03', consecutive: 'F1', personName: 'Cliente de prueba', currencyCode: 'COP', totalAmount: 100, status: 'Vigente', privateField: 'not-exported' }]);
  } });
  const client = new Client({ name: 'test-client', version: '1.0.0' });
  try {
    await client.connect(new StreamableHTTPClientTransport(running.url, { requestInit: { headers: { Authorization: 'Bearer ' + key } } }));
    const tools = await client.listTools();
    assert.deepEqual(tools.tools.map(t => t.name), ['consultar_facturas']);
    assert.equal(tools.tools[0].annotations?.readOnlyHint, true);
    const call = (args = {}) => client.callTool({ name: 'consultar_facturas', arguments: { fecha: '2026-10-03', ...args } });
    const first = await call();
    const data = JSON.parse((first.content as any)[0].text);
    assert.equal(data.facturas[0].numero, 'F1');
    assert.equal(data.pagina_siguiente, 2);
    assert.equal(JSON.stringify(data).includes('not-exported'), false);
    const last = await call({ pagina: 2 });
    assert.equal(JSON.parse((last.content as any)[0].text).pagina_siguiente, null);
    const before = calls;
    assert.equal((await call({ fecha: '2026-02-30' })).isError, true);
    assert.equal(calls, before);
    for (mode of ['401', 'date', 'shape', 'error']) {
      const result = await call();
      assert.equal(result.isError, true);
      assert.equal(JSON.stringify(result).includes('secret-should-not-appear'), false);
    }
  } finally { await client.close(); await running.close(); }
});
