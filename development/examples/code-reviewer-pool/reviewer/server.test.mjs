import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { startReviewer } from './review_server.mjs';
import { mintToken } from './lease-token.mjs';

test('MCP clients share worker capacity and can list workspace tools', { timeout: 5000 }, async t => {
  let started;
  const entered = new Promise(resolve => { started = resolve; });
  let finish;
  const result = new Promise(resolve => { finish = resolve; });
  const workspace = {
    info: () => ({ baseKey: 'public' }),
    listFindings: async () => [],
    publishFinding: async () => {},
  };
  const listener = await startReviewer({ port: 0, workspace,
    run: async () => { started(); return result; } });
  const clients = [];
  t.after(async () => {
    finish('review');
    for (const client of clients) await client.close();
    listener.closeAllConnections();
    await new Promise(resolve => listener.close(resolve));
  });
  async function client() {
    const c = new Client({ name: 'test', version: '1' });
    clients.push(c);
    await c.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${listener.address().port}/mcp`)));
    return c;
  }
  const a = await client(), b = await client();
  assert.deepEqual((await a.listTools()).tools.map(tool => tool.name).sort(),
    ['list_findings', 'read_finding', 'review_code', 'workspace_info']);
  const args = { code: 'x', token: mintToken('sam-dev-pool-secret', 'test-peer', Date.now() + 60000) };
  const first = a.callTool({ name: 'review_code', arguments: args });
  await entered;
  const busy = await b.callTool({ name: 'review_code', arguments: args });
  assert.equal(busy.isError, true);
  assert.equal(busy.content[0].text, 'POOL_BUSY');
  finish('a useful review');
  assert.equal((await first).content[0].text, 'a useful review\n\n[Workspace: published]');
  const info = await b.callTool({ name: 'workspace_info', arguments: {} });
  assert.deepEqual(JSON.parse(info.content[0].text), { baseKey: 'public' });
});
