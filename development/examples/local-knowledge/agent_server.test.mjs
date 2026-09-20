import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { runGemini, startServer } from './agent_server.mjs';

test('Gemini subprocess receives the prompt and only this agent’s context', async () => {
  const previous = process.env.LOCAL_CONTEXT;
  process.env.LOCAL_CONTEXT = 'A fact held by this instance.';
  const dir = await mkdtemp(join(tmpdir(), 'sam-agent-'));
  try {
    const executable = join(dir, 'fake-gemini');
    await writeFile(executable, '#!/usr/bin/env node\nlet input=""; for await (const c of process.stdin) input += c; console.log(JSON.stringify({args:process.argv.slice(2), input}));', { mode: 0o755 });
    const output = JSON.parse(await runGemini('What do you know?', { executable }));
    assert.equal(output.args.at(-2), '-p');
    assert.ok(output.args.at(-1).length > 0);
    assert.equal(JSON.parse(output.input).question, 'What do you know?');
    assert.equal(JSON.parse(output.input).local_context, 'A fact held by this instance.');
  } finally {
    if (previous === undefined) delete process.env.LOCAL_CONTEXT;
    else process.env.LOCAL_CONTEXT = previous;
    await rm(dir, { recursive: true, force: true });
  }
});

test('MCP callers share one busy guard; results and failures release capacity', async () => {
  let finish;
  let started;
  const running = new Promise(resolve => { started = resolve; });
  const server = startServer({ port: 0, run: async question => {
    if (question === 'fail') throw new Error('model unavailable');
    started();
    return new Promise(resolve => { finish = resolve; });
  } });
  if (!server.listening) await new Promise(resolve => server.once('listening', resolve));
  const url = new URL(`http://127.0.0.1:${server.address().port}/mcp`);
  const a = new Client({ name: 'caller-a', version: '1' });
  const b = new Client({ name: 'caller-b', version: '1' });
  try {
    await a.connect(new StreamableHTTPClientTransport(url));
    await b.connect(new StreamableHTTPClientTransport(url));
    assert.deepEqual((await a.listTools()).tools.map(t => t.name), ['ask']);
    const first = a.callTool({ name: 'ask', arguments: { question: 'Question' } });
    await running;
    const second = await b.callTool({ name: 'ask', arguments: { question: 'Another question' } });
    assert.equal(second.isError, true);
    assert.equal(second.content[0].text, 'AGENT_BUSY');
    finish('Peer answer');
    assert.equal((await first).content[0].text, 'Peer answer');
    for (let n = 0; n < 2; n++) {
      const failed = await a.callTool({ name: 'ask', arguments: { question: 'fail' } });
      assert.equal(failed.isError, true);
      assert.equal(failed.content[0].text, 'model unavailable');
    }
  } finally {
    finish?.('done');
    await a.close(); await b.close();
    await new Promise(resolve => server.close(resolve));
  }
});
