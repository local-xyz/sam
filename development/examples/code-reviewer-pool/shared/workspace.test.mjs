import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { openWorkspace } from './workspace.mjs';

const codeHash = createHash('sha256').update('eval(input)').digest('hex');
async function until(check) {
  const end = Date.now() + 8000;
  while (Date.now() < end) {
    const value = await check();
    if (value) return value;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error('replication did not converge');
}
async function setup(t) {
  const dir = await mkdtemp(join(tmpdir(), 'sam-workspace-'));
  const opened = [];
  const streams = [];
  t.after(async () => {
    for (const stream of streams) stream.destroy();
    for (const ws of opened.reverse()) await ws.close();
    await rm(dir, { recursive: true, force: true });
  });
  async function open(name, bootstrapKey) {
    const ws = await openWorkspace({ directory: join(dir, name), bootstrapKey, network: false, readTimeoutMs: 200 });
    opened.push(ws);
    return ws;
  }
  function connect(a, b) {
    const left = a.replicate(true), right = b.replicate(false);
    left.on('error', () => {}); right.on('error', () => {});
    streams.push(left, right);
    left.pipe(right).pipe(left);
    return () => { left.destroy(); right.destroy(); };
  }
  return { open, connect };
}

test('replicates attributed reports, retains them on reopen and after offline publication', { timeout: 15000 }, async t => {
  const f = await setup(t);
  const a = await f.open('founder');
  const b = await f.open('reviewer', a.info().baseKey);
  let disconnect = f.connect(a, b);
  await a.admitWriter(b.info().writerKey);
  await until(() => b.info().writable);
  const first = await a.publishFinding({ codeHash, report: 'Avoid eval on user input.' });
  await until(async () => (await b.listFindings({ codeHash })).length === 1);
  const [received] = await b.listFindings({ codeHash });
  assert.equal(received.author, a.info().writerKey);
  assert.equal(await b.readFinding(received), 'Avoid eval on user input.');
  assert.equal(received.id, first.id);
  disconnect();
  await b.publishFinding({ codeHash, report: 'Use a parser instead.' });
  assert.equal((await a.listFindings({ codeHash })).length, 1);
  disconnect = f.connect(a, b);
  await until(async () => (await a.listFindings({ codeHash })).length === 2);
  const second = (await a.listFindings({ codeHash })).find(row => row.author === b.info().writerKey);
  assert.equal(await a.readFinding(second), 'Use a parser instead.');
  disconnect();
  await b.close();
  const reopened = await f.open('reviewer', a.info().baseKey);
  f.connect(a, reopened);
  await until(async () => (await reopened.listFindings({ codeHash })).length === 2);
  assert.equal(await reopened.readFinding(second), 'Use a parser instead.');
});

test('only founder can admit writers and unadmitted writers cannot publish', { timeout: 10000 }, async t => {
  const f = await setup(t), a = await f.open('a');
  const b = await f.open('b', a.info().baseKey);
  f.connect(a, b);
  await assert.rejects(b.admitWriter(a.info().writerKey), /FOUNDER_ONLY/);
  await assert.rejects(b.publishFinding({ codeHash, report: 'not admitted' }), /NOT_WRITABLE/);
  await assert.rejects(a.admitWriter('invalid'), /INVALID_KEY/);
});

test('rejects corrupt artifacts and bounds unavailable reads', { timeout: 10000 }, async t => {
  const f = await setup(t), a = await f.open('a');
  const finding = await a.publishFinding({ codeHash, report: 'A valid report' });
  await assert.rejects(a.readFinding({ ...finding, artifact: { ...finding.artifact, sha256: '0'.repeat(64) } }), /HASH_MISMATCH/);
  const b = await f.open('isolated');
  await assert.rejects(b.readFinding(finding), /ARTIFACT_UNAVAILABLE/);
  await assert.rejects(a.publishFinding({ codeHash, report: 'x'.repeat(65537) }), /REPORT_TOO_LARGE/);
});
