import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openWorkspace, codeHash } from './workspace.mjs';
import { reviewWithWorkspace } from '../reviewer/review.mjs';

const directory = await mkdtemp(join(tmpdir(), 'sam-review-demo-'));
const workspaces = [], streams = [];
async function open(name, bootstrapKey) {
  const workspace = await openWorkspace({ directory: join(directory, name), bootstrapKey, network: false });
  workspaces.push(workspace);
  return workspace;
}
function connect(a, b) {
  const left = a.replicate(true), right = b.replicate(false);
  streams.push(left, right);
  left.on('error', console.error); right.on('error', console.error);
  left.pipe(right).pipe(left);
}
async function until(check) {
  for (let n = 0; n < 200; n++) {
    if (await check()) return;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error('Workspace synchronization timed out');
}
try {
  const manager = await open('manager');
  const a = await open('reviewer-a', manager.info().baseKey);
  const b = await open('reviewer-b', manager.info().baseKey);
  connect(manager, a); connect(manager, b); connect(a, b);
  await manager.admitWriter(a.info().writerKey);
  await manager.admitWriter(b.info().writerKey);
  await until(() => a.info().writable && b.info().writable);
  const code = 'eval(userInput)';
  const first = await reviewWithWorkspace({ code, workspace: a,
    run: async () => 'Bug: untrusted input reaches eval.' });
  await until(async () => (await b.listFindings({ codeHash: codeHash(code) })).length === 1);
  const second = await reviewWithWorkspace({ code, workspace: b,
    run: async (_code, context) => {
      assert.match(context, /Bug: untrusted input reaches eval/);
      assert.ok(context.includes(a.info().writerKey));
      return 'Prior finding received; also recommend a parser instead of eval.';
    } });
  await until(async () => (await manager.listFindings({ codeHash: codeHash(code) })).length === 2);
  console.log(JSON.stringify({
    transport: 'local Hypercore replication streams (no live SAM or Hyperswarm network)',
    runner: 'deterministic fake; no LLM calls',
    reviewerA: first, reviewerB: second,
    sharedFindings: (await manager.listFindings({ codeHash: codeHash(code) })).length,
  }, null, 2));
} finally {
  for (const stream of streams) stream.destroy();
  for (const workspace of workspaces.reverse()) await workspace.close();
  await rm(directory, { recursive: true, force: true });
}
