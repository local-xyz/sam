import { test } from 'node:test';
import assert from 'node:assert/strict';
import { reviewWithWorkspace } from './review.mjs';

const finding = { id: 'prior', author: 'alice' };
test('prior findings become attributed context and new review is published', async () => {
  const saved = [];
  const workspace = {
    listFindings: async () => [finding],
    readFinding: async () => 'Unvalidated eval input.',
    publishFinding: async value => { saved.push(value); },
  };
  const result = await reviewWithWorkspace({ code: 'eval(input)', workspace,
    run: async (_code, context) => context.includes('alice') && context.includes('Unvalidated eval input.')
      && context.includes('untrusted') ? 'Agrees: validate the input.' : 'No shared context.' });
  assert.equal(result.review, 'Agrees: validate the input.');
  assert.deepEqual(saved.map(x => x.report), ['Agrees: validate the input.']);
  assert.equal(result.sharing, 'published');
});

test('failed context and publication preserve the review without rerunning it', async () => {
  let runs = 0;
  const fail = async () => { throw new Error('offline'); };
  const result = await reviewWithWorkspace({ code: 'code',
    workspace: { listFindings: fail, publishFinding: fail },
    run: async () => { runs++; return 'review is still useful'; } });
  assert.equal(result.review, 'review is still useful');
  assert.equal(result.sharing, 'unavailable');
  assert.equal(runs, 1);
});

test('caps prior context in UTF-8 bytes and skips unavailable artifacts', async () => {
  const workspace = {
    listFindings: async () => [finding, { id: 'missing', author: 'b' }, { id: 'third', author: 'c' }],
    readFinding: async row => { if (row.id === 'missing') throw new Error('offline'); return '😀'.repeat(10000); },
    publishFinding: async () => {},
  };
  const result = await reviewWithWorkspace({ code: 'code', workspace,
    run: async (_code, context) => String(Buffer.byteLength(context)) });
  assert.ok(Number(result.review) <= 16384);
  assert.ok(Number(result.review) > 0);
});

test('disabled sharing preserves ordinary review behavior', async () => {
  const result = await reviewWithWorkspace({ code: 'code',
    run: async (code, context) => `${code}:${context}` });
  assert.deepEqual(result, { review: 'code:', sharing: 'disabled' });
});
