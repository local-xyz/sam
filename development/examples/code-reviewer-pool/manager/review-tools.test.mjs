import { test } from 'node:test';
import assert from 'node:assert/strict';
import { reviewTools } from './review-tools.mjs';

test('workspace tools cannot replace the leased review tool', () => {
  const rows = [
    { peer_id: 'a', tool_name: 'mcp://code-reviewer/review_code' },
    { peer_id: 'a', tool_name: 'mcp://code-reviewer/list_findings' },
    { peer_id: 'a', tool_name: 'mcp://code-reviewer/workspace_info' },
    { peer_id: 'b', tool_name: 'mcp://other/review_code' },
    { tool_name: 'mcp://code-reviewer/review_code' },
  ];
  assert.deepEqual(reviewTools(rows, 'code-reviewer'), [rows[0]]);
});
