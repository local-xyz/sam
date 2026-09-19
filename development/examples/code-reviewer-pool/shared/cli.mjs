import { openWorkspace } from './workspace.mjs';

// Offline initialization/inspection only: stop the process owning this directory first.
const [directory, bootstrapKey] = process.argv.slice(2);
if (!directory) {
  console.error('Usage: node shared/cli.mjs <workspace-directory> [bootstrap-key]');
  process.exitCode = 1;
} else {
  const workspace = await openWorkspace({ directory, bootstrapKey, network: false });
  try { console.log(JSON.stringify(workspace.info(), null, 2)); }
  finally { await workspace.close(); }
}
