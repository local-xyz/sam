// Workspace dependencies are only loaded when sharing is explicitly enabled.
export async function workspaceFromEnv(env = process.env) {
  if (!env.SAM_WORKSPACE_DIR) return null;
  const { openWorkspace } = await import('./workspace.mjs');
  const workspace = await openWorkspace({
    directory: env.SAM_WORKSPACE_DIR,
    bootstrapKey: env.SAM_WORKSPACE_KEY || undefined,
  });
  try {
    for (const key of (env.SAM_WORKSPACE_WRITERS || '').split(',').map(s => s.trim()).filter(Boolean)) {
      await workspace.admitWriter(key);
    }
    console.log('Review workspace:', JSON.stringify(workspace.info()));
    return workspace;
  } catch (err) {
    await workspace.close();
    throw err;
  }
}
