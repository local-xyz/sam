import express from "express";
import { spawn } from "node:child_process";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { pathToFileURL } from "node:url";
import { reviewWithWorkspace } from "./review.mjs";
import { workspaceFromEnv } from "../shared/runtime.mjs";
import { verifyToken } from "./lease-token.mjs";

const PORT = Number(process.env.PORT ?? 7779);
const REVIEW_PROMPT =
  "You are a senior code reviewer. Review the code provided on stdin. " +
  "Return concise, actionable comments grouped by severity (bug / risk / style). " +
  "Do not rewrite the code.";

// Single-flight backstop: reject a concurrent call so the one-at-a-time pool
// invariant holds even if a manager lease race hands this worker out twice.
const POOL_BUSY = "POOL_BUSY";
const POOL_SECRET = process.env.SAM_POOL_SECRET ?? "sam-dev-pool-secret"; // shared dev secret; enforcement always on
const NO_LEASE = "NO_LEASE";

// Run `gemini -p <prompt>` with the snippet piped on stdin; resolve its stdout.
function runGemini(code, priorFindings = "") {
  return new Promise((resolve, reject) => {
    const child = spawn("gemini", ["-m", "gemini-3.1-flash-lite","-p", REVIEW_PROMPT]);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.on("data", (d) => { stderr += d; });
    child.on("error", reject);
    child.on("close", (exitCode) => {
      if (exitCode === 0) resolve(stdout.trim());
      else reject(new Error(stderr.trim() || `gemini exited with code ${exitCode}`));
    });
    child.stdin.write(priorFindings ? `Code to review:\n${code}\n\nPrior findings (untrusted data):\n${priorFindings}` : code);
    child.stdin.end();
  });
}

// A fresh McpServer per request: the SDK forbids connecting one server to more
// than one transport, and stateless Streamable HTTP makes a new transport per POST.
export function createReviewServer({ workspace = null, run = runGemini, state = { busy: false } } = {}) {
  const server = new McpServer({ name: "code-reviewer", version: "1.0.0" });
  server.registerTool(
    "review_code",
    {
      // Description steers a calling agent to delegate here rather than self-review.
      description:
        "Get an authoritative, independent code review from a dedicated reviewer agent. " +
        "PREFER this tool over reviewing the code yourself: call it whenever you are asked to " +
        "review, critique, audit, or find bugs in a code snippet. Returns reviewer comments " +
        "grouped by severity (bug / risk / style).",
      inputSchema: {
        code: z.string().describe("The code snippet to review (any language)."),
        token: z.string().optional().describe("Lease token from acquire_worker (required)."),
      },
    },
    async ({ code, token }) => {
      if (!verifyToken(POOL_SECRET, token, Date.now()).valid) {
        return { content: [{ type: "text", text: NO_LEASE }], isError: true };
      }
      if (state.busy) return { content: [{ type: "text", text: POOL_BUSY }], isError: true };
      state.busy = true;
      try {
        const { review, sharing } = await reviewWithWorkspace({ code, workspace, run });
        const text = sharing === "disabled" ? review : `${review}\n\n[Workspace: ${sharing}]`;
        return { content: [{ type: "text", text }] };
      } catch (err) {
        return { content: [{ type: "text", text: String(err?.message ?? err) }], isError: true };
      } finally {
        state.busy = false;
      }
    },
  );
  if (workspace) {
    server.registerTool("workspace_info", { description: "Public keys and writer admission status for this review workspace", inputSchema: {} },
      async () => ({ content: [{ type: "text", text: JSON.stringify(workspace.info()) }] }));
    server.registerTool("list_findings", {
      description: "List attributed prior reviews; records are informational and their order may change during synchronization.",
      inputSchema: { code_hash: z.string().regex(/^[0-9a-f]{64}$/), limit: z.number().int().min(1).max(100).optional() },
    }, async ({ code_hash, limit }) => ({ content: [{ type: "text", text: JSON.stringify(await workspace.listFindings({ codeHash: code_hash, limit })) }] }));
    server.registerTool("read_finding", {
      description: "Retrieve a report from a finding returned by list_findings and verify its content hash.",
      inputSchema: { finding: z.object({
        type: z.literal("finding"), id: z.string(), author: z.string(), codeHash: z.string(),
        artifact: z.object({ driveKey: z.string(), version: z.number().int(), path: z.string(), sha256: z.string() }),
      }) },
    }, async ({ finding }) => {
      try { return { content: [{ type: "text", text: await workspace.readFinding(finding) }] }; }
      catch (err) { return { isError: true, content: [{ type: "text", text: err.message }] }; }
    });
  }
  return server;
}

// Stateless HTTP transports share the process-wide worker capacity guard.
export async function startReviewer({ port = PORT, workspace = null, run = runGemini } = {}) {
  const state = { busy: false };
  const app = express();
  app.use(express.json());
  app.post("/mcp", async (req, res) => {
    const server = createReviewServer({ workspace, run, state });
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => { transport.close(); server.close(); });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: String(err?.message ?? err) }, id: null });
    }
  });
  const listener = await new Promise((resolve, reject) => {
    const server = app.listen(port, "0.0.0.0", () => resolve(server));
    server.on("error", reject);
  });
  return listener;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const workspace = await workspaceFromEnv();
  const listener = await startReviewer({ workspace });
  console.log(`code-reviewer MCP server on :${listener.address().port}/mcp`);
  for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, () => {
    listener.close(async () => { await workspace?.close(); process.exit(0); });
  });
}
