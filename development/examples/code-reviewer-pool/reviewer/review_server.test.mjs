import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { ClientFactory } from "@a2a-js/sdk/client";
import { Message } from "@a2a-js/sdk";
import { mintToken } from "./lease-token.mjs";

test("A2A streams Gemini events before completion and enforces leases", { timeout: 10000 }, async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "review-a2a-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeFile(join(dir, "gemini"), `#!${process.execPath}
const fs = require("node:fs");
process.stdin.resume();
process.stdin.on("end", () => {
  if (!process.argv.includes("stream-json")) process.exit(2);
  console.log(JSON.stringify({type:"tool_use", tool_name:"read_file", tool_id:"one"}));
  const deadline = Date.now() + 3000;
  const wait = setInterval(() => {
    if (Date.now() > deadline) process.exit(3);
    if (!fs.existsSync(process.env.TEST_GATE)) return;
    clearInterval(wait);
    console.log(JSON.stringify({type:"message", role:"assistant", content:"Review complete", delta:true}));
    console.log(JSON.stringify({type:"result", status:"success"}));
  }, 10);
});
`, { mode: 0o755 });
  const child = spawn(process.execPath, ["review_server.mjs"], {
    cwd: new URL(".", import.meta.url),
    env: { ...process.env, PORT: "0", PATH: `${dir}:${process.env.PATH}`, TEST_GATE: join(dir, "go"), SAM_POOL_SECRET: "test-secret" },
    stdio: ["ignore", "pipe", "inherit"],
  });
  t.after(async () => { if (child.exitCode !== null) return; const done = once(child, "close"); child.kill(); await done; });
  const lines = createInterface({ input: child.stdout });
  const [ready] = await once(lines, "line");
  const port = /on :(\d+)/.exec(ready)[1];
  const client = await new ClientFactory().createFromUrl(`http://127.0.0.1:${port}/a2a/.well-known/agent-card.json`, "");
  const message = () => Message.fromJSON({ messageId: crypto.randomUUID(), role: "ROLE_USER", parts: [{ text: "review this" }] });
  const denied = [];
  for await (const event of client.sendMessageStream({ message: message() })) denied.push(event);
  assert.equal(denied.at(-1).payload.value.status.state, 4);
  const token = mintToken("test-secret", "worker", Date.now() + 60000);
  let sawTool = false, final;
  for await (const event of client.sendMessageStream({ message: message(), metadata: { token } })) {
    const update = event.payload.value;
    const gemini = update.metadata?.gemini;
    if (gemini?.type === "tool_use") {
      sawTool = true;
      await writeFile(join(dir, "go"), "");
    }
    if (update.status?.state === 3) final = update;
  }
  assert.ok(sawTool, "tool event must arrive while Gemini is waiting");
  assert.equal(final.status.message.parts[0].content.value, "Review complete");
});
