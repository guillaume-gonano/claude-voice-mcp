// End-to-end test without Cloudflare: full OAuth flow, then the tools with a fake Claude Code.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { accessGuard, createApp, createOAuthProvider, createTaskRunner, passwordGuard, resolveSettings } from "./server.mjs";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "voice-mcp-"));
const fakeClaude = path.join(tmp, "claude");
fs.writeFileSync(fakeClaude, `#!/bin/sh\nsleep "\${FAKE_SLEEP:-0}"\necho '{"type":"result","is_error":false,"result":"It is noon.","session_id":"sess-1"}'\n`, { mode: 0o755 });

const port = 47861;
const base = `http://127.0.0.1:${port}`;
const provider = createOAuthProvider(path.join(tmp, "state.json"));
let accessOk = false;
const settings = resolveSettings({ userName: "Alex" });
const app = createApp({ publicUrl: base, provider, guard: accessGuard(async () => accessOk), runner: createTaskRunner({ bin: fakeClaude }), settings });
const httpServer = app.listen(port, "127.0.0.1");
await new Promise((resolve) => httpServer.once("listening", resolve));

try {
  // MCP without a token → 401 with the OAuth metadata address.
  const anonymous = await fetch(`${base}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  assert.equal(anonymous.status, 401);
  assert.match(anonymous.headers.get("www-authenticate"), /oauth-protected-resource/);

  // Registration refused outside the Claude redirect URIs.
  const bad = await fetch(`${base}/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: ["https://evil.example/cb"] }) });
  assert.equal(bad.status, 400);

  const redirectUri = "https://claude.ai/api/mcp/auth_callback";
  const reg = await fetch(`${base}/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: [redirectUri], token_endpoint_auth_method: "none", client_name: "test" }) });
  assert.equal(reg.status, 201);
  const client = await reg.json();

  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const authUrl = `${base}/authorize?${new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: redirectUri, code_challenge: challenge, code_challenge_method: "S256", state: "xyz" })}`;

  // Without a Cloudflare Access sign-in: refused.
  assert.equal((await fetch(authUrl, { redirect: "manual" })).status, 403);
  accessOk = true;
  const authorized = await fetch(authUrl, { redirect: "manual" });
  assert.equal(authorized.status, 302);
  const location = new URL(authorized.headers.get("location"));
  assert.equal(location.searchParams.get("state"), "xyz");

  const tokenResponse = await fetch(`${base}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code: location.searchParams.get("code"), code_verifier: verifier, client_id: client.client_id, redirect_uri: redirectUri }),
  });
  assert.equal(tokenResponse.status, 200);
  const tokens = await tokenResponse.json();

  const refreshed = await fetch(`${base}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: client.client_id }),
  });
  assert.equal(refreshed.status, 200);
  const { access_token } = await refreshed.json();

  const mcp = new Client({ name: "test", version: "1" });
  await mcp.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${access_token}` } } }));
  const { tools } = await mcp.listTools();
  assert.deepEqual(tools.map((tool) => tool.name).sort(), ["ask_claude_code", "get_task_result"]);

  const answer = await mcp.callTool({ name: "ask_claude_code", arguments: { request: "What time is it?" } });
  assert.match(answer.content[0].text, /It is noon\.[\s\S]*sess-1/);

  // Allowed tools are passed to Claude Code as permission rules.
  const argsFile = path.join(tmp, "args.txt");
  const echoClaude = path.join(tmp, "claude-args");
  fs.writeFileSync(echoClaude, `#!/bin/sh\nprintf '%s\\n' "$@" > "${argsFile}"\necho '{"result":"ok","session_id":"s"}'\n`, { mode: 0o755 });
  const echoRunner = createTaskRunner({ bin: echoClaude, allowedTools: ["Bash(kite send:*)"] });
  await echoRunner.wait(echoRunner.start("send it"), 5000);
  assert.match(fs.readFileSync(argsFile, "utf8"), /--allowedTools\nBash\(kite send:\*\)\n/);

  // Long task: "running" answer, then the result via get_task_result.
  process.env.FAKE_SLEEP = "2";
  const slowRunner = createTaskRunner({ bin: fakeClaude });
  const slow = await slowRunner.wait(slowRunner.start("long"), 300);
  assert.equal(slow.status, "running");
  await slowRunner.wait(slow, 5000);
  assert.equal(slow.status, "done");

  await mcp.close();

  // Password mode (any tunnel): form, wrong password, right password, then lock after five failures.
  assert.throws(() => passwordGuard("short"));
  const password = "correct horse battery staple";
  const pwApp = createApp({ publicUrl: `http://127.0.0.1:${port + 1}`, provider, guard: passwordGuard(password), runner: createTaskRunner({ bin: fakeClaude }), settings });
  const pwServer = pwApp.listen(port + 1, "127.0.0.1");
  await new Promise((resolve) => pwServer.once("listening", resolve));
  try {
    const pwBase = `http://127.0.0.1:${port + 1}`;
    const params = { response_type: "code", client_id: client.client_id, redirect_uri: redirectUri, code_challenge: challenge, code_challenge_method: "S256", state: "pw" };
    const form = await fetch(`${pwBase}/authorize?${new URLSearchParams(params)}`, { redirect: "manual" });
    assert.equal(form.status, 200);
    const html = await form.text();
    assert.match(html, /type="password"/);
    assert.match(html, new RegExp(`name="client_id" value="${client.client_id}"`));
    const submit = (pw) => fetch(`${pwBase}/authorize`, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ ...params, password: pw }) });
    assert.equal((await submit("wrong password, long enough")).status, 401);
    const ok = await submit(password);
    assert.equal(ok.status, 302);
    assert.equal(new URL(ok.headers.get("location")).searchParams.get("state"), "pw");
    for (let i = 0; i < 5; i++) await submit("still the wrong password");
    assert.equal((await submit(password)).status, 429);
  } finally {
    pwServer.close();
  }
  console.log("OK: OAuth, Access and password guards, tools");
} finally {
  httpServer.close();
  fs.rmSync(tmp, { recursive: true, force: true });
}
