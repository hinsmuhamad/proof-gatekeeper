// Test harness for the Proof Gatekeeper agent.
// Run:  npm test   (or: node test/run-tests.js)
// Exits 0 only if every check passes. No network, no secrets, no
// registration. Uses a temp state dir so the real seen-proofs.json is
// untouched, and a throwaway HMAC secret for the HTTP tests.
//
// What is tested:
//   1. decide() on mock payloads: valid + all six scored trap types +
//      unfinalized + malformed + boundary values.
//   2. decision-vs-circuit agreement: for every mock task, the decision
//      from decide() must produce a Groth16 proof that verifies against
//      the official verification key, and the OPPOSITE decision must fail
//      to prove (the circuit asserts decision correctness).
//   3. HTTP server: /health, /preflight, /agent with a valid HMAC,
//      tampered body (401), wrong secret (401), trap decisions, the
//      PROOF_REUSED path across requests, and replay of the same task.

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

// --- test env (must be set before importing the server/config) ---
process.env.ALLOW_UNSIGNED = "false";
process.env.AGENT_GAMES_HMAC_SECRET = "test-secret-do-not-use-in-production";
process.env.STATE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "gk-test-state-"));
process.env.PORT = "0"; // ephemeral port for the HTTP tests

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { decide, REASON } = await import("../src/decision.js");
const { buildCircuitInput, generateDecisionProof, loadVkey } = await import("../src/prover.js");
const { createServer } = await import("../src/server.js");
const { hmacHex } = await import("../src/hmac.js");
const { groth16 } = await import("snarkjs");

const SECRET = "test-secret-do-not-use-in-production";
const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const VK_OTHER = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RECIPIENT = "0xDe42000000000000000000000000000000009f01";
const RECIPIENT_OTHER = "0x1111111111111111111111111111111111111111";
const PROOF_TX = "0xa4c1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8ff1";

let passed = 0;
let failed = 0;
const failures = [];
function check(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  PASS ${name}`);
  } catch (e) {
    failed++;
    failures.push(name);
    console.log(`  FAIL ${name} :: ${e.message}`);
  }
}
async function checkAsync(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  PASS ${name}`);
  } catch (e) {
    failed++;
    failures.push(name);
    console.log(`  FAIL ${name} :: ${e.message}`);
  }
}

function mockTask(overrides = {}, inputOverrides = {}) {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "gk_24_9d1",
    mode: "competition",
    issued_at: "2026-11-15T10:30:00.000Z",
    deadline_at: "2026-11-15T10:31:00.000Z",
    input: {
      registered_vk: VK,
      proof_vk: VK,
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: RECIPIENT,
      condition_recipient: RECIPIENT,
      amount: "500",
      max_transfer: "1000",
      proof_tx: PROOF_TX,
      ...inputOverrides,
    },
    ...overrides,
  };
}

// The decision tests run "now" inside the task window so the deadline
// check does not fire. (Real tasks carry their own deadline_at.)
const NOW = Date.parse("2026-11-15T10:30:30.000Z");
const emptySeen = new Set();

console.log("\n== 1. decision logic ==");
const decisionCases = [
  ["valid -> APPROVE/VALID_CONDITION", mockTask(), "APPROVE", REASON.VALID],
  ["VK_SUBSTITUTION -> REJECT", mockTask({}, { proof_vk: VK_OTHER }), "REJECT", REASON.VK_SUBSTITUTION],
  ["THRESHOLD_MISMATCH -> REJECT", mockTask({}, { public_balance: "999" }), "REJECT", REASON.THRESHOLD_MISMATCH],
  ["RECIPIENT_MISMATCH -> REJECT", mockTask({}, { recipient: RECIPIENT_OTHER }), "REJECT", REASON.RECIPIENT_MISMATCH],
  ["AMOUNT_OVERFLOW -> REJECT", mockTask({}, { amount: "1001" }), "REJECT", REASON.AMOUNT_OVERFLOW],
  ["EXPIRED_CONDITION (block) -> REJECT", mockTask({}, { current_block: 19842201 }), "REJECT", REASON.EXPIRED_CONDITION],
  ["EXPIRED_CONDITION (deadline) -> REJECT", mockTask({ deadline_at: "2026-11-15T10:30:00.000Z" }), "REJECT", REASON.EXPIRED_CONDITION],
  ["UNFINALIZED_PROOF -> REJECT", mockTask(), "REJECT", REASON.UNFINALIZED_PROOF],
  ["boundary: balance == minimum -> APPROVE", mockTask({}, { public_balance: "1000" }), "APPROVE", REASON.VALID],
  ["boundary: amount == max_transfer -> APPROVE", mockTask({}, { amount: "1000" }), "APPROVE", REASON.VALID],
  ["boundary: current_block == expiry_block - 1 -> APPROVE", mockTask({}, { current_block: 19842200 }), "APPROVE", REASON.VALID],
  ["malformed: wrong type -> REJECT/INVALID_TASK", mockTask({ type: "something.else" }), "REJECT", REASON.INVALID_TASK],
  ["malformed: missing input field -> REJECT/INVALID_TASK", mockTask({}, { amount: undefined }), "REJECT", REASON.INVALID_TASK],
];
for (const [name, task, wantDecision, wantReason] of decisionCases) {
  check(name, () => {
    const finalized = name.startsWith("UNFINALIZED") ? false : null;
    const r = decide(task, { seenProofs: emptySeen, finalized, nowMs: NOW });
    assert.equal(r.decision, wantDecision);
    assert.equal(r.reason_code, wantReason);
  });
}
// PROOF_REUSED: same proof_tx under a different task_id
check("PROOF_REUSED -> REJECT", () => {
  const seen = new Set([PROOF_TX.toLowerCase()]);
  const r = decide(mockTask({ task_id: "gk_24_9d2" }), { seenProofs: seen, finalized: null, nowMs: NOW });
  assert.equal(r.decision, "REJECT");
  assert.equal(r.reason_code, REASON.PROOF_REUSED);
});
// Replay: same proof_tx under the SAME task_id is not reuse
check("replay (same task_id) is not reuse", () => {
  const seen = new Set(); // server excludes same-task proofs via seenSetFor()
  const r = decide(mockTask(), { seenProofs: seen, finalized: null, nowMs: NOW });
  assert.equal(r.decision, "APPROVE");
});

console.log("\n== 2. decision-vs-circuit agreement ==");
const vkey = loadVkey();
async function circuitAgrees(name, task, finalized = null) {
  const r = decide(task, { seenProofs: emptySeen, finalized, nowMs: NOW });
  // The decision from decide() must prove and verify.
  const input = buildCircuitInput(task, r.decision, "abcd");
  const res = await generateDecisionProof(input);
  assert.equal(res.ok, true, `proof for ${r.decision} failed: ${res.error ?? ""}`);
  // The opposite decision must NOT prove (circuit asserts correctness).
  const opposite = r.decision === "APPROVE" ? "REJECT" : "APPROVE";
  const oppInput = buildCircuitInput(task, opposite, "abcd");
  const oppRes = await generateDecisionProof(oppInput);
  assert.equal(oppRes.ok, false, `opposite decision ${opposite} unexpectedly proved`);
  return r;
}
await checkAsync("circuit agrees: valid APPROVE", async () => {
  await circuitAgrees("valid", mockTask());
});
await checkAsync("circuit agrees: VK_SUBSTITUTION REJECT", async () => {
  await circuitAgrees("vk", mockTask({}, { proof_vk: VK_OTHER }));
});
await checkAsync("circuit agrees: THRESHOLD_MISMATCH REJECT", async () => {
  await circuitAgrees("threshold", mockTask({}, { public_balance: "500" }));
});
await checkAsync("circuit agrees: RECIPIENT_MISMATCH REJECT", async () => {
  await circuitAgrees("recipient", mockTask({}, { recipient: RECIPIENT_OTHER }));
});
await checkAsync("circuit agrees: AMOUNT_OVERFLOW REJECT", async () => {
  await circuitAgrees("amount", mockTask({}, { amount: "1500" }));
});
await checkAsync("circuit agrees: EXPIRED_CONDITION REJECT", async () => {
  await circuitAgrees("expired", mockTask({}, { current_block: 19850000 }));
});
await checkAsync("circuit agrees: boundary amount == max APPROVE", async () => {
  await circuitAgrees("boundary", mockTask({}, { amount: "1000" }));
});

console.log("\n== 3. HTTP server ==");
const server = createServer();
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const port = server.address().port;
const base = `http://127.0.0.1:${port}`;

async function post(pathname, bodyObj, { sign = true, secret = SECRET, rawBody = null } = {}) {
  const raw = rawBody ?? Buffer.from(JSON.stringify(bodyObj));
  const headers = { "content-type": "application/json" };
  if (sign) headers["x-agent-games-signature"] = hmacHex(secret, raw);
  const res = await fetch(`${base}${pathname}`, { method: "POST", headers, body: raw });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* ignore */
  }
  return { status: res.status, json, text, sig: res.headers.get("x-agent-games-signature"), raw: Buffer.from(text) };
}

await checkAsync("GET /health returns ok", async () => {
  const res = await fetch(`${base}/health`);
  assert.equal(res.status, 200);
  const j = await res.json();
  assert.equal(j.ok, true);
  assert.equal(j.protocolVersion, "v1");
  assert.equal(j.prover_available, true);
});
await checkAsync("POST /preflight returns {ok:true, protocolVersion:v1}", async () => {
  const r = await post("/preflight", {});
  assert.equal(r.status, 200);
  assert.deepEqual(r.json, { ok: true, protocolVersion: "v1" });
});
await checkAsync("POST /agent preflight handshake -> {ok:true, protocolVersion:v1}, signed", async () => {
  const r = await post("/agent", { type: "preflight" });
  assert.equal(r.status, 200);
  assert.deepEqual(r.json, { ok: true, protocolVersion: "v1" });
  assert.ok(r.sig, "missing response signature");
  assert.equal(hmacHex(SECRET, r.raw), r.sig);
});
await checkAsync("POST /agent empty object -> preflight answer", async () => {
  const r = await post("/agent", {});
  assert.equal(r.status, 200);
  assert.deepEqual(r.json, { ok: true, protocolVersion: "v1" });
});
await checkAsync("POST /agent wrong-type payload -> preflight answer, not a decision", async () => {
  const r = await post("/agent", mockTask({ type: "something.else" }));
  assert.equal(r.status, 200);
  assert.deepEqual(r.json, { ok: true, protocolVersion: "v1" });
});
await checkAsync("POST /agent empty body -> preflight answer", async () => {
  const r = await post("/agent", null, { rawBody: Buffer.alloc(0) });
  assert.equal(r.status, 200);
  assert.deepEqual(r.json, { ok: true, protocolVersion: "v1" });
});
let agentTimingMs = 0;
await checkAsync("POST /agent valid task -> APPROVE, signed response", async () => {
  const t0 = Date.now();
  const r = await post("/agent", mockTask());
  agentTimingMs = Date.now() - t0;
  assert.equal(r.status, 200);
  assert.equal(r.json.decision, "APPROVE");
  assert.equal(r.json.reason_code, REASON.VALID);
  assert.equal(typeof r.json.proof_tx, "string");
  // Response must carry a valid HMAC over the raw body.
  assert.ok(r.sig, "missing response signature");
  assert.equal(hmacHex(SECRET, r.raw), r.sig);
  assert.ok(agentTimingMs < 60000, `too slow: ${agentTimingMs}ms`);
});
await checkAsync("POST /agent tampered body -> 401", async () => {
  const task = mockTask();
  const raw = Buffer.from(JSON.stringify(task));
  const sig = hmacHex(SECRET, raw);
  const tampered = Buffer.from(JSON.stringify(mockTask({}, { amount: "999" })));
  const res = await fetch(`${base}/agent`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": sig },
    body: tampered,
  });
  assert.equal(res.status, 401);
});
await checkAsync("POST /agent wrong secret -> 401", async () => {
  const r = await post("/agent", mockTask(), { secret: "wrong-secret" });
  assert.equal(r.status, 401);
});
await checkAsync("POST /agent missing signature -> 401", async () => {
  const r = await post("/agent", mockTask(), { sign: false });
  assert.equal(r.status, 401);
});
await checkAsync("POST /agent trap -> REJECT/VK_SUBSTITUTION", async () => {
  const r = await post("/agent", mockTask({ task_id: "gk_24_9d3" }, { proof_vk: VK_OTHER }));
  assert.equal(r.status, 200);
  assert.equal(r.json.decision, "REJECT");
  assert.equal(r.json.reason_code, REASON.VK_SUBSTITUTION);
});
await checkAsync("POST /agent same proof_tx, new task -> PROOF_REUSED", async () => {
  // The first /agent test already answered PROOF_TX under gk_24_9d1.
  const r = await post("/agent", mockTask({ task_id: "gk_24_9d9" }));
  assert.equal(r.status, 200);
  assert.equal(r.json.decision, "REJECT");
  assert.equal(r.json.reason_code, REASON.PROOF_REUSED);
});
await checkAsync("POST /agent replay same task_id -> APPROVE again (not reuse)", async () => {
  const r = await post("/agent", mockTask());
  assert.equal(r.status, 200);
  assert.equal(r.json.decision, "APPROVE");
  assert.equal(r.json.reason_code, REASON.VALID);
});

server.close();

console.log(`\n========================================`);
console.log(`passed: ${passed}  failed: ${failed}`);
if (agentTimingMs) console.log(`valid-task /agent round trip: ${agentTimingMs}ms (limit 60000ms)`);
if (failed > 0) {
  console.log(`failures: ${failures.join("; ")}`);
  process.exit(1);
}
console.log("ALL TESTS PASS");
process.exit(0);
