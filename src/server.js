// HTTP server for the Proof Gatekeeper agent.
// Pure Node.js http, no framework. Routes:
//   GET  /          - human-readable status
//   GET  /health    - JSON health (no auth needed; used by the platform's
//                      health check before registration)
//   POST /preflight - returns { ok: true, protocolVersion: "v1" }
//   POST /agent     - the competition endpoint: HMAC-verified task in,
//                     signed { decision, reason_code, proof_tx } out,
//                     inside the 60s platform deadline.
//
// Flow per task (fail closed, decision first, proof second):
//   1. Verify x-agent-games-signature over the RAW body (before parsing).
//   2. Parse + decide with decision.js (pure field checks, ~instant).
//   3. Record proof_tx in the seen store (only once the response is
//      about to be sent, so a crash does not poison the reuse set).
//   4. If time remains in the proof budget: generate the Groth16 decision
//      proof locally and submit it to Kurier; proof_tx in the response is
//      the Kurier job reference. If anything in step 4 fails or the
//      budget runs out, the decision is still returned with the incoming
//      proof_tx echoed (the shape the event page's sample response shows)
//      and the failure is logged. A correct decision is worth +12; a
//      missing proof costs at most -2 and the reliability bonus, so the
//      decision is never sacrificed for the proof.

import http from "node:http";
import path from "node:path";
import { config, log } from "./config.js";
import { verifyHmac, signBody } from "./hmac.js";
import { decide, EXPECTED_TYPE } from "./decision.js";
import { SeenStore } from "./seenStore.js";
import { KurierClient } from "./kurier.js";
import { buildCircuitInput, generateDecisionProof, artifactsPresent } from "./prover.js";

const seenStore = new SeenStore(path.join(config.stateDir, "seen-proofs.json"));
const kurier = new KurierClient();

function jsonResponse(res, status, obj, { sign = true } = {}) {
  const body = Buffer.from(JSON.stringify(obj));
  const headers = { "content-type": "application/json" };
  if (sign && config.hmacSecret) {
    headers["x-agent-games-signature"] = signBody(config.hmacSecret, body);
  }
  res.writeHead(status, headers);
  res.end(body);
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > 5 * 1024 * 1024) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function checkAuth(req, rawBody) {
  if (!config.hmacSecret) {
    if (config.allowUnsigned) {
      log("debug", "no HMAC secret configured; accepting unsigned request (ALLOW_UNSIGNED=true)");
      return { ok: true, mode: "unsigned-dev" };
    }
    return { ok: false, error: "server has no AGENT_GAMES_HMAC_SECRET configured" };
  }
  const sig = req.headers["x-agent-games-signature"];
  if (!sig) return { ok: false, error: "missing x-agent-games-signature header" };
  if (!verifyHmac(config.hmacSecret, rawBody, sig)) {
    return { ok: false, error: "HMAC signature mismatch" };
  }
  return { ok: true, mode: "hmac" };
}

async function handleAgent(req, res) {
  const started = Date.now();
  const deadlineMs = started + config.responseDeadlineMs;
  let responded = false;
  const failClosed = (decision, reason_code, proof_tx) => {
    if (responded) return;
    responded = true;
    jsonResponse(res, 200, { decision, reason_code, proof_tx });
  };
  // Hard deadline guard: never let the platform see a timeout if we can
  // still answer with the decision we already computed.
  const guard = setTimeout(() => {
    if (!responded) {
      log("info", "internal deadline hit; returning fail-closed REJECT");
      failClosed("REJECT", "INVALID_TASK", "0x0000000000000000000000000000000000000000");
    }
  }, config.responseDeadlineMs);
  guard.unref?.();

  try {
    const rawBody = await readRawBody(req);
    const auth = checkAuth(req, rawBody);
    if (!auth.ok) {
      clearTimeout(guard);
      if (!responded) {
        responded = true;
        jsonResponse(res, 401, { error: auth.error }, { sign: false });
      }
      return;
    }

    let task;
    try {
      task = JSON.parse(rawBody.toString("utf8"));
    } catch {
      clearTimeout(guard);
      failClosed("REJECT", "INVALID_TASK", "0x0000000000000000000000000000000000000000");
      return;
    }

    const input = task?.input ?? {};
    const proofTx = typeof input.proof_tx === "string" ? input.proof_tx : "";
    const taskId = typeof task?.task_id === "string" ? task.task_id : "";

    // Best-effort incoming-proof finalization check (Kurier), short budget.
    // Runs before deciding; unknown status is treated as "unknown", not as
    // a failure (see decision.js for the reasoning).
    let finalized = null;
    if (kurier.configured && proofTx) {
      try {
        finalized = await Promise.race([
          kurier.incomingProofFinalized(proofTx),
          new Promise((r) => setTimeout(() => r(null), 5000)),
        ]);
      } catch {
        finalized = null;
      }
    }

    const result = decide(task, {
      seenProofs: seenStore.seenSetFor(taskId),
      finalized,
      nowMs: Date.now(),
    });
    const elapsedMs = Date.now() - started;
    log("info", "task decided", {
      task_id: taskId,
      decision: result.decision,
      reason_code: result.reason_code,
      finalized,
      elapsedMs,
    });

    // Proof generation + Kurier submission, bounded by the remaining budget.
    let proofTxOut = proofTx; // default: echo the incoming reference (sample shape)
    let proofStatus = "skipped";
    const proofBudgetLeft = Math.min(
      config.proofBudgetMs,
      deadlineMs - Date.now() - 2000
    );
    const isProvable = result.reason_code !== "PROOF_REUSED";
    if (isProvable && artifactsPresent() && proofBudgetLeft > 3000) {
      try {
        const circuitInput = buildCircuitInput(task, result.decision);
        const proofRes = await Promise.race([
          generateDecisionProof(circuitInput),
          new Promise((r) =>
            setTimeout(() => r({ ok: false, error: "proof budget exhausted" }), proofBudgetLeft)
          ),
        ]);
        if (proofRes.ok) {
          proofStatus = "generated-locally";
          if (kurier.configured) {
            const submit = await Promise.race([
              kurier.submitProof({
                proof: proofRes.proof,
                publicSignals: proofRes.publicSignals,
                vkHash: config.gatekeeperVkHash,
              }),
              new Promise((r) =>
                setTimeout(() => r({ ok: false, error: "submit budget exhausted" }), 10000)
              ),
            ]);
            if (submit.ok) {
              proofTxOut = submit.jobId;
              proofStatus = "submitted-kurier";
              log("info", "decision proof submitted to Kurier", {
                task_id: taskId,
                jobId: submit.jobId,
                proveMs: proofRes.ms,
              });
              // Fire-and-forget finalization poll in the background: the
              // response must not wait for on-chain finality.
              kurier
                .pollJob(submit.jobId, { budgetMs: 60000 })
                .then((p) =>
                  log("info", "kurier job poll finished", { task_id: taskId, ...p })
                )
                .catch(() => {});
            } else {
              proofStatus = `submit-failed:${submit.error}`;
              log("info", "kurier submit failed; returning decision with echoed proof_tx", {
                task_id: taskId,
                error: submit.error,
              });
            }
          } else {
            log("info", "proof generated locally but KURIER_API_KEY is not set; not submitted", {
              task_id: taskId,
              proveMs: proofRes.ms,
            });
          }
        } else {
          proofStatus = `prove-failed:${proofRes.error}`;
          log("info", "proof generation failed; returning decision only", {
            task_id: taskId,
            error: proofRes.error,
          });
        }
      } catch (e) {
        proofStatus = `prove-error:${String(e).split("\n")[0]}`;
        log("info", "proof step errored; returning decision only", {
          task_id: taskId,
          error: String(e),
        });
      }
    } else if (!isProvable) {
      proofStatus = "not-provable:PROOF_REUSED has no proof to submit";
    }

    // Record the proof reference now that the response is about to go out.
    if (proofTx) seenStore.add(proofTx, taskId);

    log("info", "responding", {
      task_id: taskId,
      decision: result.decision,
      reason_code: result.reason_code,
      proof_status: proofStatus,
      totalMs: Date.now() - started,
    });
    clearTimeout(guard);
    failClosed(result.decision, result.reason_code, proofTxOut);
  } catch (e) {
    clearTimeout(guard);
    log("info", "handler error", { error: String(e) });
    if (!responded) {
      responded = true;
      jsonResponse(res, 500, { error: "internal error" }, { sign: false });
    }
  }
}

async function handlePreflight(req, res) {
  let rawBody = Buffer.alloc(0);
  try {
    rawBody = await readRawBody(req);
  } catch {
    /* preflight may have no body; ignore */
  }
  // If a signature is present, verify it; if absent, still answer (the
  // platform's preflight is a liveness check, not a task).
  if (rawBody.length > 0 && req.headers["x-agent-games-signature"] && config.hmacSecret) {
    if (!verifyHmac(config.hmacSecret, rawBody, req.headers["x-agent-games-signature"])) {
      jsonResponse(res, 401, { error: "HMAC signature mismatch" }, { sign: false });
      return;
    }
  }
  jsonResponse(res, 200, { ok: true, protocolVersion: "v1" });
}

function handleHealth(_req, res) {
  jsonResponse(
    res,
    200,
    {
      ok: true,
      protocolVersion: "v1",
      uptime_s: Math.floor(process.uptime()),
      seen_proofs: seenStore.size,
      prover_available: artifactsPresent(),
      kurier_configured: kurier.configured,
      hmac_configured: Boolean(config.hmacSecret),
    },
    { sign: false }
  );
}

function handleRoot(_req, res) {
  res.writeHead(200, { "content-type": "text/plain" });
  res.end(
    "Proof Gatekeeper agent (zkVerify Agent Games)\n" +
      `type: ${EXPECTED_TYPE}\n` +
      "endpoints: POST /agent, POST /preflight, GET /health\n"
  );
}

export function createServer() {
  return http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    if (req.method === "GET" && url.pathname === "/") return handleRoot(req, res);
    if (req.method === "GET" && url.pathname === "/health") return handleHealth(req, res);
    if (req.method === "POST" && url.pathname === "/preflight") return handlePreflight(req, res);
    if (req.method === "POST" && url.pathname === "/agent") return handleAgent(req, res);
    jsonResponse(res, 404, { error: "not found" }, { sign: false });
  });
}
