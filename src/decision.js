// Decision logic for the Proof Gatekeeper agent.
// Pure functions: no I/O, no network. Fully unit-testable.
//
// Canonical reason codes come from the event page trap encyclopedia
// (https://agentgames.zkverify.io/events/proof-gatekeeper). The earlier
// briefing used different names for some traps; those are kept here as
// aliases so nothing is silently dropped:
//   AMOUNT_MISMATCH   -> AMOUNT_OVERFLOW
//   EXPIRED_TASK      -> EXPIRED_CONDITION
//   PROOF_REUSE       -> PROOF_REUSED
//   CIRCUIT_MISMATCH  -> VK_SUBSTITUTION (a proof's circuit is identified
//                          by its verification key, so a circuit mismatch
//                          IS a VK mismatch in the payload we receive)
// UNFINALIZED_PROOF is NOT one of the six scored trap types on the event
// page (the six traps sum to 100% of tasks). It is a check from the build
// guide ("the verification reached a finalized state before approval").
// It is applied only when finalization status is actually known
// (ctx.finalized === false); when unknown we log and continue, because
// failing closed on unknown finalization would reject every valid task
// whenever the Kurier check is unavailable.

export const REASON = Object.freeze({
  VALID: "VALID_CONDITION",
  VK_SUBSTITUTION: "VK_SUBSTITUTION",
  THRESHOLD_MISMATCH: "THRESHOLD_MISMATCH",
  PROOF_REUSED: "PROOF_REUSED",
  EXPIRED_CONDITION: "EXPIRED_CONDITION",
  RECIPIENT_MISMATCH: "RECIPIENT_MISMATCH",
  AMOUNT_OVERFLOW: "AMOUNT_OVERFLOW",
  UNFINALIZED_PROOF: "UNFINALIZED_PROOF",
  // Defensive only: used when the task payload itself is unparseable.
  // Not part of the platform's trap encyclopedia; should never occur
  // in competition because the platform sends well-formed tasks.
  INVALID_TASK: "INVALID_TASK",
});

export const ALIASES = Object.freeze({
  AMOUNT_MISMATCH: REASON.AMOUNT_OVERFLOW,
  EXPIRED_TASK: REASON.EXPIRED_CONDITION,
  PROOF_REUSE: REASON.PROOF_REUSED,
  CIRCUIT_MISMATCH: REASON.VK_SUBSTITUTION,
});

export const EXPECTED_TYPE = "agent-games.proof-gatekeeper.v1";

// Field element modulus of BN128 (the circuit curve). Used to map 256-bit
// hashes (vk hashes) and addresses into field elements.
export const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function toBigInt(value) {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return BigInt(Math.trunc(value));
  if (typeof value === "string") {
    const s = value.trim();
    if (s === "") throw new Error("empty numeric field");
    return BigInt(s); // handles "123" and "0x..." hex
  }
  throw new Error(`cannot convert ${typeof value} to bigint`);
}

function sameAddress(a, b) {
  return String(a).trim().toLowerCase() === String(b).trim().toLowerCase();
}

function sameHex(a, b) {
  return String(a).trim().toLowerCase() === String(b).trim().toLowerCase();
}

/**
 * Decide a Proof Gatekeeper task.
 *
 * @param {object} task - parsed task envelope. Expected shape:
 *   { type, task_id, mode, issued_at, deadline_at,
 *     input: { registered_vk, proof_vk, minimum, public_balance,
 *              expiry_block, current_block, recipient, condition_recipient,
 *              amount, max_transfer, proof_tx } }
 * @param {object} ctx
 * @param {Set<string>} ctx.seenProofs - proof_tx values already answered
 *   (lowercased). Used for PROOF_REUSED detection.
 * @param {boolean|null} ctx.finalized - finalization status of the incoming
 *   proof on-chain, if known. null = unknown (check unavailable).
 * @param {number} [ctx.nowMs=Date.now()] - clock used for deadline checks.
 * @returns {{ decision: "APPROVE"|"REJECT", reason_code: string,
 *             checks: Array<{name: string, passed: boolean, detail: string}> }}
 */
export function decide(task, ctx) {
  const checks = [];
  const fail = (name, reason, detail) => {
    checks.push({ name, passed: false, detail });
    return { decision: "REJECT", reason_code: reason, checks };
  };
  const pass = (name, detail) => checks.push({ name, passed: true, detail });

  // ---- 0. Envelope sanity (fail closed on unparseable tasks) ----
  if (!task || typeof task !== "object") {
    return fail("envelope", REASON.INVALID_TASK, "task is not an object");
  }
  if (task.type !== EXPECTED_TYPE) {
    return fail(
      "envelope",
      REASON.INVALID_TASK,
      `unexpected type ${JSON.stringify(task.type)}`
    );
  }
  const input = task.input;
  if (!input || typeof input !== "object") {
    return fail("envelope", REASON.INVALID_TASK, "missing input object");
  }
  const required = [
    "registered_vk",
    "proof_vk",
    "minimum",
    "public_balance",
    "expiry_block",
    "current_block",
    "recipient",
    "condition_recipient",
    "amount",
    "max_transfer",
    "proof_tx",
  ];
  for (const f of required) {
    if (input[f] === undefined || input[f] === null || input[f] === "") {
      return fail("envelope", REASON.INVALID_TASK, `missing input.${f}`);
    }
  }

  let numbers;
  try {
    numbers = {
      minimum: toBigInt(input.minimum),
      publicBalance: toBigInt(input.public_balance),
      amount: toBigInt(input.amount),
      maxTransfer: toBigInt(input.max_transfer),
      expiryBlock: toBigInt(input.expiry_block),
      currentBlock: toBigInt(input.current_block),
    };
  } catch (e) {
    return fail("envelope", REASON.INVALID_TASK, `bad numeric field: ${e.message}`);
  }

  const nowMs = ctx.nowMs ?? Date.now();

  // ---- 1. Expiry: task deadline, then condition block-height expiry ----
  if (task.deadline_at) {
    const deadlineMs = Date.parse(task.deadline_at);
    if (!Number.isNaN(deadlineMs) && nowMs > deadlineMs) {
      return fail(
        "expiry",
        REASON.EXPIRED_CONDITION,
        `deadline_at ${task.deadline_at} already passed`
      );
    }
  }
  // NOTE: the circuit treats currentBlock == expiryBlock as expired
  // (verified empirically: an APPROVE proof with equal blocks fails the
  // circuit assert at GatekeeperEvaluation line 102). The expiry rule is
  // therefore currentBlock >= expiryBlock, not strictly greater.
  if (numbers.currentBlock >= numbers.expiryBlock) {
    return fail(
      "expiry",
      REASON.EXPIRED_CONDITION,
      `current_block ${numbers.currentBlock} >= expiry_block ${numbers.expiryBlock}`
    );
  }
  pass("expiry", `current_block ${numbers.currentBlock} < expiry_block ${numbers.expiryBlock}`);

  // ---- 2. VK substitution: proof VK must equal the registered condition VK ----
  if (!sameHex(input.proof_vk, input.registered_vk)) {
    return fail(
      "vk",
      REASON.VK_SUBSTITUTION,
      `proof_vk ${input.proof_vk} != registered_vk ${input.registered_vk}`
    );
  }
  pass("vk", "proof_vk matches registered_vk");

  // ---- 3. Proof reuse: proof_tx must not have been answered before ----
  const proofRef = String(input.proof_tx).trim().toLowerCase();
  if (ctx.seenProofs && ctx.seenProofs.has(proofRef)) {
    return fail("reuse", REASON.PROOF_REUSED, `proof_tx ${input.proof_tx} already seen`);
  }
  pass("reuse", "proof_tx not previously seen");

  // ---- 4. Recipient: proof recipient must match the condition recipient ----
  if (!sameAddress(input.recipient, input.condition_recipient)) {
    return fail(
      "recipient",
      REASON.RECIPIENT_MISMATCH,
      `recipient ${input.recipient} != condition_recipient ${input.condition_recipient}`
    );
  }
  pass("recipient", "recipient matches condition_recipient");

  // ---- 5. Amount cap: requested amount must not exceed max_transfer ----
  if (numbers.amount > numbers.maxTransfer) {
    return fail(
      "amount",
      REASON.AMOUNT_OVERFLOW,
      `amount ${numbers.amount} > max_transfer ${numbers.maxTransfer}`
    );
  }
  pass("amount", `amount ${numbers.amount} <= max_transfer ${numbers.maxTransfer}`);

  // ---- 6. Threshold: public balance in the proof must meet the minimum ----
  if (numbers.publicBalance < numbers.minimum) {
    return fail(
      "threshold",
      REASON.THRESHOLD_MISMATCH,
      `public_balance ${numbers.publicBalance} < minimum ${numbers.minimum}`
    );
  }
  pass(
    "threshold",
    `public_balance ${numbers.publicBalance} >= minimum ${numbers.minimum}`
  );

  // ---- 7. Finalization: only enforced when the status is actually known ----
  if (ctx.finalized === false) {
    return fail(
      "finalization",
      REASON.UNFINALIZED_PROOF,
      `proof_tx ${input.proof_tx} is not finalized on-chain`
    );
  }
  if (ctx.finalized === true) {
    pass("finalization", "incoming proof is finalized on-chain");
  } else {
    pass("finalization", "finalization unknown (check unavailable); continuing");
  }

  return { decision: "APPROVE", reason_code: REASON.VALID, checks };
}

/** Map any alias reason code to its canonical code. */
export function canonicalReason(code) {
  return ALIASES[code] ?? code;
}
