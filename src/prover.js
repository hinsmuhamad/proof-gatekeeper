// Groth16 decision-proof generation with snarkjs + the official
// gatekeeper circuit artifacts (downloaded from
// https://agentgames.zkverify.io/api/circuit-info):
//   circuits/gatekeeper.wasm (1.76 MB) and circuits/gatekeeper_final.zkey
//   vk_hash 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0
//
// The circuit's 13 input signals were discovered by probing the wasm's
// FNV-hashed signal map (see probe.mjs / probe2.mjs):
//   decision, amount, minimum, publicBalance, maxTransfer, recipient,
//   conditionRecipient, expiryBlock, currentBlock, taskId, salt,
//   registeredVkHash, proofVkHash
// The verification key has 13 public signals (IC length 14), matching the
// 13 inputs, so every input is a public signal: the proof is fully
// transparent, it re-proves the decision logic on public data for
// on-chain verifiability, not privacy.
//
// Encodings (best effort, documented; confirm in Practice mode):
//   decision          1 = APPROVE, 0 = REJECT
//   amount/minimum/publicBalance/maxTransfer  decimal integers
//   recipient/conditionRecipient  Ethereum address as a field element
//   expiryBlock/currentBlock      block numbers
//   taskId            numeric task ids are used directly; otherwise
//                     SHA-256(task_id string) mod FIELD_PRIME
//                     (the payload task_id is a string like "gk_24_9d1";
//                     the platform's own encoding is not published)
//   salt              fresh random field element per proof
//   registeredVkHash/proofVkHash  the 0x vk hash taken mod FIELD_PRIME
//                     (a 256-bit hash does not fit the ~254-bit BN128
//                     field, so it is reduced mod p)
// If the experiment (experiment.mjs) shows a different encoding verifies,
// update buildCircuitInput() accordingly.

import crypto from "node:crypto";
import fs from "node:fs";
import { config, log } from "./config.js";
import { FIELD_PRIME } from "./decision.js";

export const INPUT_SIGNALS = Object.freeze([
  "decision",
  "amount",
  "minimum",
  "publicBalance",
  "maxTransfer",
  "recipient",
  "conditionRecipient",
  "expiryBlock",
  "currentBlock",
  "taskId",
  "salt",
  "registeredVkHash",
  "proofVkHash",
]);

function toFieldBigInt(value) {
  const n = BigInt(value);
  return ((n % FIELD_PRIME) + FIELD_PRIME) % FIELD_PRIME;
}

function hashToField(text) {
  const digest = crypto.createHash("sha256").update(String(text), "utf8").digest();
  return (BigInt(`0x${digest.toString("hex")}`) % FIELD_PRIME).toString();
}

/**
 * Encode the payload task_id (a string like "gk_24_9d1") as a field
 * element. If it parses as a plain integer it is used directly; otherwise
 * SHA-256(task_id) mod FIELD_PRIME. The platform has not published its
 * own task_id encoding; if Practice mode shows the proof being rejected
 * for a public-signal mismatch, this is the first thing to adjust
 * (alternatives: Poseidon of the char codes, or the numeric suffix).
 */
export function encodeTaskId(taskId) {
  const s = String(taskId ?? "").trim();
  if (/^[0-9]+$/.test(s)) return toFieldBigInt(s).toString();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return toFieldBigInt(s).toString();
  return hashToField(s);
}

/**
 * Build the circuit input object from a task + decision.
 * @param {object} task - parsed task envelope
 * @param {"APPROVE"|"REJECT"} decision
 * @param {string} [saltHex] - optional fixed salt (tests); otherwise random
 */
export function buildCircuitInput(task, decision, saltHex) {
  // Defensive: the proof step must never crash with a raw TypeError on a
  // malformed task (seen live 2026-11-15: "Cannot read properties of
  // undefined (reading 'amount')" when the platform's preflight handshake
  // reached the proof step). Fail with a clear message instead; the
  // caller logs it and still returns the decision.
  const input = task?.input;
  if (!input || typeof input !== "object") {
    throw new Error("buildCircuitInput: task.input is missing");
  }
  for (const f of [
    "amount",
    "minimum",
    "public_balance",
    "max_transfer",
    "recipient",
    "condition_recipient",
    "expiry_block",
    "current_block",
    "registered_vk",
    "proof_vk",
  ]) {
    if (input[f] === undefined || input[f] === null || input[f] === "") {
      throw new Error(`buildCircuitInput: missing input.${f}`);
    }
  }
  const salt = saltHex
    ? toFieldBigInt(`0x${saltHex}`).toString()
    : toFieldBigInt(`0x${crypto.randomBytes(31).toString("hex")}`).toString();
  return {
    decision: decision === "APPROVE" ? 1 : 0,
    amount: BigInt(input.amount).toString(),
    minimum: BigInt(input.minimum).toString(),
    publicBalance: BigInt(input.public_balance).toString(),
    maxTransfer: BigInt(input.max_transfer).toString(),
    recipient: BigInt(input.recipient).toString(),
    conditionRecipient: BigInt(input.condition_recipient).toString(),
    expiryBlock: BigInt(input.expiry_block).toString(),
    currentBlock: BigInt(input.current_block).toString(),
    taskId: encodeTaskId(task.task_id ?? ""),
    salt,
    registeredVkHash: toFieldBigInt(input.registered_vk).toString(),
    proofVkHash: toFieldBigInt(input.proof_vk).toString(),
  };
}

let snarkjsPromise = null;
function loadSnarkjs() {
  if (!snarkjsPromise) {
    snarkjsPromise = import("snarkjs").then((m) => m.groth16);
  }
  return snarkjsPromise;
}

let vkeyCache = null;
export function loadVkey() {
  if (!vkeyCache) {
    vkeyCache = JSON.parse(fs.readFileSync(config.vkeyPath, "utf8"));
  }
  return vkeyCache;
}

export function artifactsPresent() {
  return fs.existsSync(config.wasmPath) && fs.existsSync(config.zkeyPath);
}

/**
 * Generate a Groth16 proof for a decision and verify it locally against
 * the verification key. Returns { ok, proof, publicSignals, ms } or
 * { ok: false, error, ms }. Never throws for a bad witness: a proof that
 * fails local verification is reported, not returned as valid.
 */
export async function generateDecisionProof(circuitInput, { verifyLocally = true } = {}) {
  const t0 = Date.now();
  if (!artifactsPresent()) {
    return { ok: false, error: "circuit artifacts missing", ms: Date.now() - t0 };
  }
  try {
    const groth16 = await loadSnarkjs();
    const { proof, publicSignals } = await groth16.fullProve(
      circuitInput,
      config.wasmPath,
      config.zkeyPath
    );
    if (verifyLocally) {
      const valid = await groth16.verify(loadVkey(), publicSignals, proof);
      if (!valid) {
        return {
          ok: false,
          error: "locally generated proof FAILED groth16.verify (circuit constraints not satisfied)",
          ms: Date.now() - t0,
          publicSignals,
        };
      }
    }
    return { ok: true, proof, publicSignals, ms: Date.now() - t0 };
  } catch (e) {
    log("debug", "proof generation failed", { error: String(e) });
    return { ok: false, error: String(e).split("\n")[0], ms: Date.now() - t0 };
  }
}
