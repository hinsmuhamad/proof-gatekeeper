// Probe script: discover the gatekeeper circuit's input signal names by
// testing candidate names against the wasm's FNV-hashed signal map.
// Read-only: never submits anything, never touches secrets.
import fs from "node:fs";
import { WitnessCalculatorBuilder } from "circom_runtime";

// FNV-1a 64-bit, copied from circom_runtime/js/utils.js (same function the
// witness calculator uses to map a signal name to its hash).
function fnvHash(str) {
  const uint64_max = BigInt(2) ** BigInt(64);
  let hash = BigInt("0xCBF29CE484222325");
  for (let i = 0; i < str.length; i++) {
    hash ^= BigInt(str[i].charCodeAt(0));
    hash *= BigInt(0x100000001B3);
    hash %= uint64_max;
  }
  let shash = hash.toString(16);
  shash = "0".repeat(16 - shash.length) + shash;
  return shash;
}

const WASM = "circuits/gatekeeper.wasm";

const CANDIDATES = [
  // decision / outcome
  "decision", "decisionCode", "isApproved", "approved", "approve", "outcome",
  "valid", "isValid", "is_valid", "checksPassed", "checks_passed",
  // reason / trap
  "reason_code", "reasonCode", "reason", "trap", "trapType", "trap_code",
  "trapCode", "rejection_reason", "rejectionReason",
  // amounts / thresholds
  "amount", "transfer_amount", "transferAmount", "payment_amount",
  "minimum", "min_balance", "minBalance", "threshold", "required_minimum",
  "requiredMinimum", "public_balance", "balance", "publicBalance",
  "max_transfer", "maxTransfer", "cap", "max_amount", "maxAmount",
  // addresses
  "recipient", "condition_recipient", "conditionRecipient",
  "expected_recipient", "expectedRecipient", "payer", "sender",
  // blocks / time
  "expiry_block", "expiryBlock", "expiry", "expiration_block", "expirationBlock",
  "current_block", "currentBlock", "block_number", "blockNumber", "blockHeight",
  "timestamp", "issued_at", "issuedAt", "deadline_at", "deadlineAt",
  // verification key / proof identity
  "registered_vk", "registeredVk", "expected_vk", "expectedVk", "condition_vk",
  "conditionVk", "proof_vk", "proofVk", "actual_vk", "actualVk", "vk",
  "vk_hash", "vkHash", "registered_vk_hash", "proof_vk_hash",
  "proof_tx", "proofTx", "proof_ref", "proofRef", "proofHash", "proof_hash",
  "tx_hash", "txHash", "aggregation_id", "aggregationId",
  // task identity
  "task_id", "taskId", "task_hash", "taskHash", "id",
  // finalization
  "finalized", "is_finalized", "isFinalized", "proof_finalized", "is_onchain",
  "onchain", "verified", "proof_verified", "proofVerified",
  // misc
  "nonce", "salt", "nullifier", "mode", "version", "domain", "chain_id",
  "chainId", "circuit_version", "circuitVersion", "protocol_version",
  "public_inputs_hash", "publicInputsHash", "commitment", "root",
  // dotted variants (sub-component paths, just in case)
  "main.decision", "main.amount", "main.recipient",
  // single letters sometimes used in toy circuits
  "a", "b", "c", "x", "y", "in", "out",
];

const wasm = fs.readFileSync(WASM);
const wc = await WitnessCalculatorBuilder(wasm);
console.log("circom version:", wc.circom_version());
console.log("witness size:", wc.witnessSize);
console.log("total input values (getInputSize):", wc.instance.exports.getInputSize());

const found = [];
for (const name of CANDIDATES) {
  const h = fnvHash(name);
  const hMSB = parseInt(h.slice(0, 8), 16);
  const hLSB = parseInt(h.slice(8, 16), 16);
  let size = -1;
  try {
    size = wc.instance.exports.getInputSignalSize(hMSB, hLSB);
  } catch {
    size = -1;
  }
  if (size >= 0) {
    found.push({ name, size });
    console.log(`FOUND: ${name} (size ${size})`);
  }
}
console.log(`\n${found.length} input signals found, total size ${found.reduce((s, f) => s + f.size, 0)}`);
fs.writeFileSync("circuits/probe-result.json", JSON.stringify(found, null, 2));
