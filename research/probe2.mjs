// Round 2: extended candidate list for the 2 missing input values.
import fs from "node:fs";
import { WitnessCalculatorBuilder } from "circom_runtime";
function fnvHash(str) {
  const uint64_max = BigInt(2) ** BigInt(64);
  let hash = BigInt("0xCBF29CE484222325");
  for (let i = 0; i < str.length; i++) {
    hash ^= BigInt(str[i].charCodeAt(0));
    hash *= BigInt(0x100000001B3);
    hash %= uint64_max;
  }
  let shash = hash.toString(16);
  return "0".repeat(16 - shash.length) + shash;
}
const CANDIDATES = [
  "block", "current", "proof", "condition", "expected", "actual", "match",
  "matches", "ok", "pass", "passed", "check", "checks", "flag", "flags",
  "validProof", "proofOk", "vkOk", "vkMatch", "vkMatches", "vk_match",
  "balanceOk", "amountOk", "recipientOk", "expiryOk", "notExpired",
  "isExpired", "expired", "reused", "isReused", "proofReused", "seen",
  "seenBefore", "duplicate", "reasonNum", "code", "trapId", "trapCodeNum",
  "round", "roundId", "round_id", "agent", "agentId", "owner", "min", "max",
  "limit", "transfer", "payment", "value", "total", "available", "required",
  "hash", "digest", "commitmentHash", "nullifierHash", "publicInput",
  "publicInputHash", "inputsHash", "decisionHash", "saltHash", "taskSalt",
  "random", "randomness", "seed", "proofId", "ref", "reference", "index",
  "idx", "seq", "sequence", "number", "count", "day", "date", "time",
  "deadline", "createdAt", "updatedAt", "status", "state", "result",
  "verdict", "allow", "allowed", "deny", "denied", "reject", "rejected",
  "gate", "gatekeeper", "proofGatekeeper", "event", "eventId", "competition",
  "season", "publicSignals", "pubInputs", "pub_signals", "public_inputs",
  "registeredVK", "proofVK", "VK", "vkRegistered", "registered",
  "proofTxHash", "tx", "sig", "signature", "signer", "from", "to",
  "amountWei", "balanceWei", "minimumWei", "thresholdMet", "threshold_ok",
  "aboveMinimum", "meetsMinimum", "sufficient", "enough",
  "recipientMatches", "recipient_match", "amountWithinCap", "withinCap",
  "notReused", "fresh", "isFresh", "unique", "isUnique",
  "blockOk", "block_ok", "inWindow", "withinWindow", "active", "isActive",
  "decisionValid", "decision_ok", "decisionIsValid",
  "expectedRecipientHash", "recipientHash", "amountHash", "taskHashNum",
  "inputHash", "inputs_hash", "proofHashNum", "vkHashNum",
  "registeredVkHash", "proofVkHash", "vkHash1", "vkHash2",
  "a1", "b1", "c1", "x1", "y1", "in0", "in1", "input0", "input1",
  "s0", "s1", "v0", "v1", "p0", "p1",
];
const wasm = fs.readFileSync("circuits/gatekeeper.wasm");
const wc = await WitnessCalculatorBuilder(wasm);
console.log("total input values:", wc.instance.exports.getInputSize());
for (const name of CANDIDATES) {
  const h = fnvHash(name);
  const size = wc.instance.exports.getInputSignalSize(parseInt(h.slice(0,8),16), parseInt(h.slice(8,16),16));
  if (size >= 1) console.log(`FOUND: ${name} (size ${size})`);
}
console.log("done");
