// Confirm the fixed boundary: equal blocks + REJECT must verify, and
// currentBlock one below expiry + APPROVE must verify.
import fs from "node:fs";
import { groth16 } from "snarkjs";
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const VK = (BigInt("0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0") % P).toString();
const RECIP = BigInt("0xDe42000000000000000000000000000000009f01").toString();
const vkey = JSON.parse(fs.readFileSync("circuits/gatekeeper_vkey.json", "utf8"));
const base = {
  decision: 1, amount: 500, minimum: 1000, publicBalance: 1460, maxTransfer: 1000,
  recipient: RECIP, conditionRecipient: RECIP,
  expiryBlock: 19842201, currentBlock: 19832000, taskId: 12345, salt: 999,
  registeredVkHash: VK, proofVkHash: VK,
};
async function run(name, input, expectVerify) {
  try {
    const { proof, publicSignals } = await groth16.fullProve(input, "circuits/gatekeeper.wasm", "circuits/gatekeeper_final.zkey");
    const ok = await groth16.verify(vkey, publicSignals, proof);
    console.log(`${ok === expectVerify ? "PASS" : "FAIL"} | ${name} | verify=${ok} (expected ${expectVerify})`);
    return ok === expectVerify;
  } catch (e) {
    const pass = expectVerify === false;
    console.log(`${pass ? "PASS" : "FAIL"} | ${name} | threw (expected verify=${expectVerify})`);
    return pass;
  }
}
let all = true;
all &= await run("L2 equal blocks + REJECT", { ...base, decision: 0, currentBlock: 19842201 }, true);
all &= await run("L3 one below expiry + APPROVE", { ...base, currentBlock: 19842200 }, true);
all &= await run("L4 equal blocks + APPROVE", { ...base, currentBlock: 19842201 }, false);
console.log(all ? "BOUNDARY CONFIRMED" : "BOUNDARY MISMATCH");
process.exit(all ? 0 : 1);
