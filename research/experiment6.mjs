// Full decision/proof matrix: does the circuit accept exactly the correct
// decision for each trap type?
import fs from "node:fs";
import { groth16 } from "snarkjs";
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const VK = (BigInt("0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0") % P).toString();
const RECIP = BigInt("0xDe42000000000000000000000000000000009f01").toString();
const OTHER = BigInt("0x1111111111111111111111111111111111111111").toString();
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
    const verdict = ok === expectVerify ? "PASS" : "FAIL";
    console.log(`${verdict} | ${name} | verify=${ok} (expected ${expectVerify})`);
    return ok === expectVerify;
  } catch (e) {
    const failedAsExpected = expectVerify === false;
    const verdict = failedAsExpected ? "PASS" : "FAIL";
    console.log(`${verdict} | ${name} | witness/prove threw (expected verify=${expectVerify}) :: ${String(e).split("\n")[0].slice(0, 90)}`);
    return failedAsExpected;
  }
}
let all = true;
all &= await run("A valid + APPROVE", base, true);
all &= await run("B valid + REJECT", { ...base, decision: 0 }, false);
all &= await run("C recip mismatch + APPROVE", { ...base, recipient: OTHER }, false);
all &= await run("D recip mismatch + REJECT", { ...base, decision: 0, recipient: OTHER }, true);
all &= await run("E low balance + APPROVE", { ...base, publicBalance: 500 }, false);
all &= await run("F low balance + REJECT", { ...base, decision: 0, publicBalance: 500 }, true);
all &= await run("G expired + APPROVE", { ...base, currentBlock: 19850000 }, false);
all &= await run("G2 expired + REJECT", { ...base, decision: 0, currentBlock: 19850000 }, true);
all &= await run("H vk mismatch + APPROVE", { ...base, proofVkHash: "12345" }, false);
all &= await run("H2 vk mismatch + REJECT", { ...base, decision: 0, proofVkHash: "12345" }, true);
all &= await run("I amount over cap + APPROVE", { ...base, amount: 1500 }, false);
all &= await run("I2 amount over cap + REJECT", { ...base, decision: 0, amount: 1500 }, true);
// Boundaries: equal values must APPROVE
all &= await run("J amount == maxTransfer + APPROVE", { ...base, amount: 1000 }, true);
all &= await run("K balance == minimum + APPROVE", { ...base, publicBalance: 1000 }, true);
all &= await run("L currentBlock == expiryBlock + APPROVE", { ...base, currentBlock: 19842201 }, true);
console.log(all ? "\nALL MATRIX CASES PASS" : "\nSOME MATRIX CASES FAILED");
process.exit(all ? 0 : 1);
