import fs from "node:fs";
const mark = (s) => fs.appendFileSync("experiment3.log", `${Date.now()} ${s}\n`);
mark("script start");
const { groth16 } = await import("snarkjs");
mark("snarkjs imported");
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const VK_HASH = BigInt("0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0");
const input = {
  decision: 1, amount: 500, minimum: 1000, publicBalance: 1460, maxTransfer: 1000,
  recipient: BigInt("0xDe42000000000000000000000000000000009f01").toString(),
  conditionRecipient: BigInt("0xDe42000000000000000000000000000000009f01").toString(),
  expiryBlock: 19842201, currentBlock: 19832000, taskId: 12345, salt: 999,
  registeredVkHash: (VK_HASH % P).toString(), proofVkHash: (VK_HASH % P).toString(),
};
mark("calling fullProve");
const p = groth16.fullProve(input, "circuits/gatekeeper.wasm", "circuits/gatekeeper_final.zkey");
const timeout = new Promise((_, rej) => setTimeout(() => rej(new Error("TIMEOUT 40s")), 40000));
try {
  const { proof, publicSignals } = await Promise.race([p, timeout]);
  mark("fullProve done");
  const vkey = JSON.parse(fs.readFileSync("circuits/gatekeeper_vkey.json", "utf8"));
  const ok = await groth16.verify(vkey, publicSignals, proof);
  mark(`verify done valid=${ok} publicSignals=${JSON.stringify(publicSignals)}`);
} catch (e) {
  mark(`ERROR: ${e.message}`);
}
process.exit(0);
