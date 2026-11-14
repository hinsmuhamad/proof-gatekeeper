// Step-by-step instrumentation, markers written to a file (unbuffered).
import fs from "node:fs";
const mark = (s) => fs.appendFileSync("experiment2.log", `${Date.now()} ${s}\n`);
mark("script start");
const { groth16 } = await import("snarkjs");
mark("snarkjs imported");
import wtnsCalculate from "snarkjs/src/wtns_calculate.js";
mark("wtns_calculate imported");
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const VK_HASH = BigInt("0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0");
const input = {
  decision: 1, amount: 500, minimum: 1000, publicBalance: 1460, maxTransfer: 1000,
  recipient: BigInt("0xDe42000000000000000000000000000000009f01").toString(),
  conditionRecipient: BigInt("0xDe42000000000000000000000000000000009f01").toString(),
  expiryBlock: 19842201, currentBlock: 19832000, taskId: 12345, salt: 999,
  registeredVkHash: (VK_HASH % P).toString(), proofVkHash: (VK_HASH % P).toString(),
};
mark("calling wtnsCalculate");
const wtns = { type: "mem" };
await wtnsCalculate(input, "circuits/gatekeeper.wasm", wtns);
mark("witness done, calling groth16.prove");
import groth16Prove from "snarkjs/src/groth16_prove.js";
const { proof, publicSignals } = await groth16Prove("circuits/gatekeeper_final.zkey", wtns);
mark("prove done");
const vkey = JSON.parse(fs.readFileSync("circuits/gatekeeper_vkey.json", "utf8"));
const ok = await groth16.verify(vkey, publicSignals, proof);
mark(`verify done valid=${ok} publicSignals=${JSON.stringify(publicSignals)}`);
