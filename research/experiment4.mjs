// Which inputs feed public signal [0]? Vary one input at a time.
import fs from "node:fs";
import { groth16 } from "snarkjs";
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const VK = (BigInt("0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0") % P).toString();
const RECIP = BigInt("0xDe42000000000000000000000000000000009f01").toString();
const base = {
  decision: 1, amount: 500, minimum: 1000, publicBalance: 1460, maxTransfer: 1000,
  recipient: RECIP, conditionRecipient: RECIP,
  expiryBlock: 19842201, currentBlock: 19832000, taskId: 12345, salt: 999,
  registeredVkHash: VK, proofVkHash: VK,
};
async function sig0(name, input) {
  const { publicSignals } = await groth16.fullProve(input, "circuits/gatekeeper.wasm", "circuits/gatekeeper_final.zkey");
  console.log(name, "sig0 =", publicSignals[0], "| decision pub =", publicSignals[11], "| taskId pub =", publicSignals[12]);
}
await sig0("base            ", base);
await sig0("salt=1000       ", { ...base, salt: 1000 });
await sig0("taskId=12346    ", { ...base, taskId: 12346 });
await sig0("decision=0      ", { ...base, decision: 0 });
await sig0("amount=501      ", { ...base, amount: 501 });
await sig0("recipient other ", { ...base, recipient: BigInt("0x1111111111111111111111111111111111111111").toString() });
process.exit(0);
