// Experiment: map the gatekeeper circuit's public signals and test whether
// the circuit enforces decision correctness.
// All local, no network, no secrets.
import fs from "node:fs";
import { groth16 } from "snarkjs";

const WASM = "circuits/gatekeeper.wasm";
const ZKEY = "circuits/gatekeeper_final.zkey";
const VKEY = JSON.parse(fs.readFileSync("circuits/gatekeeper_vkey.json", "utf8"));

const P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const VK_HASH = BigInt(
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"
);
const VK_HASH_MOD_P = (VK_HASH % P).toString();
const RECIPIENT = BigInt("0xDe42000000000000000000000000000000009f01").toString();
const OTHER_RECIPIENT = BigInt("0x1111111111111111111111111111111111111111").toString();

function baseInput(overrides = {}) {
  return {
    decision: 1,
    amount: 500,
    minimum: 1000,
    publicBalance: 1460,
    maxTransfer: 1000,
    recipient: RECIPIENT,
    conditionRecipient: RECIPIENT,
    expiryBlock: 19842201,
    currentBlock: 19832000,
    taskId: 12345,
    salt: 999,
    registeredVkHash: VK_HASH_MOD_P,
    proofVkHash: VK_HASH_MOD_P,
    ...overrides,
  };
}

async function tryCase(name, input) {
  const t0 = Date.now();
  try {
    const { proof, publicSignals } = await groth16.fullProve(input, WASM, ZKEY);
    const ok = await groth16.verify(VKEY, publicSignals, proof);
    console.log(
      `\n[${name}] prove ${Date.now() - t0}ms | groth16.verify: ${ok}`
    );
    console.log("  publicSignals:", JSON.stringify(publicSignals));
    return { ok, publicSignals };
  } catch (e) {
    console.log(`\n[${name}] ERROR: ${String(e).split("\n")[0]}`);
    return { ok: false, error: String(e) };
  }
}

// Case A: fully valid task, decision APPROVE (1)
await tryCase("A valid + APPROVE", baseInput());
// Case B: fully valid task, decision REJECT (0) — should FAIL if circuit enforces correctness
await tryCase("B valid + REJECT", baseInput({ decision: 0 }));
// Case C: recipient mismatch + APPROVE — should FAIL
await tryCase(
  "C recipient mismatch + APPROVE",
  baseInput({ recipient: OTHER_RECIPIENT })
);
// Case D: recipient mismatch + REJECT — should pass
await tryCase(
  "D recipient mismatch + REJECT",
  baseInput({ decision: 0, recipient: OTHER_RECIPIENT })
);
// Case E: balance below minimum + APPROVE — should FAIL
await tryCase("E low balance + APPROVE", baseInput({ publicBalance: 500 }));
// Case F: low balance + REJECT — should pass
await tryCase(
  "F low balance + REJECT",
  baseInput({ decision: 0, publicBalance: 500 })
);
// Case G: expired + APPROVE — should FAIL
await tryCase("G expired + APPROVE", baseInput({ currentBlock: 19850000 }));
// Case H: vk mismatch + APPROVE — should FAIL
await tryCase(
  "H vk mismatch + APPROVE",
  baseInput({ proofVkHash: "12345" })
);
// Case I: amount over cap + APPROVE — should FAIL
await tryCase("I amount over cap + APPROVE", baseInput({ amount: 1500 }));
