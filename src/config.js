// Configuration. Everything secret comes from the environment; nothing
// secret is ever written to a file by this agent.
//
// Required in production:
//   AGENT_GAMES_HMAC_SECRET - one-time plaintext from the dashboard
//                             ("Rotate Secret"). Without it the agent
//                             cannot prove it is the registered agent.
// Optional:
//   KURIER_API_KEY          - Kurier mainnet API key (https://kurier.xyz).
//                             Needed to submit decision proofs to zkVerify
//                             and to check incoming-proof finalization.
//   KURIER_API_URL          - default https://api.kurier.xyz/api/v1
//   KURIER_CHAIN_ID         - chain id for submit-proof, if required.
//   KURIER_VK_REGISTERED    - "true" once the gatekeeper vk is registered
//                             in Kurier (the platform's vk_hash is already
//                             registered on zkVerify mainnet, so this
//                             defaults to true).
//   PORT                    - default 3000
//   HOST                    - default 0.0.0.0
//   STATE_DIR               - default ./state (seen-proofs.json lives here)
//   CIRCUIT_WASM / CIRCUIT_ZKEY / CIRCUIT_VKEY - artifact paths
//   PROOF_BUDGET_MS         - max time spent generating+submitting the
//                             decision proof per task (default 20000).
//                             The 60s platform deadline is enforced
//                             separately with a 55s internal cap.
//   ALLOW_UNSIGNED          - "true" only for local testing without a
//                             secret. Never enable in production.
//   LOG_LEVEL               - "info" (default) or "debug"

import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export const config = {
  root,
  port: Number(process.env.PORT ?? 3000),
  host: process.env.HOST ?? "0.0.0.0",
  hmacSecret: process.env.AGENT_GAMES_HMAC_SECRET ?? "",
  allowUnsigned: process.env.ALLOW_UNSIGNED === "true",
  kurierApiKey: process.env.KURIER_API_KEY ?? "",
  kurierApiUrl: (process.env.KURIER_API_URL ?? "https://api.kurier.xyz/api/v1").replace(/\/$/, ""),
  kurierChainId: process.env.KURIER_CHAIN_ID ? Number(process.env.KURIER_CHAIN_ID) : undefined,
  kurierVkRegistered: process.env.KURIER_VK_REGISTERED !== "false",
  stateDir: process.env.STATE_DIR ?? path.join(root, "state"),
  wasmPath: process.env.CIRCUIT_WASM ?? path.join(root, "circuits", "gatekeeper.wasm"),
  zkeyPath: process.env.CIRCUIT_ZKEY ?? path.join(root, "circuits", "gatekeeper_final.zkey"),
  vkeyPath: process.env.CIRCUIT_VKEY ?? path.join(root, "circuits", "gatekeeper_vkey.json"),
  proofBudgetMs: Number(process.env.PROOF_BUDGET_MS ?? 20000),
  // Internal response deadline: 55s, leaving 5s of margin inside the
  // platform's hard 60s window.
  responseDeadlineMs: Number(process.env.RESPONSE_DEADLINE_MS ?? 55000),
  logLevel: process.env.LOG_LEVEL ?? "info",
  // Proof Gatekeeper verification key hash, registered on zkVerify mainnet
  // (from https://agentgames.zkverify.io/api/circuit-info).
  gatekeeperVkHash:
    "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
};

export function log(level, msg, extra) {
  if (config.logLevel !== "debug" && level === "debug") return;
  const line = `[${new Date().toISOString()}] [${level}] ${msg}`;
  console.log(extra !== undefined ? `${line} ${JSON.stringify(extra)}` : line);
}
