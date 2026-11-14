# Proof Gatekeeper agent — zkVerify Agent Games

An HTTP agent that plays the **Proof Gatekeeper** track: it receives
payment-gatekeeper tasks, checks every field, verifies the attached proof,
decides APPROVE/REJECT, and proves its decision with a real Groth16
zero-knowledge proof (the official gatekeeper circuit, verified locally
against the official verification key).

Competition: https://agentgames.zkverify.io — Proof Gatekeeper, 8 daily
rounds 13–20 Nov 2026, 8 tasks per agent per day, arena live nightly
17:30–03:30 WIB. Prize pool 100,000 VFY for this track
(1st 50,000 / 2nd 30,000 / 3rd 20,000). Registration closes 21 Nov 2026.

## What works right now

- **Decision logic** (`src/decision.js`): pure, fully tested. Checks, in
  order: envelope sanity, expiry (task deadline, then block height),
  VK substitution, proof reuse (persistent seen-set), recipient match,
  amount cap, threshold, and incoming-proof finalization (only when the
  status is actually known; see below).
- **HMAC contract** (`src/hmac.js`): verifies `x-agent-games-signature`
  (HMAC-SHA256 over the raw body) before parsing, and signs every
  response the same way. Tampered bodies and wrong secrets get 401.
- **Groth16 decision proofs** (`src/prover.js`): generates a real proof
  with snarkjs + the official circuit artifacts and verifies it locally
  against the official verification key before doing anything with it.
  Proving takes ~300 ms on this machine — far inside the 60 s deadline.
- **Kurier submission** (`src/kurier.js`): submits the decision proof to
  zkVerify mainnet via Kurier REST (`POST /submit-proof/{API_KEY}`,
  poll `/job-status/`), and best-effort checks the incoming proof's
  finalization. Degrades cleanly without an API key.
- **HTTP server** (`src/server.js`): `GET /`, `GET /health`,
  `POST /preflight` → `{ ok: true, protocolVersion: "v1" }`,
  `POST /agent` → `{ decision, reason_code, proof_tx }`, signed.
  Internal 55 s deadline guard (platform limit is 60 s); fail-closed
  REJECT if the deadline is ever hit.
- **Replay safety**: the same `proof_tx` under a *different* `task_id`
  is PROOF_REUSED; the same `task_id` re-sent (platform retry) replays
  the same decision instead of being flagged as reuse.

## Scoring (from the event page — this overrides the +10/−10 numbers in
an earlier briefing)

| Outcome | Points |
|---|---|
| Correct APPROVE (verified) | +12 |
| Correct REJECT (verified) | +12 |
| Incorrect APPROVE | −6 |
| Incorrect REJECT | −3 |
| Delivery timeout (no response in 60 s) | −2 |
| Missing / invalid proof | −2 |
| Reliability bonus (pro-rated by share of provable tasks whose Groth16 proof verified) | +0 to +5 per round |

Ties: more correct decisions first, then fewer timeouts. The decision is
worth the most (+12); the proof is worth up to +5/round plus avoiding
−2/task. That is why the agent **never sacrifices the decision for the
proof**: if proof generation or Kurier submission fails or runs out of
budget, the decision is still returned on time.

## Trap encyclopedia (canonical codes, from the event page)

| Code | Meaning | Approx. share |
|---|---|---|
| `VALID_CONDITION` | Everything checks out — approve | ~50% |
| `VK_SUBSTITUTION` | Proof verifies but its VK ≠ registered condition VK | ~13% |
| `THRESHOLD_MISMATCH` | Public balance < required minimum | ~8% |
| `PROOF_REUSED` | `proof_tx` already answered in an earlier task | ~11% |
| `EXPIRED_CONDITION` | `current_block >= expiry_block` (equal counts as expired — verified against the circuit) or `deadline_at` passed | ~6% |
| `RECIPIENT_MISMATCH` | Recipient ≠ condition recipient | ~6% |
| `AMOUNT_OVERFLOW` | Amount > `max_transfer` | ~6% |
| `UNFINALIZED_PROOF` | Incoming proof not finalized on-chain. **Not** one of the six scored trap types (they sum to 100%); it is a check from the build guide, applied only when finalization status is known. | — |

Aliases from an earlier briefing that map onto the canonical codes:
`AMOUNT_MISMATCH` → `AMOUNT_OVERFLOW`, `EXPIRED_TASK` →
`EXPIRED_CONDITION`, `PROOF_REUSE` → `PROOF_REUSED`,
`CIRCUIT_MISMATCH` → `VK_SUBSTITUTION` (a proof's circuit is identified
by its verification key).

## The circuit, reverse-engineered and verified

Artifacts (downloaded from `https://agentgames.zkverify.io/api/circuit-info`):
`circuits/gatekeeper.wasm`, `circuits/gatekeeper_final.zkey`,
`circuits/gatekeeper_vkey.json`. vk_hash
`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`.

- Template `GatekeeperEvaluation`, Groth16/BN128, 13 public signals.
- The 13 input signals (discovered by probing the wasm's FNV-hashed
  signal map; see `research/`): `decision, amount, minimum,
  publicBalance, maxTransfer, recipient, conditionRecipient, expiryBlock,
  currentBlock, taskId, salt, registeredVkHash, proofVkHash`.
- Public signals, in order: `[Poseidon(salt, taskId), registeredVkHash,
  proofVkHash, minimum, publicBalance, expiryBlock, currentBlock,
  recipient, conditionRecipient, amount, maxTransfer, decision, taskId]`.
  Every input is a public signal; `salt` is private and only appears
  inside the Poseidon commitment. `Poseidon([salt, taskId])` was confirmed
  by direct computation with circomlibjs.
- **The circuit enforces decision correctness**: a wrong decision fails
  witness generation outright (assert in `GatekeeperEvaluation`, line
  102). So the prover is a second checker on the decision logic — a proof
  that verifies locally is strong evidence the decision is right.
- Boundary semantics confirmed against the circuit: `amount ==
  maxTransfer` approves, `publicBalance == minimum` approves,
  `currentBlock == expiryBlock` is expired (reject).

## How to run

```bash
npm install
npm test        # full suite, must print ALL TESTS PASS
AGENT_GAMES_HMAC_SECRET='<one-time plaintext from the dashboard>' \
KURIER_API_KEY='<kurier mainnet key>' \
npm start       # listens on http://0.0.0.0:3000
```

Copy `.env.example` to `.env` for the variable list. Never commit a real
`.env`, never paste a secret into any tool.

## How preflight works

`POST /preflight` answers `{ ok: true, protocolVersion: "v1" }` (signed
with the HMAC secret when one is configured). If a signature header is
present on the preflight request it is verified; if absent the endpoint
still answers, because preflight is a liveness check. Run it, then run at
least one Practice task from the dashboard before the first scored round.

## What was tested

`npm test` — **31 checks, all passing** (run 2026-11-14):

1. **Decision logic (15 checks)**: valid approve; each of the six scored
   traps; unfinalized; the three boundary values (balance == minimum,
   amount == max, one block before expiry); malformed payloads;
   PROOF_REUSED across task ids; replay of the same task id.
2. **Decision-vs-circuit agreement (7 checks)**: for a valid task and
   one task per trap type, the decision from `decide()` generates a
   Groth16 proof that verifies against the official verification key,
   **and the opposite decision fails to prove**. This is the strongest
   check in the suite: decision logic and circuit agree exactly.
3. **HTTP server (9 checks)**: `/health`, `/preflight`, `/agent` with a
   valid signature (decision APPROVE, response signature verifies,
   round trip ~309 ms), tampered body → 401, wrong secret → 401,
   missing signature → 401, trap → correct REJECT, PROOF_REUSED across
   requests, replay → same decision.
4. **Standalone smoke test**: `npm start` binds, `/health` and
   `/preflight` answer correctly.

## Honest status of the proof-generation step

**The proof-generation step itself is DONE and verified** — real Groth16
proofs are generated with the official circuit and verify locally against
the official key, and the test suite proves the decision logic and the
circuit agree on every trap type. What is still missing is everything
outside this codebase:

1. **Kurier API key** — not available in this session. `src/kurier.js`
   implements `register-vk`, `submit-proof`, and `job-status` polling
   against `https://api.kurier.xyz/api/v1` (mainnet; the host answers,
   the key is a path parameter per the zkVerify docs), but no live
   submission has been made. Get a key at https://kurier.xyz.
2. **`proof_tx` semantics** — the event page's sample response echoes
   the incoming `proof_tx`, while the build guide says to "include the
   proof in your response" and the scoring implies the platform verifies
   the agent's own Groth16 proof. This agent resolves the ambiguity by
   sending the **Kurier job reference as `proof_tx` when a submission
   succeeds**, and echoing the incoming `proof_tx` otherwise (matching
   the documented sample shape). Confirm in Practice mode which one the
   platform accepts.
3. **`taskId` encoding** — the payload `task_id` is a string
   (`"gk_24_9d1"`); the circuit takes a field element. This agent uses
   the number directly when the string is numeric, otherwise
   SHA-256(`task_id`) mod p. The platform has not published its encoding.
   If Practice mode rejects proofs for a public-signal mismatch, this is
   the first thing to adjust.
4. **Incoming-proof finalization** — Kurier's `job-status` is keyed by
   Kurier job id, while the task carries `proof_tx` (a chain reference).
   The check is best-effort and returns "unknown" when the reference
   does not resolve; the decision does not depend on it.

## Hosting requirements

- A **public HTTPS endpoint** (not localhost) that the platform can
  reach, registered in the dashboard under Manage Agents with its full
  path (e.g. `https://<host>/agent`).
- The process must stay up **every night 17:30–03:30 WIB** (rounds
  13–20 Nov) and answer each task **within 60 s**. Proof generation is
  ~300 ms, so the budget is comfortable; the risk is the host sleeping,
  not the compute.
- **The InstaBox box is NOT suitable as the host**: it auto-pauses after
  30 minutes idle and has an 8-hour max run plus a 2-hour cooldown, so
  it would miss tasks overnight.
- **Candidates: Railway or Cloady.** Railway (VLESS work is next on the
  list anyway) or a Cloady free-tier workspace (US East / US West, 0.5
  vCPU / 1 GB RAM / 5 GB SSD, no card) can host this Node.js server
  behind their HTTPS gateway. Keep the process on a free tier that does
  not sleep: verify the host's idle/sleep policy before registering the
  endpoint, or the agent will time out and eat −2 per missed task.
- Keep `state/seen-proofs.json` persistent across restarts (it is the
  PROOF_REUSED memory). If the host wipes the disk, reuse detection
  resets and reused proofs will be approved (+−6 each).
- Set `AGENT_GAMES_HMAC_SECRET` from the dashboard (Rotate Secret) and
  `KURIER_API_KEY` as environment variables on the host. No secrets are
  stored in this repo.

## Files

```
src/
  index.js       entry point
  server.js      HTTP server: / /health /preflight /agent
  decision.js    pure decision logic + trap codes
  hmac.js        HMAC-SHA256 verify/sign
  prover.js      Groth16 proof generation (snarkjs, official circuit)
  kurier.js      Kurier REST client (submit/poll/finalization check)
  seenStore.js   persistent proof_tx -> task_id map
  config.js      env-based configuration
test/
  run-tests.js   31-check suite (npm test)
circuits/
  gatekeeper.wasm / gatekeeper_final.zkey / gatekeeper_vkey.json
research/        how the circuit inputs were discovered (probe scripts,
                 proof matrix, boundary experiments)
```
