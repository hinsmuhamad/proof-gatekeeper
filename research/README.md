# Circuit research notes (how the gatekeeper circuit was reverse-engineered)

Public sources only: the official artifacts from
https://agentgames.zkverify.io/api/circuit-info and the event/build pages.
No login, no secrets.

- `probe.mjs`, `probe2.mjs` — discovered the 13 input signal names by
  testing candidate names against the wasm's FNV-hashed signal map.
- `experiment3.mjs` — first working Groth16 proof; revealed the 13 public
  signals and their order.
- `experiment4.mjs` — public signal [0] depends on salt and taskId.
- `experiment5.mjs` — public signal [0] is Poseidon([salt, taskId]).
- `experiment6.mjs` — full decision/proof matrix: the circuit asserts
  decision correctness (wrong decisions fail witness generation at
  GatekeeperEvaluation line 102). One boundary found: currentBlock ==
  expiryBlock counts as EXPIRED.
- `experiment7.mjs` — confirmed the expiry boundary (>=, not >).
- `experiment.mjs` / `experiment1.mjs` / `experiment2.mjs` — early
  attempts; the "hang" was a red herring: snarkjs leaves worker threads
  alive so a script without process.exit() never terminates. Proving
  itself takes ~300ms.

Findings (all verified, see test/run-tests.js for the regression suite):
- Template: GatekeeperEvaluation. Groth16/BN128, 13 public signals:
  [Poseidon(salt, taskId), registeredVkHash, proofVkHash, minimum,
  publicBalance, expiryBlock, currentBlock, recipient,
  conditionRecipient, amount, maxTransfer, decision, taskId]
- decision: 1 = APPROVE, 0 = REJECT. Expiry rule: currentBlock >=
  expiryBlock. Amount rule: amount > maxTransfer rejects (equal ok).
  Threshold rule: publicBalance < minimum rejects (equal ok).
