// Persistent seen-set for proof_tx values: PROOF_REUSED detection must
// survive restarts, because the platform re-issues a reused proof in a
// later task and the agent is expected to remember it.
// Storage is a small JSON file (state/seen-proofs.json). Only proof
// references, task ids and timestamps are stored; no secrets, no task
// content. The map is proof_tx -> task_id so that a platform RETRY of the
// same task (same task_id, same proof_tx) is recognised as a replay, not
// as reuse. Reuse means the same proof_tx under a DIFFERENT task_id.

import fs from "node:fs";
import path from "node:path";

export class SeenStore {
  constructor(filePath) {
    this.filePath = filePath;
    // Map<lowercased proof_tx, lowercased task_id>
    this.map = new Map();
    this.load();
  }

  load() {
    try {
      const raw = fs.readFileSync(this.filePath, "utf8");
      const data = JSON.parse(raw);
      const list = Array.isArray(data) ? data : data.proofs ?? [];
      for (const entry of list) {
        const ref = typeof entry === "string" ? entry : entry.proof_tx;
        const taskId = typeof entry === "object" ? entry.task_id ?? "" : "";
        if (ref) this.map.set(String(ref).trim().toLowerCase(), String(taskId).trim().toLowerCase());
      }
    } catch {
      // Missing or corrupt file: start empty. A corrupt file is renamed
      // aside instead of deleted so nothing is silently lost.
      if (fs.existsSync(this.filePath)) {
        try {
          fs.renameSync(this.filePath, `${this.filePath}.corrupt-${Date.now()}`);
        } catch {
          /* ignore */
        }
      }
    }
  }

  save() {
    const dir = path.dirname(this.filePath);
    fs.mkdirSync(dir, { recursive: true });
    const data = {
      updated_at: new Date().toISOString(),
      proofs: [...this.map.entries()].map(([proof_tx, task_id]) => ({
        proof_tx,
        task_id,
        first_seen: new Date().toISOString(),
      })),
    };
    const tmp = `${this.filePath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
    fs.renameSync(tmp, this.filePath);
  }

  has(proofTx) {
    return this.map.has(String(proofTx).trim().toLowerCase());
  }

  /** task_id this proof_tx was first answered under, or null. */
  taskIdFor(proofTx) {
    return this.map.get(String(proofTx).trim().toLowerCase()) ?? null;
  }

  /**
   * @returns {"new"|"replay"|"reused"} - "replay" means the same task_id
   *   was already answered (platform retry); "reused" means the proof_tx
   *   was already answered under a different task_id.
   */
  classify(proofTx, taskId) {
    const prev = this.taskIdFor(proofTx);
    if (prev === null) return "new";
    return prev === String(taskId).trim().toLowerCase() ? "replay" : "reused";
  }

  /** Set of proof refs that count as "already seen" for a given task. */
  seenSetFor(taskId) {
    const out = new Set();
    const tid = String(taskId).trim().toLowerCase();
    for (const [ref, prevTask] of this.map.entries()) {
      if (prevTask !== tid) out.add(ref);
    }
    return out;
  }

  add(proofTx, taskId) {
    const ref = String(proofTx).trim().toLowerCase();
    const tid = String(taskId ?? "").trim().toLowerCase();
    if (!this.map.has(ref)) {
      this.map.set(ref, tid);
      this.save();
    }
  }

  get size() {
    return this.map.size;
  }
}
