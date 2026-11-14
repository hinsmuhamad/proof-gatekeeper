// Kurier REST client (zkVerify mainnet relay).
// Docs: https://docs.zkverify.io/handbook/quickstart
// Endpoints (API key is a path parameter, not a header):
//   POST {API_URL}/register-vk/{API_KEY}
//   POST {API_URL}/submit-proof/{API_KEY}
//   GET  {API_URL}/job-status/{API_KEY}/{jobId}
// Job status flow: Queued -> Valid -> Submitted -> IncludedInBlock
//   -> Finalized (or Failed). Aggregation flows may also show
//   AggregationPending / Aggregated.
//
// No Kurier call is ever required for the decision itself: the decision is
// pure field logic (see decision.js). Kurier is used for two optional
// steps: (a) submit the agent's own Groth16 decision proof, and
// (b) best-effort finalization check of the incoming proof. Both degrade
// gracefully when no API key is configured.

import { config, log } from "./config.js";

const DEFAULT_TIMEOUT_MS = 15000;

async function fetchJson(url, { method = "GET", body, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method,
      headers: { "content-type": "application/json" },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: ctrl.signal,
    });
    const text = await res.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = { _raw: text };
    }
    return { status: res.status, ok: res.ok, data };
  } finally {
    clearTimeout(timer);
  }
}

export class KurierClient {
  constructor(apiKey = config.kurierApiKey, apiUrl = config.kurierApiUrl) {
    this.apiKey = apiKey;
    this.apiUrl = apiUrl;
  }

  get configured() {
    return Boolean(this.apiKey);
  }

  /** One-time setup: register the gatekeeper verification key. */
  async registerVk(vk) {
    if (!this.configured) return { ok: false, error: "KURIER_API_KEY not configured" };
    const params = {
      proofType: "groth16",
      proofOptions: { library: "snarkjs", curve: "bn128" },
      vk,
    };
    const res = await fetchJson(`${this.apiUrl}/register-vk/${this.apiKey}`, {
      method: "POST",
      body: params,
    });
    if (!res.ok) return { ok: false, error: `register-vk HTTP ${res.status}`, data: res.data };
    return { ok: true, data: res.data };
  }

  /**
   * Submit a Groth16 proof for verification.
   * @returns {{ ok: boolean, jobId?: string, error?: string, data?: any }}
   */
  async submitProof({ proof, publicSignals, vkHash }) {
    if (!this.configured) return { ok: false, error: "KURIER_API_KEY not configured" };
    const params = {
      proofType: "groth16",
      vkRegistered: config.kurierVkRegistered,
      proofOptions: { library: "snarkjs", curve: "bn128" },
      proofData: { proof, publicSignals, vk: vkHash },
    };
    if (config.kurierChainId !== undefined) params.chainId = config.kurierChainId;
    const res = await fetchJson(`${this.apiUrl}/submit-proof/${this.apiKey}`, {
      method: "POST",
      body: params,
      timeoutMs: 30000,
    });
    if (!res.ok) return { ok: false, error: `submit-proof HTTP ${res.status}`, data: res.data };
    const jobId = res.data?.jobId ?? res.data?.job_id ?? null;
    if (!jobId) return { ok: false, error: "submit-proof returned no jobId", data: res.data };
    return { ok: true, jobId, data: res.data };
  }

  /** Poll a job until Finalized / Failed or the budget runs out. */
  async pollJob(jobId, { budgetMs = 15000, intervalMs = 2000 } = {}) {
    if (!this.configured) return { ok: false, status: "unknown", error: "KURIER_API_KEY not configured" };
    const deadline = Date.now() + budgetMs;
    let last = null;
    while (Date.now() < deadline) {
      const res = await fetchJson(`${this.apiUrl}/job-status/${this.apiKey}/${jobId}`, {
        timeoutMs: 10000,
      });
      if (res.ok && res.data) {
        last = res.data;
        const status = res.data.status ?? res.data.state ?? "unknown";
        if (status === "Finalized") return { ok: true, status, data: res.data };
        if (status === "Failed") return { ok: false, status, data: res.data };
      }
      await new Promise((r) => setTimeout(r, intervalMs));
    }
    return { ok: false, status: last?.status ?? "unknown", error: "poll budget exhausted", data: last };
  }

  /**
   * Best-effort finalization check for the INCOMING proof.
   * Kurier job-status is keyed by Kurier jobId, while the task payload
   * carries proof_tx (a chain transaction reference). If the platform
   * uses the same identifier for both, this resolves; otherwise the API
   * answers 404/unknown and we return null (unknown) instead of guessing.
   * @returns {Promise<boolean|null>} true = finalized, false = not
   *   finalized (or failed), null = unknown.
   */
  async incomingProofFinalized(proofTx) {
    if (!this.configured) return null;
    try {
      const res = await fetchJson(
        `${this.apiUrl}/job-status/${this.apiKey}/${encodeURIComponent(proofTx)}`,
        { timeoutMs: 10000 }
      );
      if (!res.ok || !res.data) return null;
      const status = res.data.status ?? res.data.state;
      if (status === "Finalized") return true;
      if (status === "Failed") return false;
      // Queued / Valid / Submitted / IncludedInBlock / AggregationPending:
      // the proof exists but is not finalized yet.
      if (typeof status === "string" && status.length > 0) return false;
      return null;
    } catch (e) {
      log("debug", "incoming finalization check failed", { error: String(e) });
      return null;
    }
  }
}
