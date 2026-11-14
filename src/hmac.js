// HMAC-SHA256 helpers for the Agent Games platform contract.
// Incoming: platform sends x-agent-games-signature over the RAW request
// body. Outgoing: every response is signed the same way over the RAW
// response body. The secret comes from the dashboard ("Rotate Secret"),
// never a local placeholder.

import crypto from "node:crypto";

export function hmacHex(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}

function normalizeSignature(sig) {
  if (!sig) return "";
  let s = String(sig).trim();
  if (s.toLowerCase().startsWith("sha256=")) s = s.slice("sha256=".length);
  return s.toLowerCase();
}

/**
 * Timing-safe comparison of a received signature against the expected HMAC.
 * Accepts both a bare hex digest and a "sha256=<hex>" prefixed value.
 */
export function verifyHmac(secret, rawBody, receivedSignature) {
  if (!secret || !receivedSignature) return false;
  const expected = hmacHex(secret, rawBody);
  const received = normalizeSignature(receivedSignature);
  if (received.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(received, "utf8"), Buffer.from(expected, "utf8"));
}

export function signBody(secret, rawBody) {
  return hmacHex(secret, rawBody);
}
