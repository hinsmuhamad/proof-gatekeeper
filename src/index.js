// Entry point: start the Proof Gatekeeper HTTP server.
import { config, log } from "./config.js";
import { createServer } from "./server.js";

const server = createServer();
server.listen(config.port, config.host, () => {
  log("info", `proof-gatekeeper listening on http://${config.host}:${config.port}`);
  if (!config.hmacSecret) {
    log(
      "info",
      "WARNING: AGENT_GAMES_HMAC_SECRET is not set. " +
        (config.allowUnsigned
          ? "ALLOW_UNSIGNED dev mode is ON; set the real secret before registering the endpoint."
          : "The /agent endpoint will reject every request until the secret is set.")
    );
  }
  if (!config.kurierApiKey) {
    log(
      "info",
      "NOTE: KURIER_API_KEY is not set. Decisions will still be served, but decision proofs will only be generated locally, never submitted to zkVerify."
    );
  }
});

process.on("SIGINT", () => process.exit(0));
process.on("SIGTERM", () => process.exit(0));
