import { chatEndpoint } from "@isaiandco/ape-share-core/ai/transport";
import "./kuma-adapter.js";

export function localAiEndpoint(value) {
  const endpoint = chatEndpoint(value || "", { expandBase: true });
  if (!globalThis.KumApeAdapter.isLocalNetworkHost(endpoint.hostname)) throw new Error("AI endpoint должен находиться на этом компьютере или в локальной сети");
  return endpoint;
}
