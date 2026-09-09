import test from "node:test";
import assert from "node:assert/strict";
import { requestPreparedAi } from "../src/shared/ai-request.js";

test("slow AI request uses the visible chat context and preserves the reviewed body", async () => {
  const body = '{"model":"local","messages":[]}';
  let request;
  const browserApi = {
    storage: { local: { get: async () => ({ ai: { endpoint: "http://127.0.0.1:8080/v1" }, aiApiKey: " key " }) } },
    permissions: { contains: async (permissions) => {
      assert.deepEqual(permissions, { origins: ["http://127.0.0.1/*"] });
      return true;
    } },
  };
  const result = await requestPreparedAi({ endpoint: "http://127.0.0.1:8080/v1/chat/completions", body }, {
    browserApi,
    requestImpl: async (endpoint, serialized, options) => {
      request = { endpoint: endpoint.href, serialized, options };
      return { content: "Готово" };
    },
  });
  assert.deepEqual(request, { endpoint: "http://127.0.0.1:8080/v1/chat/completions", serialized: body, options: { apiKey: "key" } });
  assert.equal(result.content, "Готово");
});

test("changed endpoint invalidates the reviewed payload before network access", async () => {
  const browserApi = {
    storage: { local: { get: async () => ({ ai: { endpoint: "http://127.0.0.1:9090/v1/chat/completions" } }) } },
    permissions: { contains: async () => true },
  };
  await assert.rejects(requestPreparedAi({ endpoint: "http://127.0.0.1:8080/v1/chat/completions", body: "{}" }, {
    browserApi,
    requestImpl: () => assert.fail("Unexpected network request"),
  }), /изменились/);
});
