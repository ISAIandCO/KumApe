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

test("public endpoints are rejected on direct chat requests before network access", async () => {
  const browserApi = { storage: { local: { get: async () => ({ ai: { endpoint: "https://example.org/v1" } }) } }, permissions: { contains: async () => true } };
  await assert.rejects(requestPreparedAi({ endpoint: "https://example.org/v1/chat/completions", body: "{}" }, { browserApi, requestImpl: () => assert.fail("Unexpected network request") }), /локальн/);
});

test("context tool calls use the shared whitelist and reject malformed arguments", async () => {
  const browserApi = { storage: { local: { get: async () => ({ ai: { endpoint: "http://localhost/v1" } }) } }, permissions: { contains: async () => true } };
  const result = await requestPreparedAi({ endpoint: "http://localhost/v1/chat/completions", body: "{}" }, {
    browserApi, allowTools: true, contextType: "context", requestImpl: async () => ({ tool_calls: [
      { id: "accepted", function: { name: "get_additional_context", arguments: '{"reason":"Check parent"}' } },
      { function: { name: "execute_command", arguments: "{}" } },
      { function: { name: "get_additional_context", arguments: "invalid" } },
    ] }),
  });
  assert.deepEqual(result.toolCalls, [{ id: "accepted", name: "get_additional_context", arguments: { reason: "Check parent" } }]);
});
