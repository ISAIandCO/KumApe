import * as AiChat from "@isaiandco/ape-share-core/ai/chat";

const AI_CONTEXT_MAX_BYTES = Reflect.get(AiChat, "AI_CONTEXT_MAX_BYTES") ?? AiChat.AI_CHAT_MAX_BYTES;
// Compatibility while consumer PRs can still resolve ApeShareCore 1.0.x.
const compactAiContextItems = Reflect.get(AiChat, "compactAiContextItems") ?? ((items, identity) => {
  const unique = new Map();
  for (const item of items) unique.set(String(identity(item)), item);
  return [...unique.values()];
});

(function initAiPrivacy(global) {
  "use strict";

  const STRICT_FIELDS = new Set([
    "ID", "EventID", "EventId", "Timestamp", "EventTime", "DeviceReceiptTime", "DeviceEventClassID", "DeviceEventCategory",
    "DeviceHostName", "SourceHostName", "DestinationHostName", "SourceAddress", "DestinationAddress",
    "SourceUserName", "DestinationUserName", "DeviceProcessName", "SourceProcessName", "DestinationProcessName",
    "DeviceProcessID", "SourceProcessID", "DestinationProcessID", "FileName", "FilePath", "FileHash",
    "RequestUrl", "CorrelationRuleID", "CorrelationRuleName", "Message",
  ]);
  const SENSITIVE_FIELD = /(password|passwd|secret|token|cookie|authorization|credential|api.?key|private.?key)/i;
  const SENSITIVE_VALUE = /((?:bearer|token|password|passwd|secret|api[_-]?key)\s*[:=]\s*)[^\s,;]+/gi;

  function redact(value) {
    if (Array.isArray(value)) return value.map(redact);
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, SENSITIVE_FIELD.test(key) ? "[REDACTED]" : redact(item)]));
    return typeof value === "string" ? value.replace(SENSITIVE_VALUE, "$1[REDACTED]") : value;
  }

  function prepareEvent(event, mode = "strict") {
    if (!event || typeof event !== "object" || Array.isArray(event)) throw new TypeError("Для AI требуется структурированное событие");
    if (Array.isArray(event.Events)) return { Events: event.Events.slice(0, 100).map(item => prepareEvent(item, mode)) };
    if (mode === "full") return structuredClone(event);
    if (mode === "redacted") return redact(event);
    return Object.fromEntries(Object.entries(event).filter(([key, value]) => STRICT_FIELDS.has(key) && value !== undefined && value !== null && value !== ""));
  }

  function preview(event, mode = "strict") {
    const payload = prepareEvent(event, mode);
    const serialized = JSON.stringify(payload);
    return { payload, fields: Object.keys(payload), bytes: new TextEncoder().encode(serialized).byteLength, mode };
  }

  function contextEvents(context, mode) {
    const payload = prepareEvent(context, mode);
    return Array.isArray(payload.Events) ? payload.Events : [payload];
  }

  function packEvents(events) {
    return events.length === 1 ? events[0] : { Events: events };
  }

  function eventIdentity(event) {
    const id = event?.ID ?? event?.EventID ?? event?.EventId;
    return id === undefined || id === null || id === "" ? JSON.stringify(event) : `event:${id}`;
  }

  function mergeContexts(contexts, mode = "strict") {
    const events = contexts.filter(Boolean).flatMap((context) => contextEvents(context, mode));
    const payload = packEvents(compactAiContextItems(events, eventIdentity).slice(-100));
    const serialized = JSON.stringify(payload);
    return { payload, fields: Object.keys(payload), bytes: new TextEncoder().encode(serialized).byteLength, mode };
  }

  function contextDelta(context, previousContexts, mode = "strict") {
    const known = new Set(previousContexts.filter(Boolean).flatMap((item) => contextEvents(item, mode)).map(eventIdentity));
    const events = compactAiContextItems(contextEvents(context, mode), eventIdentity).filter((event) => !known.has(eventIdentity(event)));
    return events.length ? packEvents(events) : null;
  }

  function compactMessageContexts(messages) {
    const known = new Set();
    return messages.map((message) => {
      if (message?.role !== "user" || !message.context) return message;
      const events = contextEvents(message.context, "full");
      const fresh = events.filter((event) => !known.has(JSON.stringify(event)));
      events.forEach((event) => known.add(JSON.stringify(event)));
      const compacted = { ...message };
      if (fresh.length) compacted.context = packEvents(fresh);
      else delete compacted.context;
      return compacted;
    });
  }

  global.KumApeAiPrivacy = Object.freeze({ AI_CONTEXT_MAX_BYTES, compactMessageContexts, contextDelta, mergeContexts, prepareEvent, preview, redact });
})(globalThis);
