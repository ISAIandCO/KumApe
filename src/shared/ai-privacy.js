(function initAiPrivacy(global) {
  "use strict";

  const STRICT_FIELDS = new Set([
    "Timestamp", "EventTime", "DeviceReceiptTime", "DeviceEventClassID", "DeviceEventCategory",
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

  global.KumApeAiPrivacy = Object.freeze({ prepareEvent, preview, redact });
})(globalThis);
