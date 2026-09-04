(function initKumaPage(global) {
  "use strict";

  if (global.KumApePage) return;

  const EVENT_HINTS = [
    "Timestamp", "DeviceReceiptTime", "EventTime", "Message", "SourceAddress",
    "DestinationAddress", "DeviceHostName", "DeviceEventClassID", "CorrelationRuleID",
  ];

  function parseJsonCandidate(text) {
    let source = String(text ?? "").trim();
    if (!source || source.length > 10_000_000) return null;
    const fenced = source.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
    if (fenced) source = fenced[1];
    try {
      const parsed = JSON.parse(source);
      if (parsed && typeof parsed === "object") return parsed;
    } catch {
      return null;
    }
    return null;
  }

  function candidateScore(value, text, label = "") {
    if (!value || typeof value !== "object") return -1;
    const entries = Array.isArray(value) ? value.length : Object.keys(value).length;
    const haystack = `${Object.keys(value).join(" ")} ${label}`;
    const hints = EVENT_HINTS.filter((field) => haystack.toLowerCase().includes(field.toLowerCase())).length;
    return hints * 1000 + Math.min(entries, 500) + Math.min(String(text).length / 1000, 100);
  }

  function extractFromTextNodes(documentObject) {
    const nodes = [...documentObject.querySelectorAll("pre, textarea, code")];
    const candidates = [];
    for (const node of nodes) {
      const text = "value" in node ? node.value : node.textContent;
      const value = parseJsonCandidate(text);
      if (!value) continue;
      const label = node.closest("section, article, [role='dialog'], [class*='detail'], [class*='raw']")?.textContent?.slice(0, 300) || "";
      candidates.push({ event: value, raw: String(text).trim(), source: node.tagName.toLowerCase(), score: candidateScore(value, text, label) });
    }
    return candidates;
  }

  function extractFromTables(documentObject) {
    const candidates = [];
    for (const container of documentObject.querySelectorAll("table, dl, [role='dialog'], [class*='detail']")) {
      const event = {};
      for (const row of container.querySelectorAll("tr")) {
        const cells = row.querySelectorAll("th, td");
        if (cells.length < 2) continue;
        const key = cells[0].textContent.trim();
        const value = cells[1].textContent.trim();
        if (/^[A-Za-z][A-Za-z0-9_.]{1,127}$/.test(key) && value) event[key] = value;
      }
      for (const term of container.querySelectorAll("dt")) {
        const key = term.textContent.trim();
        const value = term.nextElementSibling?.matches("dd") ? term.nextElementSibling.textContent.trim() : "";
        if (/^[A-Za-z][A-Za-z0-9_.]{1,127}$/.test(key) && value) event[key] = value;
      }
      const score = candidateScore(event, JSON.stringify(event), container.textContent.slice(0, 300));
      if (Object.keys(event).length >= 3 && score >= 1000) {
        candidates.push({ event, raw: JSON.stringify(event, null, 2), source: "field-table", score });
      }
    }
    return candidates;
  }

  function findRawText(documentObject) {
    const nodes = [...documentObject.querySelectorAll("pre")];
    return nodes
      .map((node) => ({ text: node.textContent.trim(), label: node.parentElement?.textContent?.slice(0, 160) || "" }))
      .filter((item) => item.text)
      .sort((a, b) => (/raw/i.test(b.label) - /raw/i.test(a.label)) || b.text.length - a.text.length)[0]?.text || null;
  }

  function routeContext(urlValue) {
    const url = new URL(urlValue);
    const uuids = url.href.match(/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/gi) || [];
    return {
      origin: url.origin,
      route: `${url.pathname}${url.search}${url.hash}`,
      eventId: url.searchParams.get("eventId") || url.searchParams.get("eventID") || uuids.at(-1) || null,
      tenantId: url.searchParams.get("tenantId") || url.searchParams.get("tenantID") || null,
    };
  }

  function extractPageContext(documentObject = document, urlValue = location.href) {
    const candidates = [...extractFromTextNodes(documentObject), ...extractFromTables(documentObject)]
      .sort((a, b) => b.score - a.score);
    const best = candidates[0] || null;
    const raw = best?.raw || findRawText(documentObject);
    const title = documentObject.title || "";
    return {
      ...routeContext(urlValue),
      title,
      isKuma: /\bKUMA\b/i.test(title) || /\bKUMA\b/i.test(documentObject.body?.innerText?.slice(0, 2000) || ""),
      event: best?.event || null,
      raw,
      source: best?.source || (raw ? "raw-pre" : null),
      score: best?.score || 0,
    };
  }

  global.KumApePage = Object.freeze({ candidateScore, extractPageContext, parseJsonCandidate, routeContext });
})(globalThis);
