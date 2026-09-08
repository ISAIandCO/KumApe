import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

const source = await readFile(new URL("../src/popup/popup.js", import.meta.url), "utf8");

test("useful filters use one dropdown with missing-field labels and preview actions", async () => {
  const html = await readFile(new URL("../src/popup/popup.html", import.meta.url), "utf8");
  assert.match(html, /id="useful-filter"/);
  assert.match(html, /id="filter-preview"/);
  assert.match(source, /нет полей:/);
  assert.doesNotMatch(html, /id="filter-list"/);
});

function popup(executeScript) {
  const elements = new Map();
  const context = vm.createContext({
    URL,
    document: {
      querySelector(selector) {
        if (!elements.has(selector)) elements.set(selector, { style: {}, addEventListener() {}, replaceChildren() {} });
        return elements.get(selector);
      },
    },
    browser: {
      runtime: { getManifest: () => ({ version: "test" }) },
      tabs: { query: () => new Promise(() => {}) },
      scripting: { executeScript },
    },
  });
  vm.runInContext(source, context);
  vm.runInContext("state.tab = { id: 7 }", context);
  return { extract: () => vm.runInContext("extractContext()", context), context, elements };
}

test("popup resolves the injected file from the extension root and selects the event frame", async () => {
  const event = { event: { Message: "synthetic" }, score: 1000, rootsChecked: 1 };
  const app = popup(async ({ target, files }) => {
    assert.equal(target.tabId, 7);
    assert.equal(target.allFrames, true);
    const url = new URL(files[0], "moz-extension://test/popup/popup.html");
    assert.equal(url.pathname, "/content/content.js");
    await readFile(new URL("../src" + url.pathname, import.meta.url));
    return [{ result: { event: null, score: 0, rootsChecked: 1 } }, { result: event }];
  });
  assert.equal(await app.extract(), event);
});

test("top-frame fallback uses the same extension-root file", async () => {
  let calls = 0;
  const app = popup(async ({ target, files }) => {
    assert.equal(new URL(files[0], "moz-extension://test/popup/popup.html").pathname, "/content/content.js");
    calls++;
    if (target.allFrames) throw new Error("Frame access denied");
    assert.equal(target.tabId, 7);
    return [{ result: { event: null, score: 0, rootsChecked: 1 } }];
  });
  assert.equal((await app.extract()).rootsChecked, 1);
  assert.equal(calls, 2);
});

test("missing injection results are reported as a read error instead of zero DOM contexts", async () => {
  for (const results of [[], [{ result: undefined }], [{ error: { message: "Unable to load script" } }]]) {
    const app = popup(async () => results);
    await vm.runInContext("refreshContext()", app.context);
    const status = app.elements.get("#status").textContent;
    assert.match(status, /^Не удалось прочитать вкладку:/);
    assert.doesNotMatch(status, /Поля не найдены/);
    if (results[0]?.error) assert.match(status, /Unable to load script/);
  }
});

test("successful extraction is retained when another frame reports an error", async () => {
  const result = { event: null, score: 0, rootsChecked: 1 };
  const app = popup(async () => [{ error: "Frame access denied" }, { result }]);
  assert.equal(await app.extract(), result);
});
