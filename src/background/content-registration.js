"use strict";

// Register only on the configured KUMA host after the user grants host access.
async function syncIocContent() {
  const id = "kumape-ioc-menu";
  const { uiOrigin = "" } = await browser.storage.local.get("uiOrigin");
  let origin = "";
  try { if (uiOrigin) origin = globalThis.KumApeAdapter.normalizeOrigin(uiOrigin); } catch { /* Unconfigured host. */ }
  const matches = origin ? [permissionPattern(origin)] : [];
  const allowed = origin && await browser.permissions.contains({ origins: matches });
  const scripts = await browser.scripting.getRegisteredContentScripts({ ids: [id] });
  if (scripts.length) await browser.scripting.unregisterContentScripts({ ids: [id] });
  if (allowed) await browser.scripting.registerContentScripts([{
    id, matches, js: ["shared/kuma-adapter.js", "shared/ioc-providers.js", "content/content.js", "content/ioc-menu.js"],
    allFrames: true, runAt: "document_idle", persistAcrossSessions: true,
  }]);
  for (const tab of await browser.tabs.query({})) {
    if (!tab.id || !tab.url?.startsWith("http")) continue;
    // Remove any menu from a previously configured host.
    await browser.tabs.sendMessage(tab.id, { type: "ioc:menu:stop" }).catch(() => {});
    if (!allowed || new URL(tab.url).origin !== origin) continue;
    const files = ["/shared/kuma-adapter.js", "/shared/ioc-providers.js", "/content/content.js", "/content/ioc-menu.js"];
    try {
      await browser.scripting.executeScript({ target: { tabId: tab.id, allFrames: true }, files });
    } catch {
      await browser.scripting.executeScript({ target: { tabId: tab.id }, files }).catch(() => {});
    }
  }
}
let contentSync = Promise.resolve();
function scheduleIocContent() {
  contentSync = contentSync.then(syncIocContent).catch(() => {});
}
browser.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.uiOrigin) scheduleIocContent();
});
browser.permissions.onAdded.addListener(scheduleIocContent);
browser.permissions.onRemoved.addListener(scheduleIocContent);
scheduleIocContent();
