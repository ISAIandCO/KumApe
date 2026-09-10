import { lookupIoc } from "@isaiandco/ape-share-core/ioc/client";

// Compatibility boundary: keep existing KumApe messages, key names and permissions.
async function lookup(providerId, input) {
  const provider = globalThis.KumApeIoc.PROVIDERS[providerId];
  const ioc = globalThis.KumApeIoc.validateIoc(input);
  if (!provider?.types.includes(ioc.type)) throw new Error("Провайдер не поддерживает этот тип IOC");
  const { iocApiKeys = {} } = await browser.storage.local.get("iocApiKeys");
  const key = String(iocApiKeys[providerId] ?? "").trim();
  if (!key) throw new Error(`${provider.name}: добавьте API-ключ в настройках KumApe`);
  if (!await browser.permissions.contains({ origins: [`${provider.origin}/*`], data_collection: ["websiteContent", "authenticationInfo"] })) throw new Error(`${provider.name}: сохраните ключ заново, чтобы выдать доступ Firefox`);
  try {
    return await lookupIoc(providerId, { type: ["md5", "sha1", "sha256"].includes(ioc.type) ? "hash" : ioc.type, value: ioc.value }, { [provider.secret]: key });
  } catch (error) {
    if (error.status === 404) return { provider: provider.name, verdict: "unknown", summary: "Отчёт не найден. Это не означает, что IOC безопасен." };
    const hint = error.status === 429 ? "Лимит запросов; повторите позже."
      : error.status === 401 ? "Сохранённый ключ отклонён API провайдера."
        : error.status === 403 ? "Сохранённый ключ не даёт доступа к этому API." : null;
    if (hint) throw new Error(`${provider.name}: HTTP ${error.status}. ${hint}`);
    if (error.name === "AbortError") throw new Error(`${provider.name}: превышено время ожидания`);
    throw error;
  }
}
globalThis.KumApeLookup = Object.freeze({ lookup });
