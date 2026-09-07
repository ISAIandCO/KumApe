(function (global) {
  "use strict";
  // Provider endpoints follow ApePatrol's read-only IOC lookups (Apache-2.0).
  async function lookup(providerId, input) {
    const provider = global.KumApeIoc.PROVIDERS[providerId];
    const ioc = global.KumApeIoc.validateIoc(input);
    if (!provider?.types.includes(ioc.type)) throw new Error("Провайдер не поддерживает этот тип IOC");
    const { iocApiKeys = {} } = await browser.storage.local.get("iocApiKeys");
    const key = iocApiKeys[providerId];
    if (!key) throw new Error(`${provider.name}: добавьте API-ключ в настройках KumApe`);
    if (!await browser.permissions.contains({ origins: [`${provider.origin}/*`], data_collection: ["websiteContent", "authenticationInfo"] })) {
      throw new Error(`${provider.name}: сохраните ключ заново, чтобы выдать доступ Firefox`);
    }
    let url;
    const headers = { Accept: "application/json" };
    const hash = ["md5", "sha1", "sha256"].includes(ioc.type);
    if (providerId === "virustotal") {
      let value = ioc.value;
      if (ioc.type === "url") {
        let binary = "";
        for (const byte of new TextEncoder().encode(value)) binary += String.fromCharCode(byte);
        value = btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
      }
      const resource = hash ? "files" : { ip: "ip_addresses", domain: "domains", url: "urls" }[ioc.type];
      url = new URL(`/api/v3/${resource}/${encodeURIComponent(value)}`, provider.origin);
      headers["x-apikey"] = key;
    } else if (providerId === "opentip") {
      url = new URL(`/api/v1/search/${hash ? "hash" : ioc.type}`, provider.origin);
      url.searchParams.set("request", ioc.value);
      headers["x-api-key"] = key;
    } else {
      url = new URL("/api/v2/check", provider.origin);
      url.searchParams.set("ipAddress", ioc.value);
      url.searchParams.set("maxAgeInDays", "90");
      headers.Key = key;
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20_000);
    try {
      const response = await fetch(url, { method: "GET", headers, credentials: "omit", redirect: "error", signal: controller.signal });
      if (response.status === 404) return { provider: provider.name, summary: "Отчёт не найден. Это не означает, что IOC безопасен." };
      if (!response.ok) {
        const hint = response.status === 429 ? "Лимит запросов; повторите позже."
          : [401, 403].includes(response.status) ? "Проверьте ключ и права API провайдера." : "Не удалось получить отчёт.";
        throw new Error(`${provider.name}: HTTP ${response.status}. ${hint}`);
      }
      const body = await response.json();
      let details;
      let summary;
      if (providerId === "virustotal") {
        const stats = body?.data?.attributes?.last_analysis_stats;
        if (!stats) throw new Error("VirusTotal: в ответе нет результатов анализа");
        details = stats;
        summary = `Вредоносных: ${stats.malicious ?? 0}; подозрительных: ${stats.suspicious ?? 0}; без детекта: ${stats.undetected ?? 0}. Отсутствие детектов не гарантирует безопасность.`;
      } else if (providerId === "opentip") {
        if (!body?.Zone) throw new Error("OpenTIP: в ответе нет оценки Zone");
        const info = body.FileGeneralInfo ?? body.IpGeneralInfo ?? body.DomainGeneralInfo ?? body.UrlGeneralInfo ?? {};
        summary = `Зона: ${body.Zone}; статус: ${info.FileStatus ?? info.Status ?? body.Status ?? "не указан"}`;
        details = { zone: body.Zone, categories: info.Categories ?? body.Categories ?? [] };
      } else {
        if (body?.data?.abuseConfidenceScore == null) throw new Error("AbuseIPDB: в ответе нет оценки");
        const data = body.data;
        summary = `Оценка злоупотреблений: ${data.abuseConfidenceScore}%; жалоб: ${data.totalReports ?? 0}; страна: ${data.countryCode ?? "не указана"}`;
        details = { lastReportedAt: data.lastReportedAt, isp: data.isp, usageType: data.usageType };
      }
      return { provider: provider.name, summary, details };
    } catch (error) {
      if (error.name === "AbortError") throw new Error(`${provider.name}: превышено время ожидания`);
      throw error;
    } finally { clearTimeout(timer); }
  }
  global.KumApeLookup = Object.freeze({ lookup });
})(globalThis);
