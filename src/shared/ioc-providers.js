(function (global) {
  "use strict";
  const PROVIDERS = Object.freeze({
    virustotal: { name: "VirusTotal", origin: "https://www.virustotal.com", types: ["ip", "domain", "url", "md5", "sha1", "sha256"] },
    opentip: { name: "Kaspersky OpenTIP", origin: "https://opentip.kaspersky.com", types: ["ip", "domain", "url", "md5", "sha1", "sha256"] },
    abuseipdb: { name: "AbuseIPDB", origin: "https://api.abuseipdb.com", types: ["ip"] },
  });

  function validateIoc(input) {
    const value = typeof input?.value === "string" ? input.value.trim() : "";
    const type = global.KumApeAdapter.iocType(value);
    if (!type || type !== input.type || value.length > 8192) throw new Error("Недопустимый IOC");
    if (type === "ip" || type === "url") {
      try {
        const url = new URL(type === "url" ? value : `https://${value.includes(":") ? `[${value}]` : value}`);
        if (url.username || url.password) throw new Error();
      } catch { throw new Error("Некорректный IP или URL"); }
    }
    return { type, value };
  }

  global.KumApeIoc = Object.freeze({ PROVIDERS, validateIoc });
})(globalThis);
