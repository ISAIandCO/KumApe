import { IOC_API_PROVIDERS } from "./core/providers.js";
(function (global) {
  "use strict";
  const PROVIDERS = Object.freeze(Object.fromEntries(Object.entries(IOC_API_PROVIDERS).map(([id, provider]) => [id, {
    ...provider, origin: provider.origin.replace(/\/\*$/, ""),
    types: provider.types.flatMap(type => type === "hash" ? ["md5", "sha1", "sha256"] : [type]),
  }])));

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
