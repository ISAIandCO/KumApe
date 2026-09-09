import { prepareCore } from "./resolve-core.mjs";
import { build } from "esbuild";
import { cp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const coreBuild = await prepareCore();
const corePackage = path.dirname(fileURLToPath(import.meta.resolve("@isaiandco/ape-share-core/package.json")));
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const argValue = (name) => {
  const prefix = `${name}=`;
  const value = process.argv.find((arg) => arg.startsWith(prefix));
  return value ? value.slice(prefix.length) : undefined;
};
const output = path.resolve(root, argValue("--out-dir") ?? "dist/firefox");
const selfHosted = process.argv.includes("--self-hosted");
const packageJson = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
const updateUrl = `https://github.com/${process.env.GITHUB_REPOSITORY || "ISAIandCO/KumApe"}/releases/latest/download/updates.json`;

await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
await writeFile(path.join(output, "apesharecore-build.json"), `${JSON.stringify(coreBuild, null, 2)}\n`);
for (const directory of ["ai", "background", "content", "options", "popup", "process-graph", "shared", "workspace"]) {
  await cp(path.join(root, "src", directory), path.join(output, directory), { recursive: true });
}
async function moduleEntries(directory) {
  const entries = [];
  for (const item of await readdir(directory, { withFileTypes: true })) {
    const file = path.join(directory, item.name);
    if (item.isDirectory()) entries.push(...await moduleEntries(file));
    else if (item.name.endsWith(".js") && /^(?:import|export)\s/m.test(await readFile(file, "utf8"))) entries.push(file);
  }
  return entries;
}
const classic = new Set(["shared/ioc-providers.js", "background/ioc-lookup.js"].map(file => path.join(root, "src", file)));
await build({ entryPoints: (await moduleEntries(path.join(root, "src"))).filter(file => !classic.has(file)),
  outbase: path.join(root, "src"), outdir: output, bundle: true, format: "esm", platform: "browser", target: "firefox140" });
// Classic-script boundaries bundle the same ES modules consumed by ApePatrol.
await build({ entryPoints: ["shared/ioc-providers.js", "background/ioc-lookup.js"].map(file => path.join(root, "src", file)),
  outbase: path.join(root, "src"), outdir: output, bundle: true, format: "iife", platform: "browser", target: "firefox140" });
await cp(path.join(root, "assets", "icons"), path.join(output, "assets", "icons"), { recursive: true });

await mkdir(path.join(output, "licenses"), { recursive: true });
await cp(path.join(corePackage, "LICENSE"), path.join(output, "licenses", "ApeShareCore-LICENSE.txt"));

const template = await readFile(path.join(root, "src", "manifest.firefox.json"), "utf8");
const manifest = JSON.parse(template
  .replaceAll("__VERSION__", packageJson.version)
  .replace("__SELF_HOSTED_UPDATE_URL__", updateUrl));
if (!selfHosted) delete manifest.browser_specific_settings.gecko.update_url;
await writeFile(path.join(output, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);

console.log(`Built Firefox extension ${packageJson.version} in ${path.relative(root, output)}`);
