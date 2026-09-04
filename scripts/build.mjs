import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

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
for (const directory of ["background", "content", "options", "popup", "shared"]) {
  await cp(path.join(root, "src", directory), path.join(output, directory), { recursive: true });
}
await cp(path.join(root, "assets", "icons"), path.join(output, "assets", "icons"), { recursive: true });

const template = await readFile(path.join(root, "src", "manifest.firefox.json"), "utf8");
const manifest = JSON.parse(template
  .replaceAll("__VERSION__", packageJson.version)
  .replace("__SELF_HOSTED_UPDATE_URL__", updateUrl));
if (!selfHosted) delete manifest.browser_specific_settings.gecko.update_url;
await writeFile(path.join(output, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);

console.log(`Built Firefox extension ${packageJson.version} in ${path.relative(root, output)}`);
