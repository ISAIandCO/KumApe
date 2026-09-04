import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const output = path.join(root, "dist", "firefox");
const packageJson = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));

await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
for (const directory of ["background", "content", "options", "popup", "shared"]) {
  await cp(path.join(root, "src", directory), path.join(output, directory), { recursive: true });
}
await cp(path.join(root, "assets", "icons"), path.join(output, "assets", "icons"), { recursive: true });

const template = await readFile(path.join(root, "src", "manifest.firefox.json"), "utf8");
const manifest = JSON.parse(template.replace("__VERSION__", packageJson.version));
await writeFile(path.join(output, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);

console.log(`Built Firefox extension ${packageJson.version} in dist/firefox`);
