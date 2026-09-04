import { mkdir, readFile, rm } from "node:fs/promises";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const packageJson = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
const artifactDirectory = path.join(root, "artifacts");
const artifact = path.join(artifactDirectory, `kumape-${packageJson.version}-firefox.zip`);

await import("./build.mjs");
await mkdir(artifactDirectory, { recursive: true });
await rm(artifact, { force: true });

await new Promise((resolve, reject) => {
  const child = spawn("zip", ["-q", "-r", artifact, "."], { cwd: path.join(root, "dist", "firefox"), stdio: "inherit" });
  child.on("error", () => reject(new Error("Для упаковки нужен системный пакет zip")));
  child.on("exit", (code) => code === 0 ? resolve() : reject(new Error(`zip завершился с кодом ${code}`)));
});

console.log(`Created ${path.relative(root, artifact)}`);
