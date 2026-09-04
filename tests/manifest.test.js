import test from "node:test";
import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(await readFile(path.join(root, "src", "manifest.firefox.json"), "utf8"));

test("manifest avoids persistent all-site access", () => {
  assert.equal(manifest.manifest_version, 3);
  assert.ok(!JSON.stringify(manifest).includes("<all_urls>"));
  assert.deepEqual(manifest.permissions.sort(), ["activeTab", "scripting", "storage", "tabs"]);
});

test("manifest entry points and icons exist", async () => {
  const paths = [
    manifest.action.default_popup,
    manifest.options_ui.page,
    ...manifest.background.scripts,
    ...Object.values(manifest.icons),
  ];
  await Promise.all(paths.map((file) => access(path.join(file.startsWith("assets/") ? root : path.join(root, "src"), file))));
});
