import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";

const html = await readFile(new URL("../index.html", import.meta.url), "utf8");
const match = html.match(/<script\s+type=["']module["']\s*>([\s\S]*?)<\/script>/i);
if (!match) {
  console.error("No module script found in index.html");
  process.exit(1);
}
const checked = spawnSync(process.execPath, ["--check", "--input-type=module"], {
  input: match[1],
  encoding: "utf8"
});
if (checked.status !== 0) {
  process.stderr.write(checked.stderr || checked.stdout || "Inline module syntax check failed.\n");
  process.exit(checked.status || 1);
}
console.log("Inline browser module syntax: OK");
