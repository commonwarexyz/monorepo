import { rm } from "node:fs/promises";
import { relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = new URL("../", import.meta.url);
const outdir = fileURLToPath(new URL("dist/", root));

await rm(outdir, { recursive: true, force: true });

const result = await Bun.build({
  entrypoints: [fileURLToPath(new URL("src/index.html", root))],
  outdir,
  target: "browser",
  minify: true,
});

if (!result.success) {
  for (const log of result.logs) {
    console.error(log);
  }
  process.exit(1);
}

for (const output of result.outputs) {
  const relativePath = relative(outdir, output.path);
  console.log(`${relativePath}  ${(output.size / 1024).toFixed(2)} KB`);
}
