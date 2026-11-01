#!/usr/bin/env node
// Guards the "generated SQL goes through the governance wrapper" rule.
//
// User-typed SQL reaches the audited entry points in `query`. Schema changes,
// imports, exports, and rebuilds call drivers directly; those call sites are
// allowed to exist only in the recorded baseline. Adding a new direct driver
// execution (or another one to an existing file) fails this check until the
// call is routed through `governance::execute_generated_sql` and the baseline
// is updated deliberately.
//
// Usage:
//   node scripts/check-governed-sql.mjs           # verify
//   node scripts/check-governed-sql.mjs --update  # rewrite the baseline

import { readFileSync, writeFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, relative, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const baselinePath = join(root, "scripts", "governed-sql-baseline.json");
const scanRoots = ["crates/dbx-core/src", "src-tauri/src", "crates/dbx-mcp/src", "crates/dbx-cli/src"];
const skipDirs = new Set(["target", "node_modules", "tests", "testdata", "fixtures"]);
// The wrapper itself and the audited query entry points are the sanctioned
// funnels; everything else must be in the baseline.
const sanctioned = new Set([
  "crates/dbx-core/src/query/mod.rs",
  "crates/dbx-core/src/governance/mod.rs",
]);

// Only driver-layer calls: rusqlite `conn.execute_batch` on DBX's own storage
// is schema management, not a target-database operation.
const pattern = /\bdb::[a-z_0-9:]*::execute|\bpool\.execute_|\bclient\.execute_/;

function walk(directory, files) {
  if (!existsSync(directory)) return;
  for (const entry of readdirSync(directory)) {
    if (skipDirs.has(entry)) continue;
    const full = join(directory, entry);
    const stats = statSync(full);
    if (stats.isDirectory()) {
      walk(full, files);
    } else if (entry.endsWith(".rs") && !entry.endsWith("_tests.rs")) {
      files.push(full);
    }
  }
}

const counts = new Map();
for (const scanRoot of scanRoots) {
  const files = [];
  walk(join(root, scanRoot), files);
  for (const file of files) {
    const rel = relative(root, file).replaceAll("\\", "/");
    if (sanctioned.has(rel)) continue;
    const lines = readFileSync(file, "utf8").split("\n");
    // Test-only code does not run in production; stop counting at the first
    // `#[cfg(test)]` attribute (tests are conventionally at the file end).
    const testStart = lines.findIndex((line) => line.trim() === "#[cfg(test)]");
    const productionLines = testStart >= 0 ? lines.slice(0, testStart) : lines;
    let count = 0;
    for (const line of productionLines) {
      if (line.trimStart().startsWith("//")) continue;
      if (pattern.test(line)) count += 1;
    }
    if (count > 0) counts.set(rel, count);
  }
}

const current = Object.fromEntries([...counts.entries()].sort(([a], [b]) => a.localeCompare(b)));

if (process.argv.includes("--update")) {
  writeFileSync(baselinePath, `${JSON.stringify(current, null, 2)}\n`);
  console.log(`governed-sql: baseline updated with ${Object.keys(current).length} file(s)`);
  process.exit(0);
}

const baseline = existsSync(baselinePath) ? JSON.parse(readFileSync(baselinePath, "utf8")) : {};
const problems = [];
for (const [file, count] of Object.entries(current)) {
  const allowed = baseline[file] ?? 0;
  if (count > allowed) {
    problems.push(`${file}: ${count} direct driver call(s), baseline ${allowed}`);
  }
}

if (problems.length > 0) {
  console.error("governed-sql: new direct driver execution(s) must go through governance::execute_generated_sql");
  for (const problem of problems) console.error(`  ${problem}`);
  console.error("If the call is intentional, route it through the wrapper; do not raise the baseline.");
  process.exit(1);
}

console.log(`governed-sql: ${Object.keys(current).length} file(s) match the baseline`);
