#!/usr/bin/env node

/**
 * axios-vuln-scanner
 * Scans Node.js projects for vulnerable axios versions.
 * Vulnerability data fetched live from OSV API (https://osv.dev).
 * https://github.com/ikhd/axios-vuln-scanner
 */

const fs    = require("fs");
const path  = require("path");
const https = require("https");

// ── Colors ──────────────────────────────────────────────────
const RESET  = "\x1b[0m";
const RED    = "\x1b[31m";
const YELLOW = "\x1b[33m";
const GREEN  = "\x1b[32m";
const CYAN   = "\x1b[36m";
const BOLD   = "\x1b[1m";
const DIM    = "\x1b[2m";

// ── OSV API ──────────────────────────────────────────────────
// POST https://api.osv.dev/v1/query
// Docs: https://google.github.io/osv.dev/api/
function osvQuery(version) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      version,
      package: { name: "axios", ecosystem: "npm" },
    });

    const req = https.request(
      "https://api.osv.dev/v1/query",
      {
        method: "POST",
        headers: {
          "Content-Type":  "application/json",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          try { resolve(JSON.parse(data)); }
          catch { reject(new Error("OSV response parse error")); }
        });
      }
    );
    req.on("error", reject);
    req.setTimeout(8000, () => req.destroy(new Error("OSV request timed out")));
    req.write(body);
    req.end();
  });
}

function parseOsvVulns(osvData) {
  if (!osvData?.vulns?.length) return [];
  return osvData.vulns.map((v) => {
    const cve      = v.aliases?.find((a) => a.startsWith("CVE-")) ?? v.id;
    const severity = v.database_specific?.severity ?? v.severity?.[0]?.score ?? "UNKNOWN";
    const summary  = v.summary ?? "No description";
    const fixed    = extractFixed(v);
    return { id: v.id, cve, severity, summary, fixed };
  });
}

function extractFixed(vuln) {
  for (const aff of vuln.affected ?? []) {
    for (const range of aff.ranges ?? []) {
      for (const ev of range.events ?? []) {
        if (ev.fixed) return ev.fixed;
      }
    }
  }
  return null;
}

// ── Offline fallback DB ──────────────────────────────────────
function parseVersion(v) {
  return v.replace(/[^0-9.]/g, "").split(".").map(Number);
}
function isBelow(version, threshold) {
  const a = parseVersion(version);
  const b = parseVersion(threshold);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] || 0, y = b[i] || 0;
    if (x < y) return true;
    if (x > y) return false;
  }
  return false;
}

const OFFLINE_DB = [
  {
    cve: "CVE-2023-45857", severity: "HIGH", fixed: "1.6.0",
    summary: "CSRF via forged request headers",
    affects: (v) => isBelow(v, "0.28.0") || (!isBelow(v, "1.0.0") && isBelow(v, "1.6.0")),
  },
];

function checkOffline(version) {
  if (!version) return [];
  return OFFLINE_DB
    .filter((r) => r.affects(version))
    .map(({ cve, severity, summary, fixed }) => ({ id: cve, cve, severity, summary, fixed }));
}

// ── CLI flags ────────────────────────────────────────────────
function parseArgs() {
  const flags = { includeDist: false, scanDev: true, exitOnVuln: true, offline: false, target: null };
  for (const arg of process.argv.slice(2)) {
    if      (arg === "--no-dev")        flags.scanDev     = false;
    else if (arg === "--include-dist")  flags.includeDist = true;
    else if (arg === "--no-exit")       flags.exitOnVuln  = false;
    else if (arg === "--offline")       flags.offline     = true;
    else if (!arg.startsWith("--"))     flags.target      = arg;
  }
  return flags;
}

// ── Filesystem scan ──────────────────────────────────────────
const SKIP_ALWAYS = ["node_modules", ".git"];
const SKIP_BUILD  = ["dist", ".next", "build", "out"];

function collectProjects(dir, flags) {
  let results = [];
  let files;
  try { files = fs.readdirSync(dir); } catch { return results; }

  for (const file of files) {
    const fullPath = path.join(dir, file);
    let stat;
    try { stat = fs.statSync(fullPath); } catch { continue; }

    if (stat.isDirectory()) {
      if (SKIP_ALWAYS.includes(file)) continue;
      if (!flags.includeDist && SKIP_BUILD.includes(file)) continue;
      results = results.concat(collectProjects(fullPath, flags));
      continue;
    }

    if (file !== "package.json") continue;

    const projectDir  = path.dirname(fullPath);
    const projectName = path.basename(projectDir);
    let directAxios = null, installedAxios = null;

    try {
      const pkg = JSON.parse(fs.readFileSync(fullPath, "utf-8"));
      if (pkg.dependencies?.axios)                        directAxios = pkg.dependencies.axios;
      else if (flags.scanDev && pkg.devDependencies?.axios) directAxios = `[dev] ${pkg.devDependencies.axios}`;
    } catch {}

    const axiosPkgPath = path.join(projectDir, "node_modules", "axios", "package.json");
    if (fs.existsSync(axiosPkgPath)) {
      try { installedAxios = JSON.parse(fs.readFileSync(axiosPkgPath, "utf-8")).version; } catch {}
    }

    if (directAxios || installedAxios) {
      results.push({ projectName, pkgPath: fullPath, directAxios, installedAxios });
    }
  }
  return results;
}

// ── Fetch vulns (dedup versions, parallel requests) ──────────
async function fetchVulnsMap(versions, flags) {
  const map    = {};
  const unique = [...new Set(versions.filter(Boolean))];

  if (flags.offline || unique.length === 0) {
    for (const v of unique) map[v] = checkOffline(v);
    return map;
  }

  process.stdout.write(`${DIM}Querying OSV API for ${unique.length} version(s)...${RESET}\n`);

  await Promise.all(unique.map(async (v) => {
    try {
      map[v] = parseOsvVulns(await osvQuery(v));
    } catch {
      process.stdout.write(`${YELLOW}  ⚠ OSV unreachable for axios@${v} — using offline fallback${RESET}\n`);
      map[v] = checkOffline(v);
    }
  }));

  return map;
}

// ── Main ─────────────────────────────────────────────────────
async function main() {
  const flags     = parseArgs();
  const absTarget = path.resolve(flags.target || process.cwd());

  console.log(`\n${BOLD}${CYAN}axios-vuln-scanner${RESET}`);
  console.log(`${DIM}Scanning     : ${absTarget}${RESET}`);
  console.log(`${DIM}devDeps      : ${flags.scanDev     ? "included" : "ignored"}${RESET}`);
  console.log(`${DIM}dist/.next   : ${flags.includeDist ? "included" : "ignored"}${RESET}`);
  console.log(`${DIM}Vuln source  : ${flags.offline     ? "offline DB" : "OSV API (live)"}${RESET}\n`);

  const projects = collectProjects(absTarget, flags);

  if (projects.length === 0) {
    console.log(`${GREEN}✔ No axios dependencies found.${RESET}\n`);
    return;
  }

  const vulnsMap = await fetchVulnsMap(projects.map((p) => p.installedAxios), flags);
  let vulnerable = 0, safe = 0;

  for (const r of projects) {
    const vulns    = r.installedAxios ? (vulnsMap[r.installedAxios] ?? []) : [];
    const hasVulns = vulns.length > 0;
    if (hasVulns) vulnerable++; else safe++;

    const marker = hasVulns ? `${RED}✖ VULNERABLE${RESET}` : `${GREEN}✔ OK${RESET}`;

    console.log("─".repeat(52));
    console.log(`${BOLD}Project   :${RESET} ${r.projectName}  ${marker}`);
    console.log(`${DIM}Path      : ${r.pkgPath}${RESET}`);
    console.log(`Declared  : ${r.directAxios   ?? "—"}`);
    console.log(`Installed : ${r.installedAxios ?? "—"}`);

    for (const v of vulns) {
      const sev   = String(v.severity).toUpperCase();
      const color = sev.includes("HIGH") || sev.includes("CRITICAL") ? RED : YELLOW;
      console.log(`${color}  ⚠  ${v.cve} [${v.severity}]${RESET}`);
      console.log(`${color}     ${v.summary}${RESET}`);
      if (v.fixed) console.log(`${color}     Fix: upgrade axios to >= ${v.fixed}${RESET}`);
    }
  }

  console.log("─".repeat(52));
  console.log(`\n${BOLD}Summary:${RESET} ${projects.length} project(s) — ` +
    `${RED}${vulnerable} vulnerable${RESET}, ${GREEN}${safe} safe${RESET}\n`);

  if (flags.exitOnVuln && vulnerable > 0) process.exit(1);
}

main().catch((err) => {
  console.error(`${RED}Fatal: ${err.message}${RESET}`);
  process.exit(2);
});