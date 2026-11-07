"use strict";
// Shipmark SBOM action: finds mobile lockfiles, writes a CycloneDX 1.6 SBOM
// and (optionally) checks every component against OSV.dev.
// No dependencies: runs on the Node 20 runtime that GitHub provides.

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { parserFor, purl } = require("./parsers");

const SKIP_DIRS = new Set(["node_modules", ".git", "Pods", "build", ".dart_tool", ".gradle", "DerivedData", ".expo", "vendor"]);
const SEVERITY_RANK = { LOW: 1, MODERATE: 2, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

function input(name, fallback = "") {
  const v = process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`];
  return v === undefined || v === "" ? fallback : v.trim();
}

function setOutput(name, value) {
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
}

function summary(md) {
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, md + "\n");
}

function findLockfiles(root) {
  const found = [];
  (function walk(dir, depth) {
    if (depth > 8) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name) && !e.name.startsWith(".") || e.name === ".swiftpm" || e.name.endsWith(".xcworkspace") || e.name.endsWith(".xcodeproj")) walk(full, depth + 1);
      } else if (e.isFile() && parserFor(e.name)) {
        found.push(full);
      }
    }
  })(root, 0);
  return found.sort();
}

async function osvQuery(comps) {
  const checkable = comps.filter((c) => c.eco !== "CocoaPods" && !c.pinnedByRevision);
  const hits = {};
  for (let i = 0; i < checkable.length; i += 500) {
    const chunk = checkable.slice(i, i + 500);
    const res = await fetch("https://api.osv.dev/v1/querybatch", {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": "shipmark-sbom-action" },
      body: JSON.stringify({ queries: chunk.map((c) => ({ package: { name: c.name, ecosystem: c.eco }, version: c.version })) }),
    });
    if (!res.ok) throw new Error(`OSV returned ${res.status}`);
    const json = await res.json();
    (json.results || []).forEach((r, k) => {
      for (const v of r.vulns || []) (hits[v.id] = hits[v.id] || []).push(chunk[k]);
    });
  }
  const details = {};
  const ids = Object.keys(hits);
  for (let i = 0; i < ids.length; i += 10) {
    await Promise.all(ids.slice(i, i + 10).map(async (id) => {
      try {
        const r = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { headers: { "user-agent": "shipmark-sbom-action" } });
        if (r.ok) details[id] = await r.json();
      } catch { /* details are optional */ }
    }));
  }
  return { hits, details };
}

function severityOf(v) {
  const s = v && v.database_specific && String(v.database_specific.severity || "").toUpperCase();
  return SEVERITY_RANK[s] ? s : "UNKNOWN";
}

function buildBom(appName, comps, hits, details) {
  const bom = {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
      tools: { components: [{ type: "application", name: "Shipmark SBOM Action", publisher: "Shipmark",
        externalReferences: [{ type: "website", url: "https://shipmark.eu/" }] }] },
      component: { type: "application", "bom-ref": "app", name: appName },
    },
    components: comps.map((c) => {
      const o = { type: "library", "bom-ref": c.purl, name: c.display || c.name, version: c.version, purl: c.purl };
      if (c.dev) o.scope = "excluded";
      return o;
    }),
    dependencies: [{ ref: "app", dependsOn: comps.filter((c) => c.direct).map((c) => c.purl) }],
  };
  const vulns = Object.keys(hits).map((id) => {
    const d = details[id] || {};
    const sev = severityOf(d);
    const o = { "bom-ref": `vuln-${id}`, id, source: { name: "OSV", url: `https://osv.dev/vulnerability/${id}` },
      affects: [...new Set(hits[id].map((c) => c.purl))].map((ref) => ({ ref })) };
    if (d.summary) o.description = d.summary;
    if (sev !== "UNKNOWN") o.ratings = [{ source: { name: "OSV" }, severity: sev === "MODERATE" ? "medium" : sev.toLowerCase() }];
    return o;
  });
  if (vulns.length) bom.vulnerabilities = vulns;
  return bom;
}

async function main() {
  const root = path.resolve(process.env.GITHUB_WORKSPACE || process.cwd(), input("path", "."));
  const output = input("output", "sbom.cdx.json");
  const appName = input("app-name", (process.env.GITHUB_REPOSITORY || path.basename(root)).split("/").pop());
  const check = input("check-vulnerabilities", "true") !== "false";
  const includeDev = input("include-dev", "false") === "true";
  const failOn = input("fail-on", "none").toUpperCase();

  const files = findLockfiles(root);
  if (!files.length) {
    console.log(`::error::No supported lockfile found under ${root}. Supported: pubspec.lock, package-lock.json, yarn.lock, Podfile.lock, Package.resolved, gradle.lockfile.`);
    process.exit(1);
  }

  const byPurl = new Map();
  for (const f of files) {
    const comps = parserFor(path.basename(f))(fs.readFileSync(f, "utf8"));
    console.log(`${path.relative(root, f) || path.basename(f)}: ${comps.length} components`);
    for (const c of comps) {
      c.purl = purl(c);
      const prev = byPurl.get(c.purl);
      if (prev) { prev.direct = prev.direct || c.direct; prev.dev = prev.dev && c.dev; } else byPurl.set(c.purl, c);
    }
  }
  let comps = [...byPurl.values()];
  if (!includeDev) comps = comps.filter((c) => !c.dev);

  let hits = {}, details = {};
  if (check) {
    try { ({ hits, details } = await osvQuery(comps)); }
    catch (e) { console.log(`::warning::Vulnerability check skipped: ${e.message}`); }
  }

  const bom = buildBom(appName, comps, hits, details);
  const outPath = path.resolve(process.env.GITHUB_WORKSPACE || process.cwd(), output);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(bom, null, 2) + "\n");

  const ids = Object.keys(hits);
  const worst = ids.reduce((m, id) => Math.max(m, SEVERITY_RANK[severityOf(details[id])] || 0), 0);
  setOutput("sbom-path", outPath);
  setOutput("components", comps.length);
  setOutput("vulnerabilities", ids.length);

  console.log(`SBOM written to ${output}: ${comps.length} components, ${ids.length} known vulnerabilities.`);
  for (const id of ids) {
    const d = details[id] || {};
    const names = [...new Set(hits[id].map((c) => `${c.display || c.name}@${c.version}`))].join(", ");
    console.log(`::warning title=${id} (${severityOf(d)})::${names}: ${d.summary || "see https://osv.dev/vulnerability/" + id}`);
  }

  let md = `### SBOM for ${appName}\n\n`;
  md += `| Lockfiles | Components | Known vulnerabilities |\n|---|---|---|\n| ${files.length} | ${comps.length} | ${check ? ids.length : "not checked"} |\n\n`;
  if (ids.length) {
    md += `| ID | Severity | Component | Summary |\n|---|---|---|---|\n`;
    for (const id of ids.slice(0, 50)) {
      const d = details[id] || {};
      const names = [...new Set(hits[id].map((c) => `${c.display || c.name}@${c.version}`))].join(", ");
      md += `| [${id}](https://osv.dev/vulnerability/${id}) | ${severityOf(d)} | ${names} | ${(d.summary || "").replace(/\|/g, "\\|")} |\n`;
    }
    if (ids.length > 50) md += `\n…and ${ids.length - 50} more, all listed in the SBOM.\n`;
  }
  md += `\nCycloneDX 1.6 SBOM: \`${output}\`. Generated by [Shipmark SBOM Action](https://github.com/shipmark-eu/sbom-action). Need to keep SBOMs for every release under the EU Cyber Resilience Act? See [shipmark.eu](https://shipmark.eu/).\n`;
  summary(md);

  const threshold = failOn === "ANY" ? 1 : SEVERITY_RANK[failOn] || 0;
  if (threshold && ids.length && (failOn === "ANY" || worst >= threshold)) {
    console.log(`::error::Known vulnerabilities at or above "${failOn.toLowerCase()}" were found.`);
    process.exit(2);
  }
}

if (require.main === module) {
  main().catch((e) => { console.log(`::error::${e.stack || e.message}`); process.exit(1); });
}

module.exports = { findLockfiles, buildBom, severityOf };
