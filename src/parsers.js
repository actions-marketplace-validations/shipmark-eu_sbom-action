"use strict";
// Lockfile parsers for mobile app projects. Each returns
// [{ name, version, eco, direct, dev?, display?, pinnedByRevision?, deps?, depsComplete?, license?, sha512?, resolved? }]
// eco uses OSV ecosystem names: Pub, npm, CocoaPods, SwiftURL, Maven.

function parsePubspec(text) {
  const comps = [];
  let cur = null, inPackages = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^packages:\s*$/.test(line)) { inPackages = true; continue; }
    if (/^\S/.test(line)) { inPackages = false; cur = null; continue; }
    if (!inPackages) continue;
    let m;
    if ((m = line.match(/^  ([A-Za-z0-9_]+):\s*$/))) { cur = { name: m[1], eco: "Pub", direct: false }; comps.push(cur); continue; }
    if (!cur) continue;
    if ((m = line.match(/^    dependency:\s*"?([^"]+)"?/))) { cur.direct = m[1].startsWith("direct"); cur.dev = m[1] === "direct dev"; }
    if ((m = line.match(/^    source:\s*(\S+)/))) cur.source = m[1];
    if ((m = line.match(/^    version:\s*"?([^"\s]+)"?/))) cur.version = m[1];
  }
  return comps.filter((c) => c.version && c.source !== "sdk").map(({ source, ...c }) => c);
}

// npm and Yarn record the SHA-512 of the downloaded tarball as "integrity" (base64); the SBOM wants hex.
function integrityHex(integrity) {
  const m = /(?:^|\s)sha512-([A-Za-z0-9+/=]+)/.exec(integrity || "");
  if (!m) return null;
  const hex = Buffer.from(m[1], "base64").toString("hex");
  return hex.length === 128 ? hex : null;
}

const httpUrl = (u) => (/^https?:\/\//.test(u || "") ? u : null);

// Each parser may also return, per component: deps (the components it depends on, from the same
// lockfile), depsComplete (false when a required dependency is missing from the lockfile),
// license (as declared in package.json), sha512 (hex) and resolved (download URL).
function parsePackageLock(text) {
  const j = JSON.parse(text);
  const comps = [];
  if (j.packages) {
    const root = j.packages[""] || {};
    const directs = Object.assign({}, root.dependencies, root.devDependencies, root.optionalDependencies);
    const byPath = {}, wants = new Map();
    for (const path of Object.keys(j.packages)) {
      if (!path) continue;
      const p = j.packages[path];
      const i = path.lastIndexOf("node_modules/");
      if (i < 0 || p.link || !p.version) continue;
      const name = p.name || path.slice(i + 13);
      const c = { name, version: p.version, eco: "npm", dev: !!p.dev,
        direct: path === "node_modules/" + name && Object.prototype.hasOwnProperty.call(directs, name),
        license: typeof p.license === "string" ? p.license : null,
        sha512: integrityHex(p.integrity), resolved: httpUrl(p.resolved) };
      byPath[path] = c;
      wants.set(c, { path, p });
      comps.push(c);
    }
    // Node resolution: look in the package's own node_modules, then in each parent's, up to the root.
    for (const c of comps) {
      const { path, p } = wants.get(c);
      const find = (dep) => {
        let base = path;
        for (;;) {
          const hit = byPath[base + "/node_modules/" + dep];
          if (hit) return hit;
          const k = base.lastIndexOf("/node_modules/");
          if (k < 0) return byPath["node_modules/" + dep] || null;
          base = base.slice(0, k);
        }
      };
      const found = [];
      let complete = true;
      for (const [kind, required] of [["dependencies", true], ["optionalDependencies", false], ["peerDependencies", false]]) {
        for (const dep of Object.keys(p[kind] || {})) {
          const hit = find(dep);
          if (hit) found.push(hit);
          else if (required) complete = false;
        }
      }
      c.deps = found;
      c.depsComplete = complete;
    }
  } else if (j.dependencies) {
    (function walk(deps) {
      for (const n of Object.keys(deps)) {
        const d = deps[n];
        if (d.version) comps.push({ name: n, version: d.version, eco: "npm", dev: !!d.dev, direct: false,
          sha512: integrityHex(d.integrity), resolved: httpUrl(d.resolved) });
        if (d.dependencies) walk(d.dependencies);
      }
    })(j.dependencies);
  }
  return comps;
}

// yarn.lock, classic (v1) and Berry (v2+). Entries are keyed by the specifiers that resolve to them,
// so dependencies are found by looking up "name@range".
function parseYarnLock(text) {
  const all = [], bySpec = {}, wants = new Map();
  let cur = null, block = null;
  const unq = (s) => s.trim().replace(/^"|"$/g, "");
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line[0] === "#") continue;
    let m;
    if (/^\S/.test(line)) {
      const specs = line.replace(/:\s*$/, "").split(",").map(unq);
      const at = specs[0].indexOf("@", 1);
      const name = at > 0 ? specs[0].slice(0, at) : specs[0];
      block = null;
      if (name === "__metadata") { cur = null; continue; }
      cur = { name, eco: "npm", direct: false };
      wants.set(cur, { specs, list: [] });
      continue;
    }
    if (!cur) continue;
    if (/^  \S/.test(line)) {
      block = null;
      if ((m = line.match(/^  (dependencies|optionalDependencies|peerDependencies):\s*$/))) { block = m[1]; continue; }
      if ((m = line.match(/^  version:?\s+"?([^"\s]+)"?/))) {
        cur.version = m[1];
        all.push(cur);
        for (const s of wants.get(cur).specs) bySpec[s] = cur;
        continue;
      }
      if ((m = line.match(/^  resolved:?\s+"?([^"\s]+)"?/))) { const u = httpUrl(m[1].replace(/#.*$/, "")); if (u) cur.resolved = u; continue; }
      if ((m = line.match(/^  integrity:?\s+"?([^"\s]+)"?/))) { cur.sha512 = integrityHex(m[1]); continue; }
      continue;
    }
    if (block && (m = line.match(/^    ("?[^"\s:]+"?):?\s+(.+)$/))) {
      wants.get(cur).list.push({ name: unq(m[1]), range: unq(m[2]), required: block === "dependencies" });
    }
  }
  const local = (c) => /^0\.0\.0-use\.local$/.test(c.version);
  for (const c of all) {
    const w = wants.get(c);
    const found = [];
    let complete = true;
    for (const d of w.list) {
      const r = d.range.replace(/^npm:/, "");
      const hit = bySpec[d.name + "@" + d.range] || bySpec[d.name + "@npm:" + r] || bySpec[d.name + "@" + r];
      if (hit && !local(hit)) found.push(hit);
      else if (!hit && d.required) complete = false;
    }
    c.deps = found;
    c.depsComplete = complete;
    // Yarn Berry lists the project itself as "name@workspace:."; its dependencies are the direct ones.
    if (w.specs.some((s) => /@workspace:\.$/.test(s))) for (const d of found) d.direct = true;
  }
  return all.filter((c) => !local(c));
}

function parsePodfileLock(text) {
  const comps = [], directs = {}, byName = {}, wants = new Map();
  let section = "", cur = null;
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line)) { section = line.replace(/:.*$/, ""); cur = null; continue; }
    let m;
    if (section === "PODS" && (m = line.match(/^  - "?([^\s"(]+) \(([^)]+)\)/))) {
      cur = { name: m[1], version: m[2], eco: "CocoaPods", direct: false };
      wants.set(cur, []);
      byName[cur.name] = cur;
      comps.push(cur);
    } else if (section === "PODS" && cur && (m = line.match(/^    - "?([^\s"(]+)/))) {
      wants.get(cur).push(m[1]);
    } else if (section === "DEPENDENCIES" && (m = line.match(/^  - "?([^\s"(]+)/))) {
      directs[m[1]] = true;
    }
  }
  for (const c of comps) {
    const w = wants.get(c);
    c.direct = !!directs[c.name];
    c.deps = w.map((n) => byName[n]).filter(Boolean);
    c.depsComplete = c.deps.length === w.length;
  }
  return comps;
}

function parsePackageResolved(text) {
  const j = JSON.parse(text);
  const pins = j.pins || (j.object && j.object.pins) || [];
  return pins.map((p) => {
    const url = (p.location || p.repositoryURL || "").replace(/^https?:\/\//, "").replace(/\.git$/, "").replace(/\/$/, "");
    const v = p.state && (p.state.version || (p.state.revision && p.state.revision.slice(0, 12)));
    return { name: url || p.identity || p.package, display: p.identity || p.package, version: v, eco: "SwiftURL",
      direct: false, pinnedByRevision: !(p.state && p.state.version) };
  }).filter((c) => c.name && c.version);
}

function parseGradleLock(text) {
  const seen = new Set(), comps = [];
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^([^#=\s:]+):([^=\s:]+):([^=\s:]+)=(.*)$/);
    if (!m) continue;
    const key = `${m[1]}:${m[2]}@${m[3]}`;
    if (seen.has(key)) continue;
    seen.add(key);
    comps.push({ name: `${m[1]}:${m[2]}`, version: m[3], eco: "Maven", direct: false,
      dev: !m[4].split(",").some((c) => /runtimeclasspath$/i.test(c) && !/test/i.test(c) && !/^debug/i.test(c)) });
  }
  return comps;
}

// Lockfile names this action understands, mapped to their parser.
const LOCKFILES = {
  "pubspec.lock": parsePubspec,
  "package-lock.json": parsePackageLock,
  "npm-shrinkwrap.json": parsePackageLock,
  "yarn.lock": parseYarnLock,
  "Podfile.lock": parsePodfileLock,
  "Package.resolved": parsePackageResolved,
  "gradle.lockfile": parseGradleLock,
};

function parserFor(fileName) {
  if (LOCKFILES[fileName]) return LOCKFILES[fileName];
  if (fileName.endsWith(".lockfile")) return parseGradleLock; // per-configuration Gradle lockfiles
  return null;
}

function purl(c) {
  const v = "@" + encodeURIComponent(c.version);
  switch (c.eco) {
    case "Pub": return `pkg:pub/${c.name.toLowerCase()}${v}`;
    case "npm":
      if (c.name.startsWith("@")) { const [scope, n] = c.name.split("/"); return `pkg:npm/%40${scope.slice(1)}/${n}${v}`; }
      return `pkg:npm/${c.name}${v}`;
    case "CocoaPods": {
      const parts = c.name.split("/");
      return `pkg:cocoapods/${parts[0]}${v}${parts[1] ? "#" + parts.slice(1).join("/") : ""}`;
    }
    case "SwiftURL": return `pkg:swift/${c.name}${v}`;
    case "Maven": { const [g, a] = c.name.split(":"); return `pkg:maven/${g}/${a}${v}`; }
  }
  return "";
}

module.exports = { integrityHex, parsePubspec, parsePackageLock, parseYarnLock, parsePodfileLock, parsePackageResolved, parseGradleLock, parserFor, purl, LOCKFILES };
