"use strict";
// Lockfile parsers for mobile app projects. Each returns
// [{ name, version, eco, direct, dev?, display?, pinnedByRevision? }]
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

function parsePackageLock(text) {
  const j = JSON.parse(text);
  const comps = [];
  if (j.packages) {
    const root = j.packages[""] || {};
    const directs = Object.assign({}, root.dependencies, root.devDependencies, root.optionalDependencies);
    for (const path of Object.keys(j.packages)) {
      if (!path) continue;
      const p = j.packages[path];
      const i = path.lastIndexOf("node_modules/");
      if (i < 0 || p.link || !p.version) continue;
      const name = p.name || path.slice(i + 13);
      comps.push({ name, version: p.version, eco: "npm", dev: !!p.dev,
        direct: path === "node_modules/" + name && Object.prototype.hasOwnProperty.call(directs, name) });
    }
  } else if (j.dependencies) {
    (function walk(deps) {
      for (const n of Object.keys(deps)) {
        const d = deps[n];
        if (d.version) comps.push({ name: n, version: d.version, eco: "npm", dev: !!d.dev, direct: false });
        if (d.dependencies) walk(d.dependencies);
      }
    })(j.dependencies);
  }
  return comps;
}

function parseYarnLock(text) {
  const comps = [];
  let name = null;
  for (const line of text.split(/\r?\n/)) {
    if (!line || line[0] === "#") continue;
    if (/^\S/.test(line)) {
      const key = line.replace(/:\s*$/, "").split(",")[0].trim().replace(/^"|"$/g, "");
      const at = key.indexOf("@", 1);
      name = at > 0 ? key.slice(0, at) : key;
      if (name === "__metadata") name = null;
      continue;
    }
    const m = line.match(/^\s+version:?\s+"?([^"\s]+)"?/);
    if (m && name) { comps.push({ name, version: m[1], eco: "npm", direct: false }); name = null; }
  }
  return comps.filter((c) => !/^0\.0\.0-use\.local$/.test(c.version));
}

function parsePodfileLock(text) {
  const comps = [], directs = {};
  let section = "";
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line)) { section = line.replace(/:.*$/, ""); continue; }
    let m;
    if (section === "PODS" && (m = line.match(/^  - "?([^\s"(]+) \(([^)]+)\)/))) {
      comps.push({ name: m[1], version: m[2], eco: "CocoaPods", direct: false });
    } else if (section === "DEPENDENCIES" && (m = line.match(/^  - "?([^\s"(]+)/))) {
      directs[m[1]] = true;
    }
  }
  for (const c of comps) c.direct = !!directs[c.name];
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

module.exports = { parsePubspec, parsePackageLock, parseYarnLock, parsePodfileLock, parsePackageResolved, parseGradleLock, parserFor, purl, LOCKFILES };
