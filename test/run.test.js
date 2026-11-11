"use strict";
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const P = require("../src/parsers");
const { findLockfiles, buildBom, parseContact } = require("../src/index");
const fx = (p) => fs.readFileSync(path.join(__dirname, "fixtures", p), "utf8");

test("pubspec.lock: skips the SDK, marks dev and direct", () => {
  const c = P.parsePubspec(fx("flutter/pubspec.lock"));
  assert.deepStrictEqual(c.map((x) => x.name).sort(), ["flutter_lints", "http", "path"]);
  assert.ok(c.find((x) => x.name === "http").direct);
  assert.ok(c.find((x) => x.name === "flutter_lints").dev);
});

test("package-lock.json v3: direct, scoped and dev packages", () => {
  const c = P.parsePackageLock(fx("rn/package-lock.json"));
  assert.strictEqual(c.length, 4);
  assert.ok(c.find((x) => x.name === "axios").direct);
  assert.ok(c.find((x) => x.name === "jest").dev);
  assert.strictEqual(P.purl(c.find((x) => x.name === "@babel/core")), "pkg:npm/%40babel/core@7.22.0");
});

test("Podfile.lock: subspecs and direct dependencies", () => {
  const c = P.parsePodfileLock(fx("rn/ios/Podfile.lock"));
  assert.strictEqual(c.length, 3);
  assert.ok(c.find((x) => x.name === "Firebase/Analytics").direct);
  assert.strictEqual(P.purl(c[0]), "pkg:cocoapods/Firebase@10.12.0#Analytics");
});

test("gradle.lockfile: test-only configurations are dev", () => {
  const c = P.parseGradleLock(fx("rn/android/app/gradle.lockfile"));
  assert.strictEqual(c.length, 2);
  assert.ok(!c.find((x) => x.name === "com.squareup.okhttp3:okhttp").dev);
  assert.ok(c.find((x) => x.name === "junit:junit").dev);
});

test("finds lockfiles recursively and skips node_modules", () => {
  const f = findLockfiles(path.join(__dirname, "fixtures")).map((p) => path.relative(path.join(__dirname, "fixtures"), p));
  assert.deepStrictEqual(f, ["flutter/pubspec.lock", "rn/android/app/gradle.lockfile", "rn/ios/Podfile.lock", "rn/package-lock.json"]);
});

test("builds a CycloneDX 1.6 document", () => {
  const comps = P.parsePubspec(fx("flutter/pubspec.lock")).map((c) => ({ ...c, purl: P.purl(c) }));
  const bom = buildBom("demo", comps, { "GHSA-x": [comps[0]] }, { "GHSA-x": { summary: "test", database_specific: { severity: "HIGH" } } });
  assert.strictEqual(bom.bomFormat, "CycloneDX");
  assert.strictEqual(bom.specVersion, "1.6");
  assert.strictEqual(bom.components.length, 3);
  assert.strictEqual(bom.vulnerabilities[0].ratings[0].severity, "high");
});

const crypto = require("crypto");
const sri = (s) => "sha512-" + crypto.createHash("sha512").update(s).digest("base64");
const hex = (s) => crypto.createHash("sha512").update(s).digest("hex");

test("integrity: base64 SHA-512 becomes hex, other algorithms are ignored", () => {
  assert.strictEqual(P.integrityHex(sri("a")), hex("a"));
  assert.strictEqual(P.integrityHex("sha1-abc"), null);
  assert.strictEqual(P.integrityHex(undefined), null);
});

test("package-lock.json: dependency graph, nested resolution, hashes, licences, completeness", () => {
  const lock = JSON.stringify({ lockfileVersion: 3, packages: {
    "": { name: "app", dependencies: { a: "^1" } },
    "node_modules/a": { version: "1.0.0", license: "MIT", integrity: sri("a"),
      resolved: "https://registry.npmjs.org/a/-/a-1.0.0.tgz", dependencies: { b: "^2", missing: "^1" }, peerDependencies: { nope: "*" } },
    "node_modules/a/node_modules/b": { version: "2.0.0", license: "(MIT OR Apache-2.0)" },
    "node_modules/b": { version: "1.0.0", license: "SEE LICENSE IN LICENSE" },
  } });
  const c = P.parsePackageLock(lock);
  const a = c.find((x) => x.name === "a");
  assert.strictEqual(a.sha512, hex("a"));
  assert.strictEqual(a.resolved, "https://registry.npmjs.org/a/-/a-1.0.0.tgz");
  assert.deepStrictEqual(a.deps.map((d) => d.version), ["2.0.0"]); // nested b, not the root one
  assert.strictEqual(a.depsComplete, false); // "missing" is required and absent; peer "nope" is not required
  assert.strictEqual(c.find((x) => x.version === "2.0.0").depsComplete, true);
});

test("yarn.lock classic: graph, hash and download URL", () => {
  const y = `# yarn lockfile v1\n\n"a@^1.0.0":\n  version "1.0.0"\n  resolved "https://registry.yarnpkg.com/a/-/a-1.0.0.tgz#abc"\n  integrity ${sri("a")}\n  dependencies:\n    b "^2.0.0"\n\nb@^2.0.0:\n  version "2.1.0"\n`;
  const c = P.parseYarnLock(y);
  const a = c.find((x) => x.name === "a");
  assert.strictEqual(a.resolved, "https://registry.yarnpkg.com/a/-/a-1.0.0.tgz");
  assert.strictEqual(a.sha512, hex("a"));
  assert.deepStrictEqual(a.deps.map((d) => d.name), ["b"]);
  assert.strictEqual(a.depsComplete, true);
});

test("yarn.lock Berry: workspace root gives the direct dependencies, a missing dependency is incomplete", () => {
  const y = `__metadata:\n  version: 8\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n  resolution: "app@workspace:."\n  dependencies:\n    a: "npm:^1.0.0"\n\n"a@npm:^1.0.0":\n  version: 1.0.0\n  resolution: "a@npm:1.0.0"\n  dependencies:\n    gone: "npm:^3.0.0"\n`;
  const c = P.parseYarnLock(y);
  assert.deepStrictEqual(c.map((x) => x.name), ["a"]);
  assert.ok(c[0].direct);
  assert.strictEqual(c[0].depsComplete, false);
});

test("Podfile.lock: dependency graph between pods", () => {
  const c = P.parsePodfileLock(fx("rn/ios/Podfile.lock"));
  const fa = c.find((x) => x.name === "Firebase/Analytics");
  assert.deepStrictEqual(fa.deps.map((d) => d.name), ["Firebase/Core"]);
  assert.strictEqual(fa.depsComplete, true);
});

test("SBOM: dependencies, compositions, hashes, declared licences and contact", () => {
  const a = { name: "a", version: "1.0.0", eco: "npm", direct: true, license: "MIT", sha512: hex("a"),
    resolved: "https://registry.npmjs.org/a/-/a-1.0.0.tgz", depPurls: ["pkg:npm/b@2.0.0", "pkg:npm/dropped@1.0.0"], depsComplete: true };
  const b = { name: "b", version: "2.0.0", eco: "npm", direct: false, license: "SEE LICENSE IN x", depPurls: [], depsComplete: false };
  const g = { name: "g:x", version: "1", eco: "Maven", direct: false };
  for (const c of [a, b, g]) c.purl = P.purl(c);
  const bom = buildBom("demo", [a, b, g], {}, {}, { email: "security@example.com" });
  assert.deepStrictEqual(bom.metadata.manufacturer, { contact: [{ email: "security@example.com" }] });
  assert.deepStrictEqual(bom.dependencies.find((d) => d.ref === a.purl).dependsOn, [b.purl]); // unknown refs are dropped
  assert.deepStrictEqual(bom.compositions, [
    { aggregate: "incomplete", dependencies: ["app"] },
    { aggregate: "complete", dependencies: [a.purl] },
    { aggregate: "incomplete", dependencies: [b.purl] },
    { aggregate: "unknown", dependencies: [g.purl] },
  ]);
  const ca = bom.components[0];
  assert.deepStrictEqual(ca.licenses, [{ expression: "MIT", acknowledgement: "declared" }]);
  assert.deepStrictEqual(ca.externalReferences, [{ type: "distribution", url: a.resolved, hashes: [{ alg: "SHA-512", content: hex("a") }] }]);
  assert.deepStrictEqual(bom.components[1].licenses, [{ license: { name: "SEE LICENSE IN x", acknowledgement: "declared" } }]);
  const refs = new Set(["app", ...bom.components.map((c) => c["bom-ref"])]);
  for (const d of bom.dependencies) { assert.ok(refs.has(d.ref)); d.dependsOn.forEach((r) => assert.ok(refs.has(r))); }
  for (const k of bom.compositions) k.dependencies.forEach((r) => assert.ok(refs.has(r)));
});

test("sbom-contact: email, https URL, empty or invalid", () => {
  assert.deepStrictEqual(parseContact("security@example.com"), { email: "security@example.com" });
  assert.deepStrictEqual(parseContact("https://example.com/security"), { url: "https://example.com/security" });
  assert.strictEqual(parseContact(""), null);
  assert.strictEqual(parseContact("not a contact"), false);
  assert.strictEqual(parseContact("http://example.com"), false);
});
