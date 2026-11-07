"use strict";
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const P = require("../src/parsers");
const { findLockfiles, buildBom } = require("../src/index");
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
