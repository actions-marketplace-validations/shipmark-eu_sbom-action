# Shipmark SBOM for mobile apps

A GitHub Action that creates a **CycloneDX 1.6 SBOM** for a mobile app from its lockfiles and checks every component against **[OSV.dev](https://osv.dev)**.

It covers the whole app, not just one package manager:

| Stack | Lockfiles read |
|---|---|
| Flutter | `pubspec.lock` |
| React Native, Expo, Ionic/Capacitor | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` |
| iOS | `Podfile.lock` (CocoaPods), `Package.resolved` (Swift Package Manager) |
| Android | `gradle.lockfile` (Gradle dependency locking) |

Lockfiles are found recursively, so a React Native repo with `ios/Podfile.lock` and `android/app/gradle.lockfile` ends up in one SBOM. `node_modules`, `Pods` and build folders are skipped. No dependencies, no Docker: it runs in a couple of seconds.

## Usage

```yaml
name: SBOM
on:
  push:
    branches: [main]
  release:
    types: [published]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: shipmark-eu/sbom-action@v1
        id: sbom
      - uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.cdx.json
```

The job summary lists the components and any known vulnerabilities, and each vulnerability also shows up as a warning annotation.

### Attach the SBOM to every release

The EU Cyber Resilience Act expects an SBOM for each version you ship. Keeping one per GitHub release is the simplest way to do that:

```yaml
on:
  release:
    types: [published]

permissions:
  contents: write

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: shipmark-eu/sbom-action@v1
        with:
          output: sbom-${{ github.event.release.tag_name }}.cdx.json
      - run: gh release upload "${{ github.event.release.tag_name }}" sbom-*.cdx.json
        env:
          GH_TOKEN: ${{ github.token }}
```

### Fail the build on serious vulnerabilities

```yaml
      - uses: shipmark-eu/sbom-action@v1
        with:
          fail-on: high
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Folder to search for lockfiles. |
| `output` | `sbom.cdx.json` | Where to write the SBOM. |
| `app-name` | repository name | Name of the app in the SBOM metadata. |
| `check-vulnerabilities` | `true` | Check components against OSV.dev. Only package names and versions are sent. |
| `include-dev` | `false` | Include dev dependencies and test/debug-only configurations. |
| `fail-on` | `none` | `none`, `any`, `low`, `medium`, `high` or `critical`. |

## Outputs

| Output | Description |
|---|---|
| `sbom-path` | Absolute path of the SBOM file. |
| `components` | Number of components. |
| `vulnerabilities` | Number of known vulnerabilities. |

## Notes

- CocoaPods packages are listed in the SBOM, but OSV has no CocoaPods advisories yet, so they are not checked.
- Swift packages pinned to a commit instead of a version are listed but not checked.
- Gradle only writes `gradle.lockfile` when [dependency locking](https://docs.gradle.org/current/userguide/dependency_locking.html) is enabled. Run `./gradlew dependencies --write-locks` once and commit the file.

## Why this exists

From 11 December 2027, apps sold or monetised in the EU need an SBOM for every release under the [Cyber Resilience Act](https://eur-lex.europa.eu/eli/reg/2024/2847/oj), and since 11 September 2026 actively exploited vulnerabilities must be reported to ENISA within 24 hours. Both are much easier when every release has an SBOM.

This action is made by [Shipmark](https://shipmark.eu/), which helps app agencies keep SBOMs, vulnerability alerts and CRA documentation for all their clients' apps. There is also a [free in-browser scanner](https://shipmark.eu/scan/) and a set of [practical guides](https://shipmark.eu/guides/).

## License

MIT
