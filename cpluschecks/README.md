# CXX SCA v0.14 — strict fingerprint identity

Experimental source-based SCA for vendored C/C++ dependencies. It does **not** require a successful build, package manager, or ML model.

## Detection contract

```text
checker -> candidate + metadata/version
fingerprint -> component identity
```

A component is emitted only after an accepted exact/normalized fingerprint. Checker signatures, root anchors and metadata may rank a fingerprint-confirmed candidate and provide its version, but they never create identity on their own.

```text
checker only                         -> REJECT
checker + version                    -> REJECT
strong fingerprint                  -> name@unknown
strong fingerprint + checker version -> name@version
```

Tests/gtest trees are hard-skipped before context/fingerprint extraction.

### v0.14 final exact dedup + v0.13/v0.12/v0.11 precision/recall changes

- After all root rewrites/collapse stages, exact duplicate results with the same normalized component name, version, and canonical root are merged once. The strongest fingerprint snapshot is retained while methods, evidence files, identity methods, and conflicts are unioned, preventing duplicate CycloneDX entries without double-counting fingerprint counters.
- Fingerprint-confirmed sibling roots that inherited the same known component version from one trusted ancestor metadata root are collapsed into one canonical component at that metadata root. This turns Boost `libs/*` sibling detections into one `boost@version` while leaving vendored copies under `third_party` separate.
- Nested Git submodules are no longer blindly pruned: a submodule is indexed as owned only when an ancestor `.gitmodules` explicitly declares it with a relative URL, and its path is outside vendor boundaries. This supports Boost `libs/*` while keeping external/unknown nested repos conservative.
- C++ extractor descends into unrecognized wrapper blocks such as `namespace { ... }` and `extern "C" { ... }` instead of skipping all nested functions/types. This restores fingerprints for namespace/header/template-heavy C++.
- `shared_ratio` is an ambiguity signal, not an automatic veto. High-shared fingerprints are allowed when the root names the component or the exact match is near-complete.
- Partial high-shared foreign matches without affinity remain rejected, preserving the old gtest->opencv protection.
- Fingerprints still never infer versions.

## Fingerprint policy

- `off`: no components can be confirmed (fingerprint identity is mandatory).
- `fallback`: validates discovered component contexts with fingerprints.
- `always`: scans all contexts for benchmark/debug use.

**v0.14 does not change the fingerprint DB schema.** If you already rebuilt the DB with v0.12 (`identity-only-v6-owned-submodules`), reuse it. Only users coming from v0.11 or older must rebuild.

## Build an identity fingerprint database

Catalog layout:

```text
catalog/
  libhtp/
    reference/      # source-label only; not version evidence
      ... sources ...
```

Build:

```bash
python build_fingerprint_index.py catalog --db fingerprints.sqlite
```

The builder prints progress per snapshot, classifies source ownership scope, computes component-frequency metadata, and builds SQLite indexes after bulk loading.

**v0.5 changes the SQLite schema; rebuild any v0.3/v0.4 fingerprint database.**

### Fingerprint ownership

Nested third-party trees are no longer attributed to the parent component. Child trees below conventional vendoring directories such as:

```text
third_party/
3rdparty/
vendor/
deps/
dependencies/
external/
contrib/
```

are pruned from the parent fingerprint corpus. Unknown/external nested Git worktrees/submodules are pruned too. Explicit relative submodules declared in an ancestor `.gitmodules` may be treated as owned when they are outside vendoring boundaries.

For example:

```text
clickhouse-cpp/reference/
  clickhouse/...       -> clickhouse-cpp fingerprints
  contrib/zstd/...     -> NOT clickhouse-cpp fingerprints
  contrib/gtest/...    -> NOT clickhouse-cpp fingerprints
```

Build statistics include `nested_roots_pruned`.

### Scoped + discriminative fingerprints (v0.5)

Indexed source code is classified as `PRIMARY`, `TEST`, `VENDORED`, or
`AUXILIARY`. Only `PRIMARY` hashes may create a component identity. This stops
repository test dependencies (for example `fmt/test/gtest`) from identifying a
foreign GoogleTest tree as `fmt`.

For PRIMARY hashes the DB stores `primary_component_frequency`. Runtime scoring
converts that frequency to a normalized IDF-like rarity weight: hashes unique
to one component are strong, while hashes shared across many components are
down-weighted or ignored.

Build output includes `files_by_scope` and `segments_by_scope`.

## Component collapse

Same-component ancestor/descendant contexts are merged after resolution:

```text
brotli@1.2.0  root=brotli/reference
brotli@unknown root=brotli/reference/c/include/brotli

=> one brotli@1.2.0 root=brotli/reference
```

Sibling copies are preserved. Nested copies with two different known versions are also preserved.

Stats include:

```text
components_before_collapse
components_collapsed
```

## Scan

Strict identity mode requires fingerprints. `--fingerprint-policy off` keeps
checker execution available for diagnostics but emits no confirmed components.

Fingerprint-required scan:

```bash
python scanner.py repos \
  --fingerprint-db fingerprints.sqlite \
  --fingerprint-policy fallback \
  --sbom out/known.cdx.json \
  --unknown out/unknown.cdx.json \
  --stats out/stats.json
```

In v0.10, `fallback` and `always` both fingerprint every component context because
checker evidence is not allowed to establish identity. `fallback` is retained for
CLI compatibility.

`out/` and other output parent directories are created automatically.

## CycloneDX identity properties

```text
detection.identity_confirmed
detection.identity_methods
fingerprint.identity.coverage
fingerprint.identity.exact_matches
fingerprint.identity.normalized_matches
fingerprint.identity.matched_segments
fingerprint.identity.total_segments
fingerprint.identity.matched_files
fingerprint.identity.sampled_files
fingerprint.identity.mean_idf
fingerprint.identity.high_idf_matches
fingerprint.identity.shared_matches
fingerprint.identity.weighted_score
```

Fingerprints never set or infer the version.


## v0.6 shared-ratio gate

For fingerprint-only identities, shared PRIMARY hashes are treated as weaker
evidence. `shared_ratio > 0.50` is rejected; `0.20 < shared_ratio <= 0.50`
requires root/component affinity. The ratio is emitted as
`fingerprint.identity.shared_ratio` in CycloneDX. No fingerprint DB rebuild is
needed when upgrading from v0.5.

## v0.8 hard test/gtest exclusion

For production-oriented SBOM precision, test/gtest code is a hard exclusion. The scanner and fingerprint builder do not descend into test/gtest directories and skip common test filenames. Dedicated googletest/gmock catalog components are not inserted into the fingerprint DB. This exclusion cannot be overridden by `--include-tests-docs`. See `MIGRATION_V0.8.md`.

## v0.10 strict fingerprint-required identity

Every emitted component must independently pass the fingerprint precision gate.
Checker evidence is candidate/metadata evidence only:

```text
checker:signature / checker:root-anchor / checker:context-score
    -> candidate/support only

checker:version / checker:check_meta
    -> version/metadata only

hash:exact / hash:normalized
    -> the only identity-confirming methods
```

A checker match cannot bypass fingerprint coverage, file-diversity, IDF, or
shared-ratio gates. `detection.identity_methods` therefore contains only
`hash:*`; checker methods remain in `detection.methods` for explainability.

No fingerprint DB rebuild is required from v0.8 because the SQLite schema is
unchanged.


## v0.10 ancestor metadata + rejection diagnostics

Identity remains fingerprint-only. v0.10 adds two explainability/recall features without
weakening that rule:

1. A fingerprint-confirmed descendant may inherit checker version metadata from the nearest
   trusted ancestor for the same component, provided the path does not cross a vendored
   boundary (`third_party`, `vendor`, `deps`, `dependencies`, `external`, `contrib`,
   `bundled`, ...). The SBOM records the source as `metadata.version.source_root`.
2. `--fingerprint-rejections FILE.json` writes rejected fingerprint candidates with exact
   `reject_reason`, coverage, files, IDF, shared ratio, exact/normalized matches and score.

Example:

```bash
python scanner.py /path/to/catalog \
  --fingerprint-db fingerprints.sqlite \
  --fingerprint-policy fallback \
  --sbom out/v010-known.json \
  --unknown out/v010-unknown.json \
  --stats out/v010-stats.json \
  --fingerprint-rejections out/v010-fingerprint-rejections.json
```


## v0.12 owned Git submodules

The fingerprint builder no longer treats every nested `.git` marker as third-party.
A nested Git worktree is indexed only when:

1. an ancestor `.gitmodules` explicitly declares its path;
2. the declared URL is relative (`../repo.git` or `./repo.git`);
3. the path is not below `third_party`, `vendor`, `deps`, `dependencies`, `external`, `contrib`, or another vendor boundary.

This is designed for umbrella projects such as Boost, whose `libs/*` repositories are official same-namespace submodules. Absolute external URLs, unlisted nested repos, and vendored submodules remain pruned.

v0.12 changes fingerprint ownership and therefore requires a fresh SQLite DB.


## v0.15 modified-source support with token winnowing

v0.15 keeps exact/normalized whole-segment hashes as the identity contract and
adds a third, weaker evidence layer for locally modified code. Each parsed
function/type/macro is tokenized into overlapping 12-token k-grams, winnowed
with a 16-gram window, and capped at 32 local fingerprints per segment.

`hash:snippet-winnowing` is **supporting evidence only**. Snippet-only matches
never create candidates and never appear in `detection.identity_methods`. A
weak exact/normalized seed can be rescued only by strong, multi-file, high-IDF
snippet support. CycloneDX exposes the supporting metrics under
`fingerprint.support.snippet_*`.

The SQLite schema is now `identity-only-v7-snippet-winnowing`, so v0.15
requires rebuilding `fingerprints.sqlite`. See `MIGRATION_V0.15.md`.

---

## Adding new checkers

This copy of the engine ships without the onboarding agent (`agent/`,
`AGENT_ONBOARDING.md`) — checkers are added/edited by hand:

1. Add a `BaseChecker` subclass under `checkers/` (see existing checkers for
   the pattern: `VENDOR`/`PRODUCT`/`LINK_SOURCE`, `CONTAINS_PATTERNS`,
   `VERSION_PATTERNS`, optional `check_meta`).
2. `checkers/__init__.py` registration is optional — `cxxsca.checker_catalog`
   auto-discovers any `BaseChecker` subclass under `checkers/` that isn't in
   `ALL_CHECKERS`, so a forgotten import never silently drops a checker.
3. To make the component confirmable, add reference source snapshots to a
   `catalog/<product>/` tree and rebuild the fingerprint DB with
   `build_fingerprint_index.py` (see below) — a checker alone never confirms
   identity, only a matching fingerprint does.

`fingerprints.sqlite` and `catalog/` are intentionally not shipped in this
source archive. They are generated/runtime data, not source code.

## CycloneDX identifiers

For both `known` and `unknown` SBOMs:

- checker-provided CPE is emitted when available; unknown versions use the checker wildcard-version CPE;
- PURL is always plain `pkg:generic/<name>@<version>` (including `@unknown`) with no `#` fragment;
- `bom-ref` is a separate `urn:uuid:...` identifier, so it cannot be confused with a PURL.


## CMake-declared third-party dependencies

The scanner also treats explicit CMake download declarations as strong third-party
component evidence, even when the dependency source is not vendored in the tree:

- `ExternalProject_Add(...)`
- `FetchContent_Declare(...)`

For URL-based declarations it resolves local `set(VAR ...)` references, derives a
version from the archive name, records `URL_HASH` when available, and preserves
`DEPENDS` target names as relationship evidence. For Git declarations it uses
`GIT_REPOSITORY` and `GIT_TAG`.

Example:

```cmake
set(AVRO_URL "${REPOSITORY}/avro/avro-cpp-1.12.1.dirty.tar.gz")
set(AVRO_URL_HASH "SHA256=...")
ExternalProject_Add(avro
  DEPENDS boost fmt snappy zlib
  URL ${AVRO_URL}
  URL_HASH ${AVRO_URL_HASH}
)
```

This emits `avro@1.12.1` with detection method
`build:cmake:ExternalProject_Add`. `DEPENDS` names alone do not create components,
because CMake targets may be internal; those targets must be independently
declared or detected by the existing C/C++ scanner.
