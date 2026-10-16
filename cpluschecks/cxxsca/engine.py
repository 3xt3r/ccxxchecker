from __future__ import annotations
import json
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from .checker_catalog import CheckerCatalog
from .cmake_dependencies import (
    discover_cmake_declared_components,
    merge_declared_components,
)
from .checker_engine import CheckerEngine, CheckerEngineConfig
from .cyclonedx import write_split_sbom
from .discovery import ComponentRootDiscovery
from .fingerprint_db import FingerprintDB
from .fingerprint_engine import FingerprintEngine, FingerprintEngineConfig
from .models import (
    CheckerMetadataObservation,
    Evidence,
    FingerprintRejection,
    ResolvedComponent,
    ScanStats,
)
from .resolver import EvidenceResolver
from .tree_index import TreeIndexer
from .util import is_known_version, is_under, normalize_version, path_parts

VENDORED_BOUNDARY_PARTS = {
    "third_party",
    "third-party",
    "3rdparty",
    "3rd-party",
    "vendor",
    "vendors",
    "vendored",
    "deps",
    "dependencies",
    "external",
    "externals",
    "contrib",
    "bundled",
}


@dataclass(slots=True)
class ScanConfig:
    threads: int = 8
    max_checkers_per_context: int = 10
    fingerprint_db: str = ""
    fingerprint_policy: str = "fallback"
    fingerprint_checker_confidence_threshold: float = 0.92
    include_soft_skips: bool = False
    checker: CheckerEngineConfig = field(default_factory=CheckerEngineConfig)
    fingerprint: FingerprintEngineConfig = field(
        default_factory=FingerprintEngineConfig
    )


@dataclass(slots=True)
class ScanResult:
    components: list[ResolvedComponent]
    stats: ScanStats
    fingerprint_rejections: list[FingerprintRejection] = field(default_factory=list)


class ScanEngine:
    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        self.catalog = CheckerCatalog()
        self.discovery = ComponentRootDiscovery(self.catalog)
        self.checker_engine = CheckerEngine(self.config.checker)
        self.resolver = EvidenceResolver(self.catalog)
        self.fp_engine: FingerprintEngine | None = None
        if self.config.fingerprint_db:
            db_path = Path(self.config.fingerprint_db)
            if db_path.is_file():
                fp_db = FingerprintDB(db_path)
                fp_db.validate_compatible()
                self.fp_engine = FingerprintEngine(fp_db, self.config.fingerprint)

    @staticmethod
    def _combine_confidences(values: list[float]) -> float:
        miss = 1.0
        for value in values:
            value = min(0.999, max(0.0, float(value)))
            miss *= 1.0 - value
        return 1.0 - miss

    @classmethod
    def _collect_checker_metadata(
        cls,
        root: str,
        evidence: list[Evidence],
    ) -> list[CheckerMetadataObservation]:
        grouped: dict[str, list[Evidence]] = defaultdict(list)
        for item in evidence:
            name = (item.component or "").strip()
            if name:
                grouped[name].append(item)
        observations: list[CheckerMetadataObservation] = []
        for component, items in grouped.items():
            if not any(item.identity_confirming for item in items):
                continue
            by_version: dict[str, list[float]] = defaultdict(list)
            for item in items:
                if is_known_version(item.version):
                    by_version[normalize_version(item.version)].append(item.confidence)
            ranked_versions = sorted(
                (
                    (version, cls._combine_confidences(scores))
                    for version, scores in by_version.items()
                ),
                key=lambda x: (-x[1], x[0]),
            )
            conflicts: list[str] = []
            version = ranked_versions[0][0] if ranked_versions else "unknown"
            confidence = (
                ranked_versions[0][1]
                if ranked_versions
                else cls._combine_confidences(
                    [item.confidence for item in items if item.identity_confirming]
                )
            )
            if (
                len(ranked_versions) > 1
                and ranked_versions[0][1] - ranked_versions[1][1] < 0.12
            ):
                conflicts.append(
                    f"ancestor metadata version candidates close: "
                    f"{ranked_versions[0][0]} vs {ranked_versions[1][0]}"
                )
                version = "unknown"
            strongest = sorted(items, key=lambda e: -e.confidence)
            vendor = next((e.vendor for e in strongest if e.vendor), "")
            vcs = next((e.vcs for e in strongest if e.vcs), "")
            cpe = ""
            if is_known_version(version):
                cpe = next(
                    (
                        e.cpe
                        for e in strongest
                        if e.cpe
                        and is_known_version(e.version)
                        and normalize_version(e.version) == version
                    ),
                    "",
                )
            if not cpe:
                cpe = next((e.cpe for e in strongest if e.cpe), "")
            observations.append(
                CheckerMetadataObservation(
                    root=root,
                    component=component,
                    version=version,
                    confidence=confidence,
                    vendor=vendor,
                    vcs=vcs,
                    cpe=cpe,
                    methods=tuple(sorted({e.method for e in items if e.method})),
                    evidence_files=tuple(
                        sorted({e.source_file for e in items if e.source_file})
                    ),
                    conflicts=tuple(conflicts),
                )
            )
        return observations

    def _scan_context(self, ctx) -> tuple[ResolvedComponent | None, dict]:
        shortlisted = self.catalog.shortlist(
            ctx, max_checkers=self.config.max_checkers_per_context
        )
        checker_evidence: list[Evidence] = []
        for scored in shortlisted:
            checker_evidence.extend(self.checker_engine.inspect(ctx, scored))
        metadata_observations = self._collect_checker_metadata(
            ctx.display_root, checker_evidence
        )
        fingerprints = []
        fp_stats = {
            "segments": 0,
            "exact_hits": 0,
            "normalized_hits": 0,
            "snippet_fingerprints": 0,
            "snippet_hits": 0,
            "snippet_non_primary_hits_ignored": 0,
            "snippet_high_fanout_hits_ignored": 0,
            "non_primary_hits_ignored": 0,
            "high_fanout_hits_ignored": 0,
            "candidate_rejections": [],
        }
        should_fp = (
            self.fp_engine is not None and self.config.fingerprint_policy != "off"
        )
        if should_fp and self.fp_engine:
            fingerprints, fp_stats = self.fp_engine.match(ctx)
        engine_rejections = list(fp_stats.pop("candidate_rejections", []))
        resolved, resolver_rejections = self.resolver.resolve_with_diagnostics(
            ctx.display_root,
            checker_evidence,
            fingerprints,
        )
        return resolved, {
            "checker_invocations": len(shortlisted),
            "fingerprint_used": bool(should_fp),
            "metadata_observations": metadata_observations,
            "fingerprint_rejections": engine_rejections + resolver_rejections,
            **fp_stats,
        }

    @staticmethod
    def _norm_root(root: str) -> str:
        return "" if root == "(root)" else (root or "").strip("/")

    @classmethod
    def _is_strict_ancestor(cls, ancestor: str, descendant: str) -> bool:
        a = cls._norm_root(ancestor)
        d = cls._norm_root(descendant)
        return a != d and is_under(d, a)

    @classmethod
    def _crosses_vendored_boundary(cls, ancestor: str, descendant: str) -> bool:
        a = path_parts(cls._norm_root(ancestor))
        d = path_parts(cls._norm_root(descendant))
        if len(d) <= len(a):
            return False
        tail = [part.lower() for part in d[len(a) :]]
        return any(part in VENDORED_BOUNDARY_PARTS for part in tail)

    def _cpe_for_component_version(self, component: str, version: str) -> str:
        if not is_known_version(version):
            return ""
        profile = self.catalog.profile_for_component(component)
        if not profile:
            return ""
        try:
            return profile.cls().make_result(version, "").get("cpe", "") or ""
        except Exception:
            return ""

    def _propagate_ancestor_metadata(
        self,
        components: list[ResolvedComponent],
        observations: list[CheckerMetadataObservation],
    ) -> tuple[list[ResolvedComponent], int]:
        by_name: dict[str, list[CheckerMetadataObservation]] = defaultdict(list)
        for obs in observations:
            by_name[obs.component.lower()].append(obs)
        out: list[ResolvedComponent] = []
        inherited = 0
        for component in components:
            if is_known_version(component.version):
                out.append(component)
                continue
            candidates = [
                obs
                for obs in by_name.get(component.name.lower(), [])
                if is_known_version(obs.version)
                and self._is_strict_ancestor(obs.root, component.root)
                and not self._crosses_vendored_boundary(obs.root, component.root)
            ]
            if not candidates:
                out.append(component)
                continue
            candidates.sort(
                key=lambda obs: (
                    -len(path_parts(self._norm_root(obs.root))),
                    -obs.confidence,
                    obs.root.lower(),
                )
            )
            nearest = candidates[0]
            cpe = nearest.cpe or self._cpe_for_component_version(
                component.name, nearest.version
            )
            out.append(
                replace(
                    component,
                    version=nearest.version,
                    vendor=component.vendor or nearest.vendor,
                    vcs=component.vcs or nearest.vcs,
                    cpe=component.cpe or cpe,
                    methods=tuple(
                        sorted(set(component.methods) | set(nearest.methods))
                    ),
                    evidence_files=tuple(
                        sorted(
                            set(component.evidence_files) | set(nearest.evidence_files)
                        )
                    ),
                    conflicts=tuple(
                        sorted(set(component.conflicts) | set(nearest.conflicts))
                    ),
                    metadata_version_source_root=nearest.root,
                )
            )
            inherited += 1
        return out, inherited

    @staticmethod
    def _merge_nested(
        parent: ResolvedComponent, child: ResolvedComponent
    ) -> ResolvedComponent:
        parent_known = is_known_version(parent.version)
        child_known = is_known_version(child.version)
        version = parent.version
        cpe = parent.cpe
        metadata_version_source_root = parent.metadata_version_source_root
        if not parent_known and child_known:
            version = child.version
            cpe = child.cpe or cpe
            metadata_version_source_root = child.metadata_version_source_root
        elif (
            parent_known and child_known and parent.version == child.version and not cpe
        ):
            cpe = child.cpe
        matched = (
            parent.fingerprint_matched_segments + child.fingerprint_matched_segments
        )
        total = parent.fingerprint_total_segments + child.fingerprint_total_segments
        if total > 0:
            fp_coverage: float | None = matched / total
        else:
            vals = [
                x
                for x in (parent.fingerprint_coverage, child.fingerprint_coverage)
                if x is not None
            ]
            fp_coverage = max(vals) if vals else None
        combined_fp_matched = max(1, matched)
        combined_mean_idf = (
            (
                parent.fingerprint_mean_idf * parent.fingerprint_matched_segments
                + child.fingerprint_mean_idf * child.fingerprint_matched_segments
            )
            / combined_fp_matched
            if matched
            else max(parent.fingerprint_mean_idf, child.fingerprint_mean_idf)
        )
        return replace(
            parent,
            version=version,
            confidence=max(parent.confidence, child.confidence),
            vendor=parent.vendor or child.vendor,
            vcs=parent.vcs or child.vcs,
            cpe=cpe,
            identity_confirmed=parent.identity_confirmed or child.identity_confirmed,
            identity_methods=tuple(
                sorted(set(parent.identity_methods) | set(child.identity_methods))
            ),
            methods=tuple(sorted(set(parent.methods) | set(child.methods))),
            evidence_files=tuple(
                sorted(set(parent.evidence_files) | set(child.evidence_files))
            ),
            fingerprint_coverage=fp_coverage,
            fingerprint_exact_matches=parent.fingerprint_exact_matches
            + child.fingerprint_exact_matches,
            fingerprint_normalized_matches=(
                parent.fingerprint_normalized_matches
                + child.fingerprint_normalized_matches
            ),
            fingerprint_matched_segments=matched,
            fingerprint_total_segments=total,
            fingerprint_matched_files=parent.fingerprint_matched_files
            + child.fingerprint_matched_files,
            fingerprint_sampled_files=(
                parent.fingerprint_sampled_files + child.fingerprint_sampled_files
            ),
            fingerprint_mean_idf=combined_mean_idf,
            fingerprint_high_idf_matches=(
                parent.fingerprint_high_idf_matches + child.fingerprint_high_idf_matches
            ),
            fingerprint_shared_matches=(
                parent.fingerprint_shared_matches + child.fingerprint_shared_matches
            ),
            fingerprint_shared_ratio=(
                (parent.fingerprint_shared_matches + child.fingerprint_shared_matches)
                / matched
                if matched
                else max(
                    parent.fingerprint_shared_ratio, child.fingerprint_shared_ratio
                )
            ),
            fingerprint_weighted_score=(
                parent.fingerprint_weighted_score + child.fingerprint_weighted_score
            ),
            fingerprint_snippet_matches=(
                parent.fingerprint_snippet_matches + child.fingerprint_snippet_matches
            ),
            fingerprint_snippet_total=(
                parent.fingerprint_snippet_total + child.fingerprint_snippet_total
            ),
            fingerprint_snippet_coverage=(
                (parent.fingerprint_snippet_matches + child.fingerprint_snippet_matches)
                / max(
                    1,
                    parent.fingerprint_snippet_total + child.fingerprint_snippet_total,
                )
            ),
            fingerprint_snippet_matched_files=(
                parent.fingerprint_snippet_matched_files
                + child.fingerprint_snippet_matched_files
            ),
            fingerprint_snippet_mean_idf=max(
                parent.fingerprint_snippet_mean_idf, child.fingerprint_snippet_mean_idf
            ),
            fingerprint_snippet_high_idf_matches=(
                parent.fingerprint_snippet_high_idf_matches
                + child.fingerprint_snippet_high_idf_matches
            ),
            fingerprint_snippet_shared_matches=(
                parent.fingerprint_snippet_shared_matches
                + child.fingerprint_snippet_shared_matches
            ),
            fingerprint_snippet_shared_ratio=(
                (
                    parent.fingerprint_snippet_shared_matches
                    + child.fingerprint_snippet_shared_matches
                )
                / max(
                    1,
                    parent.fingerprint_snippet_matches
                    + child.fingerprint_snippet_matches,
                )
            ),
            fingerprint_snippet_weighted_score=(
                parent.fingerprint_snippet_weighted_score
                + child.fingerprint_snippet_weighted_score
            ),
            conflicts=tuple(sorted(set(parent.conflicts) | set(child.conflicts))),
            metadata_version_source_root=metadata_version_source_root,
        )

    @classmethod
    def _collapse_metadata_families(
        cls,
        components: list[ResolvedComponent],
    ) -> tuple[list[ResolvedComponent], int]:
        grouped: dict[tuple[str, str, str], list[ResolvedComponent]] = defaultdict(list)
        passthrough: list[ResolvedComponent] = []
        for component in components:
            source_root = cls._norm_root(component.metadata_version_source_root)
            if not source_root or not is_known_version(component.version):
                passthrough.append(component)
                continue
            key = (component.name.lower(), component.version, source_root.lower())
            grouped[key].append(component)
        out = list(passthrough)
        collapsed = 0
        for (_, _, _), group in sorted(grouped.items()):
            if len(group) < 2:
                out.extend(group)
                continue
            source_root = cls._norm_root(group[0].metadata_version_source_root)
            eligible = all(
                (
                    cls._norm_root(item.root) == source_root
                    or cls._is_strict_ancestor(source_root, item.root)
                )
                and not cls._crosses_vendored_boundary(source_root, item.root)
                for item in group
            )
            if not eligible:
                out.extend(group)
                continue
            ordered = sorted(
                group,
                key=lambda c: (
                    0 if cls._norm_root(c.root) == source_root else 1,
                    -c.confidence,
                    cls._norm_root(c.root).lower(),
                ),
            )
            merged = replace(ordered[0], root=source_root)
            for item in ordered[1:]:
                merged = cls._merge_nested(merged, item)
                collapsed += 1
            out.append(merged)
        out.sort(
            key=lambda c: (c.name.lower(), cls._norm_root(c.root).lower(), c.version)
        )
        return out, collapsed

    @staticmethod
    def _merge_exact_duplicate(
        left: ResolvedComponent,
        right: ResolvedComponent,
    ) -> ResolvedComponent:
        def fp_rank(item: ResolvedComponent) -> tuple:
            return (
                item.confidence,
                item.fingerprint_matched_segments,
                item.fingerprint_matched_files,
                item.fingerprint_exact_matches,
                item.fingerprint_normalized_matches,
                item.fingerprint_snippet_matches,
                item.fingerprint_snippet_coverage,
                item.fingerprint_weighted_score,
            )

        strongest, other = (
            (left, right) if fp_rank(left) >= fp_rank(right) else (right, left)
        )
        return replace(
            strongest,
            confidence=max(left.confidence, right.confidence),
            vendor=strongest.vendor or other.vendor,
            vcs=strongest.vcs or other.vcs,
            cpe=strongest.cpe or other.cpe,
            identity_confirmed=left.identity_confirmed or right.identity_confirmed,
            identity_methods=tuple(
                sorted(set(left.identity_methods) | set(right.identity_methods))
            ),
            methods=tuple(sorted(set(left.methods) | set(right.methods))),
            evidence_files=tuple(
                sorted(set(left.evidence_files) | set(right.evidence_files))
            ),
            conflicts=tuple(sorted(set(left.conflicts) | set(right.conflicts))),
            metadata_version_source_root=(
                strongest.metadata_version_source_root
                or other.metadata_version_source_root
            ),
        )

    @classmethod
    def _dedupe_exact_results(
        cls,
        components: list[ResolvedComponent],
    ) -> tuple[list[ResolvedComponent], int]:
        unique: dict[tuple[str, str, str], ResolvedComponent] = {}
        collapsed = 0
        for component in sorted(
            components,
            key=lambda c: (
                c.name.lower(),
                normalize_version(c.version),
                cls._norm_root(c.root).lower(),
            ),
        ):
            key = (
                component.name.lower(),
                normalize_version(component.version),
                cls._norm_root(component.root).lower(),
            )
            old = unique.get(key)
            if old is None:
                unique[key] = component
                continue
            unique[key] = cls._merge_exact_duplicate(old, component)
            collapsed += 1
        out = sorted(
            unique.values(),
            key=lambda c: (c.name.lower(), cls._norm_root(c.root).lower(), c.version),
        )
        return out, collapsed

    @classmethod
    def _collapse_nested_components(
        cls,
        components: list[ResolvedComponent],
    ) -> tuple[list[ResolvedComponent], int]:
        by_name: dict[str, list[ResolvedComponent]] = {}
        for component in components:
            by_name.setdefault(component.name.lower(), []).append(component)
        out: list[ResolvedComponent] = []
        collapsed = 0
        for _, group in sorted(by_name.items()):
            ordered = sorted(
                group,
                key=lambda c: (
                    len(path_parts(cls._norm_root(c.root))),
                    cls._norm_root(c.root).lower(),
                    0 if is_known_version(c.version) else 1,
                    -c.confidence,
                ),
            )
            kept: list[ResolvedComponent] = []
            for component in ordered:
                ancestor_indexes = [
                    i
                    for i, candidate in enumerate(kept)
                    if cls._is_strict_ancestor(candidate.root, component.root)
                ]
                if not ancestor_indexes:
                    kept.append(component)
                    continue
                idx = max(
                    ancestor_indexes,
                    key=lambda i: len(path_parts(cls._norm_root(kept[i].root))),
                )
                ancestor = kept[idx]
                if (
                    is_known_version(ancestor.version)
                    and is_known_version(component.version)
                    and ancestor.version != component.version
                ):
                    kept.append(component)
                    continue
                kept[idx] = cls._merge_nested(ancestor, component)
                collapsed += 1
            out.extend(kept)
        out.sort(
            key=lambda c: (c.name.lower(), cls._norm_root(c.root).lower(), c.version)
        )
        return out, collapsed

    @staticmethod
    def _dedupe_rejections(
        rejections: list[FingerprintRejection],
    ) -> list[FingerprintRejection]:
        unique: dict[tuple[str, str, str], FingerprintRejection] = {}
        for row in rejections:
            key = (row.root, row.component.lower(), row.reject_reason)
            old = unique.get(key)
            if old is None or (
                row.matched_segments,
                row.matched_files,
                row.confidence,
            ) > (
                old.matched_segments,
                old.matched_files,
                old.confidence,
            ):
                unique[key] = row
        return sorted(
            unique.values(),
            key=lambda r: (r.root.lower(), r.component.lower(), r.reject_reason),
        )

    def scan(self, root: str | Path) -> ScanResult:
        stats = ScanStats(checker_profiles=len(self.catalog.profiles))
        t = time.perf_counter()
        tree = TreeIndexer(include_soft_skips=self.config.include_soft_skips).build(
            root
        )
        stats.files_indexed = len(tree.files)
        stats.timings["tree_index"] = time.perf_counter() - t
        t = time.perf_counter()
        roots = self.discovery.discover(tree)
        contexts = self.discovery.build_contexts(tree, roots)
        stats.component_contexts = len(contexts)
        stats.timings["context_discovery"] = time.perf_counter() - t
        t = time.perf_counter()
        components: list[ResolvedComponent] = []
        metadata_observations: list[CheckerMetadataObservation] = []
        fingerprint_rejections: list[FingerprintRejection] = []
        with ThreadPoolExecutor(max_workers=max(1, int(self.config.threads))) as pool:
            future_map = {pool.submit(self._scan_context, ctx): ctx for ctx in contexts}
            for future in as_completed(future_map):
                try:
                    resolved, local = future.result()
                except Exception:
                    continue
                stats.checker_invocations += int(local["checker_invocations"])
                if local["fingerprint_used"]:
                    stats.fingerprint_contexts += 1
                stats.fingerprint_segments += int(local["segments"])
                stats.fingerprint_exact_hits += int(local["exact_hits"])
                stats.fingerprint_normalized_hits += int(local["normalized_hits"])
                stats.fingerprint_snippet_fingerprints += int(
                    local.get("snippet_fingerprints", 0)
                )
                stats.fingerprint_snippet_hits += int(local.get("snippet_hits", 0))
                stats.fingerprint_snippet_non_primary_hits_ignored += int(
                    local.get("snippet_non_primary_hits_ignored", 0)
                )
                stats.fingerprint_snippet_high_fanout_hits_ignored += int(
                    local.get("snippet_high_fanout_hits_ignored", 0)
                )
                stats.fingerprint_non_primary_hits_ignored += int(
                    local.get("non_primary_hits_ignored", 0)
                )
                stats.fingerprint_high_fanout_hits_ignored += int(
                    local.get("high_fanout_hits_ignored", 0)
                )
                metadata_observations.extend(local.get("metadata_observations", []))
                fingerprint_rejections.extend(local.get("fingerprint_rejections", []))
                if resolved:
                    components.append(resolved)
        stats.timings["context_scan"] = time.perf_counter() - t
        components, inherited = self._propagate_ancestor_metadata(
            components,
            metadata_observations,
        )
        stats.metadata_versions_inherited = inherited
        unique: dict[tuple[str, str, str], ResolvedComponent] = {}
        for c in components:
            key = (c.root, c.name.lower(), c.version)
            old = unique.get(key)
            if old is None or c.confidence > old.confidence:
                unique[key] = c
        pre_collapse = list(unique.values())
        stats.components_before_collapse = len(pre_collapse)
        ownership_collapsed_components, ownership_collapsed = (
            self._collapse_metadata_families(pre_collapse)
        )
        nested_components, nested_collapsed = self._collapse_nested_components(
            ownership_collapsed_components
        )
        final, exact_collapsed = self._dedupe_exact_results(nested_components)
        stats.ownership_family_components_collapsed = ownership_collapsed
        stats.exact_duplicate_components_collapsed = exact_collapsed
        stats.components_collapsed = (
            ownership_collapsed + nested_collapsed + exact_collapsed
        )
        declared = discover_cmake_declared_components(tree, self.catalog)
        stats.cmake_declarations_found = len(declared)
        final, decl_merged, decl_added = merge_declared_components(final, declared)
        stats.cmake_declarations_merged = decl_merged
        stats.cmake_declarations_added = decl_added
        fingerprint_rejections = self._dedupe_rejections(fingerprint_rejections)
        stats.fingerprint_candidates_rejected = len(fingerprint_rejections)
        stats.fingerprint_rejections_by_reason = dict(
            sorted(Counter(row.reject_reason for row in fingerprint_rejections).items())
        )
        return ScanResult(final, stats, fingerprint_rejections)

    @staticmethod
    def write_outputs(
        result: ScanResult,
        known_path: str | Path,
        unknown_path: str | Path,
        stats_path: str | Path | None = None,
        fingerprint_rejections_path: str | Path | None = None,
    ) -> None:
        write_split_sbom(result.components, known_path, unknown_path)
        if stats_path:
            path = Path(stats_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(asdict(result.stats), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        if fingerprint_rejections_path:
            path = Path(fingerprint_rejections_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(
                    [asdict(row) for row in result.fingerprint_rejections],
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
