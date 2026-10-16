from __future__ import annotations
import math
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from .context import ComponentContext
from .fingerprint_db import FingerprintDB
from .models import FingerprintRejection, FingerprintSummary
from .segments import CodeSegment, extract_segments, snippet_fingerprints

LOW_SIGNAL_DIRS = {
    "test",
    "tests",
    "testing",
    "testsuite",
    "testsuites",
    "bench",
    "benchmark",
    "benchmarks",
    "example",
    "examples",
    "demo",
    "demos",
    "fuzz",
    "fuzzer",
    "fuzzers",
    "oss-fuzz",
}
IMPLEMENTATION_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".m", ".mm"}
HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".hxx", ".inc", ".inl"}


@dataclass(slots=True)
class FingerprintEngineConfig:
    max_files_per_context: int = 120
    max_file_bytes: int = 2_000_000
    min_matches: int = 2
    min_coverage: float = 0.04
    max_hash_component_fanout: int = 12
    high_idf_threshold: float = 0.72
    max_snippet_component_fanout: int = 20
    min_snippet_matches: int = 20
    min_snippet_coverage: float = 0.20
    min_snippet_files: int = 2
    min_snippet_mean_idf: float = 0.60
    min_snippet_high_idf_matches: int = 8


class FingerprintEngine:
    def __init__(
        self, db: FingerprintDB, config: FingerprintEngineConfig | None = None
    ) -> None:
        self.db = db
        self.config = config or FingerprintEngineConfig()

    @staticmethod
    def _relative_inside_context(ctx: ComponentContext, rel_path: str) -> str:
        rel = rel_path.replace("\\", "/")
        root = (ctx.root_rel or "").strip("/")
        if root and rel.startswith(root + "/"):
            return rel[len(root) + 1 :]
        return rel

    @classmethod
    def _file_priority(cls, ctx: ComponentContext, rec) -> tuple:
        local = cls._relative_inside_context(ctx, rec.rel_path)
        parts = [p.lower() for p in Path(local).parts]
        low_signal = 1 if any(p in LOW_SIGNAL_DIRS for p in parts) else 0
        if rec.suffix in IMPLEMENTATION_SUFFIXES:
            kind = 0
        elif rec.suffix in HEADER_SUFFIXES:
            kind = 1
        else:
            kind = 2
        if 2_048 <= rec.size <= 256_000:
            size_bucket = 0
        elif rec.size < 2_048:
            size_bucket = 1
        else:
            size_bucket = 2
        return (low_signal, kind, size_bucket, rec.rel_path.lower())

    @classmethod
    def _top_group(cls, ctx: ComponentContext, rec) -> str:
        local = cls._relative_inside_context(ctx, rec.rel_path)
        parts = Path(local).parts
        return parts[0].lower() if len(parts) > 1 else "(root)"

    def _select_files(self, ctx: ComponentContext):
        candidates = [
            rec for rec in ctx.source_files if rec.size <= self.config.max_file_bytes
        ]
        if len(candidates) <= self.config.max_files_per_context:
            return sorted(candidates, key=lambda r: self._file_priority(ctx, r))
        groups: dict[str, list] = defaultdict(list)
        for rec in candidates:
            groups[self._top_group(ctx, rec)].append(rec)
        for records in groups.values():
            records.sort(key=lambda r: self._file_priority(ctx, r))
        selected = []
        selected_paths: set[str] = set()
        per_group = max(
            2, min(8, self.config.max_files_per_context // max(1, len(groups)))
        )
        for group in sorted(groups):
            for rec in groups[group][:per_group]:
                if rec.rel_path not in selected_paths:
                    selected.append(rec)
                    selected_paths.add(rec.rel_path)
                    if len(selected) >= self.config.max_files_per_context:
                        return selected
        remaining = sorted(candidates, key=lambda r: self._file_priority(ctx, r))
        for rec in remaining:
            if rec.rel_path in selected_paths:
                continue
            selected.append(rec)
            selected_paths.add(rec.rel_path)
            if len(selected) >= self.config.max_files_per_context:
                break
        return selected

    def _extract(
        self, ctx: ComponentContext
    ) -> tuple[list[tuple[str, CodeSegment]], int]:
        files = self._select_files(ctx)
        out: list[tuple[str, CodeSegment]] = []
        for rec in files:
            text = ctx.read_text(rec, max_bytes=self.config.max_file_bytes)
            if not text:
                continue
            for seg in extract_segments(text):
                out.append((rec.rel_path, seg))
        return out, len(files)

    @staticmethod
    def _normalized_idf(total_components: int, component_frequency: int) -> float:
        n = max(1, int(total_components))
        f = max(1, min(n, int(component_frequency)))
        raw = math.log((n + 1.0) / (f + 1.0)) + 1.0
        max_raw = math.log((n + 1.0) / 2.0) + 1.0
        if max_raw <= 0:
            return 1.0
        return max(0.0, min(1.0, raw / max_raw))

    @staticmethod
    def _primary_rows(rows: list[dict]) -> list[dict]:
        return [row for row in rows if row.get("scope") == "PRIMARY"]

    def _strong_snippet_support(self, summary: FingerprintSummary) -> bool:
        return (
            summary.matched_segments >= 1
            and summary.snippet_matches >= self.config.min_snippet_matches
            and summary.snippet_coverage >= self.config.min_snippet_coverage
            and summary.snippet_matched_files >= self.config.min_snippet_files
            and summary.snippet_mean_idf >= self.config.min_snippet_mean_idf
            and summary.snippet_high_idf_matches
            >= self.config.min_snippet_high_idf_matches
        )

    def match(self, ctx: ComponentContext) -> tuple[list[FingerprintSummary], dict]:
        pairs, sampled_files = self._extract(ctx)
        segments = [seg for _, seg in pairs]
        if not segments:
            return [], {
                "segments": 0,
                "exact_hits": 0,
                "normalized_hits": 0,
                "snippet_fingerprints": 0,
                "snippet_hits": 0,
                "snippet_non_primary_hits_ignored": 0,
                "snippet_high_fanout_hits_ignored": 0,
                "sampled_files": sampled_files,
                "non_primary_hits_ignored": 0,
                "high_fanout_hits_ignored": 0,
                "candidate_rejections": [],
            }
        exact_map, norm_map = self.db.lookup_hashes(
            (s.exact_hash for s in segments), (s.normalized_hash for s in segments)
        )
        snippet_items: list[tuple[int, str, str]] = []
        for seg_idx, (rel, seg) in enumerate(pairs):
            for fp in snippet_fingerprints(seg.normalized):
                snippet_items.append((seg_idx, rel, fp))
        snippet_map = self.db.lookup_snippet_hashes(fp for _, _, fp in snippet_items)
        total_components = max(1, self.db.total_components())
        agg: dict[str, dict] = defaultdict(
            lambda: {
                "weighted": 0.0,
                "idf_sum": 0.0,
                "matched_ids": set(),
                "exact_ids": set(),
                "normalized_ids": set(),
                "high_idf_ids": set(),
                "shared_ids": set(),
                "files": set(),
                "examples": [],
                "methods": set(),
            }
        )
        exact_hit_ids: set[int] = set()
        normalized_hit_ids: set[int] = set()
        non_primary_hits_ignored: set[int] = set()
        high_fanout_hits_ignored: set[int] = set()
        for idx, (rel, seg) in enumerate(pairs):
            exact_rows_all = exact_map.get(seg.exact_hash, [])
            exact_rows = self._primary_rows(exact_rows_all)
            if exact_rows:
                rows, method, base = exact_rows, "hash:exact", 1.0
            else:
                if exact_rows_all:
                    non_primary_hits_ignored.add(idx)
                norm_rows_all = norm_map.get(seg.normalized_hash, [])
                norm_rows = self._primary_rows(norm_rows_all)
                if not norm_rows:
                    if norm_rows_all:
                        non_primary_hits_ignored.add(idx)
                    continue
                rows, method, base = norm_rows, "hash:normalized", 0.82
            primary_frequency = max(
                1, max(int(r.get("primary_component_frequency") or 1) for r in rows)
            )
            if primary_frequency > self.config.max_hash_component_fanout:
                high_fanout_hits_ignored.add(idx)
                continue
            idf = self._normalized_idf(total_components, primary_frequency)
            for component in {row["component"] for row in rows}:
                a = agg[component]
                if idx in a["matched_ids"]:
                    continue
                a["matched_ids"].add(idx)
                token_factor = min(2.0, 0.5 + seg.token_count / 120.0)
                a["weighted"] += base * idf * token_factor
                a["idf_sum"] += idf
                a["files"].add(rel)
                a["methods"].add(method)
                if primary_frequency > 1:
                    a["shared_ids"].add(idx)
                if idf >= self.config.high_idf_threshold:
                    a["high_idf_ids"].add(idx)
                if method == "hash:exact":
                    a["exact_ids"].add(idx)
                    exact_hit_ids.add(idx)
                else:
                    a["normalized_ids"].add(idx)
                    normalized_hit_ids.add(idx)
                if rel not in a["examples"] and len(a["examples"]) < 12:
                    a["examples"].append(rel)
        snip_agg: dict[str, dict] = defaultdict(
            lambda: {
                "ids": set(),
                "files": set(),
                "idf_sum": 0.0,
                "high_idf": set(),
                "shared": set(),
                "weighted": 0.0,
            }
        )
        snippet_hit_ids: set[int] = set()
        snippet_non_primary_ignored: set[int] = set()
        snippet_high_fanout_ignored: set[int] = set()
        for sid, (_seg_idx, rel, fp_hash) in enumerate(snippet_items):
            rows_all = snippet_map.get(fp_hash, [])
            rows = self._primary_rows(rows_all)
            if not rows:
                if rows_all:
                    snippet_non_primary_ignored.add(sid)
                continue
            primary_frequency = max(
                1, max(int(r.get("primary_component_frequency") or 1) for r in rows)
            )
            if primary_frequency > self.config.max_snippet_component_fanout:
                snippet_high_fanout_ignored.add(sid)
                continue
            idf = self._normalized_idf(total_components, primary_frequency)
            for component in {row["component"] for row in rows}:
                if component not in agg:
                    continue
                a = snip_agg[component]
                if sid in a["ids"]:
                    continue
                a["ids"].add(sid)
                a["files"].add(rel)
                a["idf_sum"] += idf
                a["weighted"] += idf
                if idf >= self.config.high_idf_threshold:
                    a["high_idf"].add(sid)
                if primary_frequency > 1:
                    a["shared"].add(sid)
                snippet_hit_ids.add(sid)
        summaries: list[FingerprintSummary] = []
        candidate_rejections: list[FingerprintRejection] = []
        total = len(segments)
        snippet_total = len(snippet_items)
        for component, a in agg.items():
            matched = len(a["matched_ids"])
            coverage = matched / total if total else 0.0
            mean_idf = a["idf_sum"] / matched if matched else 0.0
            shared_ratio = len(a["shared_ids"]) / matched if matched else 0.0
            quality = 1.0 - math.exp(-a["weighted"] / 10.0)
            coverage_factor = math.sqrt(min(1.0, coverage))
            file_factor = min(1.0, len(a["files"]) / 5.0)
            confidence = min(
                0.995,
                max(
                    0.0,
                    0.30
                    + 0.22 * quality
                    + 0.18 * coverage_factor
                    + 0.12 * file_factor
                    + 0.18 * mean_idf
                    - 0.18 * shared_ratio,
                ),
            )
            sa = snip_agg.get(component)
            snip_matches = len(sa["ids"]) if sa else 0
            snip_cov = snip_matches / snippet_total if snippet_total else 0.0
            snip_mean = (sa["idf_sum"] / snip_matches) if sa and snip_matches else 0.0
            snip_shared = len(sa["shared"]) if sa else 0
            snip_shared_ratio = snip_shared / snip_matches if snip_matches else 0.0
            summary = FingerprintSummary(
                component=component,
                confidence=confidence,
                coverage=coverage,
                exact_matches=len(a["exact_ids"]),
                normalized_matches=len(a["normalized_ids"]),
                matched_segments=matched,
                total_segments=total,
                matched_files=len(a["files"]),
                sampled_files=sampled_files,
                mean_idf=mean_idf,
                high_idf_matches=len(a["high_idf_ids"]),
                shared_matches=len(a["shared_ids"]),
                shared_ratio=shared_ratio,
                weighted_score=a["weighted"],
                snippet_matches=snip_matches,
                snippet_total=snippet_total,
                snippet_coverage=snip_cov,
                snippet_matched_files=len(sa["files"]) if sa else 0,
                snippet_mean_idf=snip_mean,
                snippet_high_idf_matches=len(sa["high_idf"]) if sa else 0,
                snippet_shared_matches=snip_shared,
                snippet_shared_ratio=snip_shared_ratio,
                snippet_weighted_score=sa["weighted"] if sa else 0.0,
                methods=tuple(sorted(a["methods"])),
                supporting_methods=(
                    ("hash:snippet-winnowing",) if snip_matches else ()
                ),
                source_examples=tuple(a["examples"]),
            )
            strong_snippets = self._strong_snippet_support(summary)
            if matched < self.config.min_matches and not strong_snippets:
                candidate_rejections.append(
                    self._rejection(
                        ctx,
                        summary,
                        f"fingerprint_engine:matched_segments<{self.config.min_matches}",
                    )
                )
                continue
            if coverage < self.config.min_coverage and not strong_snippets:
                candidate_rejections.append(
                    self._rejection(
                        ctx,
                        summary,
                        f"fingerprint_engine:coverage<{self.config.min_coverage:.2f}",
                    )
                )
                continue
            summaries.append(summary)
        summaries.sort(
            key=lambda s: (
                -s.confidence,
                -s.mean_idf,
                -s.high_idf_matches,
                -s.snippet_coverage,
                -s.coverage,
                -s.matched_files,
                -s.matched_segments,
                s.component,
            )
        )
        return summaries, {
            "segments": total,
            "exact_hits": len(exact_hit_ids),
            "normalized_hits": len(normalized_hit_ids),
            "snippet_fingerprints": snippet_total,
            "snippet_hits": len(snippet_hit_ids),
            "snippet_non_primary_hits_ignored": len(snippet_non_primary_ignored),
            "snippet_high_fanout_hits_ignored": len(snippet_high_fanout_ignored),
            "sampled_files": sampled_files,
            "non_primary_hits_ignored": len(non_primary_hits_ignored),
            "high_fanout_hits_ignored": len(high_fanout_hits_ignored),
            "candidate_rejections": candidate_rejections,
        }

    @staticmethod
    def _rejection(
        ctx: ComponentContext, summary: FingerprintSummary, reason: str
    ) -> FingerprintRejection:
        return FingerprintRejection(
            component=summary.component,
            root=ctx.display_root,
            stage="fingerprint_engine",
            reject_reason=reason,
            confidence=summary.confidence,
            coverage=summary.coverage,
            exact_matches=summary.exact_matches,
            normalized_matches=summary.normalized_matches,
            matched_segments=summary.matched_segments,
            total_segments=summary.total_segments,
            matched_files=summary.matched_files,
            sampled_files=summary.sampled_files,
            mean_idf=summary.mean_idf,
            high_idf_matches=summary.high_idf_matches,
            shared_matches=summary.shared_matches,
            shared_ratio=summary.shared_ratio,
            weighted_score=summary.weighted_score,
            snippet_matches=summary.snippet_matches,
            snippet_total=summary.snippet_total,
            snippet_coverage=summary.snippet_coverage,
            snippet_matched_files=summary.snippet_matched_files,
            snippet_mean_idf=summary.snippet_mean_idf,
            snippet_high_idf_matches=summary.snippet_high_idf_matches,
            snippet_shared_matches=summary.snippet_shared_matches,
            snippet_shared_ratio=summary.snippet_shared_ratio,
            snippet_weighted_score=summary.snippet_weighted_score,
        )
