from __future__ import annotations
import math
from collections import defaultdict
from .checker_catalog import CheckerCatalog
from .models import (
    Evidence,
    FingerprintRejection,
    FingerprintSummary,
    ResolvedComponent,
)
from .util import (
    is_known_version,
    normalize_version,
    path_parts,
    repo_token_from_url,
    weak_name_match,
)


class EvidenceResolver:
    def __init__(self, catalog: CheckerCatalog) -> None:
        self.catalog = catalog

    @staticmethod
    def _combine_confidences(values: list[float]) -> float:
        miss = 1.0
        for value in values:
            value = min(0.999, max(0.0, value))
            miss *= 1.0 - value
        return 1.0 - miss

    def _root_has_component_affinity(self, root: str, component: str) -> bool:
        tokens = [component.strip().lower()]
        profile = self.catalog.profile_for_component(component)
        if profile:
            repo = repo_token_from_url(profile.vcs)
            if repo:
                tokens.append(repo.lower())
        parts = [p.lower() for p in path_parts("" if root == "(root)" else root)]
        for part in parts:
            for token in tokens:
                if token and weak_name_match(part, token):
                    return True
        return False

    def fingerprint_gate_decision(
        self,
        root: str,
        fp: FingerprintSummary,
    ) -> tuple[bool, str]:
        affinity = self._root_has_component_affinity(root, fp.component)
        strong_snippet_support = (
            fp.matched_segments >= 1
            and fp.snippet_matches >= 20
            and fp.snippet_coverage >= 0.20
            and fp.snippet_matched_files >= 2
            and fp.snippet_mean_idf >= 0.60
            and fp.snippet_high_idf_matches >= 8
            and (fp.snippet_shared_ratio <= 0.35 or affinity)
        )
        if fp.matched_segments < 2 and not strong_snippet_support:
            return False, "resolver:matched_segments<2"
        if fp.coverage < 0.04 and not strong_snippet_support:
            return False, "resolver:coverage<0.04"
        shared_ratio = (
            fp.shared_ratio
            if fp.shared_ratio > 0.0
            else (
                fp.shared_matches / fp.matched_segments if fp.matched_segments else 0.0
            )
        )
        exact_ratio = (
            fp.exact_matches / fp.matched_segments if fp.matched_segments else 0.0
        )
        near_complete_exact = (
            fp.coverage >= 0.90
            and exact_ratio >= 0.80
            and fp.matched_segments >= 4
            and fp.matched_files >= 3
            and fp.mean_idf >= 0.55
        )
        if shared_ratio > 0.50 and not (
            affinity or near_complete_exact or strong_snippet_support
        ):
            return False, "resolver:high_shared_without_affinity"
        if shared_ratio > 0.20 and not (
            affinity or near_complete_exact or strong_snippet_support
        ):
            return False, "resolver:shared_ratio>0.20_without_root_affinity"
        if fp.mean_idf < 0.45 and not (affinity or strong_snippet_support):
            return False, "resolver:mean_idf<0.45_without_root_affinity"
        if (
            fp.total_segments <= 64
            and fp.coverage >= 0.90
            and fp.matched_segments >= 2
            and (
                fp.exact_matches >= max(2, int(fp.matched_segments * 0.80))
                or (fp.total_segments <= 16 and fp.normalized_matches >= 2)
            )
            and (fp.high_idf_matches >= 1 or affinity)
        ):
            return True, "accepted:compact_high_coverage"
        strong_hash_signal = fp.exact_matches >= 2 or fp.normalized_matches >= 8
        if not strong_hash_signal and strong_snippet_support:
            return True, "accepted:snippet_supported_seed"
        if not strong_hash_signal:
            return False, "resolver:weak_hash_signal"
        if (
            fp.matched_files >= 3
            and fp.coverage >= 0.06
            and fp.mean_idf >= 0.55
            and fp.high_idf_matches >= 2
        ):
            return True, "accepted:multi_file"
        if (
            affinity
            and fp.matched_files >= 1
            and fp.matched_segments >= 4
            and fp.coverage >= 0.10
            and fp.mean_idf >= 0.35
        ):
            return True, "accepted:root_affinity"
        return False, "resolver:insufficient_file_diversity_or_root_affinity"

    @staticmethod
    def _fingerprint_rank_bonus(fp: FingerprintSummary | None) -> float:
        if fp is None:
            return 0.0
        return min(
            0.035,
            0.010 * min(1.0, fp.coverage)
            + 0.006 * min(1.0, fp.matched_files / 5.0)
            + 0.004 * min(1.0, math.log1p(fp.matched_segments) / 7.0)
            + 0.015 * min(1.0, fp.mean_idf)
            + 0.004 * min(1.0, fp.snippet_coverage)
            + 0.004 * min(1.0, fp.snippet_mean_idf)
            - 0.010 * min(1.0, fp.shared_ratio)
            - 0.004 * min(1.0, fp.snippet_shared_ratio),
        )

    @staticmethod
    def _rejection(
        root: str,
        fp: FingerprintSummary,
        reason: str,
        *,
        stage: str = "resolver",
    ) -> FingerprintRejection:
        return FingerprintRejection(
            component=fp.component,
            root=root,
            stage=stage,
            reject_reason=reason,
            confidence=fp.confidence,
            coverage=fp.coverage,
            exact_matches=fp.exact_matches,
            normalized_matches=fp.normalized_matches,
            matched_segments=fp.matched_segments,
            total_segments=fp.total_segments,
            matched_files=fp.matched_files,
            sampled_files=fp.sampled_files,
            mean_idf=fp.mean_idf,
            high_idf_matches=fp.high_idf_matches,
            shared_matches=fp.shared_matches,
            shared_ratio=fp.shared_ratio,
            weighted_score=fp.weighted_score,
            snippet_matches=fp.snippet_matches,
            snippet_total=fp.snippet_total,
            snippet_coverage=fp.snippet_coverage,
            snippet_matched_files=fp.snippet_matched_files,
            snippet_mean_idf=fp.snippet_mean_idf,
            snippet_high_idf_matches=fp.snippet_high_idf_matches,
            snippet_shared_matches=fp.snippet_shared_matches,
            snippet_shared_ratio=fp.snippet_shared_ratio,
            snippet_weighted_score=fp.snippet_weighted_score,
        )

    def resolve(
        self,
        root: str,
        checker_evidence: list[Evidence],
        fingerprints: list[FingerprintSummary],
    ) -> ResolvedComponent | None:
        resolved, _ = self.resolve_with_diagnostics(
            root, checker_evidence, fingerprints
        )
        return resolved

    def resolve_with_diagnostics(
        self,
        root: str,
        checker_evidence: list[Evidence],
        fingerprints: list[FingerprintSummary],
    ) -> tuple[ResolvedComponent | None, list[FingerprintRejection]]:
        checker_support_scores: dict[str, list[float]] = defaultdict(list)
        context_support_scores: dict[str, list[float]] = defaultdict(list)
        fingerprint_identity_scores: dict[str, list[float]] = defaultdict(list)
        version_scores: dict[tuple[str, str], list[float]] = defaultdict(list)
        evidence_files: dict[str, set[str]] = defaultdict(set)
        meta: dict[str, dict] = defaultdict(dict)
        methods: dict[str, set[str]] = defaultdict(set)
        identity_methods: dict[str, set[str]] = defaultdict(set)
        fp_by_component: dict[str, FingerprintSummary] = {}
        rejections: list[FingerprintRejection] = []
        for evidence in checker_evidence:
            name = (evidence.component or "").strip()
            if not name:
                continue
            methods[name].add(evidence.method)
            if evidence.source_file:
                evidence_files[name].add(evidence.source_file)
            if evidence.vendor:
                meta[name]["vendor"] = evidence.vendor
            if evidence.vcs:
                meta[name]["vcs"] = evidence.vcs
            if evidence.cpe:
                meta[name].setdefault("cpe", evidence.cpe)
            if evidence.tag_template:
                meta[name].setdefault("tag_template", evidence.tag_template)
            if evidence.identity_confirming:
                checker_support_scores[name].append(evidence.confidence)
            elif evidence.method == "checker:context-score":
                context_support_scores[name].append(evidence.confidence)
            if is_known_version(evidence.version):
                version = normalize_version(evidence.version)
                version_scores[(name, version)].append(evidence.confidence)
                if evidence.cpe:
                    meta[name].setdefault("cpe_by_version", {})[version] = evidence.cpe
        for fp in fingerprints:
            name = (fp.component or "").strip()
            if not name:
                continue
            accepted, reason = self.fingerprint_gate_decision(root, fp)
            if not accepted:
                rejections.append(self._rejection(root, fp, reason))
                continue
            fingerprint_identity_scores[name].append(fp.confidence)
            identity_methods[name].update(fp.methods)
            methods[name].update(fp.methods)
            methods[name].update(fp.supporting_methods)
            evidence_files[name].update(fp.source_examples)
            old = fp_by_component.get(name)
            if old is None or (
                fp.confidence,
                fp.coverage,
                fp.matched_files,
                fp.matched_segments,
            ) > (
                old.confidence,
                old.coverage,
                old.matched_files,
                old.matched_segments,
            ):
                fp_by_component[name] = fp
        if not fingerprint_identity_scores:
            return None, rejections
        ranked_components: list[tuple[str, float, float]] = []
        for name, fp_scores in fingerprint_identity_scores.items():
            identity_confidence = self._combine_confidences(fp_scores)
            checker_support = self._combine_confidences(
                checker_support_scores.get(name, [])
            )
            context_support = self._combine_confidences(
                context_support_scores.get(name, [])
            )
            checker_rank_bonus = min(
                0.012,
                0.008 * checker_support + 0.004 * context_support,
            )
            rank_score = (
                identity_confidence
                + self._fingerprint_rank_bonus(fp_by_component.get(name))
                + checker_rank_bonus
            )
            ranked_components.append((name, identity_confidence, rank_score))
        ranked_components.sort(key=lambda item: (-item[2], -item[1], item[0].lower()))
        name, component_conf, top_rank = ranked_components[0]
        if component_conf < 0.55:
            for candidate, _, _ in ranked_components:
                rejections.append(
                    self._rejection(
                        root,
                        fp_by_component[candidate],
                        "resolver:component_confidence<0.55",
                    )
                )
            return None, rejections
        if len(ranked_components) > 1:
            second_rank = ranked_components[1][2]
            margin = top_rank - second_rank
            if margin < 0.015 or (component_conf < 0.90 and margin < 0.08):
                for candidate, _, _ in ranked_components:
                    rejections.append(
                        self._rejection(
                            root,
                            fp_by_component[candidate],
                            "resolver:ambiguous_top_candidates",
                        )
                    )
                return None, rejections
        for candidate, _, _ in ranked_components[1:]:
            rejections.append(
                self._rejection(
                    root, fp_by_component[candidate], "resolver:not_selected"
                )
            )
        versions = [
            (version, self._combine_confidences(scores))
            for (component, version), scores in version_scores.items()
            if component == name and is_known_version(version)
        ]
        versions.sort(key=lambda item: (-item[1], item[0]))
        version = versions[0][0] if versions else "unknown"
        profile = self.catalog.profile_for_component(name)
        vendor = meta[name].get("vendor", profile.vendor if profile else "")
        vcs = meta[name].get("vcs", profile.vcs if profile else "")
        cpe = meta[name].get("cpe_by_version", {}).get(version, "")
        if not cpe:
            cpe = meta[name].get("cpe", "")
        if not cpe and profile:
            try:
                checker = profile.cls()
                cpe = checker.make_result(version, "").get("cpe", "")
            except Exception:
                cpe = ""
        conflicts: list[str] = []
        if len(versions) > 1 and versions[0][1] - versions[1][1] < 0.12:
            conflicts.append(
                f"metadata version candidates close: {versions[0][0]} vs {versions[1][0]}"
            )
        fp = fp_by_component[name]
        return (
            ResolvedComponent(
                name=name,
                version=version,
                confidence=min(0.999, component_conf),
                root=root,
                vendor=vendor,
                vcs=vcs,
                cpe=cpe,
                tag_template=meta[name].get(
                    "tag_template",
                    (getattr(profile.cls, "TAG_TEMPLATE", "") or "") if profile else "",
                ),
                identity_confirmed=True,
                identity_methods=tuple(sorted(identity_methods[name])),
                methods=tuple(sorted(methods[name])),
                evidence_files=tuple(sorted(evidence_files[name])),
                fingerprint_coverage=fp.coverage,
                fingerprint_exact_matches=fp.exact_matches,
                fingerprint_normalized_matches=fp.normalized_matches,
                fingerprint_matched_segments=fp.matched_segments,
                fingerprint_total_segments=fp.total_segments,
                fingerprint_matched_files=fp.matched_files,
                fingerprint_sampled_files=fp.sampled_files,
                fingerprint_mean_idf=fp.mean_idf,
                fingerprint_high_idf_matches=fp.high_idf_matches,
                fingerprint_shared_matches=fp.shared_matches,
                fingerprint_shared_ratio=fp.shared_ratio,
                fingerprint_weighted_score=fp.weighted_score,
                fingerprint_snippet_matches=fp.snippet_matches,
                fingerprint_snippet_total=fp.snippet_total,
                fingerprint_snippet_coverage=fp.snippet_coverage,
                fingerprint_snippet_matched_files=fp.snippet_matched_files,
                fingerprint_snippet_mean_idf=fp.snippet_mean_idf,
                fingerprint_snippet_high_idf_matches=fp.snippet_high_idf_matches,
                fingerprint_snippet_shared_matches=fp.snippet_shared_matches,
                fingerprint_snippet_shared_ratio=fp.snippet_shared_ratio,
                fingerprint_snippet_weighted_score=fp.snippet_weighted_score,
                conflicts=tuple(conflicts),
            ),
            rejections,
        )
