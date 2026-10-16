from __future__ import annotations
import os
import traceback
from dataclasses import dataclass
from pathlib import Path
from checkers.base_checker import BaseChecker
from .checker_catalog import ScoredChecker
from .context import ComponentContext
from .models import Evidence, EvidenceKind
from .util import (
    is_known_version,
    normalize_version,
    regex_literal_tokens,
    repo_token_from_url,
    weak_name_match,
)


@dataclass(slots=True)
class CheckerEngineConfig:
    max_source_files_per_checker: int = 80
    max_bytes_per_file: int = 512_000
    max_checkers_per_context: int = 10


class CheckerEngine:
    def __init__(self, config: CheckerEngineConfig | None = None) -> None:
        self.config = config or CheckerEngineConfig()

    @staticmethod
    def _result_to_evidence(
        result: dict,
        checker: BaseChecker,
        ctx: ComponentContext,
        method: str,
        *,
        identity_confirming: bool,
    ) -> Evidence:
        version = normalize_version(result.get("version"))
        source_abs = (
            result.get("version_source_abs") or result.get("version_source") or ""
        )
        source_rel = ""
        if source_abs:
            try:
                source_rel = os.path.relpath(source_abs, ctx.tree.root).replace(
                    "\\", "/"
                )
            except Exception:
                source_rel = str(source_abs)
        kind = (
            EvidenceKind.VERSION if is_known_version(version) else EvidenceKind.IDENTITY
        )
        base_conf = 0.96 if kind == EvidenceKind.VERSION else 0.78
        if method == "check_meta":
            base_conf = max(base_conf, 0.97 if kind == EvidenceKind.VERSION else 0.82)
        return Evidence(
            kind=kind,
            component=(result.get("name") or checker.PRODUCT or "").strip(),
            version=version,
            confidence=base_conf,
            method=f"checker:{method}",
            source_file=source_rel,
            vendor=(result.get("vendor") or checker.VENDOR or "").strip(),
            vcs=(result.get("link") or checker.LINK_SOURCE or "").strip(),
            cpe=(result.get("cpe") or "").strip(),
            tag_template=(getattr(checker, "TAG_TEMPLATE", "") or "").strip(),
            identity_confirming=identity_confirming,
            details={"checker": checker.__class__.__name__, "root": ctx.display_root},
        )

    @staticmethod
    def _contains_prefilter_literals(checker: BaseChecker) -> set[str]:
        out: set[str] = set()
        for spec in getattr(checker, "CONTAINS_PATTERNS", ()) or ():
            if isinstance(spec, tuple) and spec:
                spec = spec[0]
            out |= regex_literal_tokens(spec)
        return {x for x in out if len(x) >= 5}

    @staticmethod
    def _strong_context_reason(scored: ScoredChecker) -> bool:
        return any(
            reason in {"root:product", "root:repo"} or reason.startswith("anchor:")
            for reason in scored.reasons
        )

    @staticmethod
    def _source_path_names_component(source_file: str, checker: BaseChecker) -> bool:
        if not source_file:
            return False
        product = (checker.PRODUCT or "").strip().lower()
        repo = repo_token_from_url(checker.LINK_SOURCE)
        tokens = [x for x in (product, repo) if x]
        if not tokens:
            return False
        parts = [p.lower() for p in source_file.replace("\\", "/").split("/") if p]
        candidates: list[str] = []
        for part in parts:
            candidates.append(part)
            candidates.append(Path(part).stem.lower())
        return any(
            weak_name_match(candidate, token)
            for candidate in candidates
            for token in tokens
        )

    def _identity_confirming(
        self,
        *,
        result: dict,
        checker: BaseChecker,
        scored: ScoredChecker,
        method: str,
        evidence: Evidence,
    ) -> bool:
        if method == "signature":
            return True
        if method == "check_meta":
            if bool(result.get("identity_confirming")):
                return True
            if bool(getattr(checker, "META_PROVES_IDENTITY", False)):
                return True
        return False

    @staticmethod
    def _append_identity_anchor_once(
        out: list[Evidence],
        *,
        checker: BaseChecker,
        method: str,
        confidence: float,
        source_file: str = "",
        details: dict | None = None,
    ) -> None:
        component = (checker.PRODUCT or "").strip()
        if not component:
            return
        if any(e.component == component and e.method == method for e in out):
            return
        out.append(
            Evidence(
                kind=EvidenceKind.IDENTITY,
                component=component,
                confidence=confidence,
                method=method,
                source_file=source_file,
                vendor=(checker.VENDOR or "").strip(),
                vcs=(checker.LINK_SOURCE or "").strip(),
                identity_confirming=True,
                details=details or {},
            )
        )

    @staticmethod
    def _uses_base_version_method(checker: BaseChecker) -> bool:
        return (
            checker.__class__.check_file_versions_only
            is BaseChecker.check_file_versions_only
        )

    def _append_result(
        self,
        out: list[Evidence],
        result: dict,
        checker: BaseChecker,
        ctx: ComponentContext,
        scored: ScoredChecker,
        method: str,
    ) -> None:
        evidence = self._result_to_evidence(
            result,
            checker,
            ctx,
            method,
            identity_confirming=False,
        )
        evidence.identity_confirming = self._identity_confirming(
            result=result,
            checker=checker,
            scored=scored,
            method=method,
            evidence=evidence,
        )
        out.append(evidence)
        if method == "version" and (
            bool(result.get("identity_confirming"))
            or bool(getattr(checker, "VERSION_PROVES_IDENTITY", False))
        ):
            self._append_identity_anchor_once(
                out,
                checker=checker,
                method="checker:product-meta",
                confidence=0.88,
                source_file=evidence.source_file,
                details={"reason": "product-specific version metadata"},
            )
        if not evidence.identity_confirming and self._strong_context_reason(scored):
            self._append_identity_anchor_once(
                out,
                checker=checker,
                method="checker:root-anchor",
                confidence=0.84,
                source_file=evidence.source_file,
                details={"reasons": scored.reasons},
            )
        elif not evidence.identity_confirming and self._source_path_names_component(
            evidence.source_file, checker
        ):
            self._append_identity_anchor_once(
                out,
                checker=checker,
                method="checker:path-anchor",
                confidence=0.82,
                source_file=evidence.source_file,
                details={"reason": "product/repository token in source path"},
            )

    def inspect(self, ctx: ComponentContext, scored: ScoredChecker) -> list[Evidence]:
        checker = scored.profile.cls()
        checker.reset()
        out: list[Evidence] = []
        try:
            meta_results = checker.check_meta(str(ctx.root_abs)) or []
        except Exception as exc:
            meta_results = []
            out.append(
                Evidence(
                    kind=EvidenceKind.IDENTITY,
                    component=checker.PRODUCT,
                    confidence=0.0,
                    method="checker:error",
                    identity_confirming=False,
                    details={"error": str(exc), "trace": traceback.format_exc(limit=2)},
                )
            )
        for result in meta_results:
            self._append_result(out, result, checker, ctx, scored, "check_meta")
        preferred = []
        for rec in ctx.files:
            try:
                if checker.match_source_filename(str(rec.abs_path)):
                    preferred.append(rec)
            except Exception:
                continue
        if self._uses_base_version_method(checker):
            ordered = list(dict.fromkeys(preferred))
        else:
            ordered = list(dict.fromkeys(preferred + list(ctx.metadata_files)))
        for rec in ordered:
            text = ctx.read_text(rec, max_bytes=self.config.max_bytes_per_file)
            if not text:
                continue
            try:
                results = (
                    checker.check_file_versions_only(text, str(rec.abs_path)) or []
                )
            except Exception:
                continue
            for result in results:
                self._append_result(out, result, checker, ctx, scored, "version")
        if getattr(checker, "CONTAINS_PATTERNS", None):
            literals = self._contains_prefilter_literals(checker)
            scan_files = list(
                dict.fromkeys(
                    preferred
                    + list(ctx.metadata_files)
                    + list(ctx.source_sample(self.config.max_source_files_per_checker))
                )
            )
            checker.reset()
            for rec in scan_files:
                text = ctx.read_text(rec, max_bytes=self.config.max_bytes_per_file)
                if not text:
                    continue
                low = text.lower()
                if literals and not any(tok in low for tok in literals):
                    continue
                try:
                    results = (
                        checker.check_file_contains_only(text, str(rec.abs_path)) or []
                    )
                except Exception:
                    continue
                for result in results:
                    self._append_result(out, result, checker, ctx, scored, "signature")
                if results:
                    break
        if out and scored.score > 0:
            out.append(
                Evidence(
                    kind=EvidenceKind.IDENTITY,
                    component=checker.PRODUCT,
                    confidence=min(0.70, 0.35 + scored.score / 100.0),
                    method="checker:context-score",
                    vendor=checker.VENDOR,
                    vcs=checker.LINK_SOURCE,
                    identity_confirming=False,
                    details={"score": scored.score, "reasons": scored.reasons},
                )
            )
        return [e for e in out if e.confidence > 0]
