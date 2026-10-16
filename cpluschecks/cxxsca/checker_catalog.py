from __future__ import annotations
import inspect
import pkgutil
import re
from dataclasses import dataclass
from importlib import import_module
from typing import Iterable
from checkers.base_checker import BaseChecker
from .context import ComponentContext
from .util import (
    GENERIC_TOKENS,
    idf,
    regex_literal_tokens,
    repo_token_from_url,
    tokenize_text,
    weak_name_match,
)


@dataclass(frozen=True, slots=True)
class CheckerProfile:
    cls: type[BaseChecker]
    vendor: str
    product: str
    vcs: str
    repo_token: str
    anchors: tuple[str, ...]
    tokens: frozenset[str]


@dataclass(frozen=True, slots=True)
class ScoredChecker:
    profile: CheckerProfile
    score: float
    reasons: tuple[str, ...]


def _checker_tokens(cls: type[BaseChecker]) -> set[str]:
    out: set[str] = set()
    product = (getattr(cls, "PRODUCT", "") or "").strip().lower()
    vendor = (getattr(cls, "VENDOR", "") or "").strip().lower()
    vcs = (getattr(cls, "LINK_SOURCE", "") or "").strip()
    for value in (product, vendor, repo_token_from_url(vcs)):
        out |= tokenize_text(value.replace("-", "_").replace("/", "_"), min_len=3)
        if len(value) >= 3:
            out.add(value)
    for name in dir(cls):
        if name.startswith("_"):
            continue
        try:
            value = getattr(cls, name)
        except Exception:
            continue
        if name in {"PRODUCT", "VENDOR", "LINK_SOURCE", "CPE_TEMPLATE"}:
            continue
        if isinstance(value, (str, re.Pattern)):
            if "RX" in name.upper() or "PATTERN" in name.upper():
                out |= regex_literal_tokens(value)
        elif isinstance(value, (list, tuple, set)) and (
            "PATTERN" in name.upper() or "ANCHOR" in name.upper()
        ):
            for item in value:
                if isinstance(item, tuple) and item:
                    item = item[0]
                out |= regex_literal_tokens(item)
    return {t for t in out if t not in GENERIC_TOKENS and len(t) >= 3}


def discover_checker_classes() -> list[type[BaseChecker]]:
    import checkers

    classes: list[type[BaseChecker]] = []
    seen_identity: set[tuple[str, str]] = set()
    for instance in getattr(checkers, "ALL_CHECKERS", []) or []:
        cls = instance.__class__
        identity = (
            (getattr(cls, "VENDOR", "") or "").strip().lower(),
            (getattr(cls, "PRODUCT", "") or "").strip().lower(),
        )
        if identity[1] and identity not in seen_identity:
            classes.append(cls)
            seen_identity.add(identity)
    for modinfo in pkgutil.iter_modules(checkers.__path__):
        if modinfo.name.startswith("_") or modinfo.name == "base_checker":
            continue
        try:
            module = import_module(f"checkers.{modinfo.name}")
        except Exception:
            continue
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if obj is BaseChecker or not issubclass(obj, BaseChecker):
                continue
            if obj.__module__ != module.__name__:
                continue
            identity = (
                (getattr(obj, "VENDOR", "") or "").strip().lower(),
                (getattr(obj, "PRODUCT", "") or "").strip().lower(),
            )
            if not identity[1] or identity in seen_identity:
                continue
            classes.append(obj)
            seen_identity.add(identity)
    classes.sort(
        key=lambda c: ((getattr(c, "PRODUCT", "") or "").lower(), c.__name__.lower())
    )
    return classes


class CheckerCatalog:
    def __init__(
        self, checker_classes: Iterable[type[BaseChecker]] | None = None
    ) -> None:
        classes = list(checker_classes or discover_checker_classes())
        self.profiles: tuple[CheckerProfile, ...] = tuple(
            CheckerProfile(
                cls=cls,
                vendor=(getattr(cls, "VENDOR", "") or "").strip(),
                product=(getattr(cls, "PRODUCT", "") or "").strip(),
                vcs=(getattr(cls, "LINK_SOURCE", "") or "").strip(),
                repo_token=repo_token_from_url(
                    (getattr(cls, "LINK_SOURCE", "") or "").strip()
                ),
                anchors=tuple(getattr(cls, "ROOT_ANCHOR_PATHS", ()) or ()),
                tokens=frozenset(_checker_tokens(cls)),
            )
            for cls in classes
        )
        self.by_product = {p.product.lower(): p for p in self.profiles if p.product}
        token_docs: dict[str, set[int]] = {}
        for i, p in enumerate(self.profiles):
            for token in p.tokens:
                token_docs.setdefault(token, set()).add(i)
        self._token_docs = token_docs
        self._token_idf = {
            token: idf(len(self.profiles), len(ids))
            for token, ids in token_docs.items()
        }

    def profile_for_component(self, name: str) -> CheckerProfile | None:
        return self.by_product.get((name or "").strip().lower())

    def shortlist(
        self, ctx: ComponentContext, *, max_checkers: int = 10
    ) -> list[ScoredChecker]:
        tokens = ctx.identity_tokens()
        score: dict[int, float] = {}
        reasons: dict[int, list[str]] = {}

        def add(i: int, value: float, reason: str) -> None:
            score[i] = score.get(i, 0.0) + value
            reasons.setdefault(i, []).append(reason)

        for token in tokens:
            for i in self._token_docs.get(token, ()):
                add(i, self._token_idf.get(token, 1.0), f"token:{token}")
        root_parts = [
            x.lower() for x in ctx.root_rel.replace("\\", "/").split("/") if x
        ]
        for i, p in enumerate(self.profiles):
            if not p.product:
                continue
            if any(weak_name_match(part, p.product.lower()) for part in root_parts):
                add(i, 12.0, "root:product")
            if p.repo_token and any(
                weak_name_match(part, p.repo_token) for part in root_parts
            ):
                add(i, 10.0, "root:repo")
            if p.anchors:
                names = ctx.filenames
                for anchor in p.anchors:
                    base = anchor.replace("\\", "/").split("/")[-1].lower()
                    if base in names:
                        add(i, 20.0, f"anchor:{anchor}")
                        break
        ranked = sorted(
            (
                ScoredChecker(self.profiles[i], s, tuple(reasons.get(i, ())))
                for i, s in score.items()
                if s > 0
            ),
            key=lambda x: (-x.score, x.profile.product.lower()),
        )
        if ranked:
            return ranked[:max_checkers]
        return [
            ScoredChecker(p, 0.0, ("fallback",)) for p in self.profiles[:max_checkers]
        ]
