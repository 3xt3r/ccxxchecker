from __future__ import annotations
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from .models import ResolvedComponent
from .util import is_known_version


def _purl(name: str, version: str) -> str | None:
    if not name:
        return None
    version = (version or "unknown").strip() or "unknown"
    return f"pkg:generic/{quote(name, safe='._-')}@{quote(version, safe='._-+')}"


def component_to_cdx(c: ResolvedComponent) -> dict:
    props = [
        {"name": "component.root", "value": c.root},
        {"name": "detection.confidence", "value": f"{c.confidence:.4f}"},
        {
            "name": "detection.identity_confirmed",
            "value": str(bool(c.identity_confirmed)).lower(),
        },
        {"name": "detection.identity_methods", "value": ",".join(c.identity_methods)},
        {"name": "detection.methods", "value": ",".join(c.methods)},
    ]
    for f in c.evidence_files:
        props.append({"name": "evidence.file", "value": f})
    if c.tag_template:
        props.append(
            {"name": "safe-versions:tag-template", "value": c.tag_template}
        )
    if c.fingerprint_coverage is not None:
        props.extend(
            [
                {
                    "name": "fingerprint.identity.coverage",
                    "value": f"{c.fingerprint_coverage:.4f}",
                },
                {
                    "name": "fingerprint.identity.exact_matches",
                    "value": str(c.fingerprint_exact_matches),
                },
                {
                    "name": "fingerprint.identity.normalized_matches",
                    "value": str(c.fingerprint_normalized_matches),
                },
                {
                    "name": "fingerprint.identity.matched_segments",
                    "value": str(c.fingerprint_matched_segments),
                },
                {
                    "name": "fingerprint.identity.total_segments",
                    "value": str(c.fingerprint_total_segments),
                },
                {
                    "name": "fingerprint.identity.matched_files",
                    "value": str(c.fingerprint_matched_files),
                },
                {
                    "name": "fingerprint.identity.sampled_files",
                    "value": str(c.fingerprint_sampled_files),
                },
                {
                    "name": "fingerprint.identity.mean_idf",
                    "value": f"{c.fingerprint_mean_idf:.4f}",
                },
                {
                    "name": "fingerprint.identity.high_idf_matches",
                    "value": str(c.fingerprint_high_idf_matches),
                },
                {
                    "name": "fingerprint.identity.shared_matches",
                    "value": str(c.fingerprint_shared_matches),
                },
                {
                    "name": "fingerprint.identity.shared_ratio",
                    "value": f"{c.fingerprint_shared_ratio:.4f}",
                },
                {
                    "name": "fingerprint.identity.weighted_score",
                    "value": f"{c.fingerprint_weighted_score:.4f}",
                },
                {
                    "name": "fingerprint.support.snippet_matches",
                    "value": str(c.fingerprint_snippet_matches),
                },
                {
                    "name": "fingerprint.support.snippet_total",
                    "value": str(c.fingerprint_snippet_total),
                },
                {
                    "name": "fingerprint.support.snippet_coverage",
                    "value": f"{c.fingerprint_snippet_coverage:.4f}",
                },
                {
                    "name": "fingerprint.support.snippet_matched_files",
                    "value": str(c.fingerprint_snippet_matched_files),
                },
                {
                    "name": "fingerprint.support.snippet_mean_idf",
                    "value": f"{c.fingerprint_snippet_mean_idf:.4f}",
                },
                {
                    "name": "fingerprint.support.snippet_high_idf_matches",
                    "value": str(c.fingerprint_snippet_high_idf_matches),
                },
                {
                    "name": "fingerprint.support.snippet_shared_matches",
                    "value": str(c.fingerprint_snippet_shared_matches),
                },
                {
                    "name": "fingerprint.support.snippet_shared_ratio",
                    "value": f"{c.fingerprint_snippet_shared_ratio:.4f}",
                },
                {
                    "name": "fingerprint.support.snippet_weighted_score",
                    "value": f"{c.fingerprint_snippet_weighted_score:.4f}",
                },
            ]
        )
    if c.metadata_version_source_root:
        props.append(
            {
                "name": "metadata.version.source_root",
                "value": c.metadata_version_source_root,
            }
        )
    if c.declaration_kind:
        props.append({"name": "build.declaration.kind", "value": c.declaration_kind})
    if c.declaration_target:
        props.append(
            {"name": "build.declaration.target", "value": c.declaration_target}
        )
    if c.declaration_source_url:
        props.append(
            {"name": "build.declaration.url", "value": c.declaration_source_url}
        )
    if c.declaration_hash_raw:
        props.append(
            {"name": "build.declaration.url_hash", "value": c.declaration_hash_raw}
        )
    if c.declared_dependencies:
        props.append(
            {
                "name": "build.declaration.depends",
                "value": ",".join(c.declared_dependencies),
            }
        )
    if c.declaration_conditions:
        props.append(
            {
                "name": "build.declaration.conditions",
                "value": " || ".join(c.declaration_conditions),
            }
        )
    for conflict in c.conflicts:
        props.append({"name": "detection.conflict", "value": conflict})
    out = {
        "type": "library",
        "name": c.name,
        "version": c.version,
        "bom-ref": f"urn:uuid:{uuid.uuid4()}",
        "properties": props,
    }
    if c.cpe:
        out["cpe"] = c.cpe
    purl = _purl(c.name, c.version)
    if purl:
        out["purl"] = purl
    external_refs = []
    if c.vcs:
        external_refs.append({"type": "vcs", "url": c.vcs})
    if c.declaration_source_url.startswith(("https://", "http://")):
        src_ref = {"type": "source-distribution", "url": c.declaration_source_url}
        if c.declaration_hash_alg and c.declaration_hash_value:
            src_ref["hashes"] = [
                {
                    "alg": c.declaration_hash_alg,
                    "content": c.declaration_hash_value,
                }
            ]
        external_refs.append(src_ref)
    if external_refs:
        out["externalReferences"] = external_refs
    return out


def make_bom(components: list[ResolvedComponent], *, name: str) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {"type": "application", "name": name},
        },
        "components": [component_to_cdx(c) for c in components],
    }


def write_split_sbom(
    components: list[ResolvedComponent],
    known_path: str | Path,
    unknown_path: str | Path,
) -> None:
    known = sorted(
        (c for c in components if is_known_version(c.version)),
        key=lambda x: (x.name.lower(), x.version, x.root),
    )
    unknown = sorted(
        (c for c in components if not is_known_version(c.version)),
        key=lambda x: (x.name.lower(), x.root),
    )
    known_path = Path(known_path)
    unknown_path = Path(unknown_path)
    known_path.parent.mkdir(parents=True, exist_ok=True)
    unknown_path.parent.mkdir(parents=True, exist_ok=True)
    known_path.write_text(
        json.dumps(make_bom(known, name="known"), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    unknown_path.write_text(
        json.dumps(make_bom(unknown, name="unknown"), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
