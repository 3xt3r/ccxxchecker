from __future__ import annotations
from collections import defaultdict
from pathlib import PurePosixPath
from .checker_catalog import CheckerCatalog
from .context import ComponentContext
from .models import TreeIndex
from .tree_index import SOURCE_EXTENSIONS
from .util import is_under, path_parts, weak_name_match

VENDOR_HINTS = {
    "third_party",
    "third-party",
    "3rdparty",
    "3rd_party",
    "vendor",
    "vendors",
    "external",
    "extern",
    "deps",
    "dependencies",
    "contrib",
    "thirdparty",
}
STRONG_ROOT_MARKERS = {
    "configure.ac",
    "configure.in",
    "cmakelists.txt",
    "meson.build",
    "vcpkg.json",
    "conanfile.txt",
    "conanfile.py",
    "jamroot",
    "module.bazel",
}


class ComponentRootDiscovery:
    def __init__(self, catalog: CheckerCatalog) -> None:
        self.catalog = catalog

    @staticmethod
    def _parent(rel: str) -> str:
        p = PurePosixPath(rel)
        parent = p.parent.as_posix()
        return "" if parent == "." else parent

    def discover(self, tree: TreeIndex) -> tuple[str, ...]:
        roots: set[str] = {""}
        roots.update(tree.git_roots)
        for d in tree.directories:
            parts = path_parts(d)
            if not parts:
                continue
            if parts[-1].lower() in VENDOR_HINTS:
                prefix = d.strip("/")
                prefix_parts = path_parts(prefix)
                for child in tree.directories:
                    cparts = path_parts(child)
                    if (
                        len(cparts) == len(prefix_parts) + 1
                        and cparts[: len(prefix_parts)] == prefix_parts
                    ):
                        roots.add(child)
        all_anchors = sorted(
            {
                a.replace("\\", "/").strip("/")
                for p in self.catalog.profiles
                for a in p.anchors
                if a
            }
        )
        rel_files = {r.rel_path for r in tree.files}
        for anchor in all_anchors:
            aparts = path_parts(anchor)
            for rel in rel_files:
                rparts = path_parts(rel)
                if len(rparts) >= len(aparts) and tuple(
                    x.lower() for x in rparts[-len(aparts) :]
                ) == tuple(x.lower() for x in aparts):
                    prefix = rparts[: -len(aparts)]
                    roots.add("/".join(prefix))
        products = [
            (p.product.lower(), p.repo_token)
            for p in self.catalog.profiles
            if p.product
        ]
        files_by_dir = tree.by_dir
        source_dirs: set[str] = {
            r.directory for r in tree.files if r.suffix in SOURCE_EXTENSIONS
        }
        for d in tree.directories:
            if not d:
                continue
            base = path_parts(d)[-1].lower()
            if not any(
                weak_name_match(base, prod) or (repo and weak_name_match(base, repo))
                for prod, repo in products
            ):
                continue
            local_names = {r.name_lower for r in files_by_dir.get(d, ())}
            has_marker = bool(local_names & STRONG_ROOT_MARKERS) or d in source_dirs
            if has_marker:
                roots.add(d)
        valid: list[str] = []
        for root in sorted(roots, key=lambda x: (len(path_parts(x)), x.lower())):
            if root == "" or any(is_under(r.rel_path, root) for r in tree.files):
                valid.append(root)
        return tuple(valid)

    def build_contexts(
        self, tree: TreeIndex, roots: tuple[str, ...] | None = None
    ) -> list[ComponentContext]:
        roots = roots or self.discover(tree)
        ordered = sorted(roots, key=lambda x: len(path_parts(x)), reverse=True)
        assigned: dict[str, list] = defaultdict(list)
        for rec in tree.files:
            owner = ""
            for root in ordered:
                if is_under(rec.rel_path, root):
                    owner = root
                    break
            assigned[owner].append(rec)
        contexts: list[ComponentContext] = []
        for root in sorted(roots, key=lambda x: (len(path_parts(x)), x.lower())):
            files = tuple(assigned.get(root, ()))
            if not files:
                continue
            children = tuple(r for r in roots if r != root and self._parent(r) == root)
            contexts.append(
                ComponentContext(
                    tree=tree, root_rel=root, files=files, child_roots=children
                )
            )
        return contexts
