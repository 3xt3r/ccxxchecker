from pathlib import Path
from cxxsca.tree_index import TreeIndexer, is_hard_test_path


def test_hard_test_path_classifier():
    assert is_hard_test_path("tests/unit/foo.cpp")
    assert is_hard_test_path("contrib/gtest/src/gtest.cc")
    assert is_hard_test_path("src/foo_test.cpp")
    assert is_hard_test_path("src/test_parser.cpp")
    assert not is_hard_test_path("src/contest.cpp")
    assert not is_hard_test_path("src/core.cpp")


def test_tree_indexer_never_descends_into_test_or_gtest(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "tests" / "unit").mkdir(parents=True)
    (tmp_path / "contrib" / "gtest" / "src").mkdir(parents=True)
    (tmp_path / "src" / "core.cpp").write_text(
        "int core(){return 7;}\n", encoding="utf-8"
    )
    (tmp_path / "tests" / "unit" / "foo.cpp").write_text(
        "int test(){return 1;}\n", encoding="utf-8"
    )
    (tmp_path / "contrib" / "gtest" / "src" / "gtest.cc").write_text(
        "int gtest(){return 2;}\n", encoding="utf-8"
    )
    (tmp_path / "src" / "parser_test.cpp").write_text(
        "int parser_test(){return 3;}\n", encoding="utf-8"
    )
    tree = TreeIndexer(include_soft_skips=True).build(tmp_path)
    assert [r.rel_path for r in tree.files] == ["src/core.cpp"]
