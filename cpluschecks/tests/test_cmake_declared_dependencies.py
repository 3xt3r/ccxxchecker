from pathlib import Path
from cxxsca.checker_catalog import CheckerCatalog
from cxxsca.cmake_dependencies import discover_cmake_declared_components
from cxxsca.tree_index import TreeIndexer


def test_external_project_add_declares_avro_with_version_hash_and_depends(
    tmp_path: Path,
):
    cmake = tmp_path / "CMakeLists.txt"
    cmake.write_text(
        """
set(REPOSITORY "https://repo.example.local")
set(AVRO_URL "${REPOSITORY}/avro/avro-cpp-1.12.1.dirty.tar.gz")
set(AVRO_URL_HASH "SHA256=1eb2f66a74b41f22d003cb6d2bd0b99f4aa901ee55b8ec4fddb2288f5414abc")
external_project_add(
  avro
  DEPENDS boost fmt snappy zlib
  URL ${AVRO_URL}
  URL_HASH ${AVRO_URL_HASH}
  DOWNLOAD_NO_PROGRESS ON
  CMAKE_ARGS -DAVRO_BUILD_STATIC=ON
  TEST_COMMAND ""
)
""",
        encoding="utf-8",
    )
    tree = TreeIndexer().build(tmp_path)
    found = discover_cmake_declared_components(tree, CheckerCatalog())
    assert len(found) == 1
    avro = found[0]
    assert avro.name == "avro"
    assert avro.version == "1.12.1"
    assert avro.cpe == "cpe:2.3:a:apache:avro:1.12.1:*:*:*:*:*:*:*"
    assert avro.declaration_source_url.endswith("/avro-cpp-1.12.1.dirty.tar.gz")
    assert avro.declaration_hash_alg == "SHA-256"
    assert avro.declaration_hash_value.startswith("1EB2F66A")
    assert avro.declared_dependencies == ("boost", "fmt", "snappy", "zlib")
    assert avro.identity_confirmed is True
    assert "build:cmake:ExternalProject_Add" in avro.identity_methods


def test_fetchcontent_declare_git_tag(tmp_path: Path):
    cmake = tmp_path / "deps.cmake"
    cmake.write_text(
        """
FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG 11.2.0
)
""",
        encoding="utf-8",
    )
    tree = TreeIndexer().build(tmp_path)
    found = discover_cmake_declared_components(tree, CheckerCatalog())
    assert len(found) == 1
    fmt = found[0]
    assert fmt.name == "fmt"
    assert fmt.version == "11.2.0"
    assert fmt.vcs == "https://github.com/fmtlib/fmt.git"
    assert fmt.declaration_kind == "cmake:FetchContent_Declare"


def test_local_external_project_without_remote_source_is_not_component(tmp_path: Path):
    (tmp_path / "CMakeLists.txt").write_text(
        "ExternalProject_Add(internal_tool SOURCE_DIR ${CMAKE_SOURCE_DIR}/tools/internal)\n",
        encoding="utf-8",
    )
    tree = TreeIndexer().build(tmp_path)
    found = discover_cmake_declared_components(tree, CheckerCatalog())
    assert found == []


def test_external_project_add_boost_underscore_version(tmp_path: Path):
    cmake = tmp_path / "CMakeLists.txt"
    cmake.write_text(
        r"""
set(BOOST_URL "${REPOSITORY}/boost/boost_1_85_0.tar.gz")
set(BOOST_URL_HASH "SHA256=f4a7d3f81b8a0f65067b769ea84135fd7b72896f4f59c7f405086c8c0dc61434")
set(BOOST_CONFIGURE_COMMAND
    cd <SOURCE_DIR> && ./bootstrap.sh
    --with-libraries=system,filesystem,program_options,iostreams,regex
)
set(BOOST_BUILD_OPTS
    --build-dir=<BINARY_DIR>
    --with-context
    --with-filesystem
    --with-iostreams
    --with-program_options
    --with-regex
    --with-system
)
set(BOOST_INSTALL_OPTS
    --prefix=<INSTALL_DIR>
    --exec-prefix=<INSTALL_DIR>
)
set(BOOST_BUILD_PROPS
    link=static
    variant=release
)
set(BOOST_BUILD_AND_INSTALL_COMMAND
    cd <SOURCE_DIR> &&
    ./b2 ${BOOST_BUILD_OPTS} ${BOOST_INSTALL_OPTS} ${BOOST_BUILD_PROPS} install
)
external_project_add(
    boost
    URL                  ${BOOST_URL}
    URL_HASH             ${BOOST_URL_HASH}
    DOWNLOAD_NO_PROGRESS ON
    CONFIGURE_COMMAND    ${BOOST_CONFIGURE_COMMAND}
    BUILD_COMMAND        ${BOOST_BUILD_AND_INSTALL_COMMAND}
    INSTALL_COMMAND      ""
    TEST_COMMAND         ""
)
""",
        encoding="utf-8",
    )
    tree = TreeIndexer().build(tmp_path)
    found = discover_cmake_declared_components(tree, CheckerCatalog())
    assert len(found) == 1
    boost = found[0]
    assert boost.name == "boost"
    assert boost.version == "1.85.0"
    assert boost.cpe == "cpe:2.3:a:boost:boost:1.85.0:*:*:*:*:*:*:*"
    assert boost.declaration_source_url == "${REPOSITORY}/boost/boost_1_85_0.tar.gz"
    assert boost.declaration_hash_alg == "SHA-256"
    assert (
        boost.declaration_hash_value
        == "F4A7D3F81B8A0F65067B769EA84135FD7B72896F4F59C7F405086C8C0DC61434"
    )


def test_cmake_alias_zeromq_uses_libzmq_checker_and_cpe(tmp_path: Path):
    (tmp_path / "CMakeLists.txt").write_text(
        """
ExternalProject_Add(
    zeromq
    URL https://github.com/zeromq/libzmq/releases/download/v4.3.5/zeromq-4.3.5.tar.gz
)
""",
        encoding="utf-8",
    )
    tree = TreeIndexer().build(tmp_path)
    found = discover_cmake_declared_components(tree, CheckerCatalog())
    assert len(found) == 1
    item = found[0]
    assert item.name == "libzmq"
    assert item.version == "4.3.5"
    assert item.cpe == "cpe:2.3:a:zeromq:libzmq:4.3.5:*:*:*:*:*:*:*"


def test_cmake_alias_libcg_uses_libcgroup_checker_and_cpe(tmp_path: Path):
    (tmp_path / "CMakeLists.txt").write_text(
        """
ExternalProject_Add(
    libcg
    URL https://github.com/libcgroup/libcgroup/releases/download/v3.1.0/libcgroup-3.1.0.tar.gz
)
""",
        encoding="utf-8",
    )
    tree = TreeIndexer().build(tmp_path)
    found = discover_cmake_declared_components(tree, CheckerCatalog())
    assert len(found) == 1
    item = found[0]
    assert item.name == "libcgroup"
    assert item.version == "3.1.0"
    assert item.cpe == "cpe:2.3:a:libcgroup_project:libcgroup:3.1.0:*:*:*:*:*:*:*"


def test_cmake_aliases_tbb_avro_cpp_sqlite3_use_existing_checkers(tmp_path: Path):
    (tmp_path / "CMakeLists.txt").write_text(
        """
ExternalProject_Add(tbb URL https://example.test/oneTBB-2022.1.0.tar.gz)
ExternalProject_Add(avro-cpp URL https://example.test/avro-cpp-1.12.1.tar.gz)
ExternalProject_Add(sqlite3 URL https://example.test/sqlite-3.49.1.tar.gz)
""",
        encoding="utf-8",
    )
    tree = TreeIndexer().build(tmp_path)
    found = discover_cmake_declared_components(tree, CheckerCatalog())
    by_name = {item.name: item for item in found}
    assert "oneTBB" in by_name
    assert by_name["oneTBB"].version == "2022.1.0"
    assert "avro" in by_name
    assert by_name["avro"].version == "1.12.1"
    assert "sqlite" in by_name
    assert by_name["sqlite"].version == "3.49.1"


def test_external_project_unresolved_artifacts_boost_and_libcg(tmp_path: Path):
    (tmp_path / "CMakeLists.txt").write_text(
        r"""
CMAKE_MINIMUM_REQUIRED(VERSION 3.6)
include (ExternalProject)
ExternalProject_Add(boost
    URL ${ARTIFACTS}/boost/boost_1_86_0.tar.bz2
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND echo
    BUILD_COMMAND echo
    INSTALL_COMMAND echo
)
ExternalProject_Add(libcg
    URL ${ARTIFACTS}/libcg/libcgroup-3.1.0.tar.gz
    CONFIGURE_COMMAND <SOURCE_DIR>/configure
        --prefix=<INSTALL_DIR>
        --host=${GNU_HOST}
)
""",
        encoding="utf-8",
    )
    tree = TreeIndexer().build(tmp_path)
    found = discover_cmake_declared_components(tree, CheckerCatalog())
    by_name = {item.name: item for item in found}
    assert by_name["boost"].version == "1.86.0"
    assert by_name["boost"].cpe == "cpe:2.3:a:boost:boost:1.86.0:*:*:*:*:*:*:*"
    assert (
        by_name["boost"].declaration_source_url
        == "${ARTIFACTS}/boost/boost_1_86_0.tar.bz2"
    )
    assert by_name["libcgroup"].version == "3.1.0"
    assert (
        by_name["libcgroup"].cpe
        == "cpe:2.3:a:libcgroup_project:libcgroup:3.1.0:*:*:*:*:*:*:*"
    )
    assert by_name["libcgroup"].declaration_target == "libcg"


def test_conditional_libpcap_emits_all_static_versions_with_conditions(tmp_path: Path):
    (tmp_path / "CMakeLists.txt").write_text(
        r"""
CMAKE_MINIMUM_REQUIRED(VERSION 3.6)
include (ExternalProject)
if("${GNU_HOST}" STREQUAL "x86_64-rhel5-linux-gnu")
    ExternalProject_Add(libpcap
        URL ${ARTIFACTS}/libpcap/libpcap-1.9.1.tar.gz
        CONFIGURE_COMMAND <SOURCE_DIR>/configure
    )
elseif("${GNU_HOST}" STREQUAL "ppc64-ibm-aix7.2")
    ExternalProject_Add(libpcap
        URL ${ARTIFACTS}/libpcap/libpcap-1.10.4.tar.gz
        CONFIGURE_COMMAND <SOURCE_DIR>/configure
    )
else()
    ExternalProject_Add(libpcap
        URL ${ARTIFACTS}/libpcap/libpcap-1.10.5.tar.xz
        CONFIGURE_COMMAND <SOURCE_DIR>/configure
    )
endif()
""",
        encoding="utf-8",
    )
    tree = TreeIndexer().build(tmp_path)
    found = discover_cmake_declared_components(tree, CheckerCatalog())
    pcaps = [item for item in found if item.name == "libpcap"]
    assert {item.version for item in pcaps} == {"1.9.1", "1.10.4", "1.10.5"}
    assert {item.cpe for item in pcaps} == {
        "cpe:2.3:a:tcpdump:libpcap:1.9.1:*:*:*:*:*:*:*",
        "cpe:2.3:a:tcpdump:libpcap:1.10.4:*:*:*:*:*:*:*",
        "cpe:2.3:a:tcpdump:libpcap:1.10.5:*:*:*:*:*:*:*",
    }
    assert all(item.declaration_conditions for item in pcaps)
    assert any(
        "x86_64-rhel5-linux-gnu" in item.declaration_conditions[0] for item in pcaps
    )
    assert any("ppc64-ibm-aix7.2" in item.declaration_conditions[0] for item in pcaps)
    assert any(item.declaration_conditions[0].startswith("else(") for item in pcaps)


def test_conditional_openssl_variable_preserves_111w_and_355(tmp_path: Path):
    (tmp_path / "CMakeLists.txt").write_text(
        r"""
CMAKE_MINIMUM_REQUIRED(VERSION 3.6)
include (ExternalProject)
if(UNIX)
    if ("${GNU_HOST}" STREQUAL "x86_64-rhel5-linux-gnu" OR
        "${GNU_HOST}" STREQUAL "ppc64-ibm-aix7.2" OR
        "${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "s390x" OR
        "${CMAKE_SYSTEM_NAME}" STREQUAL "SunOS")
        set(OPENSSL_VERSION "1.1.1w")
    else()
        set(OPENSSL_VERSION "3.5.5")
    endif()
    ExternalProject_Add(openssl
        URL ${ARTIFACTS}/openssl/openssl-${OPENSSL_VERSION}.tar.gz
        BUILD_IN_SOURCE 1
        BUILD_COMMAND make
        INSTALL_COMMAND make install_sw
    )
elseif(WIN32)
    set(OPENSSL_VERSION "3.5.5")
    ExternalProject_Add(openssl
        URL ${ARTIFACTS}/openssl/openssl-${OPENSSL_VERSION}.tar.gz
    )
endif()
""",
        encoding="utf-8",
    )
    tree = TreeIndexer().build(tmp_path)
    found = discover_cmake_declared_components(tree, CheckerCatalog())
    openssl = [item for item in found if item.name == "openssl"]
    by_version = {item.version: item for item in openssl}
    assert set(by_version) == {"1.1.1w", "3.5.5"}
    assert by_version["1.1.1w"].cpe == "cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*"
    assert by_version["1.1.1w"].declaration_source_url.endswith("openssl-1.1.1w.tar.gz")
    assert any(
        "if(UNIX)" in cond for cond in by_version["1.1.1w"].declaration_conditions
    )
    assert by_version["3.5.5"].cpe == "cpe:2.3:a:openssl:openssl:3.5.5:*:*:*:*:*:*:*"
    assert by_version["3.5.5"].declaration_source_url.endswith("openssl-3.5.5.tar.gz")
    assert len(by_version["3.5.5"].declaration_conditions) == 2
    assert any(
        "elseif(WIN32)" in cond for cond in by_version["3.5.5"].declaration_conditions
    )
