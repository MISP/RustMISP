#!/usr/bin/env python3
"""
RustMISP / PyMISP parity checker.

Compares the public API surface and integration tests of RustMISP against
PyMISP to identify missing methods and test coverage gaps.

Usage:
    python3 scripts/check_pymisp_parity.py [--pymisp-path /path/to/PyMISP]

If --pymisp-path is not given, the script looks for PyMISP in common locations:
  - ../PyMISP (sibling directory)
  - ../../PyMISP
  - /var/www/MISP7/PyMISP
"""

import argparse
import ast
import os
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

def extract_pymisp_methods(api_path: Path) -> list[str]:
    """Extract all public method names from PyMISP's api.py using the AST."""
    source = api_path.read_text()
    tree = ast.parse(source)

    methods = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "PyMISP":
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    name = item.name
                    if not name.startswith("_"):
                        methods.append(name)
    return sorted(set(methods))


def extract_pymisp_tests(test_path: Path) -> list[str]:
    """Extract all test method names from testlive_comprehensive.py."""
    source = test_path.read_text()
    tree = ast.parse(source)

    tests = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if item.name.startswith("test_"):
                        tests.append(item.name)
    return sorted(set(tests))


def extract_rustmisp_methods(client_path: Path) -> list[str]:
    """Extract all `pub async fn` names from RustMISP's client.rs."""
    source = client_path.read_text()
    # Match public async methods, skip test functions
    pattern = re.compile(r"pub async fn (\w+)")
    methods = []
    in_test = False
    for line in source.splitlines():
        if "#[cfg(test)]" in line:
            in_test = True
        if in_test:
            continue
        m = pattern.search(line)
        if m:
            methods.append(m.group(1))
    return sorted(set(methods))


def extract_rustmisp_tests(test_path: Path) -> list[str]:
    """Extract all test function names from integration_tests.rs."""
    source = test_path.read_text()
    pattern = re.compile(r"async fn (test_\w+)")
    return sorted(set(pattern.findall(source)))


# ---------------------------------------------------------------------------
# Name normalisation — maps PyMISP method names to RustMISP equivalents
# ---------------------------------------------------------------------------

# Known name differences: pymisp_name -> rustmisp_name
NAME_MAP = {
    "push_event_to_ZMQ": "push_event_to_zmq",
    "recommended_pymisp_version": None,  # Python-specific
    "pymisp_version_master": None,       # Python-specific
    "pymisp_version_main": None,         # Python-specific
    "toggle_global_pythonify": None,     # Python-specific
    "get_all_functions": None,           # Python-specific introspection
    "describe_types_local": None,        # Python-specific (reads local file)
    "cached_property": None,             # Python decorator, not an API method
    "build_complex_query": "build_complex_query",  # standalone fn in Rust
    "sign_blob": None,                   # Rare/obscure endpoint
}

# PyMISP methods that are Python-language-specific and have no Rust equivalent
PYTHON_SPECIFIC = {name for name, mapped in NAME_MAP.items() if mapped is None}


def normalise_name(pymisp_name: str) -> str | None:
    """Map a PyMISP method name to its expected RustMISP equivalent.
    Returns None if the method is Python-specific."""
    if pymisp_name in NAME_MAP:
        return NAME_MAP[pymisp_name]
    # snake_case is the same convention in both
    return pymisp_name


# ---------------------------------------------------------------------------
# Test mapping — maps PyMISP test names to RustMISP test names
# ---------------------------------------------------------------------------

# Known test name mappings: pymisp_test -> [rustmisp_tests]
# A single PyMISP test may be covered by multiple RustMISP tests
TEST_MAP = {
    "test_simple_event": ["test_event_crud_lifecycle"],
    "test_event_add_update_metadata": ["test_event_crud_lifecycle"],
    "test_attribute": ["test_attribute_crud"],
    "test_edit_attribute": ["test_attribute_crud"],
    "test_tags": ["test_tag_operations"],
    "test_object_template": ["test_object_crud"],
    "test_update_object": ["test_object_crud"],
    "test_domain_ip_object": ["test_object_crud"],
    "test_asn_object": ["test_object_crud"],
    "test_user": ["test_user_management"],
    "test_organisation": ["test_user_management"],
    "test_feeds": ["test_feed_operations"],
    "test_servers": ["test_server_operations"],
    "test_sharing_groups": ["test_sharing_group_workflow"],
    "test_sharing_group": ["test_sharing_group_workflow"],
    "test_sightings": ["test_sighting_operations"],
    "test_taxonomies": ["test_taxonomy_operations"],
    "test_warninglists": ["test_warninglist_operations"],
    "test_noticelists": ["test_noticelist_operations"],
    "test_roles": ["test_role_operations"],
    "test_roles_expanded": ["test_role_operations"],
    "test_exists": ["test_exists"],
    "test_freetext": ["test_freetext"],
    "test_statistics": ["test_statistics"],
    "test_blocklists": ["test_blocklist_operations"],
    "test_correlation_exclusions": ["test_correlation_exclusion_operations"],
    "test_galaxies": ["test_galaxy_operations"],
    "test_communities": ["test_communities"],
    "test_event_report": ["test_event_report_crud"],
    "test_user_settings": ["test_user_settings"],
    "test_search_index": ["test_search_index"],
    "test_search_value_event": ["test_search_value"],
    "test_search_value_attribute": ["test_search_value"],
    "test_search_type_event": ["test_search_type"],
    "test_search_type_attribute": ["test_search_type"],
    "test_search_tag_event": ["test_search_tag"],
    "test_search_tag_attribute": ["test_search_tag"],
    "test_search_tag_advanced_event": ["test_search_tag"],
    "test_search_tag_advanced_attributes": ["test_search_tag"],
    "test_search_timestamp_event": ["test_search_timestamp"],
    "test_search_timestamp_attribute": ["test_search_timestamp"],
    "test_search_publish_timestamp": ["test_search_publish_and_metadata"],
    "test_search_logs": ["test_search_filters"],
    "test_registrations": ["test_user_management"],
    "test_direct": [],  # direct_call is tested implicitly
    "test_server_settings": ["test_server_operations"],
    "test_describe_types": ["test_server_operations"],
    "test_versions": ["test_server_operations"],
    "test_db_schema": ["test_server_operations"],
    "test_analyst_data_CRUD": ["test_analyst_data_crud"],
    "test_analyst_data_ACL": [],  # ACL tests are MISP-internal
    "test_event_galaxy": ["test_galaxy_operations"],
    "test_attach_galaxy_cluster": ["test_galaxy_operations"],
    "test_galaxy_cluster": ["test_galaxy_operations"],
    "test_search_galaxy": ["test_galaxy_operations"],
    "test_get_non_exists_event": ["test_exists"],
    "test_delete_by_uuid": ["test_event_crud_lifecycle"],
    "test_delete_with_update": ["test_event_crud_lifecycle"],
    "test_user_search": ["test_user_management"],
    "test_user_perms": ["test_user_management"],
    "test_org_search": ["test_user_management"],
    "test_sharing_group_search": ["test_sharing_group_workflow"],
    "test_toggle_global_pythonify": [],  # Python-specific
    "test_zmq": [],  # ZMQ infrastructure test, not API coverage
    "test_live_acl": [],  # ACL debugging, not API coverage
    "test_expansion": [],  # Expansion module test, depends on modules installed
    "test_lief_and_sign": [],  # LIEF/signing, Python-specific binary analysis
}


def normalise_test_name(pymisp_test: str) -> list[str] | None:
    """Map a PyMISP test name to RustMISP test name(s).
    Returns None if no mapping is known (needs manual review)."""
    if pymisp_test in TEST_MAP:
        return TEST_MAP[pymisp_test]
    return None


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"


def print_header(title: str):
    print(f"\n{BOLD}{CYAN}{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}{RESET}\n")


def print_section(title: str):
    print(f"\n{BOLD}{title}{RESET}")
    print("-" * 50)


def percent(n: int, total: int) -> str:
    if total == 0:
        return "N/A"
    return f"{n / total * 100:.1f}%"


def run_comparison(pymisp_path: Path):
    api_path = pymisp_path / "pymisp" / "api.py"
    test_path = pymisp_path / "tests" / "testlive_comprehensive.py"

    if not api_path.exists():
        print(f"{RED}Error: {api_path} not found{RESET}", file=sys.stderr)
        sys.exit(1)
    if not test_path.exists():
        print(f"{RED}Error: {test_path} not found{RESET}", file=sys.stderr)
        sys.exit(1)

    # Find RustMISP paths relative to this script
    script_dir = Path(__file__).resolve().parent
    rust_root = script_dir.parent
    rust_client = rust_root / "src" / "client.rs"
    rust_tests = rust_root / "tests" / "integration_tests.rs"

    if not rust_client.exists():
        print(f"{RED}Error: {rust_client} not found{RESET}", file=sys.stderr)
        sys.exit(1)

    # Extract everything
    pymisp_methods = extract_pymisp_methods(api_path)
    pymisp_tests = extract_pymisp_tests(test_path)
    rust_methods = extract_rustmisp_methods(rust_client)
    rust_tests_list = extract_rustmisp_tests(rust_tests) if rust_tests.exists() else []

    rust_methods_set = set(rust_methods)
    rust_tests_set = set(rust_tests_list)

    # Also check for standalone functions (build_complex_query, register_user, etc.)
    source = rust_client.read_text()
    standalone = set(re.findall(r"^pub async fn (\w+)", source, re.MULTILINE))
    rust_methods_set |= standalone

    # Also check for functions exported from search.rs
    search_path = rust_root / "src" / "search.rs"
    if search_path.exists():
        search_src = search_path.read_text()
        search_fns = set(re.findall(r"^pub fn (\w+)", search_src, re.MULTILINE))
        rust_methods_set |= search_fns

    # ── Method parity ─────────────────────────────────────────────────
    print_header("RustMISP / PyMISP API Parity Report")

    applicable_methods = []
    python_only = []
    matched = []
    missing = []

    for method in pymisp_methods:
        rust_name = normalise_name(method)
        if rust_name is None:
            python_only.append(method)
            continue
        applicable_methods.append(method)
        if rust_name in rust_methods_set:
            matched.append((method, rust_name))
        else:
            missing.append((method, rust_name))

    total_applicable = len(applicable_methods)
    total_matched = len(matched)

    print_section("Method Coverage Summary")
    print(f"  PyMISP public methods:     {len(pymisp_methods)}")
    print(f"  Python-specific (skipped): {len(python_only)}")
    print(f"  Applicable to Rust:        {total_applicable}")
    print(f"  {GREEN}Implemented in RustMISP:   {total_matched}{RESET}  ({percent(total_matched, total_applicable)})")
    print(f"  {RED}Missing in RustMISP:       {len(missing)}{RESET}  ({percent(len(missing), total_applicable)})")

    # Extra methods in RustMISP not in PyMISP
    pymisp_rust_names = {normalise_name(m) for m in pymisp_methods if normalise_name(m) is not None}
    rust_extras = sorted(rust_methods_set - pymisp_rust_names - {"register_user", "attach_galaxy_cluster_to"})

    if missing:
        print_section(f"Missing Methods ({len(missing)})")
        for pymisp_name, rust_name in missing:
            print(f"  {RED}- {pymisp_name}{RESET}")

    if rust_extras:
        print_section(f"RustMISP-only Methods ({len(rust_extras)})")
        for name in rust_extras:
            print(f"  {CYAN}+ {name}{RESET}")

    if python_only:
        print_section(f"Python-specific Methods (not applicable) ({len(python_only)})")
        for name in python_only:
            print(f"  {YELLOW}~ {name}{RESET}")

    # ── Test parity ───────────────────────────────────────────────────
    print_header("Integration Test Parity Report")

    tests_mapped = []
    tests_missing = []
    tests_unmapped = []

    for test in pymisp_tests:
        rust_equivalents = normalise_test_name(test)
        if rust_equivalents is None:
            tests_unmapped.append(test)
            continue
        if not rust_equivalents:
            # Explicitly mapped to nothing (covered implicitly)
            tests_mapped.append((test, ["(implicit)"]))
            continue
        found = [t for t in rust_equivalents if t in rust_tests_set]
        if found:
            tests_mapped.append((test, found))
        else:
            tests_missing.append((test, rust_equivalents))

    total_pymisp_tests = len(pymisp_tests)
    total_tests_covered = len(tests_mapped)
    total_tests_missing = len(tests_missing)
    total_tests_unmapped = len(tests_unmapped)

    print_section("Test Coverage Summary")
    print(f"  PyMISP integration tests:  {total_pymisp_tests}")
    print(f"  RustMISP integration tests: {len(rust_tests_list)}")
    print(f"  {GREEN}PyMISP tests covered:      {total_tests_covered}{RESET}  ({percent(total_tests_covered, total_pymisp_tests)})")
    print(f"  {RED}PyMISP tests missing:      {total_tests_missing}{RESET}  ({percent(total_tests_missing, total_pymisp_tests)})")
    print(f"  {YELLOW}Unmapped (needs review):   {total_tests_unmapped}{RESET}  ({percent(total_tests_unmapped, total_pymisp_tests)})")

    if tests_missing:
        print_section(f"Missing Tests ({total_tests_missing})")
        for pymisp_test, expected_rust in tests_missing:
            print(f"  {RED}- {pymisp_test}{RESET}  (expected: {', '.join(expected_rust)})")

    if tests_unmapped:
        print_section(f"Unmapped Tests — Need Manual Review ({total_tests_unmapped})")
        for test in tests_unmapped:
            print(f"  {YELLOW}? {test}{RESET}")

    # RustMISP tests not mapping to any PyMISP test
    mapped_rust_tests = set()
    for _, rust_tests_names in tests_mapped + tests_missing:
        mapped_rust_tests.update(rust_tests_names)
    rust_only_tests = sorted(rust_tests_set - mapped_rust_tests - {"(implicit)"})

    if rust_only_tests:
        print_section(f"RustMISP-only Tests ({len(rust_only_tests)})")
        for test in rust_only_tests:
            print(f"  {CYAN}+ {test}{RESET}")

    # ── Final score ───────────────────────────────────────────────────
    print_header("Overall Parity Score")

    method_pct = total_matched / total_applicable * 100 if total_applicable else 0
    test_pct = total_tests_covered / total_pymisp_tests * 100 if total_pymisp_tests else 0

    bar_width = 40

    def bar(pct):
        filled = int(pct / 100 * bar_width)
        color = GREEN if pct >= 90 else YELLOW if pct >= 70 else RED
        return f"{color}{'█' * filled}{'░' * (bar_width - filled)}{RESET} {pct:.1f}%"

    print(f"  Methods: {bar(method_pct)}")
    print(f"  Tests:   {bar(test_pct)}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def find_pymisp_path() -> Path | None:
    """Try to auto-detect the PyMISP directory."""
    candidates = [
        Path(__file__).resolve().parent.parent.parent / "PyMISP",  # sibling
        Path(__file__).resolve().parent.parent.parent.parent / "PyMISP",
        Path("/var/www/MISP7/PyMISP"),
    ]
    for p in candidates:
        if (p / "pymisp" / "api.py").exists():
            return p
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Compare RustMISP API coverage against PyMISP"
    )
    parser.add_argument(
        "--pymisp-path",
        type=Path,
        default=None,
        help="Path to PyMISP repository root",
    )
    args = parser.parse_args()

    pymisp_path = args.pymisp_path or find_pymisp_path()
    if pymisp_path is None:
        print(
            f"{RED}Error: Could not find PyMISP. Use --pymisp-path to specify.{RESET}",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"PyMISP path: {pymisp_path}")
    run_comparison(pymisp_path)


if __name__ == "__main__":
    main()
