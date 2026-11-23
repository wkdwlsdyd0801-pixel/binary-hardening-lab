"""Tests for scripts/benchmark.py.

Pure helpers are tested without a compiler; the end-to-end tests compile the
benchmark workload with real profile flags (skipped if gcc/make are missing)
to check the two claims the benchmark relies on: every profile computes the
same checksum, and the code-size counter sees the mitigation's extra code.
"""
import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# scripts/ is not a package, so load benchmark.py by path.
_spec = importlib.util.spec_from_file_location("benchmark", ROOT / "scripts" / "benchmark.py")
bench = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bench)

needs_cc = pytest.mark.skipif(not (shutil.which("gcc") and shutil.which("make")),
                              reason="needs gcc and make")


def test_parse_workload_output():
    assert bench.parse_workload("checksum=42 ns=1500\n") == (42, 1500)


def test_pct_relative_to_baseline():
    assert bench.pct(110, 100) == 10.0
    assert bench.pct(100, 100) == 0.0
    assert bench.pct(5, 0) == 0.0  # broken baseline must not divide by zero


def test_quartiles_median_and_iqr():
    q1, med, q3 = bench.quartiles([1, 2, 3, 4, 5])
    assert (q1, med, q3) == (2, 3, 4)


@needs_cc
def test_flags_come_from_build_mk():
    # The benchmark must use exactly the matrix build.mk defines.
    assert "-fstack-protector-strong" in bench.profile_flags("canary")
    assert "-fno-stack-protector" in bench.profile_flags("none")
    assert "-D_FORTIFY_SOURCE=3" in bench.profile_flags("fortify")


@needs_cc
def test_workload_checksum_identical_and_canary_adds_code(tmp_path):
    bins = bench.build_all(tmp_path, ["none", "canary", "fortify"])
    sums = set()
    for path in bins.values():
        out = subprocess.run([str(path), "5000"], capture_output=True,
                             text=True, check=True).stdout
        sums.add(bench.parse_workload(out)[0])
    assert len(sums) == 1  # mitigations never change the program's result
    # The canary profile instruments every function with a char buffer.
    assert bench.code_bytes(bins["canary"]) > bench.code_bytes(bins["none"])


@needs_cc
def test_survey_classifies_own_builds(tmp_path):
    bins = bench.build_all(tmp_path, ["none", "all"])
    # Survey a directory that holds only the hardened build.
    d = tmp_path / "survey"
    d.mkdir()
    shutil.copy(bins["all"], d / "hardened")
    (d / "script.sh").write_text("#!/bin/sh\n")  # non-ELF files are ignored
    rows = {(r["group"], r["metric"]): r for r in bench.survey_rows([d])}
    assert rows[("executable", "pie")]["count"] == 1
    assert rows[("executable", "relro_full")]["count"] == 1
    assert rows[("executable", "canary")]["count"] == 1
    assert rows[("executable", "nx")]["total"] == 1
