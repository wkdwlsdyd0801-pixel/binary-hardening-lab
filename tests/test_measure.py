"""Unit tests for the pure helpers in scripts/measure.py.

These need no compiler: they check that process results are classified into the
right outcome/cause and that the ASLR entropy estimator counts varying bits
correctly. The full matrix run is exercised by hand / CI, not here.
"""
import importlib.util
import signal
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# scripts/ is not a package, so load measure.py by path.
_spec = importlib.util.spec_from_file_location("measure", ROOT / "scripts" / "measure.py")
measure = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(measure)

SIGSEGV, SIGABRT = -signal.SIGSEGV, -signal.SIGABRT


def test_classify_clean_exit():
    assert measure.classify("stack_overflow", 0, b"", b"") == ("ok", "")


def test_classify_segv_is_crash():
    assert measure.classify("stack_overflow", SIGSEGV, b"", b"") == ("crash", "segv")


def test_classify_canary_abort():
    out = measure.classify("stack_overflow", SIGABRT, b"",
                           b"*** stack smashing detected ***: terminated")
    assert out == ("blocked", "canary")


def test_classify_fortify_objsize_abort():
    out = measure.classify("heap_overflow", SIGABRT, b"",
                           b"*** buffer overflow detected ***: terminated")
    assert out == ("blocked", "fortify_objsize")


def test_classify_unknown_abort_falls_back():
    assert measure.classify("x", SIGABRT, b"", b"something") == ("blocked", "abort")


def test_classify_exploit_marker_required():
    # Right exit code and marker -> exploited.
    assert measure.classify("heap_overflow", 3, b"role=admin\n", b"") \
        == ("exploited", "priv_escalation")
    # Right code but no marker -> generic non-zero exit, not a claimed exploit.
    assert measure.classify("heap_overflow", 3, b"role=user\n", b"") \
        == ("exit", "rc=3")


def test_entropy_fixed_value_is_zero_bits():
    varying, shannon = measure.entropy_bits([0x401070] * 50)
    assert varying == 0 and shannon == 0.0


def test_entropy_counts_only_varying_bits():
    # Low 4 bits flip, everything above is constant -> exactly 4 varying bits.
    varying, _ = measure.entropy_bits([0x1000, 0x1001, 0x1008, 0x100f])
    assert varying == 4


def test_entropy_shannon_capped_by_sample_count():
    # Four equally-likely distinct values -> 2 bits of Shannon entropy.
    _, shannon = measure.entropy_bits([1, 2, 3, 4])
    assert abs(shannon - 2.0) < 1e-9
