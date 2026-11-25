"""Finite boundary tests for archive identity and retained PE metadata."""
from pathlib import Path
import importlib.util
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("relink_pe", Path(__file__).resolve().parents[1] / "tools/relink_pe.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class RelinkBoundaryTests(unittest.TestCase):
    def test_existing_or_overlapping_destinations_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            with self.assertRaises(ValueError):
                M.distinct_paths(p, p / "child", p / "other")
            with self.assertRaises(ValueError):
                M.distinct_paths(p / "parent", p, p / "other")

    def test_omission_requires_exact_native_membership(self):
        for names in (["../a.o"], ["c.o"], ["a.o", "a.o"], []):
            with self.subTest(names=names), self.assertRaises(ValueError):
                M.validate_omissions(names, ["a.o", "b.o"])
        self.assertEqual(M.validate_omissions(["a.o"], ["a.o", "b.o"]), {"a.o"})

    def test_reference_search_preserves_metadata_relocations(self):
        text = "RELOCATION RECORDS FOR [.pdata]:\n00000000 IMAGE_REL_AMD64_ADDR32NB target+0x10\n U target\n U target_suffix"
        hits = M.symbol_references(text, {"target"})
        self.assertEqual(len(hits), 2)
        self.assertEqual(M.symbol_references("U target_suffix", {"target"}), [])

    def test_undefined_and_local_section_names_not_definitions(self):
        self.assertEqual(M.defined_symbols("00000001 T entry\n         U other\n00000000 t .text"), {"entry": 1})

    def test_retained_unwind_change_rejected(self):
        a = {("live",): {"function_bytes": 16, "unwind_bytes": "01000000"}}
        b = {("live",): {"function_bytes": 16, "unwind_bytes": "01010000"}}
        with self.assertRaises(ValueError):
            M.compare_unwind(a, b, {"unused"})

    def test_unrelated_runtime_removal_rejected(self):
        rows = {("live",): {"function_bytes": 16, "unwind_bytes": "01"}}
        with self.assertRaises(ValueError):
            M.compare_unwind(rows, {}, {"unused"})
        self.assertEqual(M.compare_unwind(rows, {}, {"live"}), [("live",)])

    def test_extra_runtime_function_rejected(self):
        with self.assertRaises(ValueError):
            M.compare_unwind({}, {("new",): {}}, set())

    def test_invalid_pe_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "invalid.dll"
            p.write_bytes(b"MZ" + b"\0" * 62)
            with self.assertRaises(ValueError):
                M.PE(p)


if __name__ == "__main__":
    unittest.main()
