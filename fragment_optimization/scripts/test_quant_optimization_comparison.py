#!/usr/bin/env python3
"""Small synthetic validation tests; never launches a benchmark."""
from __future__ import annotations

import copy
import json
import math
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from compare_quant_optimization import SOURCE_FILES, comparable_metadata, compare_runs, effect, load_run, platform_identity, write_outputs
from summarize_blocks import PHASES
from test_blocks_summary import fixture, table


def write_fixture(directory: Path, optimized: bool = False, windows: bool = False) -> None:
    directory.mkdir()
    meta, rows, warm = fixture(windows)
    meta.update(compiler="synthetic-compiler", gmp="test-6", mpfr="test-4", flint="test-3", openssl="test-3",
                memory_private_commit_limit_bytes=1_400_000_000, tile_mib=32, logical_cpu=-1,
                profile_order_policy="randomized once; repetitions grouped per profile",
                block_selection="first B consecutive 256-coordinate blocks of the fixed-identity matrix",
                full_parameter_dimensions=True, complete_ciphertext=False, order_seed=("a" if optimized else "b")*64,
                source_sha256={name: str(index+1)*64 for index, name in enumerate(sorted(SOURCE_FILES))})
    if optimized:
        meta["source_sha256"]["sampler.cpp"] = "f"*64
        for row in rows + warm:
            row["quant_seconds"] = str(float(row["quant_seconds"])/2)
            row["total_seconds"] = str(sum(float(row[f"{phase}_seconds"]) for phase in PHASES))
            if windows:
                row["quant_cycles"] = str(int(row["quant_cycles"])//2)
                row["total_cycles"] = str(sum(int(row[f"{phase}_cycles"]) for phase in PHASES))
            for phase in PHASES:
                row[f"{phase}_pct"] = str(100*float(row[f"{phase}_seconds"])/float(row["total_seconds"]))
    prefix = 100 if optimized else 1
    diagnostics = [f"ours_mpk matrix_fixture_seed={prefix:064x}"]
    for i, trial in enumerate((-1, 0, 1)):
        diagnostics += [f"ours_mpk trial={trial} test_private_seed={prefix+2*i+1:064x} public_seed={prefix+2*i+2:064x} decisions=123 precision_retries=0 max_precision=384"]
    for name, value in (("metadata.json", json.dumps(meta)), ("raw.csv", table(rows)), ("warmup.csv", table(warm)),
                        ("COMPLETED.txt", "PASS synthetic validation fixture\n"), ("diagnostics.txt", "\n".join(diagnostics)+"\n")):
        (directory/name).write_text(value, encoding="utf-8")


class QuantOptimizationComparisonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        write_fixture(self.root/"baseline")
        write_fixture(self.root/"optimized", True)
        self.old = load_run(self.root/"baseline")
        self.new = load_run(self.root/"optimized")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_exact_descriptive_effect(self) -> None:
        report = compare_runs(self.old, self.new)
        item = report["comparisons"][0]
        metric = item["metrics"]["quant_ms_per_256_block"]
        self.assertAlmostEqual(metric["baseline"]["mean"], 7.5)
        self.assertAlmostEqual(metric["baseline"]["sample_sd"], math.sqrt(12.5))
        self.assertAlmostEqual(metric["optimized"]["mean"], 3.75)
        self.assertAlmostEqual(metric["absolute_decrease"], 3.75)
        self.assertAlmostEqual(metric["relative_decrease_pct"], 50)
        self.assertAlmostEqual(metric["speedup_ratio_of_means"], 2)
        self.assertAlmostEqual(sum(item["optimized_pooled_wall_time_shares_pct"].values()), 100)
        self.assertEqual(report["warnings"], [])

    def test_windows_dynamic_rss_is_only_allowed_platform_difference(self) -> None:
        before = "Windows native x64; current_RSS=100; current_private_commit=200; compiler=abc"
        after = "Windows native x64; current_RSS=900; current_private_commit=950; compiler=abc"
        self.assertEqual(platform_identity(before), platform_identity(after))
        self.assertNotEqual(platform_identity(before), platform_identity(after.replace("x64", "arm64")))
        self.assertEqual(platform_identity("Darwin; current_RSS=100"), "Darwin; current_RSS=100")

    def test_library_settings_and_unknown_metadata_changes_rejected(self) -> None:
        for key in ("platform", "compiler", "gmp", "mpfr", "flint", "openssl", "blocks", "repetitions", "warmup",
                    "tile_mib", "logical_cpu", "memory_private_commit_limit_bytes", "block_selection"):
            with self.subTest(key=key):
                new = copy.deepcopy(self.new["metadata"])
                new[key] = str(new[key])+"different"
                with self.assertRaises(ValueError): comparable_metadata(self.old["metadata"], new)
        new = copy.deepcopy(self.new["metadata"]); new["unreviewed_setting"] = 42
        with self.assertRaises(ValueError): comparable_metadata(self.old["metadata"], new)

    def test_only_sampler_source_difference_permitted(self) -> None:
        for name in SOURCE_FILES - {"sampler.cpp"}:
            with self.subTest(name=name):
                new = copy.deepcopy(self.new["metadata"]); new["source_sha256"][name] = "a"*64
                with self.assertRaises(ValueError): comparable_metadata(self.old["metadata"], new)

    def test_missing_malformed_identical_source_hash_rejected(self) -> None:
        for operation in ("missing", "malformed", "identical"):
            new = copy.deepcopy(self.new["metadata"])
            if operation == "missing": del new["source_sha256"]["main.cpp"]
            elif operation == "malformed": new["source_sha256"]["sampler.cpp"] = "f"*63
            else: new["source_sha256"]["sampler.cpp"] = self.old["metadata"]["source_sha256"]["sampler.cpp"]
            with self.assertRaises(ValueError): comparable_metadata(self.old["metadata"], new)

    def test_changed_profile_hash_rejected(self) -> None:
        new = copy.deepcopy(self.new["metadata"]); new["profiles"][0]["config_sha256"] = "a"*64
        with self.assertRaises(ValueError): comparable_metadata(self.old["metadata"], new)

    def test_diagnostic_seed_overlap_rejected(self) -> None:
        new = copy.deepcopy(self.new)
        new["diagnostics"]["trials"][0]["private_seed"] = self.old["diagnostics"]["trials"][0]["private_seed"]
        with self.assertRaises(ValueError): compare_runs(self.old, new)

    def test_missing_or_failed_completion_rejected(self) -> None:
        marker = self.root/"optimized"/"COMPLETED.txt"
        marker.unlink()
        with self.assertRaises(ValueError): load_run(self.root/"optimized")
        marker.write_text("PASS", encoding="utf-8")
        (self.root/"optimized"/"failure.txt").write_text("failure", encoding="utf-8")
        with self.assertRaises(ValueError): load_run(self.root/"optimized")

    def test_partial_or_bad_timing_run_rejected(self) -> None:
        path = self.root/"optimized"/"raw.csv"
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text("\n".join(lines[:-1])+"\n", encoding="utf-8")
        with self.assertRaises(ValueError): load_run(self.root/"optimized")

    def test_diagnostic_missing_trial_rejected(self) -> None:
        path = self.root/"optimized"/"diagnostics.txt"
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text("\n".join(lines[:-1])+"\n", encoding="utf-8")
        with self.assertRaises(ValueError): load_run(self.root/"optimized")

    def test_effect_preserves_regression_and_zero_denominator(self) -> None:
        self.assertEqual(effect(1, 2)["relative_decrease_pct"], -100)
        self.assertEqual(effect(1, 2)["speedup_ratio_of_means"], .5)
        self.assertIsNone(effect(0, 1)["relative_decrease_pct"])
        self.assertIsNone(effect(1, 0)["speedup_ratio_of_means"])

    def test_threshold_is_warning_not_filter(self) -> None:
        new = copy.deepcopy(self.new)
        new["summary"]["summaries"][0]["metrics"]["matrix_ms_per_256_block"]["mean"] *= 1.1
        result = compare_runs(self.old, new)
        self.assertEqual(len(result["warnings"]), 1)
        self.assertEqual(len(result["comparisons"]), 1)

    def test_windows_cycle_metrics_retained(self) -> None:
        write_fixture(self.root/"winold", windows=True)
        write_fixture(self.root/"winnew", optimized=True, windows=True)
        result = compare_runs(load_run(self.root/"winold"), load_run(self.root/"winnew"))
        self.assertIn("quant_cycles_per_256_block", result["comparisons"][0]["metrics"])

    def test_outputs_keep_existing_report_and_raw_unchanged(self) -> None:
        output = self.root/"comparison"; output.mkdir()
        narrative = output/"analysis-report.md"; narrative.write_text("Root owns this", encoding="utf-8")
        before = (self.root/"baseline"/"raw.csv").read_bytes()
        write_outputs(output, compare_runs(self.old, self.new))
        self.assertEqual(narrative.read_text(encoding="utf-8"), "Root owns this")
        self.assertEqual((self.root/"baseline"/"raw.csv").read_bytes(), before)
        for name in ("comparison.csv", "comparison.json", "stats-appendix.md", "figure-catalog.md"):
            self.assertTrue((output/name).is_file())
        for name in ("quant_before_after.svg", "phase_before_after.svg"):
            ET.parse(output/"figures"/name)


if __name__ == "__main__":
    unittest.main()
