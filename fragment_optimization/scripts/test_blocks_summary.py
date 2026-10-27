#!/usr/bin/env python3
"""Synthetic unit tests for validation logic, not performance measurements."""
from __future__ import annotations

import copy
import csv
import io
import math
import unittest

from summarize_blocks import FIELDS, PHASES, PROFILES, validate_and_summarize


def table(rows):
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=FIELDS)
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def fixture(windows=False):
    profile = "ours_mpk"
    p = PROFILES[profile]
    metadata = {
        "schema": 2, "mode": "blocks", "blocks": 4, "repetitions": 2, "warmup": 1,
        "share_basis": "wall_time_seconds", "fixture_kind": "uniform_fixed_identity_encryption_fixture",
        "platform": "Windows native x64; SYNTHETIC TEST" if windows else "Darwin SYNTHETIC TEST",
        "cycle_counter_available": windows,
        "cycle_counter": "Windows QueryThreadCycleTime" if windows else "unavailable",
        "profiles": [{"id": profile, "config_sha256": p["hash"], "n": p["n"], "m": p["m"],
                      "a": p["a"], "full_dimension": 2*p["m"]}],
    }

    def row(trial, scale):
        values = {"trial": str(trial), "order": "0", "mode": "blocks", "profile": profile,
                  "n": str(p["n"]), "m": str(p["m"]), "a": str(p["a"]), "full_dimension": str(2*p["m"]),
                  "blocks": "4", "block_length": "256", "processed_dimension": "1024",
                  "fragment_bytes": str((p["a"]+256+4*(256*p["a"]-p["frozen"])+7)//8),
                  "feed_seconds": "0.7", "validation_seconds": "0.00001", "peak_memory_bytes": "200000000",
                  "codec_ok": "1", "full_parameter_dimensions": "1", "complete_ciphertext": "0", "status": "PASS"}
        for phase, seconds, cycles in (("matrix", .01, 100), ("quant", .02, 200), ("other", .03, 300), ("total", .06, 600)):
            values[f"{phase}_seconds"] = str(scale*seconds)
            values[f"{phase}_cycles"] = str(scale*cycles) if windows else ""
        for phase in PHASES:
            values[f"{phase}_pct"] = str(100*float(values[f"{phase}_seconds"])/float(values["total_seconds"]))
        return values

    return metadata, [row(0,1), row(1,2)], [row(-1,1)]


class BlockSummaryTests(unittest.TestCase):
    def setUp(self):
        self.meta, self.rows, self.warm = fixture()

    def summarize(self, metadata=None, rows=None, warm=None):
        return validate_and_summarize(table(self.rows if rows is None else rows), self.meta if metadata is None else metadata,
                                      table(self.warm if warm is None else warm))

    def test_valid_nonwindows_statistics(self):
        report = self.summarize()
        summary = report["summaries"][0]
        total = summary["metrics"]["total_ms_per_256_block"]
        self.assertAlmostEqual(total["mean"], 22.5)
        self.assertAlmostEqual(total["sample_sd"], math.sqrt(112.5))
        self.assertAlmostEqual(total["median"], 22.5)
        self.assertAlmostEqual(total["iqr"], 7.5)
        self.assertAlmostEqual(sum(summary["pooled_wall_time_shares_pct"].values()),100)
        self.assertIsNone(summary["pooled_cycle_shares_pct"])
        self.assertEqual(summary["excluded_warmup_rows"],1)

    def test_valid_windows_cycles(self):
        meta, rows, warm = fixture(True)
        report = validate_and_summarize(table(rows),meta,table(warm))
        self.assertAlmostEqual(report["summaries"][0]["pooled_cycle_shares_pct"]["quant"],100/3)

    def test_exact_large_cycle_sum(self):
        meta, rows, warm = fixture(True)
        for row in rows+warm:
            for i, phase in enumerate(PHASES):
                row[f"{phase}_cycles"] = str(2**60+i+1)
            row["total_cycles"] = str(3*2**60+6)
        validate_and_summarize(table(rows),meta,table(warm))
        rows[0]["total_cycles"] = str(3*2**60+7)
        with self.assertRaises(ValueError):
            validate_and_summarize(table(rows),meta,table(warm))

    def test_pooled_share_differs_from_mean_trial_share(self):
        self.rows[0].update(matrix_seconds="0.01",quant_seconds="0.08",other_seconds="0.01",total_seconds="0.1",
                            matrix_pct="10",quant_pct="80",other_pct="10")
        self.rows[1].update(matrix_seconds="0.3",quant_seconds="0.03",other_seconds="0.27",total_seconds="0.6",
                            matrix_pct="50",quant_pct="5",other_pct="45")
        summary = self.summarize()["summaries"][0]
        self.assertAlmostEqual(summary["pooled_wall_time_shares_pct"]["quant"],100*.11/.7)
        self.assertAlmostEqual(summary["metrics"]["quant_trial_share_pct"]["mean"],42.5)

    def test_below_half_can_still_be_largest(self):
        for row in self.rows:
            row.update(matrix_seconds="0.4",quant_seconds="0.45",other_seconds="0.15",total_seconds="1",
                       matrix_pct="40",quant_pct="45",other_pct="15")
        interpretation = self.summarize()["summaries"][0]["interpretation"]
        self.assertIn("not a majority",interpretation)
        self.assertIn("largest measured phase",interpretation)
        self.assertIn("exceeds the matrix phase",interpretation)

    def test_single_repeat_sd_is_missing_not_zero(self):
        self.meta["repetitions"] = 1
        summary = self.summarize(rows=self.rows[:1])["summaries"][0]
        self.assertIsNone(summary["metrics"]["quant_ms_per_256_block"]["sample_sd"])

    def test_missing_group_rejected(self):
        with self.assertRaises(ValueError): self.summarize(rows=self.rows[:1])

    def test_duplicate_trial_rejected(self):
        with self.assertRaises(ValueError): self.summarize(rows=[self.rows[0],self.rows[0]])

    def test_missing_warmup_rejected(self):
        with self.assertRaises(ValueError): validate_and_summarize(table(self.rows),self.meta,None)

    def test_warmup_in_raw_rejected(self):
        with self.assertRaises(ValueError): self.summarize(rows=self.rows+self.warm)

    def test_bad_numeric_or_scope_fields_rejected(self):
        corruptions = {
            "n":"16", "m":"256", "a":"238", "full_dimension":"1024", "blocks":"5",
            "block_length":"128", "processed_dimension":"512", "fragment_bytes":"100",
            "matrix_seconds":"nan", "quant_seconds":"-1", "total_seconds":"0.061",
            "quant_pct":"80", "feed_seconds":"inf", "peak_memory_bytes":"1500000000",
            "codec_ok":"0", "full_parameter_dimensions":"0", "complete_ciphertext":"1",
            "status":"FAIL", "mode":"smoke", "matrix_cycles":"12",
        }
        for key,value in corruptions.items():
            with self.subTest(key=key):
                rows = copy.deepcopy(self.rows); rows[0][key] = value
                with self.assertRaises(ValueError): self.summarize(rows=rows)

    def test_bad_metadata_rejected(self):
        corruptions = {"schema":1,"mode":"full","share_basis":"cycles","blocks":0,"repetitions":0,
                       "warmup":11,"cycle_counter_available":True,"fixture_kind":"algebraic_fixed_identity"}
        for key,value in corruptions.items():
            with self.subTest(key=key):
                meta = copy.deepcopy(self.meta); meta[key] = value
                with self.assertRaises(ValueError): self.summarize(metadata=meta)

    def test_bad_hash_rejected(self):
        self.meta["profiles"][0]["config_sha256"] = "0"*64
        with self.assertRaises(ValueError): self.summarize()

    def test_bad_metadata_dimensions_rejected(self):
        self.meta["profiles"][0]["n"] = 16
        with self.assertRaises(ValueError): self.summarize()

    def test_unknown_profile_rejected(self):
        self.meta["profiles"][0]["id"] = "jkn_low"
        with self.assertRaises(ValueError): self.summarize()

    def test_duplicate_header_rejected(self):
        raw = table(self.rows).replace("matrix_seconds", "quant_seconds", 1)
        with self.assertRaises(ValueError): validate_and_summarize(raw,self.meta,table(self.warm))

    def test_incomplete_warmup_rejected(self):
        with self.assertRaises(ValueError): self.summarize(warm=[])

    def test_zero_warmup_allows_header_only(self):
        self.meta["warmup"] = 0
        self.summarize(warm=[])


if __name__ == "__main__":
    unittest.main()
