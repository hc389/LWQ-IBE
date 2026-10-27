#!/usr/bin/env python3
"""Validate and summarize real-parameter, partial-block encryption measurements.

Standard library only. No extrapolation to a complete ciphertext and no
inferential statistics across repeated trials from one machine.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import statistics
from pathlib import Path
from typing import Any

PROFILES = {
    "ours_mpk": {"n": 10072, "m": 433024, "a": 239, "frozen": 30397,
                 "hash": "dc531adc0168081ba42e6a8d0d69c50c894f5df556ee751da6da0aa522b01ec1"},
    "ours_mid": {"n": 10864, "m": 382464, "a": 256, "frozen": 32285,
                 "hash": "5c6c251cb659eae691e10dfd094c43e88ac84f39fc6c04db965aafb95a5014c7"},
    "ours_ct": {"n": 11600, "m": 352384, "a": 270, "frozen": 33699,
                "hash": "79c617ef17000937402fe140d76ddc54023fb354ab136ddeb76842693592d328"},
}
PHASES = ("matrix", "quant", "other")
FIELDS = (
    "trial", "order", "mode", "profile", "n", "m", "a", "full_dimension", "blocks", "block_length",
    "processed_dimension", "fragment_bytes", "matrix_cycles", "quant_cycles", "other_cycles", "total_cycles",
    "matrix_seconds", "quant_seconds", "other_seconds", "total_seconds", "feed_seconds", "validation_seconds",
    "matrix_pct", "quant_pct", "other_pct", "peak_memory_bytes", "codec_ok", "full_parameter_dimensions",
    "complete_ciphertext", "status",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def integer(value: Any, name: str, minimum: int = 0) -> int:
    require(type(value) in {str, int}, f"{name}: expected exact integer")
    text = str(value)
    require(text.lstrip("-").isdigit() and text not in {"", "-"}, f"{name}: invalid integer")
    number = int(text)
    require(number >= minimum, f"{name}: below permitted minimum")
    return number


def number(value: Any, name: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name}: invalid number") from error
    require(math.isfinite(result) and result >= 0, f"{name}: nonfinite or negative value")
    return result


def quantile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower, upper = math.floor(position), math.ceil(position)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def describe(values: list[float]) -> dict[str, Any]:
    require(bool(values), "Cannot summarize an empty sample")
    q1, q3 = quantile(values, .25), quantile(values, .75)
    return {"count": len(values), "mean": statistics.mean(values),
            "sample_sd": statistics.stdev(values) if len(values) > 1 else None,
            "median": statistics.median(values), "q1": q1, "q3": q3, "iqr": q3 - q1,
            "min": min(values), "max": max(values)}


def validate_and_summarize(raw_text: str, metadata: dict[str, Any], warmup_text: str | None = None) -> dict[str, Any]:
    require(metadata.get("schema") == 2 and metadata.get("mode") == "blocks", "Expected blocks metadata schema 2")
    require(metadata.get("fixture_kind") == "uniform_fixed_identity_encryption_fixture", "Wrong fixture scope")
    require(metadata.get("share_basis") == "wall_time_seconds", "Percentages must use wall-time seconds")
    blocks = integer(metadata.get("blocks"), "metadata.blocks", 1)
    repetitions = integer(metadata.get("repetitions"), "metadata.repetitions", 1)
    warmups = integer(metadata.get("warmup"), "metadata.warmup")
    require(repetitions <= 100 and warmups <= 10, "Unexpected repetition/warmup count")
    profiles = metadata.get("profiles")
    require(isinstance(profiles, list) and 1 <= len(profiles) <= 3, "Invalid requested-profile list")
    expected: dict[str, dict[str, Any]] = {}
    for item in profiles:
        require(isinstance(item, dict), "Invalid metadata profile record")
        identifier = item.get("id")
        require(identifier in PROFILES and identifier not in expected, "Unknown or duplicate metadata profile")
        frozen = PROFILES[identifier]
        require(item.get("config_sha256") == frozen["hash"], f"{identifier}: configuration hash mismatch")
        for key in ("n", "m", "a"):
            require(integer(item.get(key), key, 1) == frozen[key], f"{identifier}: parameter {key} differs from frozen profile")
        require(integer(item.get("full_dimension"), "full_dimension", 1) == 2 * frozen["m"], "Full dimension mismatch")
        require(256 * blocks <= 2 * frozen["m"], "Requested blocks exceed complete dimension")
        expected[identifier] = item
    cycle_available = metadata.get("cycle_counter_available")
    require(type(cycle_available) is bool, "Missing cycle-counter availability flag")
    platform = metadata.get("platform")
    require(isinstance(platform, str) and bool(platform), "Missing platform")
    if cycle_available:
        require(platform.startswith("Windows native") and "QueryThreadCycleTime" in metadata.get("cycle_counter", ""),
                "Cycles require the native Windows thread-cycle counter")
    else:
        require(not platform.startswith("Windows native"), "Native Windows run has no cycle counter")

    def parse(text: str | None, is_warmup: bool) -> dict[str, list[dict[str, Any]]]:
        if text is None:
            require(is_warmup and warmups == 0, "Missing required warmup table")
            return {key: [] for key in expected}
        reader = csv.DictReader(io.StringIO(text))
        require(reader.fieldnames == list(FIELDS), "CSV header is missing, duplicated, reordered, or unexpected")
        groups: dict[str, list[dict[str, Any]]] = {key: [] for key in expected}
        identities: set[tuple[str, int]] = set()
        order_by_profile: dict[str, int] = {}
        for line, row in enumerate(reader, 2):
            require(None not in row and all(value is not None for value in row.values()), f"Line {line}: wrong field count")
            identifier = row["profile"]
            require(identifier in expected, f"Line {line}: unrequested profile")
            p = PROFILES[identifier]
            require(row["mode"] == "blocks" and row["status"] == "PASS", "Failed or non-block row")
            require(row["codec_ok"] == "1" and row["full_parameter_dimensions"] == "1"
                    and row["complete_ciphertext"] == "0", "Invalid execution-scope or codec flags")
            trial = integer(row["trial"], "trial", -warmups)
            required_trials = range(-warmups, 0) if is_warmup else range(repetitions)
            require(trial in required_trials and (identifier, trial) not in identities, "Invalid/duplicate trial")
            identities.add((identifier, trial))
            order = integer(row["order"], "order")
            require(order < len(expected) and (identifier not in order_by_profile or order_by_profile[identifier] == order),
                    "Invalid or inconsistent profile order")
            order_by_profile[identifier] = order
            for key in ("n", "m", "a"):
                require(integer(row[key], key, 1) == p[key], f"Row parameter {key} differs from metadata")
            require(integer(row["full_dimension"], "full_dimension", 1) == 2 * p["m"], "Wrong full dimension")
            require(integer(row["blocks"], "blocks", 1) == blocks and row["block_length"] == "256", "Wrong block layout")
            require(integer(row["processed_dimension"], "processed_dimension", 1) == 256 * blocks, "Processed dimension mismatch")
            fragment_bytes = (p["a"] + 256 + blocks * (256 * p["a"] - p["frozen"]) + 7) // 8
            require(integer(row["fragment_bytes"], "fragment_bytes", 1) == fragment_bytes, "Fragment-size formula mismatch")
            memory = integer(row["peak_memory_bytes"], "peak_memory_bytes", 1)
            require(memory < 1_500_000_000, "Resident-memory safety ceiling reached")
            values = {key: number(row[key], key) for key in
                      ("matrix_seconds", "quant_seconds", "other_seconds", "total_seconds", "feed_seconds", "validation_seconds")}
            require(values["total_seconds"] > 0, "Total measurement time must be positive")
            require(math.isclose(sum(values[f"{phase}_seconds"] for phase in PHASES), values["total_seconds"],
                                 rel_tol=1e-9, abs_tol=1e-10), "Timing phases do not sum to total")
            for phase in PHASES:
                supplied = number(row[f"{phase}_pct"], f"{phase}_pct")
                calculated = 100 * values[f"{phase}_seconds"] / values["total_seconds"]
                require(math.isclose(supplied, calculated, rel_tol=1e-9, abs_tol=1e-6), "Supplied percentage disagrees with raw times")
                values[f"{phase}_pct"] = calculated
            cycles = {}
            for phase in (*PHASES, "total"):
                value = row[f"{phase}_cycles"]
                if cycle_available:
                    cycles[phase] = integer(value, f"{phase}_cycles")
                else:
                    require(value == "", "Non-Windows cycle value must be empty")
            if cycle_available:
                require(cycles["total"] > 0 and sum(cycles[phase] for phase in PHASES) == cycles["total"],
                        "Cycle phases do not exactly sum to total")
            groups[identifier].append({"trial": trial, "order": order, "seconds": values, "cycles": cycles,
                                       "peak_memory_bytes": memory, "fragment_bytes": fragment_bytes})
        target_trials = range(-warmups, 0) if is_warmup else range(repetitions)
        require(identities == {(profile, trial) for profile in expected for trial in target_trials},
                "Incomplete profile/repetition groups; partial measurements cannot be summarized")
        require(len(set(order_by_profile.values())) == len(order_by_profile), "Profile orders are not unique")
        return groups

    raw, warmup = parse(raw_text, False), parse(warmup_text, True)
    if warmups:
        for identifier in expected:
            require(raw[identifier][0]["order"] == warmup[identifier][0]["order"],
                    "Warmup and measured profile orders differ")
    summaries = []
    for identifier, samples in raw.items():
        p = PROFILES[identifier]
        seconds = {phase: [row["seconds"][f"{phase}_seconds"] for row in samples] for phase in (*PHASES, "total")}
        pooled = {phase: 100 * sum(seconds[phase]) / sum(seconds["total"]) for phase in PHASES}
        require(math.isclose(sum(pooled.values()), 100, rel_tol=1e-12), "Pooled shares do not sum to 100 percent")
        metrics = {f"{phase}_ms_per_256_block": describe([1000 * value / blocks for value in seconds[phase]])
                   for phase in (*PHASES, "total")}
        metrics.update({f"{phase}_trial_share_pct": describe([row["seconds"][f"{phase}_pct"] for row in samples])
                        for phase in PHASES})
        for auxiliary in ("feed", "validation"):
            metrics[f"{auxiliary}_ms_per_256_block"] = describe(
                [1000 * row["seconds"][f"{auxiliary}_seconds"] / blocks for row in samples])
        cycle_pooled = None
        if cycle_available:
            for phase in (*PHASES, "total"):
                metrics[f"{phase}_cycles_per_256_block"] = describe([row["cycles"][phase] / blocks for row in samples])
            cycle_total = sum(row["cycles"]["total"] for row in samples)
            cycle_pooled = {phase: 100 * sum(row["cycles"][phase] for row in samples) / cycle_total for phase in PHASES}
        q, m = pooled["quant"], pooled["matrix"]
        interpretation = (
            f"Quantization accounts for {q:.3f}% of pooled measured wall time. "
            + ("It is below 50% (not a majority). " if q < 50 else "It is at least 50% of the measured total. ")
            + ("It exceeds the matrix phase. " if q > m else "It does not exceed the matrix phase. ")
            + ("It is the largest measured phase. " if q > max(pooled["matrix"], pooled["other"]) else "It is not strictly the largest measured phase. ")
            + "These are descriptions of these trials only, not an extrapolation to complete ciphertext encryption."
        )
        summaries.append({"profile": identifier, "n": p["n"], "m": p["m"], "a": p["a"],
                          "full_dimension": 2 * p["m"], "blocks_per_trial": blocks, "block_length": 256,
                          "processed_dimension": 256 * blocks, "repetitions": repetitions,
                          "excluded_warmup_rows": len(warmup[identifier]), "fragment_bytes": samples[0]["fragment_bytes"],
                          "maximum_process_peak_memory_bytes": max(row["peak_memory_bytes"] for row in samples),
                          "pooled_wall_time_shares_pct": pooled, "pooled_cycle_shares_pct": cycle_pooled,
                          "metrics": metrics, "interpretation": interpretation})
    return {
        "schema": 1, "source_mode": "blocks", "platform": platform, "cycle_counter_available": cycle_available,
        "scope": "Real frozen n/q/S and partial 256-coordinate blocks only; no complete ciphertext, decryption, or full-IBE claim",
        "statistics": "Descriptive repeated trials on one machine; sample SD across trial means, not across individual blocks. No p-values, confidence intervals, or cross-platform inference. Median/IQR use linear interpolation at (n-1)p.",
        "shares": "Wall-time pooled share = sum(phase seconds)/sum(total seconds). This is distinct from mean trial share. Matrix+quantization+other exhaust measured compute time; other includes fresh randomness, scalar generation, serialization, allocation, bookkeeping and timing instrumentation. Data feed, codec validation and progress checks are excluded; feed and validation are reported separately.",
        "limitations": "Small repeated-run samples (including five trials) do not justify distributional inference. Per-block values divide measured trial totals by the number of actually executed blocks; never multiply them to claim full-ciphertext time. Peak memory is cumulative process-lifetime RSS. Quantization below 50% does not imply that it is not the largest phase.",
        "summaries": summaries,
    }


def format_number(value: float | None) -> str:
    return "NA" if value is None else f"{value:.6g}"


def write_outputs(run: Path, report: dict[str, Any]) -> None:
    (run / "summary_blocks.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    with (run / "summary_blocks.csv").open("w", encoding="utf-8", newline="") as stream:
        fields = ("profile", "n", "m", "a", "blocks_per_trial", "repetitions", "metric", "count", "mean",
                  "sample_sd", "median", "q1", "q3", "iqr", "min", "max", "pooled_share_pct")
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for summary in report["summaries"]:
            for metric, statistics_row in summary["metrics"].items():
                pooled = ""
                if metric.endswith("_trial_share_pct"):
                    pooled = summary["pooled_wall_time_shares_pct"][metric.removesuffix("_trial_share_pct")]
                writer.writerow({**{key: summary[key] for key in fields[:6]}, "metric": metric,
                                 **statistics_row, "pooled_share_pct": pooled})
    lines = ["# 分块加密计时汇总", "", report["scope"], "", f"平台：{report['platform']}", "",
             "以下为实际执行块的平均每 256 维耗时；均值 ± 样本 SD 来自重复试验的每块均值，不是单块观测的 SD。", "",
             "| 参数 | 重复次数 | 每次块数 | 矩阵乘法 ms/块 | 量化 ms/块 | 其余 ms/块 | 合计 ms/块 |",
             "|---|---:|---:|---:|---:|---:|---:|"]
    for summary in report["summaries"]:
        cells = [summary["profile"], str(summary["repetitions"]), str(summary["blocks_per_trial"])]
        for phase in (*PHASES, "total"):
            metric = summary["metrics"][f"{phase}_ms_per_256_block"]
            cells.append(f"{format_number(metric['mean'])} ± {format_number(metric['sample_sd'])}")
        lines.append("| " + " | ".join(cells) + " |")
    lines += ["", "## 时间占比", "", "汇总占比为各阶段总耗时除以所有试验总耗时，不是逐次占比的简单平均。三阶段之和为 100%。", "",
              "| 参数 | 矩阵汇总占比 | 量化汇总占比 | 其余汇总占比 | 量化逐次占比均值 ± SD |",
              "|---|---:|---:|---:|---:|"]
    for summary in report["summaries"]:
        shares = summary["pooled_wall_time_shares_pct"]
        q = summary["metrics"]["quant_trial_share_pct"]
        lines.append(f"| {summary['profile']} | {shares['matrix']:.3f}% | {shares['quant']:.3f}% | {shares['other']:.3f}% | "
                     f"{q['mean']:.3f}% ± {format_number(q['sample_sd'])} 个百分点 |")
    lines += ["", "## 结果边界与判断", "", report["statistics"], "", report["shares"], "", report["limitations"], ""]
    lines += [f"- {summary['profile']}: {summary['interpretation']}" for summary in report["summaries"]]
    lines += ["", "各阶段中位数、IQR、最小值、最大值、数据供给与验证耗时见 summary_blocks.csv/json。Windows 周期数独立于墙钟时间统计；非 Windows 运行不补造周期数。", ""]
    (run / "summary_blocks.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    args = parser.parse_args()
    run = args.run_directory.resolve()
    require(not (run / "failure.txt").exists(), "Run has failure.txt; do not summarize partial results")
    complete = run / "COMPLETED.txt"
    require(complete.is_file() and bool(complete.read_text(encoding="utf-8-sig").strip()), "Missing completion marker")
    raw_bytes = (run / "raw.csv").read_bytes()
    metadata_bytes = (run / "metadata.json").read_bytes()
    warmup_path = run / "warmup.csv"
    warmup_bytes = warmup_path.read_bytes() if warmup_path.is_file() else None
    report = validate_and_summarize(raw_bytes.decode("utf-8-sig"), json.loads(metadata_bytes.decode("utf-8-sig")),
                                    warmup_bytes.decode("utf-8-sig") if warmup_bytes is not None else None)
    sources = {"raw.csv": raw_bytes, "metadata.json": metadata_bytes, "COMPLETED.txt": complete.read_bytes()}
    if warmup_bytes is not None:
        sources["warmup.csv"] = warmup_bytes
    report["source_sha256"] = {key: hashlib.sha256(value).hexdigest() for key, value in sources.items()}
    report["analysis_script_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    write_outputs(run, report)
    print(f"Validated {sum(x['repetitions'] for x in report['summaries'])} measured rows. "
          "Wrote summary_blocks.json, summary_blocks.csv, summary_blocks.md; raw inputs unchanged.")


if __name__ == "__main__":
    main()
