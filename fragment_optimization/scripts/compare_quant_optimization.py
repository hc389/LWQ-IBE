#!/usr/bin/env python3
"""Strict, descriptive comparison of two completed partial-block benchmark runs.

No benchmarks are executed. Raw files are never changed. Requires the same
platform, libraries, settings and source hashes except for sampler.cpp.
"""
from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import io
import json
import math
import re
from pathlib import Path
from typing import Any

from plot_blocks import COLORS, LABELS, ORDER, SVG
from summarize_blocks import PHASES, require, validate_and_summarize

SOURCE_FILES = {"main.cpp", "core_arithmetic.cpp", "sampler.cpp", "platform.cpp", "core.hpp", "profile_hashes.hpp"}
REQUIRED_METADATA = {
    "compiler", "gmp", "mpfr", "flint", "openssl", "blocks", "repetitions", "warmup",
    "memory_private_commit_limit_bytes", "tile_mib", "logical_cpu", "fixture_kind", "share_basis",
    "cycle_counter_available", "cycle_counter", "profile_order_policy", "block_selection",
    "source_sha256", "order_seed", "full_parameter_dimensions", "complete_ciphertext",
}
HEX64 = re.compile(r"[0-9a-f]{64}")
RUN_COLORS = {"baseline": "#747D88", "optimized": "#0072B2"}
METRICS = tuple(f"{phase}_ms_per_256_block" for phase in (*PHASES, "total", "feed", "validation"))


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def platform_identity(text: str) -> str:
    """Strip only two documented, dynamic Windows memory counters."""
    if not text.startswith("Windows native"):
        return text
    return re.sub(r"; current_(?:RSS|private_commit)=\d+(?=;|$)", "", text)


def comparable_metadata(baseline: dict[str, Any], optimized: dict[str, Any]) -> dict[str, Any]:
    normalized = []
    for name, metadata in (("baseline", baseline), ("optimized", optimized)):
        require(REQUIRED_METADATA <= metadata.keys(), f"{name}: missing comparison metadata")
        for library in ("compiler", "gmp", "mpfr", "flint", "openssl"):
            require(isinstance(metadata[library], str) and bool(metadata[library]), f"{name}: missing {library} version")
        hashes = metadata["source_sha256"]
        require(isinstance(hashes, dict) and hashes.keys() == SOURCE_FILES, f"{name}: incomplete/unexpected source SHA set")
        require(all(isinstance(value, str) and HEX64.fullmatch(value) for value in hashes.values()),
                f"{name}: malformed source SHA-256")
        require(isinstance(metadata["order_seed"], str) and HEX64.fullmatch(metadata["order_seed"]),
                f"{name}: malformed profile-order seed")
        require(metadata["full_parameter_dimensions"] is True and metadata["complete_ciphertext"] is False,
                f"{name}: wrong comparison scope")
        item = copy.deepcopy(metadata)
        item["platform"] = platform_identity(metadata["platform"])
        item["profiles"] = sorted(item["profiles"], key=lambda profile: profile["id"])
        item["source_sha256"]["sampler.cpp"] = "permitted-implementation-change"
        del item["order_seed"]
        normalized.append(item)
    a, b = normalized
    require(a.keys() == b.keys(), "Run metadata fields differ")
    for key in a:
        require(a[key] == b[key], f"Run metadata differs: {key}")
    require(baseline["source_sha256"]["sampler.cpp"] != optimized["source_sha256"]["sampler.cpp"],
            "sampler.cpp has identical hashes; expected an implementation comparison")
    return a


def parse_diagnostics(text: str, metadata: dict[str, Any]) -> dict[str, Any]:
    """Validate test-seed coverage, not noise distributions or independence."""
    profiles = {profile["id"] for profile in metadata["profiles"]}
    matrices: dict[str, str] = {}
    trials: dict[tuple[str, int], dict[str, Any]] = {}
    matrix_pattern = re.compile(r"(\w+) matrix_fixture_seed=([0-9a-f]{64})")
    trial_pattern = re.compile(r"(\w+) trial=(-?\d+) test_private_seed=([0-9a-f]{64}) public_seed=([0-9a-f]{64}) "
                               r"decisions=(\d+) precision_retries=(\d+) max_precision=(\d+)")
    for line in text.splitlines():
        if not line.strip():
            continue
        match = matrix_pattern.fullmatch(line)
        if match:
            profile, seed = match.groups()
            require(profile in profiles and profile not in matrices, "Invalid/duplicate matrix fixture seed")
            matrices[profile] = seed
            continue
        match = trial_pattern.fullmatch(line)
        require(match is not None, "Unexpected diagnostics line")
        profile, trial, private, public, decisions, retries, precision = match.groups()
        key = profile, int(trial)
        require(profile in profiles and key not in trials, "Invalid/duplicate diagnostic trial")
        trials[key] = {"profile": profile, "trial": int(trial), "private_seed": private, "public_seed": public,
                       "decisions": int(decisions), "precision_retries": int(retries), "max_precision": int(precision)}
    expected = {(profile, trial) for profile in profiles for trial in range(-metadata["warmup"], metadata["repetitions"])}
    require(matrices.keys() == profiles and trials.keys() == expected, "Incomplete diagnostic seeds/trials")
    for profile in profiles:
        selected = [item for item in trials.values() if item["profile"] == profile]
        for key in ("private_seed", "public_seed"):
            require(len({item[key] for item in selected}) == len(selected), f"{profile}: repeated diagnostic {key}")
    return {"matrix_fixture_seeds": matrices, "trials": sorted(trials.values(), key=lambda item: (item["profile"], item["trial"]))}


def load_run(directory: Path) -> dict[str, Any]:
    require(directory.is_dir(), f"Missing run directory: {directory}")
    require(not (directory / "failure.txt").exists(), f"Failed run cannot be compared: {directory}")
    require((directory / "COMPLETED.txt").is_file(), f"Incomplete run: {directory}")
    contents = {name: (directory / name).read_bytes() for name in
                ("raw.csv", "metadata.json", "warmup.csv", "COMPLETED.txt", "diagnostics.txt")}
    require(bool(contents["COMPLETED.txt"].strip()), "Empty completion marker")
    metadata = json.loads(contents["metadata.json"].decode("utf-8-sig"))
    raw = contents["raw.csv"].decode("utf-8-sig")
    summary = validate_and_summarize(raw, metadata, contents["warmup.csv"].decode("utf-8-sig"))
    diagnostics = parse_diagnostics(contents["diagnostics.txt"].decode("utf-8-sig"), metadata)
    return {"directory_name": directory.name, "metadata": metadata, "summary": summary,
            "rows": list(csv.DictReader(io.StringIO(raw))), "diagnostics": diagnostics,
            "artifact_sha256": {name: digest(payload) for name, payload in contents.items()}}


def effect(before: float, after: float) -> dict[str, float | None]:
    return {"absolute_decrease": before - after,
            "relative_decrease_pct": 100 * (1 - after / before) if before > 0 else None,
            "speedup_ratio_of_means": before / after if after > 0 else None}


def compare_runs(baseline: dict[str, Any], optimized: dict[str, Any]) -> dict[str, Any]:
    locked = comparable_metadata(baseline["metadata"], optimized["metadata"])
    indexed = [{item["profile"]: item for item in run["summary"]["summaries"]} for run in (baseline, optimized)]
    require(indexed[0].keys() == indexed[1].keys(), "Validated parameter sets differ")
    warnings = []
    comparisons = []
    for profile in ORDER:
        if profile not in indexed[0]:
            continue
        old, new = indexed[0][profile], indexed[1][profile]
        metrics = {}
        keys = list(METRICS)
        if locked["cycle_counter_available"]:
            keys += [f"{phase}_cycles_per_256_block" for phase in (*PHASES, "total")]
        for metric in keys:
            before, after = old["metrics"][metric], new["metrics"][metric]
            metrics[metric] = {"baseline": before, "optimized": after, **effect(before["mean"], after["mean"])}
        for phase in ("matrix", "feed"):
            change = metrics[f"{phase}_ms_per_256_block"]["relative_decrease_pct"]
            if change is not None and abs(change) > 5:
                warnings.append(f"{profile}: {phase} mean changed by {-change:+.2f}% despite unchanged matrix/feed source. "
                                "The 5% flag is a descriptive sensitivity check, not a statistical threshold; "
                                "random inputs, scheduling, thermal drift or allocation/cache interactions may contribute.")
        quant, matrix = new["pooled_wall_time_shares_pct"]["quant"], new["pooled_wall_time_shares_pct"]["matrix"]
        comparisons.append({
            **{key: new[key] for key in ("profile", "n", "m", "a", "full_dimension", "blocks_per_trial", "block_length",
                                        "processed_dimension", "repetitions", "fragment_bytes")},
            "metrics": metrics,
            "baseline_pooled_wall_time_shares_pct": old["pooled_wall_time_shares_pct"],
            "optimized_pooled_wall_time_shares_pct": new["pooled_wall_time_shares_pct"],
            "baseline_trial_shares": {phase: old["metrics"][f"{phase}_trial_share_pct"] for phase in PHASES},
            "optimized_trial_shares": {phase: new["metrics"][f"{phase}_trial_share_pct"] for phase in PHASES},
            "baseline_maximum_process_peak_memory_bytes": old["maximum_process_peak_memory_bytes"],
            "optimized_maximum_process_peak_memory_bytes": new["maximum_process_peak_memory_bytes"],
            "optimized_quantization_is_below_half": quant < 50,
            "optimized_quantization_exceeds_matrix": quant > matrix,
            "optimized_quantization_is_largest_phase": quant > max(matrix, new["pooled_wall_time_shares_pct"]["other"]),
        })
    old_seeds = {item[key] for item in baseline["diagnostics"]["trials"] for key in ("private_seed", "public_seed")}
    new_seeds = {item[key] for item in optimized["diagnostics"]["trials"] for key in ("private_seed", "public_seed")}
    require(old_seeds.isdisjoint(new_seeds), "Cross-run test seeds overlap; independent-random-input comparison expected")
    require(set(baseline["diagnostics"]["matrix_fixture_seeds"].values()).isdisjoint(
        optimized["diagnostics"]["matrix_fixture_seeds"].values()), "Cross-run matrix fixtures overlap")
    return {
        "schema": 1, "analysis_kind": "descriptive_unpaired_same_host_partial_block_implementation_comparison",
        "comparison_unit": "Each measured trial's average milliseconds per actually executed 256-coordinate block",
        "locked_metadata": locked, "runs": {
            name: {"directory_name": run["directory_name"], "artifact_sha256": run["artifact_sha256"],
                   "metadata": run["metadata"], "diagnostics": run["diagnostics"],
                   "raw_measured_trials": run["rows"]} for name, run in (("baseline", baseline), ("optimized", optimized))},
        "comparisons": comparisons, "warnings": warnings,
        "limitations": [
            "Descriptive only: repeated trials on one host are not independent machines or benchmark sessions. No p-values, confidence intervals, or inferential multiple-comparison claims.",
            "Inputs and random tapes differ across runs; identical trial indices do not form pairs. Speedup is the ratio of two sample means, not the mean of per-trial ratios.",
            "The planned fixed order is baseline then optimized, not an interleaved/counterbalanced design. Thermal state, scheduling and cache conditions may drift; a difference is not isolated causal evidence.",
            "Sample SD describes variation between trial averages, not between individual blocks. Median/IQR use linear interpolation at (n-1)p; no observations are removed.",
            "Total means matrix + quantization + other measured compute. Data feed and codec verification are excluded and separately reported; this is not end-to-end encryption time.",
            "Real full n/q/S and frozen layouts are retained, but only a prefix of blocks is executed. No complete-ciphertext, full-IBE, decryption, deployment or Windows-cycle extrapolation is supported.",
            "Recorded source hashes agree except sampler.cpp and recorded compiler/library versions match. Metadata alone does not attest compiled binary provenance, identical compiler flags, or unchanged physical host; consult the separately archived build/run manifests.",
            "Maximum reported memory is cumulative process-lifetime peak RSS, not an independent per-profile allocation measurement or an OS-enforced limit on non-Windows hosts.",
            "Same-tape correctness/distribution-preserving tests belong to a separate validation artifact; these timings do not establish output-distribution equivalence.",
        ],
    }


def fmt(value: float | None, digits: int = 3) -> str:
    return "NA" if value is None else f"{value:.{digits}f}"


def mean_sd(stat: dict[str, Any]) -> str:
    return f"{fmt(stat['mean'])} ± {fmt(stat['sample_sd'])}"


def axis_ceiling(values: list[float]) -> float:
    maximum = max(values, default=1)
    return max(1, math.ceil(maximum / 10) * 10)


def figures(output: Path, report: dict[str, Any]) -> None:
    items = report["comparisons"]
    repetitions, blocks = report["locked_metadata"]["repetitions"], report["locked_metadata"]["blocks"]
    subtitle = f"{repetitions} trials/run x {blocks} blocks/trial | unpaired random inputs | descriptive, same recorded host"
    figdir = output / "figures"
    figdir.mkdir(exist_ok=True)
    svg = SVG(1180, 650, "Quantization before and after implementation optimization")
    svg.text(40, 38, "Quantization before and after implementation optimization", 24, bold=True)
    svg.text(40, 66, subtitle, 14, color="#536171")
    ceiling_values = []
    for item in items:
        for run in ("baseline", "optimized"):
            stat = item["metrics"]["quant_ms_per_256_block"][run]
            ceiling_values += [stat["mean"] + (stat["sample_sd"] or 0), stat["max"]]
    ceiling = axis_ceiling(ceiling_values)
    left, right, top, bottom = 95, 1130, 175, 470
    y = lambda value: bottom - value / ceiling * (bottom - top)
    svg.text(27, 155, "ms/block", 14, bold=True)
    for i in range(6):
        value = ceiling * i / 5
        svg.line(left, y(value), right, y(value))
        svg.text(left - 12, y(value) + 5, f"{value:g}", 13, "end", "#536171")
    for index, item in enumerate(items):
        center = left + (index + .5) * (right - left) / len(items)
        svg.text(center, 108, LABELS[item["profile"]], 18, "middle", bold=True)
        svg.text(center, 132, f"n={item['n']}, a={item['a']}", 13, "middle", "#536171")
        for ri, run in enumerate(("baseline", "optimized")):
            stat = item["metrics"]["quant_ms_per_256_block"][run]
            mean, sd = stat["mean"], stat["sample_sd"] or 0
            x = center + (ri - .5) * 112
            svg.rect(x - 35, y(mean), 70, bottom - y(mean), RUN_COLORS[run], .78)
            svg.line(x, y(max(0, mean - sd)), x, y(mean + sd), "#18232F", 1.8)
            for endpoint in (max(0, mean - sd), mean + sd):
                svg.line(x - 9, y(endpoint), x + 9, y(endpoint), "#18232F", 1.8)
            rows = sorted((row for row in report["runs"][run]["raw_measured_trials"] if row["profile"] == item["profile"]),
                          key=lambda row: int(row["trial"]))
            for j, row in enumerate(rows):
                jitter = 0 if len(rows) == 1 else -22 + 44 * j / (len(rows) - 1)
                svg.circle(x + jitter, y(float(row["quant_seconds"]) * 1000 / blocks), 4.5, "#18232F")
            svg.text(x, y(max(stat["max"], mean + sd)) - 14, f"{mean:.2f} +/- {fmt(stat['sample_sd'], 2)}", 11, "middle")
            svg.text(x, bottom + 24, run.capitalize(), 13, "middle")
        metric = item["metrics"]["quant_ms_per_256_block"]
        svg.text(center, 535, f"Mean reduction: {fmt(metric['relative_decrease_pct'], 2)}%", 15, "middle", bold=True)
    svg.text(40, 583, "Bars: mean; whiskers: sample SD of trial averages; dots: every measured trial (no pairing or exclusions).", 13, color="#536171")
    svg.text(40, 610, "Horizontal dot jitter only avoids overlap. No full-ciphertext extrapolation; feed and verification are outside compute time.", 13, color="#536171")
    svg.save(figdir / "quant_before_after.svg")

    height = 255 + 180 * len(items)
    svg = SVG(1250, height, "Before/after matrix, quantization and other measured compute")
    svg.text(40, 38, "Before/after measured compute decomposition", 24, bold=True)
    svg.text(40, 66, subtitle, 14, color="#536171")
    ceiling = axis_ceiling([item["metrics"]["total_ms_per_256_block"][run]["mean"] +
                            (item["metrics"]["total_ms_per_256_block"][run]["sample_sd"] or 0)
                            for item in items for run in ("baseline", "optimized")])
    left, width, top = 240, 760, 130
    x = lambda value: left + value / ceiling * width
    bottom = top + len(items) * 180 - 30
    for i in range(6):
        value = ceiling * i / 5
        svg.line(x(value), top, x(value), bottom, "#E0E5EB")
        svg.text(x(value), bottom + 25, f"{value:g}", 13, "middle", "#536171")
    for index, item in enumerate(items):
        yy = top + index * 180
        svg.text(40, yy + 3, LABELS[item["profile"]], 16, bold=True)
        for ri, run in enumerate(("baseline", "optimized")):
            yrow = yy + 21 + 56 * ri
            svg.text(left - 15, yrow + 23, run.capitalize(), 14, "end")
            position = 0.0
            for phase in PHASES:
                value = item["metrics"][f"{phase}_ms_per_256_block"][run]["mean"]
                svg.rect(x(position), yrow, x(position + value) - x(position), 34, COLORS[phase])
                if phase != "other" and x(position + value) - x(position) > 48:
                    svg.text(x(position + value / 2), yrow + 23, f"{value:.2f}", 13, "middle", "white", True)
                position += value
            total = item["metrics"]["total_ms_per_256_block"][run]
            sd = total["sample_sd"] or 0
            svg.line(x(max(0, position - sd)), yrow + 17, x(position + sd), yrow + 17, "#18232F", 1.8)
            for endpoint in (max(0, position - sd), position + sd):
                svg.line(x(endpoint), yrow + 10, x(endpoint), yrow + 24, "#18232F", 1.8)
            svg.text(1016, yrow + 22, f"{position:.2f} +/- {fmt(total['sample_sd'], 2)} ms", 12)
        shares = item["optimized_pooled_wall_time_shares_pct"]
        svg.text(left, yy + 132, "New pooled shares: " + " / ".join(f"{name[0].upper()} {shares[name]:.2f}%" for name in PHASES),
                 13, color="#536171")
    svg.text(615, bottom + 51, "Measured compute time (ms per executed 256-coordinate block)", 14, "middle")
    legend_y = bottom + 82
    for xx, phase, label in ((75, "matrix", "Matrix"), (260, "quant", "Quantization"), (475, "other", "Other")):
        svg.rect(xx, legend_y - 14, 17, 17, COLORS[phase]); svg.text(xx + 25, legend_y, label, 14)
    svg.text(700, legend_y, "Whisker: total trial-average sample SD", 13, color="#536171")
    svg.text(40, height - 20, "No end-to-end/full-ciphertext inference. Other includes scalar, RNG, serialization, allocation and timing overhead.", 13, color="#536171")
    svg.save(figdir / "phase_before_after.svg")


def write_outputs(output: Path, report: dict[str, Any]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    report["analysis_script_sha256"] = {path.name: digest(path.read_bytes()) for path in
        (Path(__file__), Path(__file__).with_name("summarize_blocks.py"), Path(__file__).with_name("plot_blocks.py"))}
    (output / "comparison.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    fields = ["profile", "n", "m", "a", "blocks", "repetitions", "metric", "baseline_mean", "baseline_sample_sd",
              "optimized_mean", "optimized_sample_sd", "absolute_decrease", "relative_decrease_pct", "speedup_ratio_of_means",
              "baseline_pooled_share_pct", "optimized_pooled_share_pct", "baseline_maximum_process_peak_memory_bytes",
              "optimized_maximum_process_peak_memory_bytes"]
    with (output / "comparison.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields); writer.writeheader()
        for item in report["comparisons"]:
            for metric, values in item["metrics"].items():
                phase = metric.removesuffix("_ms_per_256_block")
                writer.writerow({**{key: item[key] for key in ("profile", "n", "m", "a", "repetitions")},
                    "blocks": item["blocks_per_trial"], "metric": metric,
                    **{f"{run}_{stat}": values[run][stat] for run in ("baseline", "optimized") for stat in ("mean", "sample_sd")},
                    **{key: values[key] for key in ("absolute_decrease", "relative_decrease_pct", "speedup_ratio_of_means")},
                    **{f"{run}_pooled_share_pct": item[f"{run}_pooled_wall_time_shares_pct"].get(phase, "") for run in ("baseline", "optimized")},
                    **{f"{run}_maximum_process_peak_memory_bytes": item[f"{run}_maximum_process_peak_memory_bytes"] for run in ("baseline", "optimized")}})
    meta = report["locked_metadata"]
    lines = ["# 量化实现优化：描述性统计附录", "", "## 范围与可比性", "",
        f"每组参数在同一记录平台进行 {meta['repetitions']} 次测量，每次实际执行 {meta['blocks']} 个 256 维块；每组/每版本预热 {meta['warmup']} 次，不进入统计。",
        "矩阵维数、模数、量化宽度及冻结集合保留真实参数。仅执行前缀块，不产生完整密文；不存在完整加密或解密时间的外推。", "",
        "已逐项核对平台、编译器/库版本、块数、重复数、预热数、内存/tile/核绑定设置、参数与配置 SHA。六个源文件的记录 SHA 中仅 sampler.cpp 不同。随机种子与参数执行次序允许不同；未忽略其他元数据差异。", "",
        "平台：" + meta["platform"], "", "版本：" + "; ".join(f"{key}={meta[key]}" for key in ("compiler", "gmp", "mpfr", "flint", "openssl")), "",
        "## 核心观察（ms / 实际执行的 256 维块）", "",
        "均值 ± 样本 SD 来自试验的每块均值；并非单块 SD。下表正数表示降低，负数表示变慢。", "",
        "| 参数 | 指标 | 优化前 mean ± SD | 优化后 mean ± SD | 绝对降低 ms | 相对降低 % | 均值比 speedup |",
        "|---|---|---:|---:|---:|---:|---:|"]
    for item in report["comparisons"]:
        for phase in ("quant", "total"):
            value = item["metrics"][f"{phase}_ms_per_256_block"]
            lines += [f"| {item['profile']} | {phase} | {mean_sd(value['baseline'])} | {mean_sd(value['optimized'])} | {fmt(value['absolute_decrease'])} | {fmt(value['relative_decrease_pct'])} | {fmt(value['speedup_ratio_of_means'])}× |"]
    lines += ["", "## 阶段组成与未修改控制项", "", "占比采用累计阶段时间 / 累计总时间，M+Q+O=100%，不是逐次占比的简单平均。", "",
              "| 参数 | 前 M/Q/O % | 后 M/Q/O % | 后 Q<50% | 后 Q>M | 后 Q 最大 | 矩阵均值变化 % |",
              "|---|---:|---:|---|---|---|---:|"]
    for item in report["comparisons"]:
        shares = [" / ".join(fmt(item[f"{run}_pooled_wall_time_shares_pct"][phase]) for phase in PHASES) for run in ("baseline", "optimized")]
        change = item["metrics"]["matrix_ms_per_256_block"]["relative_decrease_pct"]
        lines += [f"| {item['profile']} | {shares[0]} | {shares[1]} | {item['optimized_quantization_is_below_half']} | {item['optimized_quantization_exceeds_matrix']} | {item['optimized_quantization_is_largest_phase']} | {fmt(-change if change is not None else None)} |"]
    lines += ["", "## 单列的输入供给、验证与内存", "", "供给与验证未包含在 total 中。RSS 为进程历史峰值；参数组执行次序可能不同，不能把组间峰值差解释成精确的缓存增量。", "",
              "| 参数 | 前供给 ms/块 | 后供给 ms/块 | 前验证 ms/块 | 后验证 ms/块 | 前 peak RSS MiB | 后 peak RSS MiB |",
              "|---|---:|---:|---:|---:|---:|---:|"]
    for item in report["comparisons"]:
        cells = [item["profile"]]
        for metric in ("feed", "validation"):
            cells += [mean_sd(item["metrics"][f"{metric}_ms_per_256_block"][run]) for run in ("baseline", "optimized")]
        cells += [fmt(item[f"{run}_maximum_process_peak_memory_bytes"] / 2**20) for run in ("baseline", "optimized")]
        lines += ["| " + " | ".join(cells) + " |"]
    lines += ["", "## 完整分布描述", "", "包含全部试验，不做异常点删除。中位数和 IQR 的分位数位置为 (n−1)p 线性插值。", "",
              "| 参数 | 版本 | 指标 | mean ± SD | median | Q1 | Q3 | IQR | min | max |", "|---|---|---|---:|---:|---:|---:|---:|---:|---:|"]
    for item in report["comparisons"]:
        for metric, values in item["metrics"].items():
            for run in ("baseline", "optimized"):
                stat = values[run]
                cells = [item["profile"], run, metric, mean_sd(stat)] + [fmt(stat[key]) for key in ("median", "q1", "q3", "iqr", "min", "max")]
                lines += ["| " + " | ".join(cells) + " |"]
    lines += ["", "## 统计方法与不可作出的推论", "",
              "绝对降低 = 前均值 − 后均值；相对降低 = 100×(1−后均值/前均值)；speedup = 前均值/后均值。分母为零时报告 NA。没有把 trial 编号对应成配对。", "",
              "使用不同测试种子与矩阵 fixture 的两批运行；实际种子覆盖与不重复已核验。固定先 baseline 后 optimized 的设计可能受热漂移、调度和缓存状态影响。小样本单机重复不支持分布假设检查、置信区间、p 值或多重比较显著性声明，因此本报告不做这些推断。", ""]
    lines += [f"- {note}" for note in report["limitations"]]
    lines += ["", "## 敏感性提示", ""] + ([f"- {warning}" for warning in report["warnings"]] or ["- 矩阵与供给均值的变化未超过预设的 5% 描述性提示线；这不证明不存在漂移。"])
    lines += ["", "## 数据来源与可追溯性", "", "原始文件只读。完整原始行、版本、源码 SHA、诊断及文件 SHA 见 comparison.json；comparison.csv 提供可复用的数值表。", ""]
    for run, record in report["runs"].items():
        lines += [f"### {run}: {record['directory_name']}", ""]
        lines += [f"- {name}: `{value}`" for name, value in record["artifact_sha256"].items()]
        lines += [""]
    (output / "stats-appendix.md").write_text("\n".join(lines), encoding="utf-8")
    figures(output, report)
    catalog = ["# 量化优化图表目录", "", "两图均由严格验证后的原始数据生成。原始文件 SHA、数值与逐次观测见 comparison.json；数据与图表来自同一次分析。", "",
        "## Figure 1 — figures/quant_before_after.svg", "",
        "目的：观察量化实现修改前后每个真实参数集的量化耗时及试验间波动。", "",
        f"图注：每版本 {meta['repetitions']} 次试验、每次 {meta['blocks']} 个实际执行的 256 维块。柱为每块平均毫秒，误差线为试验平均值的样本标准差，点为全部试验。横向点位偏移仅避免重叠，不表示数值或配对关系。输入与随机带在版本间不同。", "",
        "解读检查：先看绝对差再看比例；检查所有点和 SD。减少仅表示本次记录中的量化时间下降，不是安全性证明，也不推出完整密文时间。无显著性标记或配对连线。", "",
        "## Figure 2 — figures/phase_before_after.svg", "",
        "目的：辨别量化加速怎样反映在被测计算核总耗时中，并同时观察未修改的矩阵阶段。", "",
        "图注：共享零起点毫秒坐标；M/Q/O 分段分别为矩阵、量化、其余阶段的样本均值，其和等于总均值。末端误差线是总耗时的样本 SD，并非三个 SD 相加；下方后版本占比采用累计阶段/累计总时间。其余项包括随机数、标量、序列化、分配与计时管理开销。", "",
        "解读检查：量化下降不保证总时间按同一比例下降；量化不到 50% 也可能仍是最大阶段。供给与验证单列、不计入这些条形。检查矩阵控制项漂移，避免把固定执行顺序造成的变化全部归因于算法。", "",
        "## 数据直接支持的观察", ""]
    for item in report["comparisons"]:
        q, total = item["metrics"]["quant_ms_per_256_block"], item["metrics"]["total_ms_per_256_block"]
        catalog += [f"- {item['profile']}: quant {mean_sd(q['baseline'])} → {mean_sd(q['optimized'])} ms/块；total {mean_sd(total['baseline'])} → {mean_sd(total['optimized'])} ms/块；量化相对降低 {fmt(q['relative_decrease_pct'])}%。"]
    catalog += ["", "## 已知局限", ""] + [f"- {note}" for note in report["limitations"]]
    (output / "figure-catalog.md").write_text("\n".join(catalog) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline_directory", type=Path)
    parser.add_argument("optimized_directory", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    old, new, output = args.baseline_directory.resolve(), args.optimized_directory.resolve(), args.output.resolve()
    require(old != new, "Baseline and optimized must be distinct run directories")
    for source in (old, new):
        require(output != source and not output.is_relative_to(source), "Comparison output must not be inside either raw run")
    report = compare_runs(load_run(old), load_run(new))
    write_outputs(output, report)
    print(f"Validated comparison: {len(report['comparisons'])} profiles; wrote CSV, JSON, statistics appendix and two SVG figures to {output}")


if __name__ == "__main__":
    main()
