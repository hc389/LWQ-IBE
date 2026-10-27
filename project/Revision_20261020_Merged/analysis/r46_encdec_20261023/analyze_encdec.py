#!/usr/bin/env python3
"""Evidence-only analysis for full-dimensional Enc/Dec with algebraic test keys.

This tool does NOT execute benchmarks, implement Extract, or infer a DFR.
Requires the final locked protocol and a completely PASS sequential manifest.
Use Sage Python for numpy/scipy/matplotlib; --self-test needs no experiment data.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from scipy.stats import t

PROFILES = {
    "ours_mpk": {"label": "C-MPK", "n": 10072, "m": 433024, "a": 239,
                 "blocks": 3383, "bytes": 13019115, "vector_decisions": 7155045},
    "ours_ct": {"label": "C-CT", "n": 11600, "m": 352384, "a": 270,
                "blocks": 2753, "bytes": 12189318, "vector_decisions": 5189405},
}
TIMES = ("enc_core_seconds", "enc_feed_seconds", "enc_harness_seconds", "matrix_seconds",
         "quant_seconds", "scalar_seconds", "pack_seconds", "enc_other_seconds", "dec_seconds",
         "dec_unpack_seconds", "dec_dot_seconds", "dec_decision_seconds", "dec_other_seconds",
         "artifact_io_seconds", "validation_seconds")
ENC_COMPONENTS = ("matrix_seconds", "quant_seconds", "scalar_seconds", "pack_seconds", "enc_other_seconds")
DEC_COMPONENTS = ("dec_unpack_seconds", "dec_dot_seconds", "dec_decision_seconds", "dec_other_seconds")
ENC_GROUPED = ("matrix_seconds", "quant_seconds", "enc_other_all_seconds")
DEC_GROUPED = ("dec_unpack_seconds", "dec_dot_seconds", "dec_decision_and_other_seconds")
DERIVED_TIMES = ("enc_wrapper_monitor_seconds", "enc_other_all_seconds", "dec_decision_and_other_seconds")
PREP_TIMES = ("key_sampling_seconds", "feed_seconds", "transpose_seconds", "matvec_seconds",
              "prepare_harness_seconds", "validation_seconds", "artifact_io_seconds")


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024*1024), b""):
            h.update(block)
    return h.hexdigest()


def describe(values):
    a = np.asarray(values, dtype=float)
    if len(a) < 2 or not np.isfinite(a).all():
        raise ValueError("Need at least two finite observations")
    mean, sd = float(a.mean()), float(a.std(ddof=1))
    half = float(t.ppf(.975, len(a)-1)*sd/math.sqrt(len(a)))
    return {"n": len(a), "mean": mean, "sd": sd, "median": float(np.median(a)),
            "min": float(a.min()), "max": float(a.max()), "ci95_mean": [mean-half, mean+half],
            "df": len(a)-1, "values": list(map(float, a))}


def csv_rows(path):
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def argument(command, name):
    if command.count(name) != 1 or command.index(name)+1 >= len(command):
        raise ValueError(f"Expected exactly one command argument {name}")
    return command[command.index(name)+1]


def parse(raw, key, integer=False):
    value = int(raw[key]) if integer else float(raw[key])
    if not math.isfinite(value):
        raise ValueError(f"Nonfinite field {key}")
    return value


def read_config(path):
    fields = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        if key.strip() in ("id", "n", "m", "a", "q", "r", "S", "sigma", "N", "stop", "expected_ct_bytes"):
            fields[key.strip()] = value.strip()
    return fields


def load_inputs(root, code_root, protocol):
    if not protocol.exists():
        raise ValueError("The locked protocol.md must exist before final analysis")
    manifest_path = root/"run_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("status") != "PASS":
        raise ValueError("Manifest must be final PASS")
    if manifest.get("protocol_sha256") != sha(protocol):
        raise ValueError("Current protocol differs from the pre-run frozen protocol hash")
    runs = manifest.get("runs", [])
    if len(runs) != 2 or any(r.get("status") != "PASS" or r.get("returncode") != 0 for r in runs):
        raise ValueError("Incomplete/failed manifest jobs")
    if manifest.get("single_process_benchmark_policy") is not True:
        raise ValueError("Missing sequential benchmark policy")
    directories = {}
    for run in runs:
        command = run["command"]
        if argument(command, "--mode") != "encdec":
            raise ValueError("Formal dataset must not mix microtests or other modes")
        if argument(command, "--repetitions") != "3" or argument(command, "--warmup") != "0":
            raise ValueError("Formal command does not match locked repeat policy")
        directory = Path(argument(command, "--output")).resolve()
        if directory in directories:
            raise ValueError("Duplicate output directory in manifest")
        directories[directory] = run
    files = sorted(root.rglob("raw.csv"))
    observed = [p.parent.resolve() for p in files]
    if len(set(observed)) != len(files) or set(observed) != set(directories):
        raise ValueError("Raw directories must exactly match manifest command outputs")
    rows, preparation, provenance = [], [], []
    source_hashes = {}
    configs = {}
    for name, p in PROFILES.items():
        path = code_root/"data"/(name+".cfg")
        configs[name] = {"path": str(path.resolve()), "sha256": sha(path), "values": read_config(path)}
        if manifest.get("profile_sha256", {}).get(name) != configs[name]["sha256"]:
            raise ValueError("Current configuration differs from pre-run frozen hash")
    for path in files:
        directory = path.parent
        run = directories[directory.resolve()]
        if not (directory/"COMPLETED.txt").exists():
            raise ValueError("A formal job is missing its completion marker")
        meta = json.loads((directory/"metadata.json").read_text())
        if meta.get("schema") != 4 or meta.get("mode") != "encdec":
            raise ValueError("Unexpected EncDec metadata schema/mode")
        if meta.get("repetitions") != 3 or meta.get("warmup") != 0:
            raise ValueError("Formal analysis expects three measured trials, no extra full warmup")
        if meta.get("real_Extract_output") is not False or meta.get("complete_dimensions") is not True:
            raise ValueError("Scope flags disagree with algebraic full-dimensional test")
        if meta.get("constant_time") is not False:
            raise ValueError("The native sampler was not certified constant time")
        if csv_rows(directory/"warmup.csv"):
            raise ValueError("Unexpected full-size warmup data")
        for name, digest in meta["source_sha256"].items():
            if name in source_hashes and source_hashes[name] != digest:
                raise ValueError(f"Source changed between formal jobs: {name}")
            source_hashes[name] = digest
            if sha(code_root/"src"/name) != digest:
                raise ValueError(f"Current source no longer matches measured version: {name}")
            if manifest.get("source_sha256", {}).get("src/"+name) != digest:
                raise ValueError(f"Source metadata differs from pre-run manifest: {name}")
        for p in meta["profiles"]:
            if p["id"] not in configs or p["config_sha256"] != configs[p["id"]]["sha256"]:
                raise ValueError("Profile configuration hash mismatch")
        raw_rows = csv_rows(path)
        expected_profiles = set(argument(run["command"], "--profiles").split(","))
        if {r["profile"] for r in raw_rows} != expected_profiles:
            raise ValueError("Raw profiles disagree with invocation")
        for raw in raw_rows:
            name = raw["profile"]
            p = PROFILES[name]
            row = dict(raw)
            for key in ("trial", "n", "m", "a", "full_dimension", "active_dimension", "blocks", "message",
                        "recovered_message", "ct_bytes", "peak_memory_bytes", "scalar_decisions", "vector_decisions",
                        "precision_retries", "max_precision", "gaussian_proposals"):
                row[key] = parse(raw, key, True)
            for key in TIMES:
                row[key] = parse(raw, key)
                if row[key] < 0:
                    raise ValueError(f"Negative timer: {key}")
            if any(row[k] != p[k] for k in ("n", "m", "a", "blocks")):
                raise ValueError("Wrong full profile")
            if row["full_dimension"] != 2*p["m"] or row["active_dimension"] != 2*p["m"]:
                raise ValueError("Reduced dimensions cannot enter full benchmark analysis")
            if row["ct_bytes"] != p["bytes"] or row["vector_decisions"] != p["vector_decisions"]:
                raise ValueError("Wrong bytes or vector decision count")
            if row["status"] != "PASS" or row["decoded_ok"] != "1" or row["full_dimensions"] != "1" or row["real_extract_output"] != "0":
                raise ValueError("Trial validation/scope flags failed")
            if row["message"] != row["trial"] % 2 or row["recovered_message"] != row["message"]:
                raise ValueError("Message schedule or recovery mismatch")
            if row["max_precision"] not in (384, 768, 1536) or row["peak_memory_bytes"] >= 1_500_000_000:
                raise ValueError("Precision or RSS boundary violated")
            for components, total in ((ENC_COMPONENTS, "enc_core_seconds"), (DEC_COMPONENTS, "dec_seconds")):
                if not math.isclose(sum(row[k] for k in components), row[total], abs_tol=1e-8, rel_tol=1e-9):
                    raise ValueError(f"Component timer sum disagrees: {total}")
            row["enc_wrapper_monitor_seconds"] = row["enc_harness_seconds"]-row["enc_core_seconds"]-row["enc_feed_seconds"]
            if row["enc_wrapper_monitor_seconds"] < -1e-8:
                raise ValueError("Wall timer is less than core plus supply")
            row["enc_other_all_seconds"] = row["enc_core_seconds"]-row["matrix_seconds"]-row["quant_seconds"]
            row["dec_decision_and_other_seconds"] = row["dec_decision_seconds"]+row["dec_other_seconds"]
            if not math.isclose(row["enc_other_all_seconds"], row["scalar_seconds"]+row["pack_seconds"]+row["enc_other_seconds"], abs_tol=1e-8, rel_tol=1e-9):
                raise ValueError("Combined encryption-other timer disagrees with granular sum")
            artifact = directory/(name+"_trial_"+str(row["trial"])+".bin")
            if artifact.stat().st_size != p["bytes"] or sha(artifact) != row["ciphertext_sha256"]:
                raise ValueError("Saved ciphertext hash/length mismatch")
            row["source_csv"] = str(path.resolve())
            row["ciphertext_file"] = str(artifact.resolve())
            rows.append(row)
        prep_path = directory/"preparation.csv"
        raw_prep = csv_rows(prep_path)
        if {r["profile"] for r in raw_prep} != expected_profiles or len(raw_prep) != len(expected_profiles):
            raise ValueError("Exactly one preparation record per profile is required")
        for raw in raw_prep:
            row = dict(raw)
            p = PROFILES[raw["profile"]]
            for key in ("n", "full_dimension", "active_dimension", "key_decisions", "key_gaussian_proposals",
                        "key_precision_retries", "key_max_precision", "key_nonzero", "key_max_abs_bits",
                        "key_norm_squared_bits", "peak_memory_bytes"):
                row[key] = parse(raw, key, True)
            for key in PREP_TIMES:
                row[key] = parse(raw, key)
            if row["source"] != "generated" or row["status"] != "PASS":
                raise ValueError("Preparation must be independently recorded freshly generated test fixture")
            if row["n"] != p["n"] or row["full_dimension"] != 2*p["m"] or row["active_dimension"] != 2*p["m"]:
                raise ValueError("Preparation dimensions mismatch")
            fixture = directory/(raw["profile"]+"_fixture.bin")
            if fixture.stat().st_size != 96+40*(2*p["m"]+p["n"]) or sha(fixture) != row["fixture_sha256"]:
                raise ValueError("Test fixture artifact mismatch")
            if not 0 < row["key_nonzero"] <= row["active_dimension"] or row["key_max_precision"] not in (384, 768, 1536):
                raise ValueError("Invalid dense-key summary")
            row["source_csv"] = str(prep_path.resolve())
            row["fixture_file"] = str(fixture.resolve())
            diagnostics = (directory/"diagnostics.txt").read_text()
            pattern = re.escape(raw["profile"])+r" matrix_seed=[0-9a-f]+ key_seed=[0-9a-f]+ key_norm_squared=(\d+) key_max_absolute=(\d+) fixture_sha256="
            match = re.search(pattern, diagnostics)
            if not match:
                raise ValueError("Exact key norm and maximum are absent from diagnostics")
            row["key_norm_squared"] = match.group(1)
            row["key_max_absolute"] = match.group(2)
            if int(row["key_norm_squared"]).bit_length() != row["key_norm_squared_bits"] or int(row["key_max_absolute"]).bit_length() != row["key_max_abs_bits"]:
                raise ValueError("Key integer diagnostics disagree with CSV bitlengths")
            sigma = int(configs[raw["profile"]]["values"]["sigma"])
            if int(row["key_max_absolute"]) > 16*sigma:
                raise ValueError("Recorded test key exceeds declared scalar-sampler truncation")
            preparation.append(row)
        selected_files = [path, prep_path, directory/"metadata.json", directory/"diagnostics.txt",
                          directory/"warmup.csv", directory/"COMPLETED.txt"]
        provenance.append({"directory": str(directory.resolve()), "metadata": meta,
                           "files": {str(p.resolve()): {"sha256": sha(p), "bytes": p.stat().st_size} for p in selected_files}})
    for name in PROFILES:
        selected = [r for r in rows if r["profile"] == name]
        if len(selected) != 3 or sorted(r["trial"] for r in selected) != [0, 1, 2]:
            raise ValueError(f"Exactly trials 0,1,2 are required for {name}")
        if len([r for r in preparation if r["profile"] == name]) != 1:
            raise ValueError("Preparation must not be replicated as repeated timing")
    return rows, preparation, {"manifest": manifest, "manifest_path": str(manifest_path.resolve()),
        "manifest_sha256": sha(manifest_path), "protocol_path": str(protocol.resolve()), "protocol_sha256": sha(protocol),
        "source_sha256": source_hashes, "configs": configs, "jobs": provenance,
        "process_logs": {str(p.resolve()): sha(p) for p in root.glob("*.process.log")}}


def analyze(rows, prep, provenance):
    result = {"schema": 1, "generated_utc": datetime.now(timezone.utc).isoformat(),
              "scope": "Full-dimensional fixed-identity Enc/Dec operations on dense Gaussian algebraic test keys; NOT Extract/Setup/PubEval",
              "units": "seconds unless explicitly labelled", "raw_trials": rows, "raw_preparation": prep,
              "provenance": provenance, "profiles": {}}
    for name, profile in PROFILES.items():
        group = sorted([r for r in rows if r["profile"] == name], key=lambda r: r["trial"])
        single_prep = next(r for r in prep if r["profile"] == name)
        stats = {key: describe([r[key] for r in group]) for key in TIMES+DERIVED_TIMES}
        shares = {"enc_core": {key: describe([100*r[key]/r["enc_core_seconds"] for r in group]) for key in ENC_COMPONENTS},
                  "dec": {key: describe([100*r[key]/r["dec_seconds"] for r in group]) for key in DEC_COMPONENTS},
                  "enc_core_grouped": {key: describe([100*r[key]/r["enc_core_seconds"] for r in group]) for key in ENC_GROUPED},
                  "dec_grouped": {key: describe([100*r[key]/r["dec_seconds"] for r in group]) for key in DEC_GROUPED}}
        sigma = int(provenance["configs"][name]["values"]["sigma"])
        result["profiles"][name] = {**profile, "statistics": stats, "component_percentages": shares,
            "preparation_single_observation": single_prep, "configured_sigma": str(sigma), "log2_sigma": math.log2(sigma),
            "key_max_abs_over_sigma": int(single_prep["key_max_absolute"])/sigma,
            "key_norm_over_sigma_sqrt_d": math.sqrt(int(single_prep["key_norm_squared"])/(sigma*sigma*(2*profile["m"]))),
            "all_decoded_ok": all(r["decoded_ok"] == "1" for r in group), "messages": [r["message"] for r in group],
            "key_cases": 1, "repetitions_same_fixture": len(group),
            "peak_memory_bytes": max([r["peak_memory_bytes"] for r in group]+[single_prep["peak_memory_bytes"]]),
            "online_max_precision": max(r["max_precision"] for r in group),
            "online_precision_retries": sum(r["precision_retries"] for r in group),
            "quant_decision_error_log2_bound": math.log2(profile["vector_decisions"])-256+math.log2(1+2**-44)}
    return result


def fmt(s, digits=3, scale=1):
    return f"{s['mean']*scale:.{digits}f} ± {s['sd']*scale:.{digits}f}"


def fmt_share(s):
    return fmt(s, 6 if s["sd"] < .0005 else 3)+"%"


def reports(result, output):
    profiles = result["profiles"]
    text = ["# R4-6：全维度加密与解密运算分析", "",
        "## 范围与关键区别", "",
        "本轮实际执行全部固定身份 Encrypt 与 Decrypt 运算：生成新鲜秘密/标量噪声，计算完整 M^T s，随机极化量化并序列化；解密恢复全部向量，实际执行稠密测试密钥的内积及消息判决。不是上一轮仅量化、打包和重构的实验，也不是外推的加解密时间。", "",
        "测试密钥逐坐标使用原 sigma 的既有有限精度离散 Gaussian 采样实现生成，再设置 u0=M e。因此其代数关系成立，但它不是预先固定 u0 上的 Extract 输出，也不代表 Setup/Extract 的真实联合分布。每配置只有一份准备好的测试密钥，3次重复共享该夹具，消息依次为0、1、0，新鲜 s、标量噪声、公开种子和私有量化随机带各次独立。", "",
        "矩阵由 AES-256-CTR 流式供给，是实验输入生成器，不是新的密钥压缩技术。公开身份求值、真实Setup/Extract、文件I/O和额外验证不包括在在线算术核心中。成功恢复少量消息不能据此估计密码学DFR或宣称完整方案安全验证。", "",
        "## 1. 完整加密／解密计时", "",
        "单位为秒，均值±样本SD，n=3；首次无全长预热的试验保留。Enc core不含测试矩阵供给与监控；Enc harness包含该次加密调用的矩阵供给、资源监控和调用边界开销，不含独立准备、文件I/O、额外验证与Dec。Dec包含解析/重构、全部私钥内积、模运算、判决及余项。", "",
        "| 参数 | 完整密文字节 | Enc core | 矩阵供给 | Enc harness | Dec | 成功消息 |",
        "|---|---:|---:|---:|---:|---:|---|"]
    for p in profiles.values():
        s = p["statistics"]
        text.append(f"| {p['label']} | {p['bytes']:,} | " + " | ".join(fmt(s[k]) for k in ("enc_core_seconds", "enc_feed_seconds", "enc_harness_seconds", "dec_seconds")) + " | 0,1,0；3/3 |")
    text += ["", "Enc harness 仍不是包含 PubEval、Setup、Extract 的端到端系统延迟。不会把准备开销称为免费，也不把内存中测试夹具称为原方案可部署的MPK。", "",
        "## 2. 时间分解", "",
        "百分比是各次运行分项/核心时间比值的均值。矩阵供给不进入量化占比的分母。pack包含标量/种子头部及向量编码；scalar每次完整加密只运行一次。", "",
        "用于精简主表的聚合：EncOtherAll=EncCore−Matrix−Quant，包括scalar、pack和enc_other；DecDecisionAndOther=dec_decision+dec_other。先逐次聚合再计算均值/SD和占比，不把相关分项的SD相加。", "",
        "| 参数 | 聚合操作 | 时间均值±SD (s) | 相应核心占比均值±SD |", "|---|---|---:|---:|"]
    for p in profiles.values():
        for family, components in (("enc_core_grouped", ENC_GROUPED), ("dec_grouped", DEC_GROUPED)):
            for key in components:
                text.append(f"| {p['label']} | {key} | {fmt(p['statistics'][key], 6)} | {fmt_share(p['component_percentages'][family][key])} |")
    text += ["", "以下保留全部细分项：", "",
        "| 参数 | 操作 | 时间均值±SD (s) | 对相应核心的占比均值±SD |", "|---|---|---:|---:|"]
    for p in profiles.values():
        for family, components in (("enc_core", ENC_COMPONENTS), ("dec", DEC_COMPONENTS)):
            for key in components:
                text.append(f"| {p['label']} | {key} | {fmt(p['statistics'][key], 6)} | {fmt_share(p['component_percentages'][family][key])} |")
    text += ["", "## 3. 独立准备与密钥信息", "",
        "每配置只准备一次，因此下表为单次观测，不能写成3次均值或与每次在线成本混淆。u0由流式矩阵与稠密密钥乘法得到；全尺寸Me=u0是按该计算构造的关系，不声称另执行了独立第二遍全矩阵核验。程序还检查密钥系数规范性/截断边界、维数、实际最大绝对值及平方范数。", "",
        "| 参数 | 维度 d | 非零系数 | 最大绝对值位长 | 平方范数位长 | log2 sigma | key sampling(s) | u0矩阵乘法(s) | 输入供给(s) | 转置(s) | 准备harness(s) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for p in profiles.values():
        r = p["preparation_single_observation"]
        text.append(f"| {p['label']} | {2*p['m']:,} | {r['key_nonzero']:,} | {r['key_max_abs_bits']} | {r['key_norm_squared_bits']} | {p['log2_sigma']:.6f} | " + " | ".join(f"{r[k]:.4f}" for k in ("key_sampling_seconds", "matvec_seconds", "feed_seconds", "transpose_seconds", "prepare_harness_seconds")) + " |")
    text += ["", "## 4. 资源、精度和原始证据", "",
        "所有正式输出文件按各自的长度和SHA-256核对，测试夹具二进制亦核对哈希；0/1消息均执行实际判决。完整原始CSV、准备记录、随机种子、源代码/配置哈希、命令与平台元数据都由numeric-summary.json索引。", "",
        "| 参数 | 峰值RSS (MB十进制) | 在线最高精度 | 在线重试总数 | 准备最高精度 | 准备重试总数 | 每次向量J | 量化决策误差项log2 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for p in profiles.values():
        r = p["preparation_single_observation"]
        text.append(f"| {p['label']} | {p['peak_memory_bytes']/1e6:.3f} | {p['online_max_precision']} | {p['online_precision_retries']} | {r['key_max_precision']} | {r['key_precision_retries']} | {p['vector_decisions']:,} | {p['quant_decision_error_log2_bound']:.3f} |")
    text += ["", "J(2^-256+2^-300)只计接受的向量Bernoulli决策，不包括SC参考匹配、最终提升、scalar/私钥采样及终止事件；更不等于128位计算安全性。零重试不是全输入精度保证，程序没有常时间或侧信道安全认证。RSS是进程截至该条记录的峰值，而非MPK展开大小。", "",
        "## Claim Candidates", "",
        "- Claim: 在两个完整参数维数上，固定身份Enc和Dec操作已实际运行。",
        "  - Source evidence: 每配置3次raw.csv、精确字节产物、实际私钥内积与message/recovered_message。",
        "  - Allowed wording: Full-dimensional fixed-identity encryption and decryption operations were measured using algebraically consistent dense Gaussian test keys. 密钥不是Extract输出。",
        "  - Forbidden stronger wording: 完整Setup/Extract/IBE联合分布已实现验证；3次成功证明DFR可忽略；完整IBE已达128位具体安全或可部署。",
        "  - Uncertainty: 一份测试密钥/配置、单机少量重复、伪随机矩阵供给、没有真实身份求值。",
        "  - Next check: 若需要覆盖审稿人真实陷门密钥要求，仍需实际Extract接口集成。",
        "  - Decision: keep", "",
        "- Claim: 新增量化路径相对矩阵与解密内积的本机成本可分解。",
        "  - Source evidence: 各阶段独立计时且分项和核对；每次比值后求均值。",
        "  - Allowed wording: 在所测夹具和实现下报告实际耗时占比。",
        "  - Forbidden stronger wording: 相对JKN21/Abla24更快；旧供给器换成AES后证明方案算法加速；任何参数下量化都不重要。",
        "  - Uncertainty: 输入生成方式变动使旧实验总时间不可作算法性能对照。",
        "  - Next check: 比较其他方案需等实现、同机、同范围独立实验。",
        "  - Decision: keep", "",
        "## 旧实验与剩余边界", "",
        "上一轮分块外推和完整格式测试原样保留，仅作历史参考，不合并进本轮均值，不做跨轮显著性检验或声称速度提升。新增证据弥补了“只有重构、没有完整加解密运算”的缺口，但并没有弥补“密钥必须来自真实Extract”的要求。", ""]
    (output/"analysis-report.md").write_text("\n".join(text))
    stats = ["# 统计附录：完整Enc/Dec", "",
        "## 分析约定", "",
        "单位为单次正式运行；每参数3次共享同一份代数测试夹具，独立加密随机性，消息固定0/1/0。不是独立设备或3份真实IBE密钥。首次无全长预热的试验保留，没有慢值剔除。", "",
        "均值±样本SD，SD采用n−1；均值条件95% t区间为mean±t(.975,2)SD/√3。n=3无法充分验证正态性/独立性，区间只描述本机这一夹具的模型依赖短期不确定性，不是未来机器/最坏输入/长期运行的预测区间。给出全部原值及范围。聚合项EncOtherAll和DecDecisionAndOther均先逐次相加/相减，再对3个聚合观测计算SD；不相加组件SD。", "",
        "个别非常短或波动较大的阶段，其对称t区间可能跨越0（比例区间也可能超出0–100%）。保留原始计算而不裁剪，这反映小样本近似的局限，不是负运行时间或物理保证；正文应使用均值±SD并保留原始范围。所有正式慢值均保留。", "",
        "没有方案对照显著性检验，因此无p值、优势效应量或多重比较校正；时间占比是描述性效果量。三次消息恢复成功不用于推断密码学DFR，不能把成功率1当作总体保证。准备只有一次，不给其SD或t区间。", "",
        "| 参数 | 指标 | 均值 (s) | SD (s) | 条件95% CI (s) | 全部原值 (s) |",
        "|---|---|---:|---:|---|---|"]
    for p in profiles.values():
        for key, s in p["statistics"].items():
            stats.append(f"| {p['label']} | {key} | {s['mean']:.8f} | {s['sd']:.8f} | [{s['ci95_mean'][0]:.8f}, {s['ci95_mean'][1]:.8f}] | " + "; ".join(f"{v:.8f}" for v in s["values"]) + " |")
    stats += ["", "## 校验", "",
        "- 原始数据只从manifest中实际命令的--output目录读取，拒绝多余、缺失、非完整维度或非encdec记录。",
        "- 核对每参数trial=0,1,2；字节数、向量决策数、消息排程、实际恢复和所有产物哈希。",
        "- 核对Enc分项和=Enc core；Dec分项和=Dec总时间；Enc harness≥core+供给。差额是调用边界/监控等开销，不默认为另一个算法步骤。",
        "- 所有源代码/配置hash在各正式作业中一致；准备数据只有一条/参数，单列而非三次重复利用。",
        "- 采样器未改变，有限区间重试和显式离散Gaussian测试密钥采样成本均保留。", ""]
    (output/"stats-appendix.md").write_text("\n".join(stats))


def figures(result, output):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "pdf.fonttype": 42,
                         "axes.spines.right": False, "axes.spines.top": False})
    folder = output/"figures"
    folder.mkdir(exist_ok=True)
    ps = list(result["profiles"].values())
    colors = ("#0072B2", "#E69F00", "#009E73", "#CC79A7", "#999999")
    hatches = ("", "//", "..", "xx", "\\\\")
    fig, axes = plt.subplots(1, 2, figsize=(9.0, 4.0), constrained_layout=True)
    panels = [(ENC_GROUPED, ("Matrix", "Quantization", "Other (incl. scalar/pack)"), "enc_core_seconds", "Full Enc core"),
              (DEC_GROUPED, ("Unpack/reconstruct", "Private-key dot", "Decision + other"), "dec_seconds", "Full Dec")]
    for ax, (keys, labels, total, title) in zip(axes, panels):
        base = np.zeros(2)
        for i, (key, label) in enumerate(zip(keys, labels)):
            values = np.array([p["statistics"][key]["mean"] for p in ps])
            ax.bar(np.arange(2), values, bottom=base, width=.55, color=colors[i], hatch=hatches[i],
                   edgecolor="white", linewidth=.6, label=label)
            base += values
        ax.errorbar(np.arange(2), base, yerr=[p["statistics"][total]["sd"] for p in ps], linestyle="none", color="black", capsize=4)
        ax.set(xticks=np.arange(2), xticklabels=[p["label"] for p in ps], ylabel="Elapsed seconds", title=title, ylim=(0, max(base)*1.12))
        ax.grid(axis="y", alpha=.18)
        ax.set_axisbelow(True)
        ax.legend(loc="upper center", bbox_to_anchor=(.5, -.10), ncol=2, fontsize=8)
    for ext in ("pdf", "png"):
        fig.savefig(folder/f"figure-01-full-enc-dec-breakdown.{ext}", dpi=300)
    plt.close(fig)
    fig, axes = plt.subplots(1, 3, figsize=(10.8, 3.65), constrained_layout=True)
    for ax, key, title in zip(axes, ("enc_core_seconds", "enc_harness_seconds", "dec_seconds"), ("Enc core", "Enc + test-input supply", "Dec")):
        for i, p in enumerate(ps):
            s = p["statistics"][key]
            jitter = np.array([-.065, 0, .065])
            ax.scatter(np.repeat(i, 3)+jitter, s["values"], marker=("o", "s")[i], color=colors[i], s=28, zorder=3)
            ax.errorbar(i, s["mean"], yerr=s["sd"], marker="_", markersize=15, capsize=5, color="black", linestyle="none")
        upper = max(
            max(max(p["statistics"][key]["values"]), p["statistics"][key]["mean"]+p["statistics"][key]["sd"]) for p in ps)
        ax.set(xticks=[0, 1], xticklabels=[p["label"] for p in ps], title=title, ylabel="Elapsed seconds", xlim=(-.4, 1.4), ylim=(0, upper*1.08))
        ax.grid(axis="y", alpha=.18)
    for ext in ("pdf", "png"):
        fig.savefig(folder/f"figure-02-all-repetitions.{ext}", dpi=300)
    plt.close(fig)
    catalog = ["# 图目录", "", "两张图均由真实完整维度正式试验生成。PDF为矢量主文件，PNG为预览。各面板使用独立纵轴，不能凭柱高跨面板比较Enc和Dec。", "",
        "## Figure 1 — figure-01-full-enc-dec-breakdown.pdf", "",
        "- 目的：展示完整Enc core与完整Dec各自的阶段构成，不能让Enc的较大量级掩盖Dec。",
        "- 数据：每参数3次；堆叠高度=各组件平均秒数；顶部误差条=总项样本SD。",
        "- 图注必须说明：稠密Gaussian代数测试密钥，非Extract输出；Enc核心排除矩阵供给/监控，Dec包含真实私钥内积及判决；独立y轴。",
        "- 读图重点：量化与矩阵乘法的实际占比、Dec重构与内积的区别。各组件加和应与总项一致。",
        "- 本轮观察：" + "; ".join(f"{p['label']}量化占Enc core {p['component_percentages']['enc_core_grouped']['quant_seconds']['mean']:.2f}%，重构占Dec {p['component_percentages']['dec_grouped']['dec_unpack_seconds']['mean']:.2f}%" for p in ps) + "。这些占比支持分阶段工程分析，不是算法安全或部署结论。",
        "- 解释边界：不支持JKN/Abla速度比较，不支持完整系统部署延迟、DFR或安全性验证。", "",
        "## Figure 2 — figure-02-all-repetitions.pdf", "",
        "- 目的：公开所有3次正式运行，显示Enc供给是否成为显著成本及重复波动。",
        "- 数据：每个点是一条原始运行，轻微水平偏移仅为可读性；黑色标记=均值，误差条=样本SD。",
        "- 图注必须说明：共享同一测试密钥和矩阵夹具；独立加密随机性；三个独立纵轴均从0起；没有丢弃首次运行。",
        "- 读图重点：Enc core、含测试供给的调用总时间和Dec分别查看，不把独立准备或文件I/O误加入其中。",
        "- 解释边界：3次不足以确认正态性、长时稳定性或DFR，不将旧实验混入或声称统计速度提升。", ""]
    (output/"figure-catalog.md").write_text("\n".join(catalog))


def selftest():
    s = describe([1, 2, 3])
    assert s["mean"] == 2 and s["sd"] == 1 and s["df"] == 2
    assert math.isclose(s["ci95_mean"][0], 2-t.ppf(.975, 2)/math.sqrt(3))
    assert PROFILES["ours_mpk"]["blocks"]*256 == 2*PROFILES["ours_mpk"]["m"]
    print("SELFTEST PASS: descriptive statistics, conditional t intervals, full dimensions")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--code-root", type=Path, default=Path(__file__).resolve().parents[2]/"Experiments/R46_EncDec_20261023")
    parser.add_argument("--protocol", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        selftest()
        return
    if args.data_root is None:
        parser.error("--data-root required")
    protocol = args.protocol or args.output/"protocol.md"
    rows, prep, provenance = load_inputs(args.data_root.resolve(), args.code_root.resolve(), protocol.resolve())
    if args.check:
        print("VALID: six full-dimensional Enc/Dec trials and two independent preparation records")
        return
    result = analyze(rows, prep, provenance)
    result["analysis_script_sha256"] = sha(Path(__file__))
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output/"numeric-summary.json").write_text(json.dumps(result, indent=2, ensure_ascii=False)+"\n")
    reports(result, args.output)
    figures(result, args.output)
    print(json.dumps({p["label"]: {key: {"mean": p["statistics"][key]["mean"], "sd": p["statistics"][key]["sd"]}
                      for key in ("enc_core_seconds", "enc_feed_seconds", "enc_harness_seconds", "dec_seconds")}
                     for p in result["profiles"].values()}, indent=2))


if __name__ == "__main__":
    main()
