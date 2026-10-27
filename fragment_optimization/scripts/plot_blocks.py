#!/usr/bin/env python3
"""Render two evidence-linked SVG figures for a validated blocks run (stdlib only)."""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import math
import xml.etree.ElementTree as ET
from pathlib import Path

from summarize_blocks import PHASES, validate_and_summarize

COLORS = {"matrix": "#2D6DAB", "quant": "#C64F43", "other": "#A5ADB8"}
LABELS = {"ours_mpk": "MPK-priority", "ours_mid": "Intermediate", "ours_ct": "CT-priority"}
ORDER = ("ours_mpk", "ours_mid", "ours_ct")


class SVG:
    def __init__(self, width, height, title):
        self.parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img">',
                      f'<title>{html.escape(title)}</title>', f'<rect width="{width}" height="{height}" fill="white"/>',
                      '<g font-family="Arial, Helvetica, sans-serif">']

    def text(self, x, y, value, size=14, anchor="start", color="#18232F", bold=False):
        self.parts.append(f'<text x="{x:.3f}" y="{y:.3f}" font-size="{size}" text-anchor="{anchor}" '
                          f'fill="{color}" font-weight="{"bold" if bold else "normal"}">{html.escape(str(value))}</text>')

    def line(self, x1, y1, x2, y2, color="#CFD5DC", width=1, dashed=False):
        self.parts.append(f'<line x1="{x1:.3f}" y1="{y1:.3f}" x2="{x2:.3f}" y2="{y2:.3f}" '
                          f'stroke="{color}" stroke-width="{width}"' + (' stroke-dasharray="6,5"' if dashed else '') + '/>')

    def rect(self, x, y, width, height, color, opacity=1):
        self.parts.append(f'<rect x="{x:.3f}" y="{y:.3f}" width="{width:.3f}" height="{height:.3f}" '
                          f'fill="{color}" fill-opacity="{opacity}"/>')

    def circle(self, x, y, radius=4, color="#C64F43"):
        self.parts.append(f'<circle cx="{x:.3f}" cy="{y:.3f}" r="{radius}" fill="{color}" stroke="white" stroke-width="1"/>')

    def diamond(self, x, y, radius=6):
        self.parts.append(f'<polygon points="{x:.3f},{y-radius:.3f} {x+radius:.3f},{y:.3f} '
                          f'{x:.3f},{y+radius:.3f} {x-radius:.3f},{y:.3f}" fill="#18232F" stroke="white"/>')

    def save(self, path):
        content = "\n".join(self.parts + ["</g>", "</svg>"]) + "\n"
        ET.fromstring(content)
        path.write_text(content, encoding="utf-8")


def subtitle(report):
    sample = report["summaries"][0]
    machine = "Windows native" if report["cycle_counter_available"] else "Non-Windows validation host"
    return f"{sample['repetitions']} trials x {sample['blocks_per_trial']} measured blocks per trial | {machine} | no full-ciphertext extrapolation"


def cost_figure(path, report, summaries):
    svg = SVG(1140, 600, "Measured encryption cost per 256-coordinate block")
    svg.text(45, 38, "Measured encryption cost per 256-coordinate block", 24, bold=True)
    svg.text(45, 65, subtitle(report), 14, color="#536171")
    maximum = max(s["metrics"][f"{phase}_ms_per_256_block"]["mean"] +
                  (s["metrics"][f"{phase}_ms_per_256_block"]["sample_sd"] or 0)
                  for s in summaries for phase in PHASES)
    ceiling = max(20, math.ceil(maximum / 20) * 20)
    top, bottom, left, panel_width = 160, 450, 100, 325
    y = lambda value: bottom - value / ceiling * (bottom-top)
    svg.text(30, 147, "ms/block", 14, bold=True)
    for value in range(0, ceiling+1, max(1, ceiling//5)):
        yy = y(value)
        svg.line(left-20, yy, 1090, yy)
        svg.text(left-32, yy+5, value, 13, "end", "#536171")
    for index, summary in enumerate(summaries):
        center = left + index*panel_width + 130
        svg.text(center, 109, LABELS[summary["profile"]], 19, "middle", bold=True)
        svg.text(center, 133, f"n={summary['n']}, a={summary['a']}", 13, "middle", "#536171")
        total = summary["metrics"]["total_ms_per_256_block"]
        for column, phase in enumerate(PHASES):
            metric = summary["metrics"][f"{phase}_ms_per_256_block"]
            mean, sd = metric["mean"], metric["sample_sd"] or 0
            x = center + (column-1)*82
            svg.rect(x-26,y(mean),52,bottom-y(mean),COLORS[phase])
            svg.line(x,y(max(0,mean-sd)),x,y(mean+sd),"#18232F",1.5)
            svg.line(x-8,y(mean+sd),x+8,y(mean+sd),"#18232F",1.5)
            svg.line(x-8,y(max(0,mean-sd)),x+8,y(max(0,mean-sd)),"#18232F",1.5)
            label = f"{mean:.2f} +/- {sd:.2f}" if metric["sample_sd"] is not None else f"{mean:.2f}; SD NA"
            svg.text(x,y(mean+sd)-12,label,11,"middle")
            svg.text(x,bottom+24,{"matrix":"Matrix","quant":"Quantization","other":"Other"}[phase],12,"middle")
        sd_text = "NA" if total["sample_sd"] is None else f"{total['sample_sd']:.2f}"
        svg.text(center,510,f"Total: {total['mean']:.2f} +/- {sd_text} ms",15,"middle",bold=True)
    svg.text(45,550,"Bars: mean; whiskers: sample SD across trial averages, not across individual blocks.",13,color="#536171")
    svg.text(45,573,"Input-stream generation and codec verification are excluded. Other includes scalar, RNG, serialization and bookkeeping.",13,color="#536171")
    svg.save(path)


def shares_figure(path, report, summaries, rows):
    svg = SVG(1140,800,"Phase shares and trial-to-trial quantization shares")
    svg.text(45,38,"Phase shares and trial-to-trial quantization shares",24,bold=True)
    svg.text(45,65,subtitle(report),14,color="#536171")
    svg.text(45,102,"A. Pooled wall-time composition: sum(phase time) / sum(total time)",17,bold=True)
    left,width = 200,800
    for index,summary in enumerate(summaries):
        y = 137+index*65
        svg.text(left-15,y+23,LABELS[summary["profile"]],15,"end",bold=True)
        shares = summary["pooled_wall_time_shares_pct"]
        position = left
        for phase in PHASES:
            segment = width*shares[phase]/100
            svg.rect(position,y,segment,36,COLORS[phase])
            if phase!="other":svg.text(position+segment/2,y+24,f"{shares[phase]:.2f}%",14,"middle","white",True)
            position += segment
        svg.text(left+width+12,y+24,f"{shares['other']:.2f}%",12,color="#536171")
    for x,label,color in ((220,"Matrix",COLORS["matrix"]),(410,"Quantization",COLORS["quant"]),(650,"Other",COLORS["other"])):
        svg.rect(x,345,15,15,color);svg.text(x+24,358,label,14)
    svg.text(45,405,"B. Quantization share in each trial; 50% is a majority threshold, not a largest-phase test",17,bold=True)
    values = [float(row["quant_seconds"])/float(row["total_seconds"])*100 for row in rows]
    low = min(40,5*math.floor((min(values)-2)/5))
    high = max(60,5*math.ceil((max(values)+2)/5))
    x = lambda value:left+(value-low)/(high-low)*width
    for tick in range(int(low),int(high)+1,5):
        svg.line(x(tick),440,x(tick),674,"#E0E5EB")
        svg.text(x(tick),697,f"{tick}%",13,"middle","#536171")
    if low <=50<=high:svg.line(x(50),438,x(50),674,"#536171",1.5,True)
    jitter = (-12,-6,0,6,12)
    for index,summary in enumerate(summaries):
        yy = 470+index*82
        svg.text(left-15,yy+5,LABELS[summary["profile"]],15,"end",bold=True)
        metric = summary["metrics"]["quant_trial_share_pct"]
        svg.line(x(metric["q1"]),yy+24,x(metric["q3"]),yy+24,"#18232F",5)
        svg.line(x(metric["median"]),yy+16,x(metric["median"]),yy+32,"#18232F",2)
        trials = sorted((row for row in rows if row["profile"]==summary["profile"]),key=lambda row:int(row["trial"]))
        for i,row in enumerate(trials):
            value = 100*float(row["quant_seconds"])/float(row["total_seconds"])
            svg.circle(x(value),yy+jitter[i%len(jitter)],5)
        pooled = summary["pooled_wall_time_shares_pct"]["quant"]
        svg.diamond(x(pooled),yy,7)
        svg.text(left+width+12,yy+5,f"{pooled:.2f}%",12,bold=True)
    svg.circle(55,733,5);svg.text(70,738,"Trial",13)
    svg.diamond(150,733,7);svg.text(166,738,"Pooled share",13)
    svg.line(310,733,350,733,"#18232F",5);svg.line(330,725,330,741,"#18232F",2)
    svg.text(362,738,"Median and IQR",13)
    svg.text(45,775,"No p-values or cross-platform inference. Small samples describe this run; lower than 50% can still be the largest phase.",13,color="#536171")
    svg.save(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory",type=Path)
    args = parser.parse_args()
    run = args.run_directory.resolve()
    if (run/"failure.txt").exists() or not (run/"COMPLETED.txt").is_file():
        raise ValueError("Only completed, non-failed runs can be plotted")
    raw = (run/"raw.csv").read_bytes()
    metadata = (run/"metadata.json").read_bytes()
    warm = (run/"warmup.csv").read_bytes()
    report = validate_and_summarize(raw.decode("utf-8-sig"),json.loads(metadata.decode("utf-8-sig")),warm.decode("utf-8-sig"))
    saved = json.loads((run/"summary_blocks.json").read_text(encoding="utf-8"))
    if saved["summaries"]!=report["summaries"]:
        raise ValueError("Saved summary no longer agrees with raw observations")
    for name,payload in (("raw.csv",raw),("metadata.json",metadata),("warmup.csv",warm)):
        if saved["source_sha256"].get(name)!=hashlib.sha256(payload).hexdigest():
            raise ValueError(f"Saved summary source hash mismatch: {name}")
    indexed = {item["profile"]:item for item in report["summaries"]}
    summaries = [indexed[key] for key in ORDER if key in indexed]
    rows = list(csv.DictReader(raw.decode("utf-8-sig").splitlines()))
    figures = run/"figures"
    figures.mkdir(exist_ok=True)
    cost_figure(figures/"block_cost_breakdown.svg",report,summaries)
    shares_figure(figures/"block_phase_shares.svg",report,summaries,rows)
    catalog = ["# 分块计时图表说明", "", "来源：raw.csv、metadata.json、warmup.csv；绘图前重新执行严格验证，并核对 summary_blocks.json 的统计量和来源 SHA-256。", "",
               "## Figure 1 — block_cost_breakdown.svg", "", "目的：直接比较每个参数配置中矩阵乘法、随机极化量化和其他操作的绝对耗时。", "",
               "图注：真实参数 n/q/r/S 与冻结集合下，每次执行指定数量的 256 维块。柱高为重复试验的每块平均毫秒，误差线为这些试验均值之间的样本标准差；不是单个块的标准差或置信区间。总耗时单独列示。数据供给、编解码检查和进度监控不计入在线计算。", "",
               "解读：量化与矩阵乘法都是主要开销；不能仅因单项占比低于 50% 就认定不是最大开销。其他操作包含随机数、标量部分、序列化、分配和在线管理。", "",
               "## Figure 2 — block_phase_shares.svg", "", "目的：区分汇总阶段占比与逐次试验波动，防止平均方法或个别试验掩盖结果。", "",
               "图注：A 为各阶段累计耗时除以累计总耗时，三阶段相加为 100%；B 的圆点为各次试验的量化占比，菱形为汇总占比，横线为 IQR、竖线为中位数。虚线 50% 仅表示过半阈值。纵向点位偏移仅用于避免遮挡，不编码数据。", "",
               "解读：必须同时比较量化是否过半、是否超过矩阵乘法，以及是否为最大阶段。小样本重复测量仅描述本次机器上的观察，不作显著性、跨平台或完整密文推断。", "",
               "## 本次观察", ""]
    for summary in summaries:
        catalog += [f"- {summary['profile']}: {summary['interpretation']}"]
    catalog += ["", "## 独立计入的供给开销", "", "以下时间没有隐藏：它们在原始数据和汇总中独立报告，但不属于图中的在线计算核。不能据图声称端到端加密同样快速。", "",
                "| 参数 | 输入供给均值 ms/块 | 编解码检查均值 ms/块 |", "|---|---:|---:|"]
    for summary in summaries:
        metrics = summary["metrics"]
        catalog += [f"| {summary['profile']} | {metrics['feed_ms_per_256_block']['mean']:.3f} | {metrics['validation_ms_per_256_block']['mean']:.3f} |"]
    catalog += ["", "## 核对清单", "", "- 各图均使用全部完成的测量试验，预热单列且不进入统计。", "- SVG 文本、柱高和占比来自已核验的统计量；误差线含义明确。", "- 当前未把局部块耗时乘以完整维度，也未补造 Windows CPU cycles。", "",
                f"平台：{report['platform']}", "", f"绘图脚本 SHA-256：{hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}", ""]
    (run/"figure-catalog.md").write_text("\n".join(catalog),encoding="utf-8")
    print("Created figures/block_cost_breakdown.svg, figures/block_phase_shares.svg and figure-catalog.md")


if __name__=="__main__":
    main()
