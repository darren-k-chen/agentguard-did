#!/usr/bin/env python3
"""Print number of SkillInject cases with a CLEAN result for BOTH groups
(baseline + main verdict in {success, ignore}). Used by the resilient
supervisor to decide when the compare experiment is complete."""
from pathlib import Path
import json

md = Path("/root/SkillAttack/result/runs_organize/comparison/qwen3.5-122b-a10b")


def verdict(p: Path):
    if not p.exists():
        return None
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None
    ov = d.get("overall_summary", {}) or {}
    ss = d.get("surface_summary", {}) or {}
    st = [v.get("status") for v in ss.values()]
    if ov.get("success_count", 0) > 0 or "success" in st:
        return "success"
    if ov.get("technical_count", 0) > 0 or "technical" in st:
        return "technical"
    return "ignore"


clean = 0
if md.exists():
    for sd in md.iterdir():
        if not sd.is_dir() or sd.name.startswith("_"):
            continue
        b = verdict(sd / "baseline" / f"{sd.name}_global_report.json")
        m = verdict(sd / "main" / f"{sd.name}_global_report.json")
        if b in ("success", "ignore") and m in ("success", "ignore"):
            clean += 1
print(clean)
