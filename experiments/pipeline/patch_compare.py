#!/usr/bin/env python3
"""Make compare_run resumable: skip (skill,group) trials whose global_report
already exists with a clean verdict (success/ignore); redo technical + missing.
Idempotent — safe to run repeatedly."""
from pathlib import Path

f = Path("/root/SkillAttack/experiments/compare_run.py")
src = f.read_text(encoding="utf-8")

if "[compare] skip done" in src:
    print("already patched")
    raise SystemExit(0)

anchor = "                    trial_root = model_base / skillname / trial.group\n"
if anchor not in src:
    raise SystemExit("anchor not found — compare_run.py layout changed")

skip = (
    "                    _gr = trial_root / f\"{skillname}_global_report.json\"\n"
    "                    if _gr.exists():\n"
    "                        try:\n"
    "                            _d = json.loads(_gr.read_text(encoding=\"utf-8\"))\n"
    "                            _ov = _d.get(\"overall_summary\", {}) or {}\n"
    "                            _ss = _d.get(\"surface_summary\", {}) or {}\n"
    "                            _st = [v.get(\"status\") for v in _ss.values()]\n"
    "                            _clean = _ov.get(\"success_count\", 0) > 0 or \"success\" in _st or not (\"technical\" in _st or _ov.get(\"technical_count\", 0) > 0)\n"
    "                        except Exception:\n"
    "                            _clean = False\n"
    "                        if _clean:\n"
    "                            print(f\"[compare] skip done {skillname}/{trial.group}\")\n"
    "                            continue\n"
)

src = src.replace(anchor, anchor + skip, 1)
f.write_text(src, encoding="utf-8")
print("patched OK")
