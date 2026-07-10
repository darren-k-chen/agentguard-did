#!/usr/bin/env python3
"""Run the SkillAttack pipeline for a single Hot100 skill into an adhoc dir.

Usage: run_skill.py <skill_id> [rounds]
Writes results to result/runs_organize/adhoc/<model>/<skill_id>/ so the full
`main` batch results are never clobbered.
"""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(os.environ.get("SKILLATTACK_ROOT", "/root/SkillAttack")).resolve()
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))

from core.config_loader import ConfigLoader
from experiments import main_run

sid = sys.argv[1]
rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 3
skill = ROOT / "data" / "hot100skills" / sid
if not skill.exists():
    raise SystemExit(f"skill not found: {skill}")

adhoc_root = ROOT / "result" / "runs_organize" / "adhoc"
adhoc_root.mkdir(parents=True, exist_ok=True)

with tempfile.TemporaryDirectory(prefix="skillattack_adhoc_") as tmpdir:
    tmp_root = Path(tmpdir)
    (tmp_root / skill.name).symlink_to(skill, target_is_directory=True)

    ConfigLoader._instance = None
    ConfigLoader._config = {}
    ConfigLoader._runtime_run_root = None

    cfg = ConfigLoader()
    main_cfg = cfg.main_experiment
    project_cfg = main_cfg.setdefault("project", {})
    input_cfg = main_cfg.setdefault("input", {})

    project_cfg["max_iterations"] = rounds
    project_cfg["surface_parallelism"] = "max"
    project_cfg["max_skills"] = 1
    project_cfg["run_root"] = str(adhoc_root)
    project_cfg["experiment_output_root"] = str(adhoc_root / "_experiment_results")
    input_cfg["raw_skill_root"] = str(tmp_root)
    input_cfg["skill_summary"] = ""

    print(f"[run_skill] {sid} rounds={rounds} -> {adhoc_root}")
    rc = main_run.main([])
    print(f"[run_skill] done rc={rc}")
    raise SystemExit(rc)
