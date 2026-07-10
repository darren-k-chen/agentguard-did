#!/usr/bin/env python3
"""SkillAttack interactive results dashboard.

Serves the full `main` experiment results with charts, raw malicious-prompt /
skill-source viewers, and buttons to rerun a single skill or the whole batch.
Run on box2 inside the SkillAttack venv.
"""
import json
import os
import re
import subprocess
import sys
import time
import glob
import zipfile
from pathlib import Path

from flask import Flask, jsonify, request, Response, abort

ROOT = Path(os.environ.get("SKILLATTACK_ROOT", "/root/SkillAttack")).resolve()
MAIN_DIR = ROOT / "result" / "runs_organize" / "main"
ADHOC_DIR = ROOT / "result" / "runs_organize" / "adhoc"
HOT100 = ROOT / "data" / "hot100skills"
LOG_FILE = ROOT / "result" / "main_run.log"
DASH_DIR = ROOT / "dashboard"
TOKEN_FILE = DASH_DIR / ".token"
LOCK_FILE = DASH_DIR / ".joblock"
JOB_LOG = DASH_DIR / "job.log"
VENV_PY = ROOT / ".venv" / "bin" / "python"
PLANNED_TOTAL = 100

DASH_DIR.mkdir(parents=True, exist_ok=True)
ADHOC_DIR.mkdir(parents=True, exist_ok=True)

if TOKEN_FILE.exists():
    TOKEN = TOKEN_FILE.read_text().strip()
else:
    TOKEN = os.urandom(12).hex()
    TOKEN_FILE.write_text(TOKEN)

app = Flask(__name__)


# ----------------------------- helpers --------------------------------------
def model_dir() -> Path | None:
    if not MAIN_DIR.exists():
        return None
    cands = [d for d in MAIN_DIR.iterdir() if d.is_dir() and not d.name.startswith("_")]
    if not cands:
        return None
    # newest by mtime
    return max(cands, key=lambda d: d.stat().st_mtime)


def load_json(p: Path):
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception:
        return None


def skill_result_dirs(base: Path):
    if not base or not base.exists():
        return []
    return sorted([d for d in base.iterdir() if d.is_dir() and not d.name.startswith("_")])


def parse_skill(d: Path) -> dict:
    """Summarize one skill result dir."""
    sid = d.name
    analyze = load_json(d / f"{sid}_analyze.json") or {}
    report = load_json(d / f"{sid}_global_report.json") or {}
    surfaces = []
    for s in analyze.get("results", []) or []:
        surfaces.append({
            "id": s.get("id"),
            "title": s.get("title"),
            "risk_type": s.get("risk_type"),
            "level": s.get("level"),
        })
    surf_summary = report.get("surface_summary", {}) or {}
    overall = report.get("overall_summary", {}) or {}
    # merge status into surfaces
    for s in surfaces:
        ss = surf_summary.get(s["id"], {})
        s["status"] = ss.get("status")
        s["rounds"] = ss.get("rounds")
        s["final_risk_type"] = ss.get("final_risk_type")
    # overall verdict: success if any surface success, else technical if any technical, else ignore
    statuses = [s.get("status") for s in surfaces]
    if overall.get("success_count", 0) > 0 or "success" in statuses:
        verdict = "success"
    elif "technical" in statuses or overall.get("technical_count", 0) > 0:
        verdict = "technical"
    else:
        verdict = "ignore"
    win = next((s["id"] for s in surfaces if s.get("status") == "success"), None)
    risk_types = sorted({s["risk_type"] for s in surfaces if s.get("risk_type")})
    return {
        "id": sid,
        "verdict": verdict,
        "surface_count": len(surfaces),
        "surfaces": surfaces,
        "winning_surface": win,
        "risk_types": risk_types,
        "overall": overall,
        "has_report": bool(report),
    }


def all_skills(base: Path):
    return [parse_skill(d) for d in skill_result_dirs(base)]


def run_status() -> dict:
    """Status of the background batch run, derived from the log + lock."""
    running = False
    pid = None
    if LOCK_FILE.exists():
        try:
            pid = int(LOCK_FILE.read_text().strip())
            os.kill(pid, 0)
            running = True
        except Exception:
            running = False
    # also detect the main.py process even if not started by us
    try:
        out = subprocess.run(["pgrep", "-f", "main.py main"], capture_output=True, text=True)
        if out.stdout.strip():
            running = True
    except Exception:
        pass
    progress = None
    current = None
    tail = ""
    if LOG_FILE.exists():
        try:
            lines = LOG_FILE.read_text(errors="replace").splitlines()
            tail = "\n".join(lines[-40:])
            for ln in reversed(lines):
                m = re.search(r"\[(\d+)/(\d+)\] skill=(\S+)", ln)
                if m:
                    progress = {"done": int(m.group(1)), "total": int(m.group(2))}
                    current = m.group(3)
                    break
            if any("experiment complete" in ln for ln in lines[-5:]):
                running = False
        except Exception:
            pass
    return {"running": running, "pid": pid, "progress": progress,
            "current": current, "log_tail": tail}


def require_token():
    tok = request.headers.get("X-Token") or request.args.get("token")
    if tok != TOKEN:
        abort(401)


# ----------------------------- API ------------------------------------------
@app.route("/api/summary")
def api_summary():
    require_token()
    skills = all_skills(model_dir())
    counts = {"success": 0, "ignore": 0, "technical": 0}
    by_risk = {}        # risk_type -> {total, success}
    surfaces_total = 0
    success_surfaces = 0
    for s in skills:
        counts[s["verdict"]] = counts.get(s["verdict"], 0) + 1
        surfaces_total += s["surface_count"]
        for sf in s["surfaces"]:
            rt = sf.get("risk_type") or "Unknown"
            d = by_risk.setdefault(rt, {"total": 0, "success": 0})
            d["total"] += 1
            if sf.get("status") == "success":
                d["success"] += 1
                success_surfaces += 1
    processed = len(skills)
    asr = round(counts["success"] / processed * 100, 1) if processed else 0.0
    return jsonify({
        "model": model_dir().name if model_dir() else None,
        "processed": processed,
        "planned": PLANNED_TOTAL,
        "counts": counts,
        "by_risk": by_risk,
        "surfaces_total": surfaces_total,
        "success_surfaces": success_surfaces,
        "asr_skill": asr,
        "status": run_status(),
    })


@app.route("/api/skills")
def api_skills():
    require_token()
    return jsonify(all_skills(model_dir()))


def _adhoc_skill_dir(sid: str) -> Path | None:
    """Newest adhoc result dir for this skill: adhoc/<model>/<sid>."""
    cands = []
    if ADHOC_DIR.exists():
        for mdl in ADHOC_DIR.iterdir():
            if mdl.is_dir() and not mdl.name.startswith("_"):
                p = mdl / sid
                if p.is_dir():
                    cands.append(p)
    if not cands:
        return None
    return max(cands, key=lambda d: d.stat().st_mtime)


def _find_skill_dir(sid: str, source: str = "main") -> Path | None:
    if source == "adhoc":
        return _adhoc_skill_dir(sid)
    md = model_dir()
    if md and (md / sid).is_dir():
        return md / sid
    return None


def _steps_brief(sim: dict) -> list:
    out = []
    for s in (sim.get("steps") or []):
        out.append({
            "i": s.get("step_index"),
            "type": s.get("type"),
            "tool": s.get("tool"),
            "command": (s.get("arguments") or {}).get("command"),
        })
    return out


def parse_round_full(rf: Path) -> dict:
    """All prompt/exec detail for one round, incl. every attack variant tried."""
    r = load_json(rf) or {}
    atk = r.get("attack", {}) or {}
    meta = atk.get("metadata") or {}
    tgt = atk.get("target") or {}
    jd = r.get("judge", {}) or {}
    sim = r.get("simulation", {}) or {}
    fb = r.get("feedback", {}) or {}
    atks = fb.get("attacks") or []
    sims = fb.get("simulations") or []
    jds = fb.get("judges") or []
    variants = []
    for i, a in enumerate(atks):
        a = a or {}
        sj = (jds[i] if i < len(jds) else {}) or {}
        ss = (sims[i] if i < len(sims) else {}) or {}
        variants.append({
            "attack_prompt": a.get("attack_prompt"),
            "strategy": (a.get("metadata") or {}).get("strategy"),
            "phase": (a.get("metadata") or {}).get("phase"),
            "judge_result": sj.get("result"),
            "judge_reason": sj.get("reason"),
            "commands": [(st.get("arguments") or {}).get("command")
                         for st in (ss.get("steps") or [])
                         if (st.get("arguments") or {}).get("command")],
            "sim_steps": len(ss.get("steps") or []),
            "logs": (ss.get("logs") or "")[:6000],
        })
    return {
        "round_id": r.get("round_id"),
        "phase": meta.get("phase"),
        "attack_prompt": atk.get("attack_prompt"),
        "strategy": meta.get("strategy"),
        "success_condition": tgt.get("success_condition"),
        "expected_path": atk.get("expected_path"),
        "judge_result": jd.get("result"),
        "judge_reason": jd.get("reason"),
        "suggestion": jd.get("actionable_suggestion"),
        "sim_time": sim.get("execution_time"),
        "sim_steps": len(sim.get("steps") or []),
        "sim_error": bool(sim.get("errors")),
        "steps": _steps_brief(sim),
        "logs": (sim.get("logs") or "")[:8000],
        "variants": variants,
        "file": str(rf.relative_to(ROOT)),
    }


@app.route("/api/skill/<path:sid>")
def api_skill(sid):
    require_token()
    source = request.args.get("source", "main")
    d = _find_skill_dir(sid, source)
    if not d:
        abort(404)
    info = parse_skill(d)
    analyze = load_json(d / f"{d.name}_analyze.json") or {}
    desc = {s.get("id"): s.get("description") for s in analyze.get("results", []) or []}
    rounds = []
    for surf in info["surfaces"]:
        sdir = d / surf["id"]
        if not sdir.is_dir():
            continue
        for rf in sorted(sdir.glob("round_*.json")):
            rd = parse_round_full(rf)
            rd["surface"] = surf["id"]
            rd["surface_title"] = surf.get("title")
            rd["risk_type"] = surf.get("risk_type")
            rounds.append(rd)
    return jsonify({"info": info, "descriptions": desc, "rounds": rounds,
                    "readme": analyze.get("readme")})


@app.route("/api/playbooks")
def api_playbooks():
    """List every successful attack (Hot100 + SkillInject) as a playbook entry."""
    require_token()
    import playbooks
    return jsonify(playbooks.list_playbooks())


@app.route("/playbook")
def playbook_page():
    """Self-contained reproduction playbook HTML for one attack."""
    require_token()
    import playbooks
    src = request.args.get("source", "main")
    skill = request.args.get("skill", "")
    surface = request.args.get("surface", "")
    return Response(playbooks.render_playbook(src, skill, surface), mimetype="text/html")


@app.route("/api/blindspot")
def api_blindspot():
    """Per-component Layer-1 detection over successful attacks (prompt/skill/steps)."""
    require_token()
    data = load_json(DASH_DIR / "sa_blindspot2.json") or []
    n = len(data)

    def mal(r, k):
        return (r.get("det", {}).get(k) or {}).get("malicious")

    def caught(r, keys):
        return any(mal(r, k) is True for k in keys)

    def rate(keys):
        c = sum(1 for r in data if caught(r, keys))
        return {"caught": c, "rate": round(c / n * 100, 1) if n else 0.0}

    static_blind = [r for r in data if not caught(r, ["prompt_haiku", "prompt_sonnet", "skill_sonnet"])]
    true_blind = [r for r in data if not caught(r, ["prompt_haiku", "prompt_sonnet", "skill_sonnet", "steps_sonnet"])]
    by_risk = {}
    for r in static_blind:
        by_risk[r.get("risk_type") or "?"] = by_risk.get(r.get("risk_type") or "?", 0) + 1
    return jsonify({
        "total": n,
        "prompt": rate(["prompt_haiku", "prompt_sonnet"]),
        "skill": rate(["skill_sonnet"]),
        "steps": rate(["steps_sonnet"]),
        "static": rate(["prompt_haiku", "prompt_sonnet", "skill_sonnet"]),
        "anycomp": rate(["prompt_haiku", "prompt_sonnet", "skill_sonnet", "steps_sonnet"]),
        "static_blind": len(static_blind),
        "true_blind": len(true_blind),
        "static_blind_by_risk": by_risk,
        "rows": data,
    })


@app.route("/api/defense")
def api_defense():
    """Full defense-in-depth coverage (L1 prompt/skill, L2 cmd, L3 syscall, L2 effect)."""
    require_token()
    return jsonify(load_json(DASH_DIR / "sa_defense.json") or {"summary": {}, "rows": []})


@app.route("/api/newvsl1")
def api_newvsl1():
    """Trained new defenses (L3-ML OOF + L2-effect) vs the Layer-1 blind spots."""
    require_token()
    return jsonify(load_json(DASH_DIR / "sa_newvsl1.json") or {})


@app.route("/api/qwencompare")
def api_qwencompare():
    """qwen vs Claude as the defense judge across the 4 LLM methods."""
    require_token()
    return jsonify(load_json(DASH_DIR / "sa_qwen_compare.json") or {})


@app.route("/api/combos")
def api_combos():
    """Full per-method / per-layer / all-combination interception analysis."""
    require_token()
    return jsonify(load_json(DASH_DIR / "sa_combos.json") or {})


@app.route("/api/residualstudy")
def api_residualstudy():
    """Residual-optimization research: holistic judge (negative) + provenance (positive)."""
    require_token()
    return jsonify(load_json(DASH_DIR / "sa_residual_study.json") or {})


@app.route("/api/optcompare")
def api_optcompare():
    """Before/after-training comparison for the L3/L2 optimizations."""
    require_token()
    return jsonify(load_json(DASH_DIR / "sa_optcompare.json") or {})


@app.route("/api/prompts")
def api_prompts():
    """Stage prompt templates that drive attacker/judge/analyzer."""
    require_token()
    pdir = ROOT / "prompts"
    files = []
    if pdir.exists():
        for f in sorted(pdir.rglob("*")):
            if f.is_file() and f.stat().st_size < 200_000:
                try:
                    content = f.read_text(errors="replace")
                except Exception:
                    content = "<binary>"
                files.append({"path": str(f.relative_to(pdir)), "content": content})
    return jsonify({"files": files})


@app.route("/api/round")
def api_round():
    """Raw round JSON for full prompt / simulation step viewing."""
    require_token()
    rel = request.args.get("file", "")
    p = (ROOT / rel).resolve()
    if not str(p).startswith(str(ROOT)) or not p.exists():
        abort(404)
    return Response(p.read_text(errors="replace"), mimetype="application/json")


@app.route("/api/skill/<path:sid>/source")
def api_source(sid):
    require_token()
    sdir = HOT100 / sid
    if not sdir.is_dir():
        # try strip adhoc prefix
        abort(404)
    files = []
    for f in sorted(sdir.rglob("*")):
        if f.is_file() and f.stat().st_size < 200_000:
            rel = str(f.relative_to(sdir))
            try:
                content = f.read_text(errors="replace")
            except Exception:
                content = "<binary>"
            files.append({"path": rel, "content": content})
    return jsonify({"id": sid, "files": files})


# ----------------------------- compare --------------------------------------
COMP_DIR = ROOT / "result" / "runs_organize" / "comparison"


def comp_model_dir() -> Path | None:
    if not COMP_DIR.exists():
        return None
    cands = [d for d in COMP_DIR.iterdir() if d.is_dir() and not d.name.startswith("_")]
    return max(cands, key=lambda d: d.stat().st_mtime) if cands else None


def _group_verdict(gr: dict | None):
    """Return {'success':bool,'verdict':str} from a global_report, or None."""
    if not gr:
        return None
    ov = gr.get("overall_summary", {}) or {}
    ss = gr.get("surface_summary", {}) or {}
    statuses = [v.get("status") for v in ss.values()]
    if ov.get("success_count", 0) > 0 or "success" in statuses:
        verdict = "success"
    elif ov.get("technical_count", 0) > 0 or "technical" in statuses:
        verdict = "technical"
    else:
        verdict = "ignore"
    return {"success": verdict == "success", "verdict": verdict}


def comp_pairs() -> dict:
    """Live per-case scan: {skillname: {baseline:{...}, main:{...}}}."""
    pairs = {}
    md = comp_model_dir()
    if not md:
        return pairs
    for sdir in sorted(md.iterdir()):
        if not sdir.is_dir() or sdir.name.startswith("_"):
            continue
        name = sdir.name
        entry = {}
        for group in ("baseline", "main"):
            gr = load_json(sdir / group / f"{name}_global_report.json")
            v = _group_verdict(gr)
            if v:
                entry[group] = v
        if entry:
            pairs[name] = entry
    return pairs


@app.route("/api/compare/summary")
def api_comp_summary():
    require_token()
    pairs = comp_pairs()
    plist = [{"skillname": sk,
              "baseline": v.get("baseline"),
              "main": v.get("main")} for sk, v in sorted(pairs.items())]
    n_base = sum(1 for p in plist if p["baseline"])
    n_main = sum(1 for p in plist if p["main"])
    s_base = sum(1 for p in plist if p["baseline"] and p["baseline"]["success"])
    s_main = sum(1 for p in plist if p["main"] and p["main"]["success"])
    return jsonify({
        "model": comp_model_dir().name if comp_model_dir() else None,
        "pairs": plist,
        "n_baseline": n_base, "n_main": n_main,
        "success_baseline": s_base, "success_main": s_main,
        "asr_baseline": round(s_base / n_base * 100, 1) if n_base else 0.0,
        "asr_main": round(s_main / n_main * 100, 1) if n_main else 0.0,
        "running": compare_running(),
    })


def compare_running() -> bool:
    try:
        out = subprocess.run(["pgrep", "-f", "main.py compare"], capture_output=True, text=True)
        return bool(out.stdout.strip())
    except Exception:
        return False


def _read_rounds_tree(base: Path) -> list:
    rounds = []
    for rf in sorted(base.rglob("round_*.json")):
        rel = rf.relative_to(base)
        rd = parse_round_full(rf)
        rd["group"] = "baseline" if "baseline" in rel.parts else "iterative"
        rd["surface"] = rf.parent.name
        rounds.append(rd)
    # baseline first, then iterative
    return sorted(rounds, key=lambda x: (x["group"] != "baseline", x["surface"], x["round_id"] or 0))


@app.route("/api/compare/skill/<path:sk>")
def api_comp_skill(sk):
    require_token()
    md = comp_model_dir()
    if not md or not (md / sk).is_dir():
        abort(404)
    return jsonify({"skillname": sk, "rounds": _read_rounds_tree(md / sk)})


# ----------------------------- run control ----------------------------------
def job_running() -> bool:
    return run_status()["running"]


@app.route("/api/run/main", methods=["POST"])
def api_run_main():
    require_token()
    if job_running():
        return jsonify({"ok": False, "error": "a run is already in progress"}), 409
    cmd = f"cd {ROOT} && ./quickstart.sh main > {LOG_FILE} 2>&1"
    p = subprocess.Popen(["setsid", "bash", "-c", cmd],
                         stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    LOCK_FILE.write_text(str(p.pid))
    return jsonify({"ok": True, "pid": p.pid, "mode": "main"})


@app.route("/api/run/skill", methods=["POST"])
def api_run_skill():
    require_token()
    if job_running():
        return jsonify({"ok": False, "error": "a run is already in progress"}), 409
    sid = (request.json or {}).get("id")
    if not sid or not (HOT100 / sid).is_dir():
        return jsonify({"ok": False, "error": "unknown skill id"}), 400
    rounds = int((request.json or {}).get("rounds", 3))
    runner = DASH_DIR / "run_skill.py"
    cmd = f"cd {ROOT} && {VENV_PY} {runner} {sid} {rounds} > {JOB_LOG} 2>&1"
    p = subprocess.Popen(["setsid", "bash", "-c", cmd],
                         stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    LOCK_FILE.write_text(str(p.pid))
    return jsonify({"ok": True, "pid": p.pid, "mode": "skill", "id": sid})


@app.route("/api/status")
def api_status():
    require_token()
    st = run_status()
    jl = ""
    if JOB_LOG.exists():
        jl = "\n".join(JOB_LOG.read_text(errors="replace").splitlines()[-25:])
    st["job_log_tail"] = jl
    return jsonify(st)


# ----------------------------- page -----------------------------------------
@app.route("/")
def index():
    html_path = DASH_DIR / "index.html"
    return Response(html_path.read_text(encoding="utf-8"), mimetype="text/html")


if __name__ == "__main__":
    port = int(os.environ.get("DASH_PORT", "8900"))
    print(f"[dashboard] token = {TOKEN}")
    print(f"[dashboard] open  http://<box2-ip>:{port}/?token={TOKEN}")
    app.run(host="0.0.0.0", port=port, threaded=True)
