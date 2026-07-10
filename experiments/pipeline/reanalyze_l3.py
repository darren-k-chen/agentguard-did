#!/usr/bin/env python3
"""Re-analyze saved L3 strace traces with the (fixed) behaviour analyzer — no
docker re-run needed. Produces sa_l3_all.json keyed by skill+surface."""
import json, sys, os
from pathlib import Path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib, clawguard_behavior_v2 as cg
importlib.reload(cg)

ROOT = Path("/root/SkillAttack")
TDIR = ROOT/"dashboard/l3_traces"
bs = json.load(open(ROOT/"dashboard/sa_blindspot2.json"))

out = []
for r in bs:
    safe = (r["skill"]+"__"+r["surface"]).replace("/","_")[:120]
    tf = TDIR/(safe+".trace")
    trace = tf.read_text() if tf.exists() else ""
    res = cg.analyze_text(trace)
    out.append({**{k:r[k] for k in ("dataset","source","skill","surface","risk_type")},
                "trace_lines": trace.count("\n"),
                "l3_risk": res["risk"],
                "l3_signatures": [s["sig"] for s in res["signatures"]],
                "l3_detail": res["signatures"]})
json.dump(out, open(ROOT/"dashboard/sa_l3_all.json","w"), ensure_ascii=False, indent=1)
n=len(out); c=sum(1 for r in out if r["l3_risk"]>=0.5)
print(f"re-analyzed {n} traces; L3 caught {c} (risk>=0.5)")
for r in out:
    if r["l3_risk"]>=0.5:
        print(f"  ✅ {r['skill'][:34]:34s} {r['risk_type'][:16]:16s} {r['l3_signatures']}")
