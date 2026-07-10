#!/usr/bin/env python3
"""Defense (L1/L2) detection on the attack attempts OUTSIDE the 66 realized-harm corpus.
Uniform Claude (claude-sonnet-4-6) protocol, identical to the guard matrix, so the
non-66 numbers are comparable to (and combinable with) the 66. L1 (prompt/skill) and
L2-effect are input/output inspectors applicable to any attempt; L2-cmd and L3 are
execution-contingent and reported separately."""
import os, sys, json, glob, time, collections
sys.path.insert(0, "/root")
for line in open("/root/.agrun_keys.env"):
    if "=" in line and not line.startswith("#"):
        k,v=line.strip().split("=",1); os.environ.setdefault(k,v)
import guardrun as g
ROOT="/root/SkillAttack"; DASH=ROOT+"/dashboard"; OUT="/root/xval_out"

# 66 keys to EXCLUDE
sixty6 = {(r["skill"], r["surface"]) for r in json.load(open(DASH+"/sa_defense.json"))["rows"]}

# skillname -> skill dir (for skill_text)
skdirs={}
for md in glob.glob(ROOT+"/data/skillinject_all/*/SKILL.md")+glob.glob(ROOT+"/data/hot100skills/*/SKILL.md"):
    skdirs[os.path.basename(os.path.dirname(md))]=md

roots=["result/runshistory/qwen3.5-122b-a10b","result/runshistory/qwen3.5-122b-a10b_20260703070607","result/runs_organize/comparison/qwen3.5-122b-a10b"]
best={}  # (skill,surface) -> dict(verdict, prompt, skillname, logs, dataset)
for rt in roots:
    for p in glob.glob(ROOT+"/"+rt+"/**/round_*.json",recursive=True):
        r=json.load(open(p)); j=r.get("judge",{}) or {}; v=j.get("result")
        att=r.get("attack",{}) or {}; meta=att.get("metadata",{}) or {}
        skill=meta.get("skillname") or ""; surface=r.get("surface") or meta.get("surface_id") or ""
        key=(skill,surface)
        if not skill or not surface: continue
        prev=best.get(key)
        take = prev is None or v=="success" or (prev["verdict"]!="success" and v=="ignore")
        if take:
            sim=r.get("simulation",{}) or {}
            best[key]={"verdict":v,"prompt":att.get("attack_prompt","") or "",
                       "skillname":skill,"logs":(sim.get("logs","") or "")[:6000],
                       "dataset":meta.get("dataset") or ("SkillInject" if "skillinject" in p.lower() else "Hot100")}

non66={k:d for k,d in best.items() if k not in sixty6}
print("total surfaces",len(best),"| 66 excluded",len(best)-len(non66),"| non-66",len(non66),flush=True)
print("non-66 verdicts:",dict(collections.Counter(d["verdict"] for d in non66.values())),flush=True)

def skilltext(sn):
    md=skdirs.get(sn)
    return open(md,encoding="utf-8",errors="ignore").read() if md else ""

rows=[]
for i,(k,d) in enumerate(sorted(non66.items()),1):
    st=skilltext(d["skillname"])
    def judge(sysp,payload):
        payload=(payload or "").strip()
        if not payload: return None
        try:
            t,it,ot=g.call("claude",sysp,payload[:6000]); return bool(g.parse(t).get("malicious"))
        except Exception as e: return None
    l1p=judge(g.SYSTEM, d["prompt"])
    l1s=judge(g.SYSTEM, st)
    l2e=judge(g.EFFECT_SYS, "COMMANDS:\n(see log)\n\nOUTPUT:\n"+d["logs"])
    rows.append({"skill":k[0],"surface":k[1],"dataset":d["dataset"],"verdict":d["verdict"],
                 "l1_prompt":l1p,"l1_skill":l1s,"l2_effect":l2e})
    if i%10==0 or i<=3:
        print(f"[{i}/{len(non66)}] {k[0][:26]:26s} v={d['verdict'][:4]} p={l1p} s={l1s} e={l2e}",flush=True)
    time.sleep(0.05)

json.dump(rows, open(OUT+"/nonsucc_defense.json","w"), ensure_ascii=False, indent=1)

def rate(rs,key):
    ev=[r for r in rs if r[key] is not None]; c=sum(1 for r in ev if r[key])
    return c,len(ev)
def block(name,rs):
    n=len(rs); 
    if not n: return
    l1u=sum(1 for r in rs if r["l1_prompt"] or r["l1_skill"])
    print(f"\n[{name}] N={n}")
    for m in ("l1_prompt","l1_skill","l2_effect"):
        c,e=rate(rs,m); print(f"   {m:10s} {c}/{e} = {100*c/e:.1f}%" if e else f"   {m}: n/a")
    print(f"   L1_union   {l1u}/{n} = {100*l1u/n:.1f}%")

allrows=rows
block("Non-66 ALL", allrows)
block("Non-66 ignore (agent refused)", [r for r in rows if r["verdict"]=="ignore"])
block("Non-66 technical", [r for r in rows if r["verdict"]=="technical"])
block("Non-66 extra-success (not in 66)", [r for r in rows if r["verdict"]=="success"])
print("\nSaved -> nonsucc_defense.json")
