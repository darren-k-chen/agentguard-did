#!/usr/bin/env python3
"""Run L1 (prompt+skill firewall) and L2-effect defense on a victim's SUCCESSFUL attacks,
using the deployed claude-sonnet-4-6 protocol (same as the qwen 66-corpus). Cross-victim
defense generalization. Usage: victim_defense.py <run_dir> <model_subdir>"""
import os,sys,json,glob,collections
sys.path.insert(0,"/root")
for line in open("/root/.agrun_keys.env"):
    if "=" in line and not line.startswith("#"):
        k,v=line.strip().split("=",1); os.environ.setdefault(k,v)
import guardrun as g
ROOT="/root/SkillAttack"; os.chdir(ROOT)
run_dir=sys.argv[1]; model=sys.argv[2]
# skill dirs for skill_text
skdirs={}
for md in glob.glob(ROOT+"/data/skillinject_all/*/SKILL.md")+glob.glob(ROOT+"/data/hot100skills/*/SKILL.md"):
    skdirs[os.path.basename(os.path.dirname(md))]=md
# collect SUCCESS surfaces (skill,surface) with artifacts
succ={}
for p in glob.glob(f"result/runs_organize/{run_dir}/{model}/**/round_*.json",recursive=True):
    r=json.load(open(p)); j=r.get("judge",{}) or {}
    if j.get("result")!="success": continue
    seg=p.split(f"/{model}/")[1].split("/"); sk=seg[0]; su=r.get("surface","")
    att=r.get("attack",{}) or {}; sim=r.get("simulation",{}) or {}
    key=(sk,su)
    if key in succ: continue
    succ[key]={"prompt":att.get("attack_prompt","") or "","logs":(sim.get("logs","") or "")[:6000],"skill":sk}
print(f"{model}: {len(succ)} successful attack surfaces",flush=True)
rows=[]
for i,((sk,su),d) in enumerate(sorted(succ.items()),1):
    st=""; 
    if sk in skdirs: st=open(skdirs[sk],encoding="utf-8",errors="ignore").read()
    def J(sysp,payload):
        payload=(payload or "").strip()
        if not payload: return None
        try: t,_,_=g.call("claude",sysp,payload[:6000]); return bool(g.parse(t).get("malicious"))
        except Exception: return None
    l1p=J(g.SYSTEM,d["prompt"]); l1s=J(g.SYSTEM,st); l2e=J(g.EFFECT_SYS,"COMMANDS:\n(in log)\n\nOUTPUT:\n"+d["logs"])
    rows.append({"skill":sk,"surface":su,"l1_prompt":l1p,"l1_skill":l1s,"l2_effect":l2e})
    if i%8==0: print(f"  [{i}/{len(succ)}]",flush=True)
json.dump(rows,open(f"/root/victim_defense_{model}.json","w"),indent=1)
n=len(rows)
def rate(k): 
    ev=[r for r in rows if r[k] is not None]; c=sum(1 for r in ev if r[k]); return c,len(ev)
l1u=sum(1 for r in rows if r["l1_prompt"] or r["l1_skill"])
print(f"\n=== {model} DEFENSE on {n} successful attacks (claude deployed) ===")
for k in ("l1_prompt","l1_skill","l2_effect"):
    c,e=rate(k); print(f"  {k:10s} {c}/{e} = {100*c/e:.1f}%" if e else f"  {k}: n/a")
print(f"  L1_union   {l1u}/{n} = {100*l1u/n:.1f}%")
