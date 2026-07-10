import json, csv, collections
OUT="/root/xval_out"
# non-66 (prompt/skill/effect)
non=json.load(open(OUT+"/nonsucc_defense.json"))
# 66 uniform claude verdicts from calls_guard_api.csv
per=collections.defaultdict(dict)
for r in csv.DictReader(open(OUT+"/calls_guard_api.csv")):
    if r["model"]!="claude": continue
    per[r["item"]][r["role"]] = (r["verdict"]=="True")
def b(v): return v is True
# build unified per-surface records: prompt, skill, effect
recs=[]
for it,d in per.items():
    recs.append({"set":"66","l1_prompt":d.get("prompt"),"l1_skill":d.get("skill"),"l2_effect":d.get("effect")})
for r in non:
    recs.append({"set":"non66","l1_prompt":r["l1_prompt"],"l1_skill":r["l1_skill"],"l2_effect":r["l2_effect"]})

def rate(rs,k):
    ev=[r for r in rs if r[k] is not None]; c=sum(1 for r in ev if r[k] is True); return c,len(ev)
def l1u(rs): return sum(1 for r in rs if r["l1_prompt"] is True or r["l1_skill"] is True), len(rs)
def report(name,rs):
    print(f"\n[{name}] N={len(rs)}")
    for k in ("l1_prompt","l1_skill","l2_effect"):
        c,e=rate(rs,k); print(f"   {k:10s} {c}/{e} = {100*c/e:.1f}%" if e else f"   {k}: n/a")
    c,n=l1u(rs); print(f"   L1_union   {c}/{n} = {100*c/n:.1f}%")

report("Independent: 66 realized-harm (uniform Claude)", [r for r in recs if r["set"]=="66"])
report("Independent: non-66 attempts (uniform Claude)", [r for r in recs if r["set"]=="non66"])
report("COMBINED: all 225 attack attempts (uniform Claude)", recs)
