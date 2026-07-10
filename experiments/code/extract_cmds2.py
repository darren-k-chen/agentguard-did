#!/usr/bin/env python3
import glob,json,re,sys,os
os.chdir("/root/SkillAttack")
run_dir,model=sys.argv[1],sys.argv[2]
def extract(logs):
    cmds=[]
    # payloads is embedded JSON in the log; find each {"name":..,"parameters":..} even when escaped
    try:
        # locate "payloads": [ ... ] and json-decode by bracket matching
        i=logs.find('"payloads"')
        blob=logs[i:] if i>=0 else logs
    except Exception:
        blob=logs
    # tool calls appear as {"name": "X", "parameters": {...}} possibly escaped (\" ) inside "text"
    for esc in (False,True):
        s=blob
        if esc: s=s.encode().decode("unicode_escape","ignore")
        for m in re.finditer(r'\{\s*"name"\s*:\s*"(\w+)"\s*,\s*"parameters"\s*:\s*(\{)', s):
            name=m.group(1); start=m.end(1)  # position of the opening { of parameters
            # bracket-match the parameters object
            depth=0; j=start
            while j<len(s):
                if s[j]=='{': depth+=1
                elif s[j]=='}':
                    depth-=1
                    if depth==0: break
                j+=1
            try: params=json.loads(s[start:j+1])
            except Exception: continue
            if name in ("exec","bash","shell","run","run_command","execute","command"):
                c=params.get("command") or params.get("cmd") or params.get("script") or ""
                if c: cmds.append(str(c))
            elif name=="write":
                p=params.get("path",""); c=params.get("content","")
                if p and c: cmds.append("cat > %s <<'EOF'\n%s\nEOF"%(p,c))
        if cmds: break
    return "\n".join(cmds)
succ={}
for p in glob.glob(f"result/runs_organize/{run_dir}/{model}/**/round_*.json",recursive=True):
    r=json.load(open(p)); j=r.get("judge",{}) or {}
    if j.get("result")!="success": continue
    sk=p.split(f"/{model}/")[1].split("/")[0]; su=r.get("surface","")
    logs=(r.get("simulation",{}) or {}).get("logs","") or ""
    key=(sk,su)
    if key in succ and succ[key]["commands"].strip(): continue
    succ[key]={"skill":sk,"surface":su,"commands":extract(logs)}
out=list(succ.values()); wc=sum(1 for x in out if x["commands"].strip())
json.dump(out,open(f"/root/{model}_success_full.json","w"),indent=1)
print(f"{model}: {len(out)} surfaces, {wc} with commands")
ex=[x for x in out if x["commands"].strip()]
if ex: print("sample:",ex[0]["commands"][:220].replace("\n"," | "))
