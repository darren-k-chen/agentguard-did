import sys,glob,re
sys.path.insert(0,"/root/clawguard-experiments/scripts"); sys.path.insert(0,"/root/clawguard-experiments/demo")
from pathlib import Path
from collect_deploy_traces import extract_code, trace_in_docker, EXEC_PAT
import clawguard_infer as CI
CI.MODELS["classical"]="/root/clawguard-experiments/data/models/deploy_v1/model.joblib"
det=CI.Detector("classical")
# real govbench BENIGN skills that have runnable code (held-out, NOT in training)
cands=[]
for f in sorted(glob.glob("/root/clawguard-experiments/data/collected/benign/*.md")):
    c,lang=extract_code(Path(f).read_text(errors="replace"))
    if c and EXEC_PAT.search(c): cands.append((Path(f).stem,lang,c))
print("real benign govbench skills with code:",len(cands))
flagged=0
for n,lang,c in cands[:12]:
    seq=trace_in_docker(c,lang); p=det.score(seq)
    fp = p>=0.5
    flagged+=fp
    print("  %-34s %-6s n=%4d prob=%.3f %s"%(n[:34],lang,len(seq),p,"FALSE-POS" if fp else "ok"))
print("FALSE-POSITIVE rate on real benign skills: %d/%d"%(flagged,min(12,len(cands))))
