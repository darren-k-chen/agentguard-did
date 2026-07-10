#!/usr/bin/env python3
"""Replay benign (ignore-verdict) command sets under the same strace sandbox to
build the BENIGN class for training an L3 syscall model. Full syscall trace
(-e trace=all-ish) so the sequence model sees the real execution."""
import os, sys, json, subprocess, tempfile
from pathlib import Path
ROOT = Path("/root/SkillAttack")
IMAGE = "skillrt-l3:latest"
# MUST match the malicious l3_traces syscall set exactly (else the model learns
# a vocabulary artifact instead of real behaviour signal)
TRACE = ("execve,execveat,openat,open,connect,socket,dup2,unlink,unlinkat,"
         "rename,renameat,renameat2,ftruncate,truncate,chmod,fchmodat")
items = json.load(open(ROOT/"dashboard/sa_benign_cmds.json"))
tdir = ROOT/"dashboard/l3_traces_benign"; tdir.mkdir(exist_ok=True)
SEED = (ROOT/"dashboard/l3_seed.sh")

def run_one(rec):
    cname="cg_bn_"+str(abs(hash((rec["skill"],rec["surface"])))%10**8)
    subprocess.run(["docker","rm","-f",cname],capture_output=True)
    subprocess.run(["docker","run","-d","--name",cname,"--network","none","--cap-drop","ALL",
                    "--cap-add","SYS_PTRACE","--security-opt","no-new-privileges","--pids-limit","256",
                    "--memory","512m",IMAGE,"sleep","200"],capture_output=True)
    try:
        subprocess.run(["docker","exec",cname,"bash","-lc",
            "mkdir -p /root/.openclaw/workspace/scripts /root/.openclaw/workspace/memory/ontology; "
            "cd /root/.openclaw/workspace; "
            "{ echo BEGIN:VCALENDAR; for i in 1 2 3 4 5; do echo BEGIN:VEVENT; echo UID:e$i; echo END:VEVENT; done; echo END:VCALENDAR; } > calendar.ics; "
            "for i in 1 2 3; do cp calendar.ics event_$i.ics; printf 'a,b\\n1,2\\n' > report_$i.csv; done; "
            "printf '{}' > memory/ontology/graph.jsonl; printf 'PKdummy' > Q4_financial_report.pptx; true"],
            capture_output=True)
        script="cd /root/.openclaw/workspace\n"+(rec["commands"] or "echo nocmd")+"\n"
        with tempfile.NamedTemporaryFile("w",suffix=".sh",delete=False) as tf: tf.write(script); sp=tf.name
        subprocess.run(["docker","cp",sp,f"{cname}:/cmds.sh"],capture_output=True); os.unlink(sp)
        subprocess.run(["docker","exec",cname,"bash","-lc",
            f"timeout 45 strace -f -qq -e trace={TRACE} -o /trace.log bash /cmds.sh >/dev/null 2>&1; true"],
            capture_output=True,timeout=80)
        tr=subprocess.run(["docker","exec",cname,"bash","-lc","cat /trace.log 2>/dev/null | head -c 3000000"],
                          capture_output=True,text=True)
        return tr.stdout or ""
    except subprocess.TimeoutExpired: return ""
    finally: subprocess.run(["docker","rm","-f",cname],capture_output=True)

ok=0
for i,rec in enumerate(items,1):
    tr=run_one(rec)
    safe=(rec["skill"]+"__"+rec["surface"]).replace("/","_")[:120]
    (tdir/(safe+".trace")).write_text(tr)
    if tr.count("\n")>50: ok+=1
    print(f"[{i}/{len(items)}] {rec['skill'][:34]:34s} lines={tr.count(chr(10))}",flush=True)
print(f"\nbenign traces: {len(items)} ({ok} substantial) -> {tdir}")
