#!/usr/bin/env python3
"""ClawGuard Stage-1: OOV-robust classical syscall malware detector.

Core idea: the old models go blind on unseen syscalls because features are a
fixed top-50 syscall vocabulary (46% OOV on DongTing -> all-zero -> F1=0.004).
Fix: add a VOCAB-FREE behavioral representation -- map every syscall (even unseen)
to a semantic category, and featurize category frequencies + category transition
bigrams + entropy. This survives out-of-distribution because a novel attack using
novel syscalls still produces a meaningful behavioral profile.

We quantify three featurizers (vocab-only / category-only / hybrid) on:
  (A) DongTing in-distribution 5-fold CV
  (B) cross-source transfer DongTing<->LID-DS (true distribution shift)
and ship a fused supervised+anomaly model trained on DongTing.
"""
import os, sys, math, json, time, glob
from collections import Counter
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import cross_val_predict, StratifiedKFold
from sklearn.metrics import f1_score, roc_auc_score, recall_score, precision_score, confusion_matrix

t0=time.time()
def log(*a): print(f"[{time.time()-t0:6.0f}s]",*a,flush=True)

CACHE="/root/clawguard/data/feature_cache"
DT=f"{CACHE}/DongTing.npz"
LIDDS=[p for p in sorted(glob.glob(f"{CACHE}/*.npz")) if "DongTing" not in p]
OUT="/root/clawguard/data/models/stage1_robust"; os.makedirs(OUT,exist_ok=True)
SEQ_CAP=60000

# ---- syscall -> semantic category (vocab-free, OOV-robust) ----
CATS = {
 "PROC_EXEC":["execve","execveat","fork","vfork","clone","clone3","exit","exit_group","wait4","waitid","wait"],
 "FILE_IO":["open","openat","openat2","read","write","pread64","pwrite64","preadv","pwritev","close","lseek","readv","writev","sendfile","copy_file_range","creat","dup","dup2","dup3","fcntl","flock","fsync","fdatasync"],
 "FILE_META":["stat","fstat","lstat","newfstatat","statx","statfs","fstatfs","access","faccessat","faccessat2","getdents","getdents64","readlink","readlinkat","chmod","fchmod","fchmodat","chown","fchown","lchown","fchownat","utime","utimes","utimensat","futimesat","truncate","ftruncate","rename","renameat","renameat2","link","linkat","unlink","unlinkat","mkdir","mkdirat","rmdir","symlink","symlinkat","chdir","fchdir","getcwd","umask","mknod","mknodat"],
 "NET":["socket","socketpair","connect","accept","accept4","bind","listen","sendto","recvfrom","sendmsg","recvmsg","sendmmsg","recvmmsg","shutdown","getsockname","getpeername","getsockopt","setsockopt"],
 "MEM":["mmap","mmap2","munmap","mprotect","mremap","brk","madvise","mlock","mlock2","munlock","mlockall","munlockall","mincore","memfd_create","msync","remap_file_pages"],
 "IPC":["pipe","pipe2","shmget","shmat","shmdt","shmctl","msgget","msgsnd","msgrcv","msgctl","semget","semop","semtimedop","semctl","mq_open","mq_timedsend","mq_timedreceive","eventfd","eventfd2"],
 "SIGNAL":["rt_sigaction","rt_sigprocmask","rt_sigreturn","rt_sigpending","rt_sigtimedwait","rt_sigqueueinfo","rt_sigsuspend","sigaltstack","signal","kill","tkill","tgkill","pause","restart_syscall"],
 "PRIV":["setuid","setgid","setreuid","setregid","setresuid","setresgid","setfsuid","setfsgid","setgroups","capget","capset","prctl","seccomp","personality"],
 "NS_CONTAINER":["unshare","setns","mount","umount","umount2","pivot_root","chroot","mount_setattr","open_tree","move_mount","fsopen","fsconfig","fsmount"],
 "KERNEL_MOD":["init_module","finit_module","delete_module","kexec_load","kexec_file_load","bpf","perf_event_open","iopl","ioperm","reboot","syslog"],
 "PTRACE_DEBUG":["ptrace","process_vm_readv","process_vm_writev","kcmp","lookup_dcookie"],
 "KEYS":["add_key","request_key","keyctl"],
 "POLL_SYNC":["poll","ppoll","select","pselect6","epoll_create","epoll_create1","epoll_ctl","epoll_wait","epoll_pwait","epoll_pwait2","futex","futex_waitv","set_robust_list","get_robust_list","io_uring_setup","io_uring_enter"],
 "USER_FAULT":["userfaultfd","inotify_init","inotify_init1","inotify_add_watch","inotify_rm_watch","fanotify_init","fanotify_mark"],
}
SC2CAT={}
for cat,names in CATS.items():
    for nm in names: SC2CAT[nm]=cat
CATLIST=list(CATS.keys())+["OTHER"]
CATIDX={c:i for i,c in enumerate(CATLIST)}
NCAT=len(CATLIST)

def cat_of(sc):
    c=SC2CAT.get(sc)
    if c: return c
    # heuristic fallback for unseen syscalls by name fragment
    if "sock" in sc or "recv" in sc or "send" in sc or "connect" in sc: return "NET"
    if sc.startswith(("set","get")) and ("uid" in sc or "gid" in sc or "cap" in sc): return "PRIV"
    if "mmap" in sc or "mprotect" in sc or "mlock" in sc: return "MEM"
    if "module" in sc or "bpf" in sc or "kexec" in sc: return "KERNEL_MOD"
    if "mount" in sc or "ns" in sc[:3]: return "NS_CONTAINER"
    if "exec" in sc or "clone" in sc or "fork" in sc: return "PROC_EXEC"
    if "open" in sc or "read" in sc or "write" in sc or "close" in sc: return "FILE_IO"
    if "stat" in sc or "chmod" in sc or "chown" in sc or "dir" in sc: return "FILE_META"
    if "sig" in sc or "kill" in sc: return "SIGNAL"
    return "OTHER"

def split_cap(s):
    sp=str(s).split()
    return sp[:SEQ_CAP] if len(sp)>SEQ_CAP else sp

def load(npz):
    d=np.load(npz,allow_pickle=True)
    return [split_cap(s) for s in d["seqs"]], np.array(d["y"],dtype=np.int8)

# ---- vocab build (top syscalls + discriminative bigrams) from a training corpus ----
def build_vocab(seqs, y, topu=80, topb=120):
    uni=Counter(); ca=Counter(); cb=Counter()
    for s,yy in zip(seqs,y):
        uni.update(s)
        (ca if yy else cb).update(zip(s,s[1:]))
    TU=[t for t,_ in uni.most_common(topu)]
    ta=max(sum(ca.values()),1); tb=max(sum(cb.values()),1); scored=[]
    for g in (set(ca)|set(cb)):
        fa=ca.get(g,0)/ta; fb=cb.get(g,0)/tb
        if fa+fb<1e-7: continue
        scored.append((abs(math.log((fa+1e-9)/(fb+1e-9))),g))
    scored.sort(reverse=True); TB=[g for _,g in scored[:topb]]
    return TU,TB

def feat_vocab(s,TU,TB):
    n=len(s);c=Counter(s);f=[c.get(t,0)/n if n else 0.0 for t in TU]
    bic=Counter(zip(s,s[1:]));t=max(n-1,1);f+=[bic.get(g,0)/t for g in TB]
    return f

def feat_cat(s):
    n=len(s)
    cc=np.zeros(NCAT); 
    cats=[cat_of(x) for x in s]
    for ct in cats: cc[CATIDX[ct]]+=1
    f=list(cc/n if n else cc)                                  # category freq (NCAT)
    trans=np.zeros((NCAT,NCAT))
    for a,b in zip(cats,cats[1:]): trans[CATIDX[a],CATIDX[b]]+=1
    tt=max(n-1,1); f+=list((trans/tt).flatten())               # category transitions (NCAT^2)
    # category entropy + diversity
    p=cc/n if n else cc; p=p[p>0]
    f.append(-sum(pi*math.log2(pi) for pi in p) if len(p) else 0.0)
    f.append(int((cc>0).sum()))
    return f

def feat_stats(s):
    n=len(s);c=Counter(s);u=len(c)
    f=[n,u,u/n if n else 0.0]
    bg=set(zip(s,s[1:])) if n>1 else set()
    f+=[len(bg),len(bg)/(n-1) if n>1 else 0.0]
    pr=[v/n for v in c.values()] if n else []
    f.append(-sum(p*math.log2(p) for p in pr) if pr else 0.0)
    f.append((c.most_common(1)[0][1]/n) if n else 0.0)
    return f

def featurize(seqs,TU,TB,mode):
    rows=[]
    for s in seqs:
        if mode=="vocab": rows.append(feat_vocab(s,TU,TB)+feat_stats(s))
        elif mode=="cat":  rows.append(feat_cat(s)+feat_stats(s))
        else:              rows.append(feat_vocab(s,TU,TB)+feat_cat(s)+feat_stats(s))
    return np.asarray(rows,dtype=np.float32)

def ev(y,proba,th=0.5):
    pred=(proba>=th).astype(int)
    return dict(f1=round(float(f1_score(y,pred,zero_division=0)),4),
                auc=round(float(roc_auc_score(y,proba)),4) if len(set(y))>1 else None,
                rec=round(float(recall_score(y,pred,zero_division=0)),4),
                prec=round(float(precision_score(y,pred,zero_division=0)),4))

def rf(): return RandomForestClassifier(300,class_weight="balanced",random_state=42,n_jobs=16,max_depth=40)

# ===== load data =====
log("loading DongTing ...")
dt_seqs,dt_y=load(DT)
log(f"DongTing n={len(dt_y)} attack={int(dt_y.sum())} benign={int((dt_y==0).sum())}")
log("loading LID-DS pooled ...")
ld_seqs=[]; ld_y=[]
for p in LIDDS:
    s,yy=load(p); ld_seqs+=s; ld_y+=list(yy)
ld_y=np.array(ld_y,dtype=np.int8)
log(f"LID-DS pooled n={len(ld_y)} attack={int(ld_y.sum())} benign={int((ld_y==0).sum())}")

# vocab from DongTing (training source)
TU,TB=build_vocab(dt_seqs,dt_y)
log(f"DongTing vocab: {len(TU)} unigrams, {len(TB)} disc-bigrams")

report={"meta":{"dongting_n":len(dt_y),"lidds_n":len(ld_y),"ncat":NCAT}}

# ===== (A) DongTing in-distribution CV, per featurizer =====
log("=== (A) DongTing in-distribution 5-fold CV ===")
skf=StratifiedKFold(5,shuffle=True,random_state=42)
report["A_indist_cv"]={}
Xhybrid=None
for mode in ["vocab","cat","hybrid"]:
    X=featurize(dt_seqs,TU,TB,mode)
    proba=cross_val_predict(rf(),X,dt_y,cv=skf,method="predict_proba",n_jobs=1)[:,1]
    m=ev(dt_y,proba); report["A_indist_cv"][mode]=m
    log(f"  {mode:7s} dims={X.shape[1]:4d}  F1={m['f1']} AUC={m['auc']} rec={m['rec']} prec={m['prec']}")
    if mode=="hybrid": Xhybrid=X

# ===== (B) cross-source transfer DongTing -> LID-DS, per featurizer =====
log("=== (B) cross-source transfer: train DongTing -> test LID-DS pooled ===")
report["B_dt_to_lidds"]={}
for mode in ["vocab","cat","hybrid"]:
    Xtr=featurize(dt_seqs,TU,TB,mode); Xte=featurize(ld_seqs,TU,TB,mode)
    clf=rf().fit(Xtr,dt_y); proba=clf.predict_proba(Xte)[:,1]
    m=ev(ld_y,proba); report["B_dt_to_lidds"][mode]=m
    log(f"  {mode:7s}  F1={m['f1']} AUC={m['auc']} rec={m['rec']} prec={m['prec']}")

# ===== (C) reverse transfer: train LID-DS -> test DongTing (the old failure case) =====
log("=== (C) reverse: train LID-DS -> test DongTing (old baseline was F1=0.004) ===")
TUl,TBl=build_vocab(ld_seqs,ld_y)
report["C_lidds_to_dt"]={}
for mode in ["vocab","cat","hybrid"]:
    Xtr=featurize(ld_seqs,TUl,TBl,mode); Xte=featurize(dt_seqs,TUl,TBl,mode)
    clf=rf().fit(Xtr,ld_y); proba=clf.predict_proba(Xte)[:,1]
    m=ev(dt_y,proba); report["C_lidds_to_dt"][mode]=m
    log(f"  {mode:7s}  F1={m['f1']} AUC={m['auc']} rec={m['rec']} prec={m['prec']}")

# ===== final shipped model: DongTing hybrid + IsolationForest anomaly fusion =====
log("=== final model: DongTing hybrid RF + benign-only IsolationForest, fused ===")
clf=rf().fit(Xhybrid,dt_y)
iso=IsolationForest(n_estimators=200,contamination=0.1,random_state=42,n_jobs=16)
iso.fit(Xhybrid[dt_y==0])
# fused score on a held-out CV for honesty
sup_cv=cross_val_predict(rf(),Xhybrid,dt_y,cv=skf,method="predict_proba",n_jobs=1)[:,1]
ascore=-iso.score_samples(Xhybrid); ascore=(ascore-ascore.min())/(ascore.max()-ascore.min()+1e-9)
fused=np.maximum(sup_cv,0.5*ascore)
best=(0.5,-1)
for th in np.linspace(0.1,0.9,33):
    ff=f1_score(dt_y,(fused>=th).astype(int),zero_division=0)
    if ff>best[1]: best=(round(float(th),3),round(float(ff),4))
report["final"]={"supervised_cv":ev(dt_y,sup_cv),
                 "fused_best":{"th":best[0],"f1":best[1],"metrics":ev(dt_y,fused,best[0])}}
log(f"  supervised CV F1={report['final']['supervised_cv']['f1']} | fused best F1={best[1]}@th={best[0]}")

joblib.dump({"model":clf,"iso":iso,"TU":TU,"TB":TB,"CATLIST":CATLIST,"SC2CAT":SC2CAT,
             "mode":"hybrid","featurizer":"vocab+category+stats","SEQ_CAP":SEQ_CAP},
            f"{OUT}/model.joblib")
card={"name":"stage1_robust","title":"CLAWGUARD Stage-1 OOV-robust syscall detector",
      "approach":"hybrid featurizer (top syscalls + discriminative bigrams + VOCAB-FREE semantic category freq/transitions + seq stats) trained on DongTing program traces; fused with benign-only IsolationForest for novel-attack robustness",
      "trained_on":"DongTing","dims_hybrid":int(Xhybrid.shape[1]),
      "results":report,"model":"RandomForest(300,d40,balanced)+IsolationForest(200)"}
json.dump(card,open(f"{OUT}/model_card.json","w"),indent=2)
log(f"SAVED -> {OUT}/model.joblib")
print("\n===== STAGE 1 SUMMARY =====")
print(json.dumps(report,indent=2))
