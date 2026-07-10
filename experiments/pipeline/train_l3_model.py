#!/usr/bin/env python3
"""Train a deployment-matched L3 syscall classifier on SkillAttack replay traces.

Features = syscall-name unigram+bigram counts (same 16-syscall vocab for both
classes) + the v2 argument-aware behaviour features. Eval = GroupKFold by skill
(unseen-skill generalization). Also compares the learned model vs the hand-written
signature rule, and checks whether ML catches the CONTENT-level residual.
"""
import re, json, sys, os
from pathlib import Path
import numpy as np
sys.path.insert(0, "/root/SkillAttack/dashboard")
import clawguard_behavior_v2 as cg

ROOT = Path("/root/SkillAttack")
MAL = ROOT/"dashboard/l3_traces"
BEN = ROOT/"dashboard/l3_traces_benign"
MIN_LINES = 60  # skip replay-failed/empty traces

SC_RE = re.compile(r'^(?:\[pid\s+\d+\]\s*|\d+\s+)?(\w+)\(')  # handles "[pid N] sc(" and "N   sc("
def syscalls(text):
    out=[]
    for ln in text.splitlines():
        m=SC_RE.match(ln.strip())
        if m: out.append(m.group(1))
    return out

USE_NGRAMS = os.environ.get("USE_NGRAMS","0")=="1"  # n-grams overfit unseen skills; behaviour features generalize
def featurize(text):
    scs=syscalls(text)
    f={}
    if USE_NGRAMS:
        for s in scs: f["u_"+s]=f.get("u_"+s,0)+1
        for a,b in zip(scs,scs[1:]): f["b_%s_%s"%(a,b)]=f.get("b_%s_%s"%(a,b),0)+1
    beh=cg.Behavior()
    for ln in text.splitlines(): beh.feed(ln)
    for k,v in beh.features().items(): f["bh_"+k]=v
    f["n_syscalls"]=len(scs)
    return f, beh

def load(dirp, label):
    rows=[]
    for tf in sorted(Path(dirp).glob("*.trace")):
        txt=tf.read_text()
        if txt.count("\n")<MIN_LINES: continue
        skill=tf.name.split("__")[0]
        f,beh=featurize(txt)
        rows.append({"skill":skill,"label":label,"feat":f,"beh_risk":beh.risk()[0],"name":tf.name})
    return rows

mal=load(MAL,1); ben=load(BEN,0)
print(f"usable traces: malicious={len(mal)} benign={len(ben)} (min {MIN_LINES} lines)")
rows=mal+ben
if len(mal)<8 or len(ben)<8:
    print("not enough usable traces to train; need more substantial replays."); sys.exit(0)

# vectorize
from sklearn.feature_extraction import DictVectorizer
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import GroupKFold
from sklearn.metrics import f1_score, roc_auc_score, precision_score, recall_score
dv=DictVectorizer(sparse=False)
X=dv.fit_transform([r["feat"] for r in rows])
y=np.array([r["label"] for r in rows])
groups=np.array([r["skill"] for r in rows])
print(f"feature dim: {X.shape[1]}")

# ---- 8:2 stratified held-out split over the 171-skill trace corpus ----
from sklearn.model_selection import train_test_split
Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=0.2,stratify=y,random_state=0)
c82=HistGradientBoostingClassifier(max_iter=300,learning_rate=0.08,max_depth=4,l2_regularization=1.0,random_state=0)
c82.fit(Xtr,ytr); p82=c82.predict_proba(Xte)[:,1]; pr82=(p82>=0.5).astype(int)
print(f"\n==== 8:2 held-out split (train {len(ytr)} / test {len(yte)}) ====")
print(f"  F1={f1_score(yte,pr82):.3f} AUC={roc_auc_score(yte,p82):.3f} "
      f"precision={precision_score(yte,pr82,zero_division=0):.3f} recall={recall_score(yte,pr82):.3f} "
      f"| test mal={int(yte.sum())} ben={int(len(yte)-yte.sum())}")
json.dump({"train":len(ytr),"test":len(yte),"f1":round(f1_score(yte,pr82),3),
           "auc":round(roc_auc_score(yte,p82),3),"precision":round(precision_score(yte,pr82,zero_division=0),3),
           "recall":round(recall_score(yte,pr82),3),"test_mal":int(yte.sum()),"test_ben":int(len(yte)-yte.sum())},
          open(ROOT/"dashboard/sa_l3_82.json","w"),indent=1)

# GroupKFold unseen-skill
gkf=GroupKFold(n_splits=min(5,len(set(groups))))
oof=np.zeros(len(y))
for tr,te in gkf.split(X,y,groups):
    clf=HistGradientBoostingClassifier(max_iter=300,learning_rate=0.08,max_depth=4,
        l2_regularization=1.0,random_state=0)
    clf.fit(X[tr],y[tr]); oof[te]=clf.predict_proba(X[te])[:,1]
pred=(oof>=0.5).astype(int)
print("\n==== GroupKFold (unseen-skill) ====")
print(f"  F1={f1_score(y,pred):.3f} AUC={roc_auc_score(y,oof):.3f} "
      f"precision={precision_score(y,pred):.3f} recall={recall_score(y,pred):.3f}")
# vs hand signature
sig=np.array([1 if r["beh_risk"]>=0.5 else 0 for r in rows])
print(f"  hand-signature: F1={f1_score(y,sig):.3f} recall={recall_score(y,sig):.3f} precision={precision_score(y,sig):.3f}")
# content-residual check: of malicious caught by ML vs signature
mal_idx=[i for i,r in enumerate(rows) if r["label"]==1]
print(f"\n  malicious usable: {len(mal_idx)}")
print(f"  ML recall on malicious: {sum(pred[i]==1 for i in mal_idx)}/{len(mal_idx)}")
print(f"  signature recall on malicious: {sum(sig[i]==1 for i in mal_idx)}/{len(mal_idx)}")
# train final model on all, save
clf=HistGradientBoostingClassifier(max_iter=300,learning_rate=0.08,max_depth=4,l2_regularization=1.0,random_state=0)
clf.fit(X,y)
import joblib
joblib.dump({"model":clf,"dv":dv}, ROOT/"dashboard/l3_syscall_model.joblib")
print("\nsaved -> dashboard/l3_syscall_model.joblib")
metrics_out={
  "n_mal":len(mal_idx),"n_ben":len(rows)-len(mal_idx),
  "signature":{"f1":round(f1_score(y,sig),3),"recall":round(recall_score(y,sig),3),
               "precision":round(precision_score(y,sig,zero_division=0),3),
               "caught_mal":int(sum(sig[i]==1 for i in mal_idx))},
  "ml":{"f1":round(f1_score(y,pred),3),"auc":round(roc_auc_score(y,oof),3),
        "recall":round(recall_score(y,pred),3),"precision":round(precision_score(y,pred,zero_division=0),3),
        "caught_mal":int(sum(pred[i]==1 for i in mal_idx))}}
json.dump(metrics_out, open(ROOT/"dashboard/sa_l3_metrics.json","w"), indent=1)
print("metrics ->", metrics_out)
# save out-of-fold (unseen-skill) predictions keyed by trace name, for honest comparison
oof_out={rows[i]["name"]:{"skill":rows[i]["skill"],"label":int(rows[i]["label"]),
         "oof_prob":round(float(oof[i]),4),"oof_pred":int(oof[i]>=0.5)} for i in range(len(rows))}
json.dump(oof_out, open(ROOT/"dashboard/sa_l3_oof.json","w"), ensure_ascii=False, indent=1)
print("oof saved:",len(oof_out))
