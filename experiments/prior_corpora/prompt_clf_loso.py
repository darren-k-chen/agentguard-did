import json, urllib.request, time, os, random, numpy as np
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, roc_auc_score, recall_score, precision_score
import sys; sys.path.insert(0,"/root/clawguard-openclaw-demo")
from clawguard_judge import judge
t0=time.time(); log=lambda *a:print(f"[{time.time()-t0:4.0f}s]",*a,flush=True)
def rows(ds,split,cap=8000):
    out=[];off=0
    while off<cap:
        u=f"https://datasets-server.huggingface.co/rows?dataset={ds}&config=default&split={split}&offset={off}&length=100"
        try: d=json.loads(urllib.request.urlopen(u,timeout=40).read())
        except Exception: break
        rs=d.get("rows",[]);
        if not rs: break
        out+=[r["row"] for r in rs]; off+=len(rs)
        if len(rs)<100: break
    return out
def load(ds,sps,tk,lk,pos=None):
    rec=[]
    for sp in sps:
        for r in rows(ds,sp):
            t=r.get(tk)
            if t is None: continue
            lv=r.get(lk); y=(1 if (str(lv)==pos or (isinstance(lv,str) and pos in lv.lower())) else 0) if pos else int(lv)
            rec.append({"text":str(t),"label":y})
    return rec
SETS={"deepset":load("deepset/prompt-injections",["train","test"],"text","label"),
      "jackhhao":load("jackhhao/jailbreak-classification",["train","test"],"prompt","type",pos="jailbreak"),
      "xtram":load("xTRam1/safe-guard-prompt-injection",["train","test"],"text","label")}
def vec(tx,fit=None):
    if fit is None:
        w=TfidfVectorizer(lowercase=True,sublinear_tf=True,min_df=2,ngram_range=(1,2),max_features=40000)
        c=TfidfVectorizer(lowercase=True,sublinear_tf=True,min_df=2,analyzer="char_wb",ngram_range=(3,5),max_features=40000)
        return hstack([w.fit_transform(tx),c.fit_transform(tx)]).tocsr(),(w,c)
    w,c=fit; return hstack([w.transform(tx),c.transform(tx)]).tocsr(),fit
def ev(y,p):
    pred=(p>=0.5).astype(int)
    return dict(f1=round(f1_score(y,pred,zero_division=0),3),auc=round(roc_auc_score(y,p),3),
               rec=round(recall_score(y,pred,zero_division=0),3),prec=round(precision_score(y,pred,zero_division=0),3))
print("=== TF-IDF LEAVE-ONE-SOURCE-OUT (train on other 2, test unseen source) ===")
names=list(SETS)
for held in names:
    tr=[r for k in names if k!=held for r in SETS[k]]; te=SETS[held]
    Xtr,fit=vec([r["text"] for r in tr]); ytr=np.array([r["label"] for r in tr])
    Xte,_=vec([r["text"] for r in te],fit); yte=np.array([r["label"] for r in te])
    clf=LogisticRegression(max_iter=2000,class_weight="balanced",C=4.0).fit(Xtr,ytr)
    log(f"  held-out {held:9s} {ev(yte,clf.predict_proba(Xte)[:,1])}")
# LLM judge cross-dataset (balanced sample per set)
print("\n=== LLM JUDGE (Haiku) on each dataset (balanced ~50/50, zero-shot) ===")
key=os.environ["ANTHROPIC_API_KEY"]; random.seed(3)
for k,v in SETS.items():
    mal=[r for r in v if r["label"]==1]; ben=[r for r in v if r["label"]==0]
    random.shuffle(mal); random.shuffle(ben)
    samp=mal[:30]+ben[:30]; random.shuffle(samp)
    tp=fp=tn=fn=0
    for r in samp:
        m=judge(r["text"],api_key=key).get("malicious")
        if m is None: continue
        p=1 if m else 0; y=r["label"]
        tp+=p==1 and y==1; fp+=p==1 and y==0; tn+=p==0 and y==0; fn+=p==0 and y==1
    prec=tp/(tp+fp) if tp+fp else 0; rec=tp/(tp+fn) if tp+fn else 0
    log(f"  judge {k:9s} P={prec:.3f} R={rec:.3f} F1={2*prec*rec/(prec+rec) if prec+rec else 0:.3f} (n={tp+fp+tn+fn})")
