#!/usr/bin/env python3
"""Distill the L2-effect judge (claude-sonnet-4-6 teacher) into a resident local
distilroberta student. Text = COMMANDS+OUTPUT; label = teacher's malicious verdict.
Eval = GroupShuffleSplit by SKILL (test skills unseen in training)."""
import csv, json, time, numpy as np, torch
from torch.utils.data import DataLoader, Dataset
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import f1_score, recall_score, precision_score, roc_auc_score
from transformers import AutoTokenizer, AutoModelForSequenceClassification
torch.manual_seed(0); np.random.seed(0)
dev="cuda" if torch.cuda.is_available() else "cpu"
rows=list(csv.DictReader(open("/root/l2_distill_data.csv")))
texts=[r["text"] for r in rows]; y=np.array([int(r["label"]) for r in rows]); groups=[r["skill"] for r in rows]
tok=AutoTokenizer.from_pretrained("distilroberta-base")
gss=GroupShuffleSplit(n_splits=1,test_size=0.2,random_state=0)
tr,te=next(gss.split(texts,y,groups))
print(f"train={len(tr)} test={len(te)} | test pos={int(y[te].sum())}/{len(te)} | unseen-skill split",flush=True)
class DS(Dataset):
    def __init__(s,idx): s.idx=idx
    def __len__(s): return len(s.idx)
    def __getitem__(s,i):
        j=s.idx[i]; enc=tok(texts[j],truncation=True,max_length=384,padding="max_length",return_tensors="pt")
        return {k:v.squeeze(0) for k,v in enc.items()}, torch.tensor(y[j])
model=AutoModelForSequenceClassification.from_pretrained("distilroberta-base",num_labels=2).to(dev)
posw=torch.tensor([1.0, float((y[tr]==0).sum())/max(1,(y[tr]==1).sum())],dtype=torch.float32).to(dev)
opt=torch.optim.AdamW(model.parameters(),lr=2e-5)
lossf=torch.nn.CrossEntropyLoss(weight=posw)
dl=DataLoader(DS(tr),batch_size=8,shuffle=True)
for ep in range(4):
    model.train(); tot=0
    for enc,lab in dl:
        enc={k:v.to(dev) for k,v in enc.items()}; lab=lab.to(dev)
        opt.zero_grad(); out=model(**enc).logits; loss=lossf(out,lab); loss.backward(); opt.step(); tot+=loss.item()
    print(f"epoch {ep+1} loss={tot/len(dl):.3f}",flush=True)
# eval on unseen-skill test
model.eval(); preds=[]; probs=[]
with torch.no_grad():
    for enc,lab in DataLoader(DS(te),batch_size=16):
        enc={k:v.to(dev) for k,v in enc.items()}
        p=torch.softmax(model(**enc).logits,-1)[:,1].cpu().numpy(); probs+=list(p); preds+=list((p>0.5).astype(int))
yt=y[te]; preds=np.array(preds); probs=np.array(probs)
f1=f1_score(yt,preds,zero_division=0); rec=recall_score(yt,preds,zero_division=0); pre=precision_score(yt,preds,zero_division=0)
auc=roc_auc_score(yt,probs) if len(set(yt))>1 else float("nan")
print(f"\n==== L2-effect student (distilroberta, unseen-skill GroupShuffleSplit) ====")
print(f"  F1={f1:.3f} recall={rec:.3f} precision={pre:.3f} AUC={auc:.3f}  (n_test={len(te)}, pos={int(yt.sum())})")
json.dump({"model":"distilroberta-base","teacher":"claude-sonnet-4-6","protocol":"GroupShuffleSplit unseen-skill",
           "n_total":len(rows),"n_pos":int(y.sum()),"n_test":len(te),"f1":round(f1,3),"recall":round(rec,3),
           "precision":round(pre,3),"auc":round(float(auc),3)}, open("/root/l2_student_metrics.json","w"),indent=1)
model.save_pretrained("/root/l2_effect_student"); tok.save_pretrained("/root/l2_effect_student")
print("saved model -> /root/l2_effect_student ; metrics -> /root/l2_student_metrics.json")
