#!/usr/bin/env python3
"""
Plan-3 robust featurizer: instead of binding to the top-50/60 vocab from a
single dataset, use the FULL syscall vocabulary (every syscall seen across ALL
training data) as unigram features + behavioral stats. This makes the model
react to out-of-distribution attacks that use syscalls outside the old top-50.

Trains on ALL LID-DS-2021 scenarios pooled together (unified robust model).
Output format stays compatible with detector.py via a "vocab" field.
"""
import os, glob, json, math, time
import numpy as np
from collections import Counter
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_predict, StratifiedKFold
from sklearn.metrics import f1_score, roc_auc_score
import joblib

CACHE = "/root/clawguard/data/feature_cache"
SEQ_CAP = 200000
OUT = "/root/clawguard/data/models/lidds2021_robust"
os.makedirs(OUT, exist_ok=True)

t0 = time.time()

# 1) pool all LID-DS scenarios (skip DongTing - keep it as OOD test set)
files = [f for f in sorted(glob.glob(CACHE + "/*.npz"))
         if "DongTing" not in os.path.basename(f)]
print(f"pooling {len(files)} scenario files", flush=True)

all_seqs = []
all_y = []
for f in files:
    d = np.load(f, allow_pickle=True)
    seqs = d["seqs"]; y = [int(x) for x in d["y"]]
    for i in range(len(y)):
        s = str(seqs[i]).split()[:SEQ_CAP]
        all_seqs.append(s); all_y.append(y[i])
    print(f"  {os.path.basename(f)}: {len(y)} ({time.time()-t0:.0f}s)", flush=True)
    del d
y = np.array(all_y, dtype=np.int8)
print(f"total recordings: {len(all_seqs)} | normal {int((y==0).sum())} attack {int(y.sum())}", flush=True)

# 2) build FULL vocab (every syscall seen) - not just top-50
vocab_counter = Counter()
for s in all_seqs:
    vocab_counter.update(set(s))   # presence-based to bound work
VOCAB = sorted(vocab_counter.keys())
vidx = {sc: i for i, sc in enumerate(VOCAB)}
print(f"FULL vocab size: {len(VOCAB)} (vs old top-50)", flush=True)

# 3) featurize: full-vocab unigram freq + behavioral stats
NSTAT = 7
def feat(seq):
    n = len(seq); c = Counter(seq)
    v = np.zeros(len(VOCAB) + NSTAT, dtype=np.float32)
    if n:
        for sc, ct in c.items():
            j = vidx.get(sc)
            if j is not None:
                v[j] = ct / n
    uniq = len(c)
    bg = set(zip(seq, seq[1:])) if n > 1 else set()
    probs = [ct / n for ct in c.values()] if n else []
    ent = -sum(p * math.log2(p) for p in probs) if probs else 0.0
    base = len(VOCAB)
    v[base+0] = n
    v[base+1] = uniq
    v[base+2] = uniq / n if n else 0.0
    v[base+3] = len(bg)
    v[base+4] = len(bg) / (n - 1) if n > 1 else 0.0
    v[base+5] = ent
    v[base+6] = (c.most_common(1)[0][1] / n) if n else 0.0
    return v

print("featurizing...", flush=True)
X = np.array([feat(s) for s in all_seqs], dtype=np.float32)
print(f"X shape {X.shape} ({time.time()-t0:.0f}s)", flush=True)

# 4) train + 5-fold CV
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv = RandomForestClassifier(300, class_weight="balanced", random_state=42, n_jobs=4, max_depth=40)
print("cross-val...", flush=True)
proba = cross_val_predict(cv, X, y, cv=skf, method="predict_proba", n_jobs=4)[:, 1]
pred = (proba >= 0.5).astype(int)
f1 = f1_score(y, pred); auc = roc_auc_score(y, proba)
print(f"CV F1={f1:.4f} AUC={auc:.4f} ({time.time()-t0:.0f}s)", flush=True)

clf = RandomForestClassifier(300, class_weight="balanced", random_state=42, n_jobs=4, max_depth=40)
clf.fit(X, y)

feat_names = [f"sc::{s}" for s in VOCAB] + ["len","uniq","uniq_ratio","bigram_uniq","bigram_ratio","entropy","top1_ratio"]
joblib.dump({
    "model": clf,
    "vocab": VOCAB,                 # <-- full-vocab mode marker for detector
    "top_uni": VOCAB,               # back-compat: detector treats vocab as top_uni
    "top_bi": [],                   # no bigram vocab in robust mode
    "feat_names": feat_names,
    "robust": True,
    "key": "lidds2021_robust",
    "trained_n": int(len(y)),
    "cv_f1": float(f1),
    "cv_auc": float(auc),
}, OUT + "/model.joblib")

json.dump({
    "key": "lidds2021_robust", "scenario": "lidds2021_robust",
    "dataset": "LID-DS-2021 (pooled, full-vocab)",
    "trained_recordings": int(len(y)),
    "normal": int((y==0).sum()), "attack": int(y.sum()),
    "features": int(X.shape[1]), "vocab_size": len(VOCAB),
    "cv_f1": float(f1), "cv_auc": float(auc),
    "model": "RandomForest(300,max_depth=40,balanced) full-vocab"
}, open(OUT + "/model_card.json", "w"), indent=2)
print(f"DONE saved {OUT}/model.joblib | F1={f1:.4f} AUC={auc:.4f}", flush=True)
