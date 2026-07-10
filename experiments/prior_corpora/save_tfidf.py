import json, joblib
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
REG=json.load(open("/root/clawguard-experiments/data/prompt_datasets_all.json"))
# train on datasets that HAVE benign (balanced), so it learns both classes
train=[]
for d in REG:
    if d["ben"]>50: train+=d["prompts"]
texts=[r["text"] for r in train]; y=[r["label"] for r in train]
print("TF-IDF train on",len(texts),"prompts (mal",sum(y),"ben",len(y)-sum(y),")")
wv=TfidfVectorizer(lowercase=True,sublinear_tf=True,min_df=2,ngram_range=(1,2),max_features=40000)
cv=TfidfVectorizer(lowercase=True,sublinear_tf=True,min_df=2,analyzer="char_wb",ngram_range=(3,5),max_features=40000)
X=hstack([wv.fit_transform(texts),cv.fit_transform(texts)]).tocsr()
clf=LogisticRegression(max_iter=2000,class_weight="balanced",C=4.0).fit(X,y)
import os; os.makedirs("/root/clawguard-experiments/data/models/prompt_tfidf",exist_ok=True)
joblib.dump({"wv":wv,"cv":cv,"clf":clf},"/root/clawguard-experiments/data/models/prompt_tfidf/model.joblib")
print("saved prompt TF-IDF model")
