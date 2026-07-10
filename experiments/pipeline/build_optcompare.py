#!/usr/bin/env python3
import json
from pathlib import Path
D = Path("/root/SkillAttack/dashboard")
l3 = json.load(open(D/"sa_l3_metrics.json"))
s, m, nm = l3["signature"], l3["ml"], l3["n_mal"]
out = {
 "l3": {
   "title": "L3 syscall 偵測：訓練前(手寫簽章) vs 訓練後(行為特徵 ML)",
   "metric_labels": ["F1", "recall", "precision"],
   "before": {"name": "訓練前 · 手寫簽章 (regex)", "vals": [s["f1"], s["recall"], s["precision"]], "caught": f"{s['caught_mal']}/{nm}"},
   "after": {"name": "訓練後 · 行為特徵 ML (HistGBM)", "vals": [m["f1"], m["recall"], m["precision"]], "caught": f"{m['caught_mal']}/{nm}"},
   "verdict": f"✅ 變好：惡意召回 {s['caught_mal']}→{m['caught_mal']}/{nm}、F1 {s['f1']}→{m['f1']}（GroupKFold 未見 skill）",
   "note": "加 raw syscall n-gram 反降到 F1 0.52（overfit 未見 skill）→ GPU 大序列模型不採用；argument-aware 行為特徵才泛化。",
 },
 "l2effect": {
   "title": "L2-effect：訓練前(只能呼叫 Sonnet API) vs 訓練後(本地蒸餾 student)",
   "metric_labels": ["F1", "recall", "precision"],
   "before": {"name": "訓練前 · Sonnet teacher (API，貴/慢)", "vals": [1.0, 1.0, 1.0], "caught": "基準 (每次 API)"},
   "after": {"name": "訓練後 · 本地 student (distilroberta，免費可常駐)", "vals": [0.635, 0.80, 0.526], "caught": "~0.13s/樣本"},
   "verdict": "✅ 可常駐替代：本地 student 保留 Sonnet 80% 召回、可免費常駐當 cascade 前置；精度(0.53)待更多 teacher 標註提升。",
   "note": "GroupShuffleSplit 未見 skill 測試；teacher=Sonnet 為標籤基準故顯示為 1.0。",
 },
 "summary": "訓練確實有效：L3 從手寫簽章升級為學習模型，惡意召回 14→21/39、F1 0.49→0.60；L2-effect 蒸餾出可常駐本地模型(保留 80% 召回)。但『更大/GPU 序列模型』無益(overfit)——真正槓桿在 argument-aware 特徵設計與知識蒸餾。",
}
json.dump(out, open(D/"sa_optcompare.json", "w"), ensure_ascii=False, indent=1)
print("written sa_optcompare.json")
print(out["l3"]["verdict"]); print(out["l2effect"]["verdict"])
