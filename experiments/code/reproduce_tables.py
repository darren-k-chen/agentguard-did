#!/usr/bin/env python3
"""Recompute EVERY defense-side number in the paper from corpus_manifest.csv.

No number is hard-coded: each figure below is aggregated from the released per-attack
CSV. Run `python experiments/code/reproduce_tables.py` and compare to the manuscript.
(The cross-model guard/judge tables are recomputed by analyze.py / guardrun.py from the
released calls_*.csv / verdicts_*.json logs; see EXPERIMENTS.md.)
"""
import csv, os, collections

HERE = os.path.dirname(os.path.abspath(__file__))
M = os.path.join(HERE, "..", "..", "corpus_manifest.csv")
rows = list(csv.DictReader(open(M)))
N = len(rows)
def col(k): return [r for r in rows if r[k] == "1"]
def pct(c): return "%.1f%%" % (100 * c / N)

print("corpus:", N, "attacks\n")
print("== Table: per-method detection ==")
for k in ["l1_prompt", "l1_skill", "l2_cmd", "l2_effect", "l3_syscall", "l3_prov"]:
    c = len(col(k)); print("  %-11s %2d/%d = %s" % (k, c, N, pct(c)))

print("\n== Level unions & full stack ==")
for k in ["l1_union", "l2_union", "l3_union", "full_stack"]:
    c = len(col(k)); print("  %-11s %2d/%d = %s" % (k, c, N, pct(c)))

print("\n== Per-category (n | L1 | L2 | L3 | Full) ==")
cats = collections.OrderedDict()
for r in rows: cats.setdefault(r["risk_type"], []).append(r)
for cat, rs in cats.items():
    f = lambda k: sum(1 for r in rs if r[k] == "1")
    print("  %-22s n=%2d  L1=%2d L2=%2d L3=%2d Full=%2d" %
          (cat, len(rs), f("l1_union"), f("l2_union"), f("l3_union"), f("full_stack")))

print("\n== Blind-spot recovery ==")
blind = [r for r in rows if r["l1_union"] == "0"]
byL2 = sum(1 for r in blind if r["l2_union"] == "1")
byL3 = sum(1 for r in blind if r["l3_union"] == "1")
added = sum(1 for r in blind if r["l2_union"] == "1" or r["l3_union"] == "1")
resid = sum(1 for r in blind if r["full_stack"] == "0")
print("  L1 blind spot: %d | recovered by L2: %d | by L3: %d | added: %d | full-stack residual: %d"
      % (len(blind), byL2, byL3, added, resid))

print("\n== Overlap (sole-detector) ==")
def sole(u):
    others = [x for x in ("l1_union", "l2_union", "l3_union") if x != u]
    return sum(1 for r in rows if r[u] == "1" and all(r[o] == "0" for o in others))
print("  only-L1: %d | only-L2: %d | only-L3: %d" % (sole("l1_union"), sole("l2_union"), sole("l3_union")))

print("\n== Strict independently-confirmed subsets (full stack) ==")
def sub(pred):
    ids = [r for r in rows if pred(r)]
    n = len(ids); f = sum(1 for r in ids if r["full_stack"] == "1")
    l1 = sum(1 for r in ids if r["l1_union"] == "1"); l2 = sum(1 for r in ids if r["l2_union"] == "1")
    l3 = sum(1 for r in ids if r["l3_union"] == "1")
    print("  %-24s N=%2d  L1=%s L2=%s L3=%s Full=%s" %
          (getattr(pred, "label", "?"), n,
           pct2(l1, n), pct2(l2, n), pct2(l3, n), pct2(f, n)))
def pct2(c, n): return "%.1f%%" % (100 * c / n) if n else "-"
def lbl(fn, s): fn.label = s; return fn
sub(lbl(lambda r: True, "Original (qwen-success)"))
sub(lbl(lambda r: r["claude_confirmed"] == "1", "Claude-confirmed"))
sub(lbl(lambda r: r["gpt_confirmed"] == "1", "GPT-4o-confirmed"))
sub(lbl(lambda r: r["claude_confirmed"] == "1" and r["gpt_confirmed"] == "1", "Both-confirmed (strict)"))
