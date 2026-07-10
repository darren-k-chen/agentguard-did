#!/usr/bin/env python3
"""Build the enriched corpus_manifest.csv from the raw pipeline outputs.

Inputs : results/sa_defense.json  (66 attacks, per-method boolean verdicts)
         results/strict_confirm.json ({skill|surface: {claude, gpt}} realized-harm re-annotation)
Output : ../corpus_manifest.csv  (one row per attack; per-method verdicts + level unions +
         full-stack + qwen success label + independent Claude/GPT confirmation labels)
All downstream numbers in the paper are recomputed from this file by reproduce_tables.py.
"""
import json, csv, os

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, "..", "results")
OUT = os.path.join(HERE, "..", "..", "corpus_manifest.csv")

rows = json.load(open(os.path.join(RES, "sa_defense.json")))["rows"]
conf = json.load(open(os.path.join(RES, "strict_confirm.json")))

cols = ["idx", "dataset", "source", "skill", "surface", "risk_type",
        "l1_prompt", "l1_skill", "l2_cmd", "l2_effect", "l3_syscall", "l3_prov",
        "l1_union", "l2_union", "l3_union", "full_stack",
        "qwen_success", "claude_confirmed", "gpt_confirmed", "caught_by"]

with open(OUT, "w", newline="") as f:
    w = csv.writer(f); w.writerow(cols)
    for i, r in enumerate(rows):
        ly = r["layers"]; b = lambda k: int(bool(ly[k]))
        l1u = int(bool(ly["l1_prompt"] or ly["l1_skill"]))
        l2u = int(bool(ly["l2_cmd"] or ly["l2_effect"]))
        l3u = int(bool(ly["l3_syscall"] or ly["l3_prov"]))
        full = int(bool(l1u or l2u or l3u))
        key = r["skill"] + "|" + r["surface"]
        c = conf.get(key, {})
        cc = "" if c.get("claude") is None else int(bool(c.get("claude")))
        gc = "" if c.get("gpt") is None else int(bool(c.get("gpt")))
        w.writerow([i, r["dataset"], r.get("source", ""), r["skill"], r["surface"], r["risk_type"],
                    b("l1_prompt"), b("l1_skill"), b("l2_cmd"), b("l2_effect"), b("l3_syscall"), b("l3_prov"),
                    l1u, l2u, l3u, full, 1, cc, gc, "|".join(r["caught_by"])])
print("wrote", OUT, "with", len(rows), "rows and", len(cols), "columns")
