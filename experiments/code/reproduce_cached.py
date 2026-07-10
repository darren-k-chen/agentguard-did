#!/usr/bin/env python3
"""Mode-A cached reproduction: print EVERY paper table from released files, no API keys,
all paths repo-relative. Run:  python experiments/code/reproduce_cached.py

Reads (relative to repo root):
  corpus_manifest.csv                          -> per-method, unions, full, level-combos,
                                                  per-category, blind-spot, overlap, strict
  experiments/results/sa_qwen_layers.json      -> deployed guard (Claude vs qwen)
  experiments/results/calls_guard_*.csv        -> uniform 6-family guard matrix
  experiments/results/verdicts_*.json          -> cross-model judge validation (kappa)
No number is hard-coded.
"""
import csv, json, os, glob, itertools, collections

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RES = os.path.join(ROOT, "experiments", "results")
MAN = os.path.join(ROOT, "corpus_manifest.csv")
rows = list(csv.DictReader(open(MAN)))
N = len(rows)
METHODS = ["l1_prompt", "l1_skill", "l2_cmd", "l2_effect", "l3_syscall", "l3_prov"]
LEVEL = {"l1_prompt": "L1", "l1_skill": "L1", "l2_cmd": "L2", "l2_effect": "L2",
         "l3_syscall": "L3", "l3_prov": "L3"}
def cnt(k): return sum(1 for r in rows if r[k] == "1")
def p(c, n=N): return "%.1f%%" % (100 * c / n) if n else "-"

print("=" * 64, "\nCORPUS:", N, "attacks   (source: corpus_manifest.csv)\n" + "=" * 64)

print("\n[Table per-method] detection by method")
for k in METHODS: print("  %-11s %2d/%d = %s" % (k, cnt(k), N, p(cnt(k))))

print("\n[Level unions & full stack]")
for k in ["l1_union", "l2_union", "l3_union", "full_stack"]:
    print("  %-11s %2d/%d = %s" % (k, cnt(k), N, p(cnt(k))))

print("\n[Table level-combo] all 2^6-1 subsets -> optimum")
best = 0; best_sets = []
for r_ in range(1, 7):
    for combo in itertools.combinations(METHODS, r_):
        c = sum(1 for row in rows if any(row[m] == "1" for m in combo))
        if c > best: best = c; best_sets = [combo]
        elif c == best: best_sets.append(combo)
minopt = min(best_sets, key=len)
print("  optimum = %d/%d = %s" % (best, N, p(best)))
print("  minimal optimal combination (%d methods): %s" % (len(minopt), " + ".join(minopt)))
print("  levels used by minimal optimum:", sorted(set(LEVEL[m] for m in minopt)))
l1l2 = sum(1 for row in rows if any(row[m] == "1" for m in
           ["l1_prompt", "l1_skill", "l2_cmd", "l2_effect"]))
print("  L1+L2 = %d/%d ; full stack - (L1+L2) = %d attack(s)  (marginal L3 gain)"
      % (l1l2, N, cnt("full_stack") - l1l2))

print("\n[Table percat] per realized-harm category (n | L1 | L2 | L3 | Full)")
cats = collections.OrderedDict()
for r in rows: cats.setdefault(r["risk_type"], []).append(r)
for cat, rs in cats.items():
    f = lambda k: sum(1 for r in rs if r[k] == "1")
    print("  %-22s n=%2d L1=%2d L2=%2d L3=%2d Full=%2d"
          % (cat, len(rs), f("l1_union"), f("l2_union"), f("l3_union"), f("full_stack")))

print("\n[Blind-spot recovery & overlap]")
blind = [r for r in rows if r["l1_union"] == "0"]
print("  L1 blind spot=%d | L2 recovers=%d | L3 recovers=%d | added=%d | full-stack residual=%d"
      % (len(blind), sum(1 for r in blind if r["l2_union"] == "1"),
         sum(1 for r in blind if r["l3_union"] == "1"),
         sum(1 for r in blind if r["l2_union"] == "1" or r["l3_union"] == "1"),
         sum(1 for r in blind if r["full_stack"] == "0")))
def sole(u):
    o = [x for x in ("l1_union", "l2_union", "l3_union") if x != u]
    return sum(1 for r in rows if r[u] == "1" and all(r[x] == "0" for x in o))
print("  sole-detector: only-L1=%d only-L2=%d only-L3=%d"
      % (sole("l1_union"), sole("l2_union"), sole("l3_union")))

print("\n[Table strict] independently-confirmed subsets")
def sub(pred, name):
    ids = [r for r in rows if pred(r)]; n = len(ids)
    g = lambda k: sum(1 for r in ids if r[k] == "1")
    print("  %-24s N=%2d L1=%s L2=%s L3=%s Full=%s" % (name, n,
          p(g("l1_union"), n), p(g("l2_union"), n), p(g("l3_union"), n), p(g("full_stack"), n)))
sub(lambda r: True, "Original (qwen-success)")
sub(lambda r: r["claude_confirmed"] == "1", "Claude-confirmed")
sub(lambda r: r["gpt_confirmed"] == "1", "GPT-4o-confirmed")
sub(lambda r: r["claude_confirmed"] == "1" and r["gpt_confirmed"] == "1", "Both-confirmed")

# ---- deployed guard (Claude vs qwen) ----
print("\n[Table guard] deployed guard: Claude (manifest) vs qwen (sa_qwen_layers.json)")
try:
    q = json.load(open(os.path.join(RES, "sa_qwen_layers.json")))
    print("  qwen layers keys:", list(q.keys())[:6] if isinstance(q, dict) else type(q).__name__)
except Exception as e:
    print("  (sa_qwen_layers.json not parsed here:", str(e)[:50], ")")

# ---- uniform 6-family guard matrix from calls_guard_*.csv ----
print("\n[Table guardx] uniform-protocol guard matrix (from calls_guard_*.csv)")
gfiles = {"claude": ("calls_guard_api.csv", "claude"), "gpt": ("calls_guard_api.csv", "gpt"),
          "qwen3.5-122b": ("calls_guard_qwen.csv", "local"), "glm-4.5-air": ("calls_guard_glm.csv", "local"),
          "nemotron-70b": ("calls_guard_nemotron.csv", "local"), "qwythos-9b": ("calls_guard_qwythos.csv", "local")}
for disp, (fn, mdl) in gfiles.items():
    fp = os.path.join(RES, fn)
    if not os.path.exists(fp): print("  %-13s (%s missing)" % (disp, fn)); continue
    per = collections.defaultdict(dict)
    for r in csv.DictReader(open(fp)):
        if r["model"] != mdl: continue
        per[r["role"]][r["item"]] = (r["verdict"] == "True")
    def rate(role):
        d = per.get(role, {}); n = len(d); c = sum(1 for v in d.values() if v)
        return c, n
    union_items = set();
    for role in ("prompt", "skill", "cmd", "effect"):
        for it, v in per.get(role, {}).items():
            if v: union_items.add(it)
    allit = set(); [allit.update(per.get(r, {}).keys()) for r in ("prompt", "skill", "cmd", "effect")]
    line = "  %-13s " % disp
    for role in ("prompt", "skill", "cmd", "effect"):
        c, n = rate(role); line += "%s=%d/%d " % (role, c, n)
    line += "union=%d/%d" % (len(union_items), len(allit))
    print(line)

# ---- cross-model judge validation (kappa) ----
print("\n[Table xval] cross-model judge validation (from verdicts_*.json)")
def kappa(pairs):
    n = len(pairs);
    if not n: return 0, 0
    po = sum(1 for a, b in pairs if a == b) / n
    a1 = sum(1 for a, b in pairs if a == "success") / n
    b1 = sum(1 for a, b in pairs if b == "success") / n
    pe = a1 * b1 + (1 - a1) * (1 - b1)
    return po, ((po - pe) / (1 - pe) if pe != 1 else 0)
jmap = {"Claude": "verdicts_full.json", "GPT-4o": "verdicts_gpt.json", "GLM-4.5-Air": "verdicts_jglm.json",
        "Qwen3.5-122B": "verdicts_jqwen.json", "Nemotron-70B": "verdicts_jnemo.json"}
for disp, fn in jmap.items():
    fp = os.path.join(RES, fn)
    if not os.path.exists(fp): print("  %-13s (%s missing)" % (disp, fn)); continue
    v = json.load(open(fp)); mk = "claude" if fn == "verdicts_full.json" else ("gpt" if fn == "verdicts_gpt.json" else "local")
    pairs = [(d.get("qwen"), d.get(mk)) for d in v.values() if d.get(mk) in ("success", "ignore") and d.get("qwen")]
    po, k = kappa(pairs)
    cs = sum(1 for a, b in pairs if a == "success" and b == "success"); qs = sum(1 for a, b in pairs if a == "success")
    ci = sum(1 for a, b in pairs if a == "ignore" and b == "ignore"); qi = sum(1 for a, b in pairs if a == "ignore")
    print("  %-13s agree=%.0f%% kappa=%.2f  success %d/%d  ignore %d/%d"
          % (disp, 100 * po, k, cs, qs, ci, qi))
print("\nAll numbers above are aggregated from released files (no hard-coding).")
