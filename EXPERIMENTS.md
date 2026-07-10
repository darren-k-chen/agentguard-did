# Reproduction — quick start & modes

**One command recomputes every defense-side number in the paper from the released CSV
(nothing is hard-coded):**
```bash
python experiments/code/reproduce_cached.py   # prints ALL tables (per-method, level-combo,
                                              # per-category, blind-spot, overlap, strict,
                                              # guard matrix, xval kappa) from released files
# (optional) rebuild the manifest from raw pipeline outputs:
python experiments/code/make_manifest.py
```
This reproduces Tables per-method / level-combo / per-category / strict and the
blind-spot and overlap counts directly from `corpus_manifest.csv` (66 rows, per-attack
per-method verdicts + level unions + full-stack + independent Claude/GPT confirmation labels).

**Two reproduction modes.**
- **Mode A — cached (no API keys):** all LLM-judge / guard tables reproduce exactly from the
  released per-call logs (`experiments/results/calls_*.csv`, `verdicts_*.json`) 
  `analyze.py` (which re-aggregates the released `verdicts_*.json` into the κ / agreement and guard-matrix tables); the deterministic runtime results reproduce from
  the released traces and trained model.
- **Mode B — live rerun (API keys required):** rerunning Claude/GPT/Qwen live may produce small
  differences from provider-side model updates and sampling.
- **Mode C — full end-to-end:** regenerating the corpus from scratch needs the external SkillAttack
  repo, the OpenClaw runtime, and Docker; the `pipeline/` scripts are the *as-run* versions (with the
  original box paths) kept for provenance. Use **Mode A** (`reproduce_cached.py`, repo-relative) for portable
  verification of every table.

Integrity: `checksums.txt` lists SHA-256 for `corpus_manifest.csv` and the cross-model logs.

---

# AgentGuard-DiD — Experiments → Code Map, Standards & Reproduction

This document lists **every experiment reported in the paper**, the **code and data**
that produce it, and **how to reproduce** it. It also records a **standards/comparability
audit** so that numbers compared in the paper are measured under one consistent protocol.

Repo layout:
```
main.tex / main_ieee.tex        the paper (single-column + IEEE)
corpus_manifest.csv             the 66-attack corpus, per-method verdicts (release manifest)
experiments/
  code/         reproduce_cached.py (Mode-A: all tables), reproduce_tables.py, make_manifest.py,
                xval_runner.py (judge B1), guardrun.py (guard matrix), analyze.py
  pipeline/     ...clawguard_judge.py (real L1 firewall prompt), l3_replay.py, train_l3_model.py, ...
  pipeline/     SkillAttack-side analysis: l3_replay.py, train_l3_model.py, build_optcompare.py,
                qwen_judge_layers.py, provenance_diff.py, clawguard_behavior_v2.py, playbooks.py, ...
  prior_corpora/ large-corpus grounding scripts (DongTing, L1 generalization, benign) from the
                companion ClawGuard corpus
  results/      sa_*.json (pipeline outputs), verdicts_*.json / calls_*.csv (cross-model runs)
  configs/      models.tierc-gpt.yaml (Tier-C agent = GPT-4o)
  GPU_SERVING.md  exact vLLM/llama.cpp serve commands for the open judges
```

---

## 1. Standards & comparability audit

**One fixed evaluation set.** All defense-layer results (§6.1 per-method, combinations,
per-category, §6.2 blind-spot recovery, §6.3 guard) are scored on the **same 66-attack
corpus** — `experiments/results/sa_defense.json` (66 rows, one boolean per method per attack).
Because every layer/method is evaluated on the identical 66 items, all detection rates and
level unions are **mutually comparable and additive** (the union / combinatorial analysis in
`build_optcompare.py` operates on this single boolean matrix).

**L3 is model-free by construction.** L1 (prompt/skill firewall) and L2 (command/effect
judge) are LLM methods; L3 (system-call classifier + eBPF taint + data provenance) uses **no
LLM**. "Cross-model / guard-model" therefore applies to L1/L2 only; the paper states this
explicitly (§6.3). The L3 classifier's own model comparison is the *DongTing three-family*
agreement (gradient boosting / Transformer / CNN all ≈0.90), a different axis.

**Two guard-model protocols — kept separate, never cross-compared.**
- **Deployed protocol** (main results, Tables `tab:permethod`, `tab:guard`): the full
  `judge_hardened` cascade — Unicode NFKC normalization, a deterministic framing matcher,
  base64 re-screening, and a translation ensemble — with a Claude judge; the attacker-family
  (qwen) guard via `qwen_judge_layers.py`. This is *ClawGuard as deployed*.
- **Uniform protocol** (6-family guard matrix, `guardrun.py`): the **plain firewall SYSTEM
  prompt applied identically** to every guard model (Claude, GPT-4o, qwen, GLM-4.5-Air,
  Nemotron-70B, Qwythos-9B). Because the deterministic hardening is omitted, absolute rates
  are lower than the deployed protocol, but **all six models are measured identically**, so the
  cross-model comparison is valid. The paper reports these two tables under clearly different
  captions and **does not compare their absolute numbers**.

**Label-validation uses a different, stricter question.** The cross-model *judge* study (B1,
§6.4) asks a **stricter** "was harm *actually realized* in the log" question (`GT_SYS` in
`xval_runner.py`) to audit the pipeline's success labels. This is deliberately *not* the same
as the defense-detection question, and its rates are never compared to defense rates.

**Cross-model agent (Tier C) varies one thing.** Only the simulator (agent) model is swapped
(qwen → GPT-4o); attacker, analyzer, and success judge are held fixed (`configs/models.tierc-gpt.yaml`),
so the ASR difference is attributable to the agent alone.

---

## 2. Experiment → code → data → reproduce

| # | Paper item | Code | Data / output | Reproduce |
|---|---|---|---|---|
| §5 | SkillAttack pipeline vs OpenClaw, 171 skills; iterative 21.1→45.1%, Hot100 16%/38.5% | SkillAttack repo `main.py` + `configs/` (reproduced tool, [github.com/Zhow01/SkillAttack](https://github.com/Zhow01/SkillAttack)); `pipeline/playbooks.py` | `result/runs_organize/` | `python main.py main` / `python main.py compare` |
| Table 1 | 66-attack dual taxonomy (realized 6 / skill-intent 8) | `pipeline/playbooks.py` | `results/sa_defense.json` (`risk_type`) | recompute from `sa_defense.json` |
| §5.4 | L1 blind spot (prompt 62.1%, skill 36.4%) | L1 judge (`code/clawguard_judge.py`) | `results/sa_blindspot.json`, `sa_defense.json` | score `l1_prompt`/`l1_skill` over 66 |
| Table `permethod` | 6-method detection; full stack 84.8% | `pipeline/l3_replay.py` (L3), L1/L2 judges | `results/sa_defense.json` | union over the 6 boolean columns |
| Table `levelcombo` (all 2⁶−1 subsets; minimal optimal = 1/level) | **`code/reproduce_cached.py`** (enumerates subsets from the manifest) | `corpus_manifest.csv`; `results/sa_combos.json` | `python experiments/code/reproduce_cached.py` |
| Table `percat` + overlap | per-category detection; only-L1/L2/L3 | (analysis over `sa_defense.json`) | `corpus_manifest.csv` | counts per `risk_type` |
| §6.2 | recover blind spot (18→+8, provenance-unique) | `pipeline/l3_replay.py`, `provenance_diff.py` | `sa_defense.json`, `sa_blindspot.json` | intersect misses with deeper layers |
| Table `guard` | guard model: Claude vs qwen (deployed) | `pipeline/qwen_judge_layers.py` | `results/sa_qwen_layers.json`, `sa_defense.json` | `python pipeline/qwen_judge_layers.py` |
| **Guard matrix (6 families)** | **uniform-protocol L1/L2 across 6 guards** | **`code/guardrun.py`** | **`results/calls_guard_*.csv`, `verdicts_guard_*.json`** | `python code/guardrun.py --models claude,gpt` ; local models via vLLM (see `GPU_SERVING.md`) |
| Table `xval` | 6-family judge / label validation (κ) | `code/xval_runner.py` (`--tier B1`), `code/analyze.py` | `results/verdicts_j*.json`, `calls_*.csv` | `python code/xval_runner.py --tier B1 --models claude,gpt` |
| §6.5 (`eval-agent`) | cross-model agent: GPT-4o 0/100 vs qwen 16/100 | SkillAttack `main.py` + `configs/models.tierc-gpt.yaml` | `results/tierc_full_gpt.log`, `result/runs_organize/main/gpt-4o/` | serve/point simulator to GPT-4o, `python main.py main` |
| §6.6 (`eval-l1`) | L1 generalization: zero-shot 73.9% / 0 FP; TF-IDF LOSO FP 18.3–49% | `prior_corpora/prompt_clf_loso.py`, `save_tfidf.py` | (companion ClawGuard corpus) | `python prior_corpora/prompt_clf_loso.py` |
| §6.7 | DongTing $F_1{=}0.90$ (16,820 traces); 3 families ≈0.90 | `prior_corpora/convert_dongting.py`, `stage1_train.py`, `train_robust.py` | (DongTing dataset, companion corpus) | `python prior_corpora/stage1_train.py` |
| §6.7 | skill-replay L3 model $F_1{=}0.57$ (80/20), 0.60 (group-by-skill); n-grams hurt | `pipeline/train_l3_model.py` | `results/sa_l3_82.json`, `sa_l3_oof.json`, `sa_l3_metrics.json` | `python pipeline/train_l3_model.py` |
| §6.7 | 336-corpus execution: signatures 39.6%, LLM-on-trace 84.4%, union 88.5% | companion ClawGuard corpus scripts | (companion corpus) | see companion repo |
| §6.8 | eBPF read→connect taint; provenance controlled tests | `pipeline/provenance_diff.py`; eBPF `bpftrace` probe (on gateway host) | controlled-test logs | `python pipeline/provenance_diff.py`; run bpftrace probe |
| §6.9 | residual 10/66; holistic judge fails | (holistic-judge analysis) | `results/sa_residual_study.json` | recompute from residual set |
| §6.10 | A/B live agent 12.8→5.3% (McNemar p=0.0009); 1,678-prompt FB 0.2% | `prior_corpora/test_real_benign.py` + companion A/B harness | (companion ClawGuard corpus) | see companion repo |

Legend: items marked *(companion corpus)* use the large public/earlier datasets grounding
the framework (DongTing, the 336-sample execution corpus, and the live-agent A/B). Their
training/eval scripts are included under `prior_corpora/`; the datasets themselves are the
public/earlier ClawGuard artifacts and are cited in the paper rather than re-hosted here.

---

## 3. Reproduction workflow

**A. Attack corpus & defense-in-depth (SkillAttack side).**
1. Reproduce the attack corpus: run the SkillAttack pipeline (`main.py main`) over the 171-skill
   benchmark; outputs land in `result/runs_organize/`. The 66 successful attacks are aggregated
   into `sa_defense.json`.
2. Score defense layers: L1/L2 judges (`clawguard_judge.py`), L3 (`l3_replay.py`).
3. Combinatorial analysis: `build_optcompare.py` → `sa_combos.json` (Tables `levelcombo`, `permethod`).

**B. Cross-model studies (this repo).**
```bash
# judge / label validation (B1) — API judges:
export ANTHROPIC_API_KEY=... OPENAI_API_KEY=...
python experiments/code/xval_runner.py --tier B1 --models claude,gpt --limit 100 --tag b1
# defense guard matrix — uniform protocol, API + self-hosted:
python experiments/code/guardrun.py --models claude,gpt --tag api
XVAL_LOCAL_URL=http://<host>:<port>/v1 XVAL_LOCAL_KEY=<key> XVAL_LOCAL_MODEL=<served-name> \
  python experiments/code/guardrun.py --models local --tag <model>
python experiments/code/analyze.py     # κ / agreement / matrices
```
Self-hosting the open guard/judge models (Qwen3.5-122B, GLM-4.5-Air, Nemotron-70B, Qwythos-9B):
see `experiments/GPU_SERVING.md` for the exact vLLM / llama.cpp commands.

**C. Cross-model agent (Tier C).**
Point the SkillAttack simulator profile at a different model (`configs/models.tierc-gpt.yaml`
sets `simulator_model` → `gpt-4o`, holding attacker/analyzer/judge on qwen) and re-run
`python main.py main`.

**D. Large-corpus grounding (companion).**
DongTing training (`prior_corpora/stage1_train.py`), L1 generalization LOSO
(`prior_corpora/prompt_clf_loso.py`), 336-corpus and A/B — see the companion ClawGuard corpus.

Every cross-model API call is metered: `results/calls_*.csv` records `in_tok,out_tok,cost` per
call; the full cost/token ledger is in `tierc_experiment_log.md`.
