# Cross-Model Validation & Tier-C experiments (AgentGuard-DiD)

Code and results for the reviewer-requested cross-model validation of the
AgentGuard-DiD paper. Everything here is metered (exact API token usage read from
each response) and reproducible. Intended for open-source release.

## Layout
```
code/
  xval_runner.py     metered multi-provider judge runner (anthropic/openai/google/local-vLLM)
  analyze.py         Cohen's κ, agreement, guard matrix over the verdicts
configs/
  models.tierc-gpt.yaml   SkillAttack model profiles with simulator(agent)=gpt-4o (Tier-C)
results/
  verdicts_*.json    per-item judge verdicts (qwen label vs each judge)
  calls_*.csv        every API call: ts,tier,model,role,item,in_tok,out_tok,cost_usd,verdict
  *.log              run summaries (cost totals) + Tier-C GPT-agent run log
GPU_SERVING.md       exact vast.ai vLLM/llama.cpp serve commands for the open judges
```
(The per-attack manifest lives at the repo root: `../corpus_manifest.csv`.)

## Experiments
**B1 — success-label re-annotation.** Re-judge a balanced 100-attempt sample
(50 qwen-`success` + 50 qwen-`ignore` rounds) under a strict "harm actually realized
in the log" bar, with judges from 6 model families. Result: three well-calibrated
independent judges (Claude κ=0.60, GPT-4o κ=0.36, GLM-4.5-Air κ=0.30) confirm only
34–62 % of `success` labels but 96–98 % of `ignore`; the **same-family** Qwen3.5-122B
confirms the *fewest* (κ=0.12) — refuting a same-model-inflation account — and
Nemotron-70B over-flags everything (κ≈0). Conclusion: `success` labeling is permissive
and judge-variable, not same-model-biased; refusals are robust.

**B2 — guard matrix.** The 4 LLM defense methods (prompt/skill/cmd/effect) re-scored
across model families over the 66-attack corpus (relative cross-model comparison).

**Tier-C — cross-model agent.** Re-run the SkillAttack pipeline with the *agent*
(simulator) swapped to GPT-4o while attacker/analyzer/judge stay qwen, to test whether
a different agent family is more attack-resistant. (`configs/models.tierc-gpt.yaml`.)

## Reproduce
```bash
# API judges (Claude, GPT):
export ANTHROPIC_API_KEY=... OPENAI_API_KEY=...
python code/xval_runner.py --tier B1,B2 --models claude,gpt --limit 100 --tag run

# self-hosted judge (any OpenAI-compatible endpoint, e.g. vLLM — see GPU_SERVING.md):
export XVAL_LOCAL_URL=http://<host>:<port>/v1 XVAL_LOCAL_KEY=<key> XVAL_LOCAL_MODEL=<served-name>
python code/xval_runner.py --tier B1 --models local --limit 100 --tag run_local

python code/analyze.py     # prints κ / agreement / guard matrix
```
Data source (round-level judge labels + execution logs) is the SkillAttack `result/`
tree on the pipeline host; loaders in `xval_runner.py` (`load_b1`, `surface_logs_map`).

## Cost (this study)
API judges (Claude + GPT-4o): **≈ $5.45** total, exact per-call breakdown in `calls_*.csv`
in `calls_*.csv`. All self-hosted judges (Qwen/GLM/Nemotron/Qwythos): **$0**
compute beyond the vast.ai GPU rental.
