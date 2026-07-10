# AgentGuard-DiD

Runtime defense-in-depth against benign-looking agent-skill attacks. This repository
contains the evaluation code, the released result logs, and the trained runtime model
needed to reproduce the defense-side numbers of the paper.

## What is here

- `experiments/pipeline/` — the three detection levels as run against the agent:
  the prompt-and-skill firewall, the execution-semantic command/effect judges, the
  argument-aware system-call signatures and learned classifier, the eBPF read/connect
  taint tracer, and the before/after data-provenance diff.
- `experiments/code/` — analysis and reproduction scripts: the cross-model judge
  runner, the table reproduction, the L2 effect-judge distillation, the victim-defense
  runs, and the strict-subset recomputation.
- `experiments/results/` — per-call API logs, per-item verdicts, and the trained
  system-call model `l3_syscall_model.joblib`.
- `experiments/prior_corpora/` — training and evaluation on the external corpora
  (DongTing system calls; prompt-injection cross-source generalization).
- `corpus_manifest.csv` — the 66-attack corpus with per-attack, per-method verdicts.
- `xval_*.{csv,json}` — the cross-model success-label validation logs.
- `checksums.txt` — SHA-256 for the corpus manifest and the cross-model logs.

## Reproduce

Every defense-side table recomputes from the released files with no API keys:

```bash
pip install -r requirements.txt
python experiments/code/reproduce_cached.py
```

See `EXPERIMENTS.md` for the cached / live-rerun / full-pipeline modes and the
per-table mapping.

## License

Released under the Prosperity Public License 3.0.0 (free for noncommercial, research, and educational use; 30-day commercial trial); see `LICENSE`.
