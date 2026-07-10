# GPU model serving (vast.ai) — exact commands

Cross-model judges were self-hosted on a **2× NVIDIA H100 80GB** vast.ai instance
(160 GB vRAM, 104 vCPU, 885 GB RAM, 2.1 TB disk, CUDA 13.0, Python 3.12, vLLM 0.24.0).
All served an OpenAI-compatible `/v1` endpoint on container port 10100
(public `http://<host>:<mapped_port>/v1`) with an `--api-key`. Models are public HF
weights (re-downloadable); only code + results in this repo are the durable artifacts.

## Download (single quant for GGUF!)
```bash
export HF_TOKEN=<hf_token>
hf download Qwen/Qwen3.5-122B-A10B-FP8       --local-dir /workspace/models/qwen3.5-122b-fp8
hf download nvidia/Llama-3.1-Nemotron-70B-Instruct-HF --local-dir /workspace/models/nemotron-70b
hf download zai-org/GLM-4.5-Air-FP8          --local-dir /workspace/models/glm-4.5-air-fp8
# GGUF: grab ONE quant file, not the whole repo (repo = every quant, ~91 GB)
hf download empero-ai/Qwythos-9B-Claude-Mythos-5-1M-GGUF \
    Qwythos-9B-Claude-Mythos-5-1M-Q8_0.gguf  --local-dir /workspace/models/qwythos-9b
```

## Serve (vLLM, one big model at a time on TP=2)
```bash
# Qwen3.5-122B-A10B — hybrid MoE+Mamba: MUST cap --max-num-seqs <= Mamba cache blocks
vllm serve /workspace/models/qwen3.5-122b-fp8 --served-model-name qwen3.5-122b-a10b \
  --tensor-parallel-size 2 --api-key <KEY> --host 0.0.0.0 --port 10100 \
  --max-model-len 32768 --max-num-seqs 256 --gpu-memory-utilization 0.92

# Nemotron-70B (bf16 weights → online fp8)
vllm serve /workspace/models/nemotron-70b --served-model-name nemotron-70b \
  --tensor-parallel-size 2 --api-key <KEY> --host 0.0.0.0 --port 10100 \
  --max-model-len 16384 --quantization fp8 --gpu-memory-utilization 0.90

# GLM-4.5-Air (native fp8 MoE)
vllm serve /workspace/models/glm-4.5-air-fp8 --served-model-name glm-4.5-air \
  --tensor-parallel-size 2 --api-key <KEY> --host 0.0.0.0 --port 10100 \
  --max-model-len 16384 --max-num-seqs 256 --gpu-memory-utilization 0.90 --trust-remote-code
```

## Serve GGUF (llama.cpp, CUDA 13 built from source)
```bash
export CUDA_HOME=/usr/local/cuda
CMAKE_ARGS="-DGGML_CUDA=on" pip install "llama-cpp-python[server]" \
    --force-reinstall --no-cache-dir --no-binary llama-cpp-python   # cu124 wheels don't match CUDA 13
python -m llama_cpp.server --model /workspace/models/qwythos-9b/Qwythos-9B-Claude-Mythos-5-1M-Q8_0.gguf \
  --served-model-name qwythos-9b --host 0.0.0.0 --port 10100 --api_key <KEY> \
  --n_gpu_layers -1 --n_ctx 8192 --chat_format chatml
```

## Gotchas encountered (and fixes)
- **Qwen3.5-122B**: `max_num_seqs (1024) exceeds Mamba cache blocks (338)` → add `--max-num-seqs 256`.
- **Gemini API**: 2.5-flash is a *thinking* model; low `max_tokens` returns no text → set `generationConfig.thinkingConfig.thinkingBudget=0`.
- **GGUF via vLLM**: fails (`config.json not valid JSON`) — vLLM wants HF config; use llama.cpp instead.
- **llama-cpp prebuilt wheels** target CUDA 12 (`libcudart.so.12`); this box is CUDA 13 → build from source with nvcc 13.
- **`hf download <repo>` for a GGUF repo** pulls *every* quant (Q2…F16, ~91 GB) — always name the single file.
