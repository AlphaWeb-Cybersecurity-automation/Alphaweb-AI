"""Catalog of selectable local models.

Two serving backends:
  gguf  a GGUF file served by llama.cpp's llama-server
  hf    a Hugging Face repo (4-bit bitsandbytes) served by backend/hf_server.py

Single source of truth for model name -> file/repo, where to download it, and
how much memory it needs. config.py derives LLM_MODEL choices from this and
services/system_profiler.py uses it to recommend / pick a model for the hardware.

Order matters: it is the preference order when several models fit. An HF entry
sits right after its GGUF twin, so GGUF wins when both runtimes are installed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class ModelSpec:
    name: str                    # value for LLM_MODEL
    file: str                    # GGUF filename expected in the models dir ("" for hf models)
    repo: Optional[str]          # Hugging Face repo to download from (None = custom/local only)
    size_gb: float               # file size
    min_mem_gb: float            # VRAM (GPU) or RAM/2 (CPU) needed incl. KV cache at n_ctx=4096
    aliases: Tuple[str, ...]     # lowercase substrings that identify this model in other local files
    backend: str = "gguf"        # "gguf" | "hf"


MODEL_CATALOG: Tuple[ModelSpec, ...] = (
    ModelSpec("qwen2.5-14b-instruct", "Qwen2.5-14B-Instruct-Q4_K_M.gguf",
              "bartowski/Qwen2.5-14B-Instruct-GGUF", 8.99, 12.0,
              ("qwen2.5-14b-instruct",)),
    ModelSpec("qwen2.5-7b-instruct", "Qwen2.5-7B-Instruct-Q4_K_M.gguf",
              "bartowski/Qwen2.5-7B-Instruct-GGUF", 4.68, 6.0,
              ("qwen2.5-7b-instruct", "qwen2.5:7b")),
    ModelSpec("qwen2.5-7b-instruct-hf", "", "unsloth/Qwen2.5-7B-Instruct-bnb-4bit", 5.55, 8.0,
              ("qwen2.5-7b-instruct-bnb",), backend="hf"),
    ModelSpec("mistral-7b-instruct-v0.3", "Mistral-7B-Instruct-v0.3-Q4_K_M.gguf",
              "bartowski/Mistral-7B-Instruct-v0.3-GGUF", 4.37, 6.0,
              ("mistral-7b-instruct", "mistral:7b", "mistral:latest")),
    ModelSpec("mistral-7b-instruct-v0.3-hf", "", "unsloth/mistral-7b-instruct-v0.3-bnb-4bit", 4.14, 6.0,
              ("mistral-7b-instruct-v0.3-bnb",), backend="hf"),
    ModelSpec("llama-3.1-8b-instruct", "Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf",
              "bartowski/Meta-Llama-3.1-8B-Instruct-GGUF", 4.92, 6.5,
              ("llama-3.1-8b-instruct", "llama3.1:8b")),
    # Cybersecurity finetune: kept for the model ablation, not auto-recommended.
    ModelSpec("baronllm", "baronllm-llama3.1-v1-q6_k.gguf",
              None, 6.6, 7.5,
              ("baronllm", "barronllm")),
    ModelSpec("qwen2.5-3b-instruct", "qwen2.5-3b-instruct-q4_k_m.gguf",
              "Qwen/Qwen2.5-3B-Instruct-GGUF", 2.1, 3.0,
              ("qwen2.5-3b-instruct", "qwen2.5:3b")),
    ModelSpec("llama-3.2-3b-instruct", "Llama-3.2-3B-Instruct-Q4_K_M.gguf",
              "bartowski/Llama-3.2-3B-Instruct-GGUF", 2.02, 3.0,
              ("llama-3.2-3b-instruct", "llama3.2:3b", "llama3.2:latest")),
)

CATALOG_BY_NAME = {m.name: m for m in MODEL_CATALOG}
# Never auto-recommended (no public download / ablation-only).
RECOMMENDABLE = tuple(m for m in MODEL_CATALOG if m.repo is not None)
DEFAULT_MODEL = "qwen2.5-7b-instruct"
