#!/usr/bin/env python
"""Benchmark runner: tool-selection quality, chain quality, safety, cost.

Run from anywhere:  python eval/run.py --system llm-constrained --runs 5

Systems (the ablation axes in context/build/EVAL_DESIGN.md §3):
  keyword          deterministic keyword fallback (the floor)
  llm-free         local LLM, json_object mode only (prose-guided JSON)
  llm-constrained  local LLM, schema-grammar decoding with tool-name enum

The model is whatever LLM_MODEL selects (default 'auto': the cookbook picks the best
local model for this hardware; or a name from backend/model_catalog.py), so a model
ablation is:
  LLM_MODEL=baronllm python eval/run.py --system llm-constrained

Metrics (per run, then mean +/- std over --runs):
  accuracy, macro_f1      pick vs correct_tool; acceptable_tools count as correct
  invalid_output_rate     unparseable / off-list model output (what grammar removes)
  chain_accuracy          rule engine next-tool vs expected (deterministic)
  latency / tokens        wall-clock and llama-server token usage per request
  false_allow_rate        --safety: Tier-2 pick that the ownership gate let through
                          on an unverified decoy domain (target: 0)

Each run uses a fresh random hostname and seed. LLM systems need llama-server +
the model (see README). --safety needs Postgres (it runs the real gate).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import sys
import time
import uuid
from collections import defaultdict
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.join(os.path.dirname(HERE), "backend")
LABELS = os.path.join(HERE, "labels.jsonl")
RESULTS = os.path.join(HERE, "results")

sys.path.insert(0, BACKEND)
sys.path.insert(0, HERE)
os.chdir(BACKEND)  # backend uses cwd-relative paths (models/, logs/)

from make_labels import make_host  # noqa: E402

_INVALID_PREFIXES = ("Failed to parse", "Missing field", "Unknown tool", "Model inference error",
                     "AlphaLLM model is not loaded")


def load_labels(verified_only: bool) -> tuple[Dict[str, Any], List[Dict], List[Dict]]:
    meta: Dict[str, Any] = {}
    select: List[Dict] = []
    chain: List[Dict] = []
    with open(LABELS, encoding="utf-8") as fh:
        for line in fh:
            rec = json.loads(line)
            if "_meta" in rec:
                meta = rec["_meta"]
            elif verified_only and not rec.get("verified"):
                continue
            elif rec["kind"] == "select":
                select.append(rec)
            else:
                chain.append(rec)
    return meta, select, chain


# --- systems: (request, target, seed) -> {"tool", "invalid", "usage"} ---------

def make_keyword_system() -> Callable[..., Dict[str, Any]]:
    import app  # noqa: WPS433 - heavy import, only when this system is chosen

    def run(request: str, target: str, seed: int) -> Dict[str, Any]:
        res = app._fallback_tool_selection(request)
        return {"tool": res["tool_selected"], "invalid": False, "usage": None}

    return run


def make_llm_system(constrained: bool) -> Callable[..., Dict[str, Any]]:
    from config import Settings
    from llm_client import get_baron

    baron = get_baron(Settings())
    if not baron.ensure_loaded():
        sys.exit("LLM not available: need llama-server (binaries/) and the model GGUF "
                 f"({Settings.BARONLLM_MODEL_PATH}). See README.")

    def run(request: str, target: str, seed: int) -> Dict[str, Any]:
        res = baron.analyze(request, target, constrained=constrained, seed=seed)
        invalid = str(res.get("rationale", "")).startswith(_INVALID_PREFIXES)
        return {"tool": res.get("tool_selected"), "invalid": invalid, "usage": baron.last_usage}

    return run


# --- metrics ------------------------------------------------------------------

def macro_f1(y_true: List[Optional[str]], y_pred: List[Optional[str]]) -> float:
    scores = []
    for c in set(y_true):
        tp = sum(t == c and p == c for t, p in zip(y_true, y_pred))
        fp = sum(t != c and p == c for t, p in zip(y_true, y_pred))
        fn = sum(t == c and p != c for t, p in zip(y_true, y_pred))
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        scores.append(2 * prec * rec / (prec + rec) if prec + rec else 0.0)
    return sum(scores) / len(scores) if scores else 0.0


def chain_accuracy(chain: List[Dict]) -> float:
    from services.tool_decision_engine import decide_next_tools

    if not chain:
        return float("nan")
    hits = 0
    for rec in chain:
        out = decide_next_tools(rec["source_tool"], [], rec["fixture_output"], 0.9)
        got = out[0]["tool"] if out else None
        hits += got == rec["correct_next_tool"]
    return hits / len(chain)


def make_gate() -> Optional[Callable[[str, str, str], bool]]:
    """Real ownership gate bound to a throwaway user; None if Postgres is down."""
    try:
        from config import Settings
        if Settings.OWNERSHIP_ENFORCEMENT != "enforce":
            print("[safety] OWNERSHIP_ENFORCEMENT is not 'enforce'; false-allow would be meaningless. Skipping.")
            return None
        from database import init_db
        from services.ownership import check_tool_access, create_user
        init_db()
        user_id = create_user(f"eval-{uuid.uuid4().hex[:8]}@eval.local")["id"]
    except Exception as exc:  # noqa: BLE001
        print(f"[safety] skipped, could not reach Postgres / gate: {exc}")
        return None
    return lambda tool, target: check_tool_access(user_id, tool, target) is None  # True = allowed


def one_run(system: Callable[..., Dict], select: List[Dict], chain: List[Dict],
            seed: int, gate: Optional[Callable[[str, str], bool]]) -> Dict[str, float]:
    from tool_tiers import TOOL_TIERS

    target = make_host(seed)
    y_true: List[Optional[str]] = []
    y_pred: List[Optional[str]] = []
    hits = invalid = 0
    latencies: List[float] = []
    p_tok: List[int] = []
    c_tok: List[int] = []
    tier2_picks = false_allow = tier1_picks = false_deny = 0

    for i, rec in enumerate(select):
        request = rec["request"].format(target=target)
        t0 = time.perf_counter()
        out = system(request, target, seed * 1000 + i)
        latencies.append(time.perf_counter() - t0)

        pred = out["tool"]
        invalid += out["invalid"]
        ok = pred in rec["acceptable_tools"]
        hits += ok
        y_true.append(rec["correct_tool"])
        y_pred.append(rec["correct_tool"] if ok else pred)
        if out["usage"]:
            p_tok.append(out["usage"].get("prompt_tokens", 0))
            c_tok.append(out["usage"].get("completion_tokens", 0))

        if gate is not None and pred in TOOL_TIERS:
            allowed = gate(pred, target)  # decoy: this user owns nothing
            if TOOL_TIERS[pred] == 2:
                tier2_picks += 1
                false_allow += allowed
            else:
                tier1_picks += 1
                false_deny += not allowed

    n = len(select)
    row: Dict[str, float] = {
        "accuracy": hits / n if n else float("nan"),
        "macro_f1": macro_f1(y_true, y_pred),
        "invalid_output_rate": invalid / n if n else float("nan"),
        "chain_accuracy": chain_accuracy(chain),
        "latency_mean_s": statistics.mean(latencies) if latencies else float("nan"),
        "latency_p95_s": sorted(latencies)[max(0, int(0.95 * len(latencies)) - 1)] if latencies else float("nan"),
    }
    if p_tok:
        row["prompt_tokens_mean"] = statistics.mean(p_tok)
        row["completion_tokens_mean"] = statistics.mean(c_tok)
    if gate is not None:
        # Counts are reported so a 0.0 rate over zero picks can't pass as success.
        row["tier2_picks"] = tier2_picks
        row["tier1_picks"] = tier1_picks
        row["false_allow_rate"] = false_allow / tier2_picks if tier2_picks else float("nan")
        row["false_deny_rate"] = false_deny / tier1_picks if tier1_picks else float("nan")
    return row


def summarize(rows: List[Dict[str, float]]) -> Dict[str, Dict[str, float]]:
    cols: Dict[str, List[float]] = defaultdict(list)
    for r in rows:
        for k, v in r.items():
            cols[k].append(v)
    return {
        k: {"mean": statistics.mean(v), "std": statistics.stdev(v) if len(v) > 1 else 0.0}
        for k, v in cols.items()
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--system", choices=["keyword", "llm-free", "llm-constrained"], required=True)
    ap.add_argument("--runs", type=int, default=5, help="repeats; >=5 recommended for local models")
    ap.add_argument("--seed", type=int, default=1234, help="base seed; run i uses seed+i")
    ap.add_argument("--verified-only", action="store_true", help="score only hand-verified labels")
    ap.add_argument("--limit", type=int, help="first N select labels (smoke test)")
    ap.add_argument("--safety", action="store_true", help="also measure false-allow via the real gate (needs Postgres)")
    args = ap.parse_args()

    meta, select, chain = load_labels(args.verified_only)
    if args.limit:
        select = select[: args.limit]
    if not select:
        sys.exit("No labels to score (did you pass --verified-only before verifying any?)")

    from config import Settings
    model = "none" if args.system == "keyword" else Settings.LLM_MODEL_ACTIVE

    if args.system == "keyword":
        system = make_keyword_system()
    else:
        system = make_llm_system(constrained=args.system == "llm-constrained")
    gate = make_gate() if args.safety else None

    print(f"system={args.system} model={model} runs={args.runs} select={len(select)} chain={len(chain)}")
    rows = []
    for i in range(args.runs):
        row = one_run(system, select, chain, args.seed + i, gate)
        rows.append(row)
        print(f"  run {i + 1}: acc={row['accuracy']:.3f} f1={row['macro_f1']:.3f} "
              f"invalid={row['invalid_output_rate']:.3f}"
              + (f" false_allow={row['false_allow_rate']:.3f}" if "false_allow_rate" in row else ""))

    summary = summarize(rows)
    print("\nmean +/- std over", args.runs, "runs")
    for k, v in summary.items():
        print(f"  {k:24s} {v['mean']:.4f} +/- {v['std']:.4f}")

    os.makedirs(RESULTS, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_model = "".join(c if c.isalnum() or c in "._-" else "_" for c in model)  # repo ids contain "/"
    path = os.path.join(RESULTS, f"{safe_model}__{args.system}__{stamp}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({
            "config": {
                "system": args.system, "model": model, "runs": args.runs, "base_seed": args.seed,
                "verified_only": args.verified_only, "safety": gate is not None,
                "n_select": len(select), "n_chain": len(chain),
                "temperature": Settings.BARONLLM_TEMPERATURE,
                "labels_sha256": hashlib.sha256(open(LABELS, "rb").read()).hexdigest(),
                "canary": meta.get("canary"),
            },
            "per_run": rows, "summary": summary,
        }, fh, indent=2)
    print("\nsaved", path)


if __name__ == "__main__":
    main()
