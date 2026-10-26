"""OpenAI-compatible chat server backed by Hugging Face transformers.

Drop-in replacement for llama-server on the same port, so llm_client.py needs
no protocol changes. Runs in its own virtualenv (.venv-hf) because it needs
torch/transformers/bitsandbytes, which the main backend does not.

  .venv-hf/Scripts/python backend/hf_server.py --model unsloth/mistral-7b-v0.3-bnb-4bit

Supported request fields (the subset llm_client sends): messages, temperature,
n_predict / max_tokens, seed, repeat_penalty + repeat_last_n, and
response_format json_schema (strict) / json_object. Both are enforced by
lm-format-enforcer, so output is valid JSON and a schema enum such as the
tool-name list is a hard constraint, the same guarantee llama.cpp grammar gives.
Replies carry `usage` token counts.

Models without a chat template (base models) get the Mistral [INST] format.
Pre-quantized bitsandbytes checkpoints load as-is; full-precision checkpoints
are quantized to 4-bit NF4 on load unless --quant none.
"""
from __future__ import annotations

import argparse
import threading
import time
from typing import Any, Dict, List, Optional

import torch
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from lmformatenforcer import CharacterLevelParserConfig, JsonSchemaParser
from lmformatenforcer.integrations.transformers import build_transformers_prefix_allowed_tokens_fn
from transformers import (
    AutoConfig,
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    LogitsProcessor,
    LogitsProcessorList,
)

app = FastAPI()
_state: Dict[str, Any] = {"ready": False, "error": None, "model": None, "tokenizer": None, "name": ""}
_gen_lock = threading.Lock()  # one generation at a time on a single GPU


class WindowedRepetitionPenalty(LogitsProcessor):
    """llama.cpp-style repeat penalty: only the last `window` tokens count.

    transformers' built-in penalty covers the whole context including the prompt,
    which is much harsher on JSON (quotes, braces, tool names).
    """

    def __init__(self, penalty: float, window: int) -> None:
        self.penalty, self.window = penalty, window

    def __call__(self, input_ids: torch.LongTensor, scores: torch.FloatTensor) -> torch.FloatTensor:
        recent = input_ids[:, -self.window:]
        picked = torch.gather(scores, 1, recent)
        picked = torch.where(picked < 0, picked * self.penalty, picked / self.penalty)
        return scores.scatter(1, recent, picked)


class NoWhitespaceRuns(LogitsProcessor):
    """Forbid a whitespace-only token at the start of the reply and right after
    another one. lm-format-enforcer's own whitespace cap does not take effect at
    token level, and base models pad JSON with long newline runs otherwise.
    """

    def __init__(self, whitespace_ids: List[int], n_prompt: int) -> None:
        self.ids = torch.tensor(whitespace_ids, dtype=torch.long)
        self.set = set(whitespace_ids)
        self.n_prompt = n_prompt

    def __call__(self, input_ids: torch.LongTensor, scores: torch.FloatTensor) -> torch.FloatTensor:
        generated = input_ids[0, self.n_prompt:]
        if generated.numel() == 0 or int(generated[-1]) in self.set:
            scores[:, self.ids.to(scores.device)] = float("-inf")
        return scores


def strip_trailing_commas(text: str) -> str:
    """Drop commas directly before a closing } or ] (outside string literals).

    lm-format-enforcer lets free-form-key objects (e.g. `"parameters": {"type": "object"}`)
    end with a trailing comma, which is invalid JSON. Typed objects are unaffected.
    """
    out: List[str] = []
    in_str = escaped = False
    for i, ch in enumerate(text):
        if in_str:
            out.append(ch)
            escaped = (not escaped) and ch == "\\"
            in_str = in_str and not (ch == '"' and not escaped)
            continue
        if ch == '"':
            in_str = True
        elif ch == ",":
            rest = text[i + 1:].lstrip()
            if rest[:1] in ("}", "]"):
                continue
        out.append(ch)
    return "".join(out)


def _lmfe_schema(node: Any) -> Any:
    """Rewrite a schema so lm-format-enforcer accepts it.

    llama.cpp takes {"enum": ["a", "b", null]}; lm-format-enforcer rejects an enum
    that mixes strings with null (and silently degrades to garbage). Equivalent
    form: anyOf [{"enum": [...]}, {"type": "null"}].
    """
    if isinstance(node, list):
        return [_lmfe_schema(v) for v in node]
    if not isinstance(node, dict):
        return node
    out = {k: _lmfe_schema(v) for k, v in node.items()}
    enum = out.get("enum")
    if isinstance(enum, list) and None in enum and len(enum) > 1:
        rest = [v for v in enum if v is not None]
        out.pop("enum")
        out["anyOf"] = [{"enum": rest}, {"type": "null"}]
    return out


def _make_parser(response_format: Dict[str, Any]) -> Optional[JsonSchemaParser]:
    kind = response_format.get("type")
    if kind not in ("json_schema", "json_object"):
        return None
    # json_object means "any JSON *object*" (as in llama.cpp); a None schema would also accept 1 or true.
    schema = _lmfe_schema(response_format["json_schema"]["schema"]) if kind == "json_schema" else {"type": "object"}
    # One whitespace char at most between tokens: stops base models from padding
    # with newlines (the default allows 12 in a row).
    parser = JsonSchemaParser(schema, CharacterLevelParserConfig(max_consecutive_whitespaces=1))
    if not parser.get_allowed_characters():
        raise ValueError("schema not supported by lm-format-enforcer (no valid first character)")
    return parser


def _load(model_id: str, quant: str) -> None:
    try:
        local = {"local_files_only": True}
        try:  # prefer the local cache; only touch the network if it is not cached
            tok = AutoTokenizer.from_pretrained(model_id, **local)
            cfg = AutoConfig.from_pretrained(model_id, **local)
        except OSError:
            local = {}
            tok = AutoTokenizer.from_pretrained(model_id)
            cfg = AutoConfig.from_pretrained(model_id)
        kwargs: Dict[str, Any] = {"device_map": {"": 0} if torch.cuda.is_available() else "cpu"}
        pre_quantized = getattr(cfg, "quantization_config", None) is not None
        if not pre_quantized:
            if quant == "4bit" or (quant == "auto" and torch.cuda.is_available()):
                kwargs["quantization_config"] = BitsAndBytesConfig(
                    load_in_4bit=True, bnb_4bit_quant_type="nf4",
                    bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
            else:
                kwargs["torch_dtype"] = torch.bfloat16
        model = AutoModelForCausalLM.from_pretrained(model_id, **kwargs, **local)
        model.eval()
        ws = [i for i in range(len(tok)) if i != tok.eos_token_id and not tok.decode([i]).strip()]
        _state.update(model=model, tokenizer=tok, name=model_id, ws_ids=ws, ready=True)
    except Exception as exc:  # noqa: BLE001 - reported via /health
        _state["error"] = f"{type(exc).__name__}: {exc}"
        raise


def _build_prompt(messages: List[Dict[str, str]]) -> str:
    tok = _state["tokenizer"]
    if getattr(tok, "chat_template", None):
        return tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    # Mistral [INST] format; system text is folded into the first user turn.
    system = "\n".join(m["content"] for m in messages if m["role"] == "system")
    turns = [m for m in messages if m["role"] != "system"]
    out = ""
    for i, m in enumerate(turns):
        if m["role"] == "user":
            text = (system + "\n\n" + m["content"]) if (i == 0 and system) else m["content"]
            out += f"[INST] {text} [/INST]"
        else:
            out += f" {m['content']}</s>"
    return out


@app.get("/health")
def health() -> JSONResponse:
    if _state["ready"]:
        return JSONResponse({"status": "ok", "model": _state["name"]})
    if _state["error"]:
        return JSONResponse({"status": "error", "error": _state["error"]}, status_code=500)
    return JSONResponse({"status": "loading"}, status_code=503)


@app.post("/v1/chat/completions")
async def chat(request: Request) -> JSONResponse:
    if not _state["ready"]:
        return JSONResponse({"error": "model not ready"}, status_code=503)
    body = await request.json()
    try:
        return JSONResponse(await _run_in_thread(body))
    except ValueError as exc:  # unsupported schema etc.: fail loudly, not with garbage
        return JSONResponse({"error": str(exc)}, status_code=400)


async def _run_in_thread(body: Dict[str, Any]) -> Dict[str, Any]:
    import asyncio

    return await asyncio.to_thread(_generate, body)


def _generate(body: Dict[str, Any]) -> Dict[str, Any]:
    tok, model = _state["tokenizer"], _state["model"]
    prompt = _build_prompt(body["messages"])
    inputs = tok(prompt, return_tensors="pt", add_special_tokens=True).to(model.device)
    n_prompt = int(inputs["input_ids"].shape[1])

    temperature = float(body.get("temperature", 0.1))
    procs = LogitsProcessorList()
    if body.get("repeat_penalty") and float(body["repeat_penalty"]) != 1.0:
        procs.append(WindowedRepetitionPenalty(float(body["repeat_penalty"]), int(body.get("repeat_last_n", 64))))

    kwargs: Dict[str, Any] = {
        "max_new_tokens": int(body.get("max_tokens") or body.get("n_predict") or 512),
        "do_sample": temperature > 0,
        "pad_token_id": tok.eos_token_id,
        "logits_processor": procs,
    }
    if temperature > 0:
        kwargs["temperature"] = temperature

    parser = _make_parser(body.get("response_format") or {})
    if parser is not None:
        kwargs["prefix_allowed_tokens_fn"] = build_transformers_prefix_allowed_tokens_fn(tok, parser)
        procs.append(NoWhitespaceRuns(_state["ws_ids"], n_prompt))

    with _gen_lock:
        if body.get("seed") is not None:
            torch.manual_seed(int(body["seed"]))
        with torch.no_grad():
            out = model.generate(**inputs, **kwargs)
    new_ids = out[0][n_prompt:]
    text = tok.decode(new_ids, skip_special_tokens=True)
    if parser is not None:
        text = strip_trailing_commas(text)
    return {
        "choices": [{"message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": n_prompt, "completion_tokens": int(new_ids.shape[0]),
                  "total_tokens": n_prompt + int(new_ids.shape[0])},
        "model": _state["name"],
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", required=True, help="HF repo id or local directory")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8081)
    ap.add_argument("--quant", choices=["auto", "4bit", "none"], default="auto")
    args = ap.parse_args()

    # Load in the background so /health can answer "loading" instead of refusing connections.
    threading.Thread(target=_load, args=(args.model, args.quant), daemon=True).start()
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
