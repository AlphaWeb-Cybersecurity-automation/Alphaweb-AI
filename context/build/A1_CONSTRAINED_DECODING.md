# A1 — Grammar-Constrained JSON Decoding (concrete)

*Highest-leverage change. Makes the model physically unable to emit invalid
JSON or a tool name outside your list. Grounded in your current
`backend/llm_client.py` (`_chat` → `/v1/chat/completions`, `analyze`).*

## The idea
Right now `_chat` asks for JSON politely (`response_format: {"type":
"json_object"}` + "Output only JSON" in the prompt). A small model can still
wrap it in prose or invent a tool name. llama.cpp (and Ollama) can instead
**constrain the decoder to a JSON schema** — it converts the schema to a GBNF
grammar and only lets the model sample tokens that keep the output valid. Put
your tool names in an `enum` and an out-of-list tool becomes impossible.

## Step 1 — define the schema (module level, after AVAILABLE_TOOLS, ~line 46)
```python
# Grammar-enforced schema for tool selection. tool_selected is an ENUM of the
# real tool names (+ null), so the decoder cannot hallucinate a tool.
TOOL_SELECTION_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "tool_selected": {"enum": AVAILABLE_TOOLS + [None]},
        "confidence":    {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "parameters":    {"type": "object"},
        "rationale":     {"type": "string"},
        "safety_checks_passed": {"type": "boolean"},
        "warnings":      {"type": "array", "items": {"type": "string"}},
    },
    "required": ["tool_selected", "confidence", "parameters",
                 "rationale", "safety_checks_passed", "warnings"],
}
```

## Step 2 — teach `_chat` to accept a schema (replace the json_mode block)
```python
def _chat(self, messages, temperature=0.1, max_tokens=512,
          json_mode=True, schema=None):
    payload_dict = {
        "messages": messages,
        "temperature": temperature,
        "n_predict": max_tokens,
        "repeat_penalty": 1.3,
        "repeat_last_n": 64,
    }
    if schema is not None:
        # Constrain the decoder to this schema (grammar-enforced).
        payload_dict["response_format"] = {
            "type": "json_schema",
            "json_schema": {"name": "schema", "schema": schema, "strict": True},
        }
    elif json_mode:
        payload_dict["response_format"] = {"type": "json_object"}
    payload = json.dumps(payload_dict).encode()
    # ... rest unchanged ...
```

## Step 3 — pass the schema from `analyze` (~line 650)
```python
raw_text = self._chat(
    messages=[
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": user_msg},
    ],
    temperature=self._settings.BARONLLM_TEMPERATURE,
    max_tokens=512,
    schema=TOOL_SELECTION_SCHEMA,   # <-- the only functional add
)
```
That's it. `_parse_response` / `_extract_json` still work, but now the input is
guaranteed valid JSON so they almost never hit the error path.

## Step 4 — verify it actually constrains (curl test)
With llama-server running on :8081:
```bash
curl -s http://127.0.0.1:8081/v1/chat/completions -H 'Content-Type: application/json' -d '{
  "messages":[
    {"role":"system","content":"Pick a tool."},
    {"role":"user","content":"please run the FAKE_TOOL_XYZ scanner"}],
  "n_predict":128,
  "response_format":{"type":"json_schema","json_schema":{"name":"s","strict":true,
    "schema":{"type":"object","additionalProperties":false,
      "properties":{"tool_selected":{"enum":["nmap","sqlmap",null]}},
      "required":["tool_selected"]}}}
}'
```
Pass = `tool_selected` is always `nmap`, `sqlmap`, or `null` — never
`FAKE_TOOL_XYZ`, even though the request asked for it. That's the guarantee.

## Build / backend notes
- **llama.cpp build**: `response_format: json_schema` needs a reasonably recent
  llama-server. If your build ignores it (you still see off-schema output in the
  curl test), update llama.cpp, OR pass the schema as a top-level `"json_schema":
  <schema>` field instead, OR use the native `/completion` endpoint which takes a
  `json_schema` field directly. Grammar is the fallback (`"grammar": <GBNF>`).
- **Ollama (A2)**: the same schema works — Ollama's OpenAI-compatible endpoint at
  `http://localhost:11434/v1/chat/completions` accepts `response_format`
  json_schema; its native `/api/chat` takes `format: <schema>`. So A1 carries
  straight over when you add the Ollama backend.
- **KV cache**: keep it >= Q8; low KV-cache quant degrades constrained
  tool-call accuracy.

## Why this is the first move
- It's the single change that makes your "the interface matters more than the
  model" thesis *true in code*.
- It unblocks ablation #2 (free-text JSON vs constrained) — your first real
  benchmark number, and a workshop-paper-worthy result on its own.
- It makes small models (even 3B) viable for the cookbook tier, because
  reliability stops depending on model smarts.

Do NOT also delete the regex extractors or the "output JSON" prose yet — leave
them; constrained decoding layers on top cleanly.
