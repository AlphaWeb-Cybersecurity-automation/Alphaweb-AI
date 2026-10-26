"""Cookbook: detect hardware, find models already on disk, pick or recommend one.

  python -m services.system_profiler                       # report (run from backend/)
  python -m services.system_profiler --download            # fetch the recommended model
  python -m services.system_profiler --download mistral-7b-instruct-v0.3-hf

Two ways to serve a model, each needs its own runtime:
  gguf  llama.cpp's llama-server  (<project root>/binaries/)
  hf    backend/hf_server.py in .venv-hf (transformers + bitsandbytes)

Selection rules (see model_catalog.MODEL_CATALOG for the preference order):
  1. memory budget = VRAM on an NVIDIA GPU, 66% of RAM on Apple Silicon (unified),
     otherwise half of RAM (CPU inference).
  2. use the most-preferred model that is already on disk, fits the budget, and
     whose runtime is installed. Looked for in: the models dir, the Hugging Face
     cache, and Ollama's store (its blobs are plain GGUF files). Unrecognised HF
     models (e.g. base models) are never auto-picked; name them with LLM_HF_MODEL.
  3. nothing local qualifies -> recommend the most-preferred downloadable model
     that fits and has an installed runtime; budget too small for any -> keyword-only.

Pure stdlib; must not import config (config imports this module).
"""
from __future__ import annotations

import glob
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from model_catalog import CATALOG_BY_NAME, MODEL_CATALOG, RECOMMENDABLE, ModelSpec

_GB = 1024 ** 3
_SHARD_RE = re.compile(r"-(\d{5})-of-(\d{5})\.gguf$", re.I)


# --- hardware -------------------------------------------------------------

@dataclass
class Hardware:
    os: str
    cpu_cores: int
    ram_gb: float
    gpu_name: Optional[str]
    vram_gb: Optional[float]
    budget_gb: float
    budget_basis: str  # "vram" | "unified memory" | "half of RAM (CPU)"


def _ram_gb() -> float:
    system = platform.system()
    try:
        if system == "Windows":
            import ctypes

            class _MemStatus(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            st = _MemStatus()
            st.dwLength = ctypes.sizeof(st)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st))  # type: ignore[attr-defined]
            return st.ullTotalPhys / _GB
        if system == "Linux":
            with open("/proc/meminfo") as fh:
                for line in fh:
                    if line.startswith("MemTotal:"):
                        return int(line.split()[1]) * 1024 / _GB
        if system == "Darwin":
            return int(subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True)) / _GB
    except Exception:  # noqa: BLE001 - detection is best-effort
        pass
    return 0.0


def _nvidia_gpu() -> Tuple[Optional[str], Optional[float]]:
    """Largest NVIDIA GPU as (name, total VRAM GB), or (None, None)."""
    if not shutil.which("nvidia-smi"):
        return None, None
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
            text=True, timeout=10, stderr=subprocess.DEVNULL,
        )
    except Exception:  # noqa: BLE001
        return None, None
    best: Tuple[Optional[str], float] = (None, 0.0)
    for line in out.strip().splitlines():
        name, _, mem = line.rpartition(",")
        try:
            vram = float(mem.strip()) / 1024
        except ValueError:
            continue
        if vram > best[1]:
            best = (name.strip(), vram)
    return (best[0], round(best[1], 2)) if best[0] else (None, None)


def detect_hardware() -> Hardware:
    ram = round(_ram_gb(), 2)
    gpu, vram = _nvidia_gpu()
    if gpu and vram:
        budget, basis = vram, "vram"
    elif platform.system() == "Darwin" and platform.machine() == "arm64":
        gpu, budget, basis = "Apple Silicon (unified memory)", ram * 0.66, "unified memory"
    else:
        budget, basis = ram / 2, "half of RAM (CPU)"
    return Hardware(
        os=f"{platform.system()} {platform.release()}", cpu_cores=os.cpu_count() or 1,
        ram_gb=ram, gpu_name=gpu, vram_gb=vram, budget_gb=round(budget, 2), budget_basis=basis,
    )


# --- runtimes ---------------------------------------------------------------

def llama_server_path() -> Optional[str]:
    # Same location llm_client.LLAMA_SERVER_EXE uses: <project root>/binaries/.
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    for cand in (os.path.join(root, "binaries", "llama-server.exe"),
                 os.path.join(root, "binaries", "llama-server")):
        if os.path.isfile(cand):
            return cand
    return shutil.which("llama-server")


def hf_venv_python() -> str:
    """Interpreter of the Hugging Face model-server virtualenv (<project root>/.venv-hf)."""
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    if os.name == "nt":
        return os.path.join(root, ".venv-hf", "Scripts", "python.exe")
    return os.path.join(root, ".venv-hf", "bin", "python")


def available_backends() -> Set[str]:
    """Backends whose runtime is installed: subset of {"gguf", "hf"}."""
    found = set()
    if llama_server_path():
        found.add("gguf")
    if os.path.isfile(hf_venv_python()):
        found.add("hf")
    return found


# --- local model discovery -------------------------------------------------

@dataclass
class LocalModel:
    label: str                      # file stem, Ollama tag, or HF repo id
    path: str                       # GGUF file, or HF snapshot directory
    size_gb: float
    source: str                     # "models dir" | "huggingface cache" | "ollama"
    backend: str                    # "gguf" | "hf"
    catalog: Optional[ModelSpec]    # None = a model we don't recognise
    note: str = ""


def _match_catalog(label: str, backend: str) -> Optional[ModelSpec]:
    low = label.lower()
    for spec in MODEL_CATALOG:
        if spec.backend == backend and any(alias in low for alias in spec.aliases):
            return spec
    return None


def _gguf_group_size(path: str) -> float:
    """Size of a GGUF, summing all shards if it is split."""
    m = _SHARD_RE.search(path)
    files = glob.glob(_SHARD_RE.sub("-*-of-" + m.group(2) + ".gguf", path)) if m else [path]
    return sum(os.path.getsize(f) for f in files) / _GB


def _make_gguf(label: str, path: str, source: str) -> LocalModel:
    return LocalModel(label=label, path=path, size_gb=round(_gguf_group_size(path), 2), source=source,
                      backend="gguf", catalog=_match_catalog(label, "gguf"))


def _gguf_files(root: str, max_depth: int) -> List[str]:
    found: List[str] = []
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        return found
    base_depth = root.count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root):
        if dirpath.count(os.sep) - base_depth >= max_depth:
            dirnames[:] = []
        for fn in filenames:
            if fn.lower().endswith(".gguf"):
                m = _SHARD_RE.search(fn)
                if m and int(m.group(1)) != 1:
                    continue  # llama-server loads the remaining shards itself
                found.append(os.path.join(dirpath, fn))
    return found


def _hf_cache_dir() -> str:
    return os.environ.get("HF_HUB_CACHE") or os.path.join(
        os.environ.get("HF_HOME") or os.path.join(os.path.expanduser("~"), ".cache", "huggingface"), "hub")


def _ollama_models() -> List[LocalModel]:
    root = os.environ.get("OLLAMA_MODELS") or os.path.join(os.path.expanduser("~"), ".ollama", "models")
    out: List[LocalModel] = []
    for manifest in glob.glob(os.path.join(root, "manifests", "*", "*", "*", "*")):
        try:
            with open(manifest, encoding="utf-8") as fh:
                layers = json.load(fh).get("layers", [])
        except (OSError, ValueError):
            continue
        digest = next((l["digest"] for l in layers if l.get("mediaType", "").endswith("image.model")), None)
        if not digest:
            continue
        blob = os.path.join(root, "blobs", digest.replace(":", "-"))
        if not os.path.isfile(blob):
            continue
        parts = os.path.normpath(manifest).split(os.sep)
        namespace, model, tag = parts[-3], parts[-2], parts[-1]
        label = f"{model}:{tag}" if namespace == "library" else f"{namespace}/{model}:{tag}"
        out.append(_make_gguf(label, blob, "ollama"))
    return out


def _dir_size_gb(path: str) -> float:
    total = 0
    for f in glob.glob(os.path.join(path, "*")):
        try:
            total += os.path.getsize(os.path.realpath(f))  # snapshot files are symlinks to blobs
        except OSError:
            pass
    return total / _GB


def _hf_cache_llms() -> List[LocalModel]:
    """Text LLM repos in the HF cache that have weights but no GGUF (served by hf_server.py)."""
    out: List[LocalModel] = []
    for repo_dir in glob.glob(os.path.join(_hf_cache_dir(), "models--*")):
        repo = os.path.basename(repo_dir)[len("models--"):].replace("--", "/")
        snaps = glob.glob(os.path.join(repo_dir, "snapshots", "*"))
        if any(glob.glob(os.path.join(s, "*.gguf")) for s in snaps):
            continue
        for snap in snaps:
            try:
                with open(os.path.join(snap, "config.json"), encoding="utf-8") as fh:
                    cfg = json.load(fh)
            except (OSError, ValueError):
                continue
            if not any(str(a).endswith("ForCausalLM") for a in cfg.get("architectures", [])):
                continue  # not a text LLM (ASR, vision, TTS, ...)
            if not glob.glob(os.path.join(snap, "*.safetensors")):
                continue  # config only: weights not downloaded
            spec = _match_catalog(repo, "hf")
            note = "" if re.search(r"instruct|chat|-it\b", repo, re.I) else \
                "base model, not instruction-tuned: weak at tool selection"
            out.append(LocalModel(label=repo, path=snap, size_gb=round(_dir_size_gb(snap), 2),
                                  source="huggingface cache", backend="hf", catalog=spec, note=note))
            break
    return out


def discover_local_models(models_dir: str) -> List[LocalModel]:
    """GGUF files (models dir, HF cache, Ollama) plus HF-format LLMs in the HF cache."""
    usable: List[LocalModel] = []
    seen_paths = set()

    def add(m: LocalModel) -> None:
        key = os.path.normcase(os.path.realpath(m.path))
        if key not in seen_paths:
            seen_paths.add(key)
            usable.append(m)

    for p in _gguf_files(models_dir, max_depth=2):
        add(_make_gguf(os.path.splitext(os.path.basename(p))[0], p, "models dir"))
    for p in _gguf_files(_hf_cache_dir(), max_depth=6):
        add(_make_gguf(os.path.splitext(os.path.basename(p))[0], p, "huggingface cache"))
    for m in _ollama_models():
        add(m)
    for m in _hf_cache_llms():
        add(m)
    return usable


# --- choosing / recommending ----------------------------------------------

def choose_local_model(hw: Hardware, usable: List[LocalModel], requested: Optional[str] = None,
                       backends: Optional[Set[str]] = None) -> Optional[LocalModel]:
    """Best usable local model. `requested` (a catalog name) pins the choice."""
    if requested and requested != "auto":
        return next((m for m in usable if m.catalog and m.catalog.name == requested), None)
    backends = available_backends() if backends is None else backends
    runnable = [m for m in usable if m.backend in backends]
    fits = [m for m in runnable if m.catalog and m.catalog.min_mem_gb <= hw.budget_gb]
    if fits:
        return min(fits, key=lambda m: MODEL_CATALOG.index(m.catalog))  # type: ignore[arg-type]
    unknown = [m for m in runnable if not m.catalog and m.backend == "gguf" and m.size_gb * 1.3 <= hw.budget_gb]
    return max(unknown, key=lambda m: m.size_gb) if unknown else None


def recommend_model(hw: Hardware, backends: Optional[Set[str]] = None) -> Optional[ModelSpec]:
    """Most-preferred downloadable model that fits and can run; None = keyword-only.

    With no runtime installed at all, falls back to the best GGUF model (needs llama-server).
    """
    backends = available_backends() if backends is None else backends
    fitting = [m for m in RECOMMENDABLE if m.min_mem_gb <= hw.budget_gb]
    runnable = [m for m in fitting if m.backend in backends]
    return (runnable or fitting or [None])[0]


def download_command(spec: ModelSpec, models_dir: str) -> str:
    if spec.backend == "hf":
        return f"python -m services.system_profiler --download {spec.name}"
    return f'hf download {spec.repo} {spec.file} --local-dir "{models_dir}"'


def download_model(spec: ModelSpec, models_dir: str) -> str:
    """Download into models_dir (GGUF) or the Hugging Face cache (HF weights)."""
    if not spec.repo:
        raise ValueError(f"{spec.name} has no public download; place {spec.file} in {models_dir} yourself")
    if spec.backend == "hf":
        from huggingface_hub import snapshot_download  # lazy: only needed to download

        return snapshot_download(spec.repo)
    from huggingface_hub import hf_hub_download

    os.makedirs(models_dir, exist_ok=True)
    return hf_hub_download(spec.repo, spec.file, local_dir=models_dir)


# --- report ---------------------------------------------------------------

def build_profile(models_dir: str, requested: Optional[str] = "auto", hf_model: str = "") -> Dict[str, Any]:
    hw = detect_hardware()
    backends = available_backends()
    usable = discover_local_models(models_dir)
    chosen = choose_local_model(hw, usable, requested, backends)
    rec = recommend_model(hw, backends)
    server = llama_server_path()

    if hf_model:
        selected: Optional[Dict[str, Any]] = {"model": hf_model, "path": None,
                                              "source": "active config", "backend": "hf"}
    elif chosen:
        selected = {"model": chosen.catalog.name if chosen.catalog else chosen.label,
                    "path": chosen.path, "source": chosen.source, "backend": chosen.backend}
    else:
        selected = None
    # A more-preferred model than the one in use fits this hardware but is not on disk.
    on_disk = {m.catalog.name for m in usable if m.catalog}
    upgrade = bool(selected and rec and rec.name not in on_disk and (
        not chosen or not chosen.catalog or MODEL_CATALOG.index(rec) < MODEL_CATALOG.index(chosen.catalog)))
    return {
        "hardware": asdict(hw),
        "backends": {"gguf (llama-server)": server, "hf (.venv-hf)": hf_venv_python() if "hf" in backends else None},
        "local_models": [{**asdict(m), "catalog": m.catalog.name if m.catalog else None} for m in usable],
        "selected": selected,
        "recommended": ({"model": rec.name, "backend": rec.backend, "repo": rec.repo, "size_gb": rec.size_gb,
                         "command": download_command(rec, models_dir)} if rec else None),
        "recommended_is_upgrade": upgrade,
        "mode": "llm" if selected else "keyword-only until a model is available",
    }


def format_report(p: Dict[str, Any], models_dir: str) -> str:
    hw = p["hardware"]
    lines = ["== Hardware",
             f"  OS: {hw['os']}   CPU cores: {hw['cpu_cores']}   RAM: {hw['ram_gb']} GB",
             f"  GPU: {hw['gpu_name'] or 'none detected (CPU inference)'}"
             + (f"   VRAM: {hw['vram_gb']} GB" if hw["vram_gb"] else ""),
             f"  Model memory budget: {hw['budget_gb']} GB ({hw['budget_basis']})", "", "== Runtimes"]
    for name, path in p["backends"].items():
        lines.append(f"  {name}: {path or 'not installed'}")
    lines += ["", f"== Local models (looked in {models_dir}, HF cache, Ollama)"]
    for m in p["local_models"]:
        tag = m["catalog"] or "not in catalog"
        warn = f"; {m['note']}" if m["note"] else ""
        runnable = "" if m["backend"] in {k.split()[0] for k, v in p["backends"].items() if v} else \
            f"; needs the {m['backend']} runtime"
        lines.append(f"  [{m['backend']}] {m['label']}  ({m['size_gb']} GB, {m['source']}, {tag}{warn}{runnable})")
    if not p["local_models"]:
        lines.append("  none found")
    lines += ["", "== Decision"]
    sel, rec = p["selected"], p["recommended"]
    if sel:
        lines.append(f"  Using: {sel['model']}  ({sel['backend']}, {sel['source']})")
        if sel["path"]:
            lines.append(f"         {sel['path']}")
        if p["recommended_is_upgrade"] and rec:
            lines.append(f"  Better fit available: {rec['model']} ({rec['size_gb']} GB)")
            lines.append(f"    {rec['command']}")
    elif rec:
        lines.append(f"  No usable local model. Recommended: {rec['model']} ({rec['backend']}, {rec['size_gb']} GB)")
        lines.append(f"    {rec['command']}")
        lines.append("    or: python -m services.system_profiler --download")
    else:
        lines.append("  Memory budget too small for any local model: running keyword-only.")
    if not any(p["backends"].values()):
        lines.append("  No runtime installed. Set up .venv-hf (backend/requirements-hf.txt), or put a "
                     "llama.cpp release in <project root>/binaries/ "
                     "(https://github.com/ggml-org/llama.cpp/releases; RTX 50-series needs CUDA 12.8+).")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Detect hardware and pick/recommend a local LLM.")
    ap.add_argument("--models-dir", default=os.environ.get("LLM_MODELS_DIR", "models"))
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--download", nargs="?", const="__recommended__", metavar="MODEL",
                    help="download the recommended model, or MODEL (a catalog name)")
    args = ap.parse_args(argv)

    profile = build_profile(args.models_dir, os.environ.get("LLM_MODEL", "auto"),
                            os.environ.get("LLM_HF_MODEL", ""))
    if args.json:
        print(json.dumps(profile, indent=2))
    else:
        print(format_report(profile, args.models_dir))

    if args.download:
        if args.download == "__recommended__":
            if not profile["recommended"]:
                print("\nNothing to download: no model fits this hardware.")
                return 1
            spec = CATALOG_BY_NAME[profile["recommended"]["model"]]
        else:
            if args.download not in CATALOG_BY_NAME:
                print(f"\nUnknown model {args.download!r}; choose from {sorted(CATALOG_BY_NAME)}")
                return 2
            spec = CATALOG_BY_NAME[args.download]
        print(f"\nDownloading {spec.name} ({spec.size_gb} GB) from {spec.repo} ...")
        try:
            print("saved", download_model(spec, args.models_dir))
        except ImportError:
            print("huggingface_hub not installed. Run: pip install huggingface_hub   then retry")
            return 1
        except Exception as exc:  # noqa: BLE001
            print(f"download failed: {exc}")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
