# Refine Mode — Actionable Coding Plan (v1)
_Last updated: 2026-04-20_

## Status
> **⚠ PARITY FAILED — all refine work is blocked.**
> Manual exit checks on Run 5 combos showed exits do not match TV.
> Run 5 (`mega_results_20260420_003538_all.csv`) metrics (PF, Eq, WR, strict labels) are
> derived from a mis-specified simulator and **must not be used as a refine seed source**.
> Phases 1–6 remain unchanged but are gated on Phase 0.C passing.

## Naming convention
```
RUN6_ALL = mega_results_<run6id>_all.csv   # placeholder — fill in after Phase 0.C
```
All examples in Phases 1–6 use `RUN6_ALL`. **Never substitute `mega_results_20260420_003538_all.csv` (Run 5) — it is banned.**

## Before you start
- Both `Optimizer_Anti_2.py` and `Analyzer_Anti_2.py` compile clean ✓
- **Run 5 is invalidated**: `mega_results_20260420_003538_all.csv` — exits do not match TV ✗
- **`MEGA_REFINE_FROM` must point to a parity-certified run** (see Phase 0.C) — never Run 5
- **Hard ban in code**: if `os.path.basename(MEGA_REFINE_FROM) == "mega_results_20260420_003538_all.csv"` → `sys.exit(1)` with FATAL message
- Parity sprint (Phase 0.A/0.B/0.C) is the only active work right now

---

## PHASE 0.A — Parity check (single combo, T-ledger)
_Status: **FAILED** — exit mismatches confirmed on manual inspection._

### Step 0.A.1 — Pick one combo
Use `ID_03740` (Run 5 best Score=2.88). This combo stays the reference target throughout the parity sprint.

### Step 0.A.2 — Export TV trade list
- Load `ID_03740` params into `Trading_strategy_Anti_2.pine`
- Match `USEPROOVERRIDE` exactly to the param set (or disable it)
- Export strategy tester trade list as CSV: entry bar, exit bar, side, price, qty, P&L
- Save as `tv_trades_ID_03740.csv`

### Step 0.A.3 — Run Python forensic replay
```powershell
py -3 Analyzer_Anti_2.py --forensic ID_03740
```
Diff every trade: side, entry bar, exit bar, entry price, exit price, qty, P&L.

### CHECKPOINT 0.A
- **Pass**: all trades identical → write `parity_seal.json`, skip to Phase 0.C
- **Fail**: any mismatch → proceed to Phase 0.B

---

## PHASE 0.B — Parity debugging sprint
_Fix the simulator until the T-ledger matches TV for ID_03740. Do not touch refine code._

### Step 0.B.1 — Build dedicated parity diff harness
In `Analyzer_Anti_2.py`, implement (or wire up existing tooling into) a focused path:

```powershell
py -3 Analyzer_Anti_2.py --parity-diff ID_03740 tv_trades_ID_03740.csv
```

Output columns per trade row:
```
TradeID | Side | EBar | XBar | EPx | XPx | Qty | PnL | Source
```
where `Source` is `TV` or `PY`. Rows are aligned by TradeID/EBar; mismatched rows flagged `MISMATCH`.

Ensure:
- `MEGA_FAST_SWEEP` / any fast-path env is **off**
- TV-mirror fill flags (`MEGA_DIAGNOSTIC_TV_MIRROR_FILL_ENABLED` etc.) are **on**
- Commission = 0.06%, slippage = 3 ticks — matching Pine header

### Step 0.B.2 — Classify each mismatch
For every differing trade, label it:

| Class | Description |
|---|---|
| **Entry mismatch** | Python enters different bar/side/price than TV |
| **Exit mismatch** | Same entry, exits on different bar or price |
| **Size mismatch** | Same bars, different qty (affects PF/Eq, not pattern) |
| **Missing trade** | Python has trade TV doesn't, or vice versa |

User confirmed: **exits don't match** — prioritise exit logic, but verify entries too.

### Step 0.B.3 — Root-cause checklist (work top-down)

1. **Fill bar semantics** — `process_orders_on_close=false` in Pine means orders fill on next bar open. Confirm Python matches.
2. **Stop/TP trigger** — intra-bar high/low path vs end-of-bar close. Pine triggers stops on the bar's high/low; Python must do the same.
3. **Trail lock timing** — when does the trail move? Confirm Python updates trail on the same bar Pine does.
4. **Commission model** — Pine: `0.06%` per side (`commission_type=percent`). Confirm Python applies same rate, same direction.
5. **Slippage** — Pine: `slippage=3` (ticks). Confirm Python applies to both entries and exits.
6. **Position sizing / qty rounding** — `risk_long`/`risk_short` = 4% each. Confirm Python uses same formula and rounds identically.

### Step 0.B.4 — Iterate
For each root cause found: fix `simulate()` or the accounting layer, re-run `--parity-diff`, repeat until zero `MISMATCH` rows.

### CHECKPOINT 0.B ✓
- Zero `MISMATCH` rows in `--parity-diff` output for all battery combos
- Python T-ledger and TV T-ledger are byte-identical on every trade column
- Write `parity_seal.json` (extended schema — Fix 1.3/1.4):
  ```json
  {
    "ok": true,
    "certified_on": "<ISO date>",
    "combos": ["ID_03740", "ID_<trail_heavy>", "ID_<fast_scalp>"],
    "pine_version": "Trading_strategy_Anti_2 v20260420",
    "sim_hash": "<sha256[:16] of Optimizer_Anti_2.py + Analyzer_Anti_2.py>",
    "dataset_hash": "<sha256[:16] of OHLCV file used in parity run>",
    "allowed_results": "mega_results_<run6id>_all.csv"
  }
  ```
  `allowed_results` is filled in after Phase 0.C.1 once the Run 6 filename is known.
  Any change to simulator code invalidates `sim_hash` → refine init will FATAL until re-sealed.

---

## PHASE 0.C — Fresh parity-certified discovery run (Run 6)
_Only after Checkpoint 0.B passes._

### Step 0.C.1 — Re-run discovery
```powershell
$env:MEGA_WF_STEP='1500'
py -3 Optimizer_Anti_2.py --samples 4000
```
This produces `mega_results_<run6id>_all.csv` built on the now-certified simulator.

### Step 0.C.2 — Inspect winners
```powershell
py -3 Analyzer_Anti_2.py --sweep-report mega_results_<run6id>_all.csv
```
Expect winner count and PF/Eq/WR distributions to differ from Run 5 (they were wrong).

### Step 0.C.3 — Spot-check 2–3 Run 6 winners against TV
Repeat Step 0.A.3 for 2–3 top Run 6 combos. If they match: Run 6 is the certified seed source.

### CHECKPOINT 0.C ✓
- Run 6 `_all.csv` produced by certified simulator
- 2–3 Run 6 winner combos pass `--parity-diff` individually
- Update `parity_seal.json`: set `allowed_results = "mega_results_<run6id>_all.csv"`
- Update `RUN6_ALL` placeholder at the top of this document with the actual filename
- Run `parity_check.ps1` (see end of document) → all combos green
- **`MEGA_REFINE_FROM` = `RUN6_ALL`** — the only allowed seed source

---

## PHASE 1 — Core sampling machinery
_Gated on Checkpoint 0.C. Do not implement until `parity_seal.json` has `ok=true` and `allowed_results` is set._
_File: `Optimizer_Anti_2.py`. No run-loop changes yet. Compile after every step._

### Step 1.1 — `current_sampling_policy()`
Add near the top of the sampling section (around line 10200):

```python
def current_sampling_policy() -> str:
    """Single source of truth for which sampling dialect is active.
    Returns: 'refine' | 'discovery_typical' | 'discovery_default'
    Note: rescue path bypasses random_param_set() entirely — not listed here.
    Uses _REFINE_ACTIVE (not the raw env var) so that a failed seed load
    does NOT incorrectly return 'refine'.
    """
    if _REFINE_ACTIVE and _REFINE_SEED_POOL:   # double-guard: active flag AND non-empty pool
        return "refine"
    if TYPICAL_RANGES is not None:
        return "discovery_typical"
    return "discovery_default"
```

> **Fix 5 + 2.1**: require both `_REFINE_ACTIVE=True` AND `_REFINE_SEED_POOL` non-empty. Prevents "refine" policy if pool is empty due to import-only tests or future refactors.

**Compile check** → no errors.

---

### Step 1.2 — `build_default_sigma_and_band_maps()`
Add immediately after `current_sampling_policy()`:

```python
def build_default_sigma_and_band_maps():
    """Returns (sigma_map, band_map) — single source of truth for refine sampling.
    sigma_map: {param: sigma}  for float params, {param: int_delta} for int params
    band_map:  {param: (lo, hi)}
    """
    sigma_map = {
        'sll': 0.08,   'sls': 0.08,
        'modear': 0.25,
        'adxl': 0.20,  'adxs': 0.20,
        'zl': 0.15,    'zs': 0.25,
        'maxzl': 0.20, 'maxzs': 0.20,
        'velgate': 0.005,
        'chopmult': 0.008,
        'agel': 3,     'ages': 1,   # int deltas
        'nucl': 0.40,  'nucs': 0.30,
        'adxgate': 1.00,
        'adxdec': 1.00,
    }
    band_map = {
        'sll':     (2.2,  2.7),
        'sls':     (2.2,  2.7),
        'modear':  (3.5,  5.0),
        'adxl':    (0.4,  1.4),
        'adxs':    (-1.5, -0.1),
        'zl':      (-1.8, -1.3),
        'zs':      (0.9,  1.9),
        'maxzl':   (1.7,  2.3),
        'maxzs':   (-1.9, -1.4),
        'velgate': (0.18, 0.205),
        'chopmult':(0.17, 0.21),
        'agel':    (10,   16),
        'ages':    (3,    6),
        'nucl':    (3.0,  5.0),
        'nucs':    (2.0,  3.5),
        'adxgate': (-15.0,-5.0),
        'adxdec':  (-11.9,-2.0),
    }
    return sigma_map, band_map
```

**Compile check** → no errors.

---

### Step 1.3 — `load_refine_seed_pool()`
Add after `build_default_sigma_and_band_maps()`:

```python
def load_refine_seed_pool(csv_path: str, top_n: int, rank_by: str = "score",
                          strict_only: bool = True) -> List[Dict]:
    """Load top-N seeds from a results CSV. Seeds must pass strict predicate.
    Returns List[Dict[str, Any]], each element:
        {
            "params":   {...},        # canonical param dict
            "combo_id": "ID_03740",
            "score":    float,
            "pf":       float,
            "wr":       float,
            "tc":       int,
            "trl":      int,
            "trs":      int,
            "t_pf":     float,        # 0.0 if T_PF column absent
        }
    Ordered by rank_by descending.
    """
```

Implementation rules:
- Parse CSV using `csv.DictReader` (header-driven, never index-based)
- **Guard required columns** (Fix 2.3): on open, check that `PF`, `WR`, `TrL`, `TrS`, `Score`, `Eq`, `Trades` are present; if any missing → FATAL: `"Refine requires full GS66 schema — column X missing in <csv_path>"`
- If `rank_by="oospf"` and `T_PF` column absent → FATAL (do not silently fall back)
- **Reconstruct params via `merge_mega_results_row_into_params(base={}, csv_path, combo_id)`** — reuses the existing GS66-header-aware parser; do NOT use `row_to_params()` or index-based access. (Fix 3)
- **Strict predicate hierarchy** (Fix 1):
  ```python
  # Build agg tuples from the row (mirror Stage B usage)
  res, testres, segbundle = make_agg_tuple_from_row(row)
  base_strict = strict_profitable_combo_from_agg(
      res, testres, segbundle,
      mintrades=MIN_TRADES,
      targetwr=TARGET_WR,
      targetpf=TARGET_PF,
      segment_strict_min_trades=parse_segment_strict_min_trades_env(),
  )
  pf  = float(row["PF"]);  trl = int(row["TrL"]);  trs = int(row["TrS"])
  wr  = float(row["WR"])
  if strict_only:
      seed_extra = (pf >= 2.0 and trl >= 4 and trs >= 4)
  else:
      seed_extra = (pf >= 1.6 and wr >= 0.40 and trl > 0 and trs > 0)
  eligible = base_strict and seed_extra
  ```
  `base_strict` is **never weakened** — only `seed_extra` relaxes when `strict_only=False`.
- **Ranking**:
  - `rank_by="score"` → sort by `Score` desc, tie-break `T_PF` desc, then `Trades` desc
  - `rank_by="pf"` → sort by `PF` desc
  - `rank_by="eq"` → sort by `Eq` desc
  - `rank_by="oospf"` → sort by `T_PF` desc only if `T_PF` column present AND `T_Trades >= 5`; otherwise fall back to `"score"` with loud warning
- **Hash seed CSV**: `hashlib.sha256(open(csv_path,'rb').read()).hexdigest()[:16]`
- **Log**: `f"[refine] seed pool: {len(seeds)} loaded (requested {top_n}), rank={rank_by}, hash={csv_hash}"`
- If `len(seeds) < top_n`: log `f"[refine] Only {len(seeds)} seeds passed predicate (TOPN={top_n})"`
- Print sigma/band maps once at load time for manual inspection (verbose startup log)
- Return up to `top_n` seeds as `List[Dict]` per signature above

**Compile check** → no errors.

---

### Step 1.4 — `sample_from_seed()`
Add after `load_refine_seed_pool()`:

```python
def sample_from_seed(seed: Dict, sigma_map: Dict, band_map: Dict,
                     seed_id: str) -> Tuple[Dict, Dict]:
    """Perturb one seed with single-tier Gaussian within band_map.
    Returns (params, provenance).
    provenance = {"source": "seed", "seed_id": seed_id, "policy": "refine"}
    """
```

Implementation rules:
- `import random, math` (already imported)
- For each param in `sigma_map`:
  - If param is an **int** param (`agel`, `ages`): `new = seed[param] + random.randint(-delta, delta)`, clamp to `band_map[param]`
  - If param is a **float** param: `new = seed[param] + random.gauss(0, sigma)`, clamp to `band_map[param]`
  - Round float to 6 decimal places
- For all other params: copy from seed unchanged (**locked**)
- Special coupling: after sampling `sll`, re-apply `modear` structural clamp:
  `modear = min(params['modear'], min(6.0, 2.5 * params['sll']))`
- Return `(params, {"source": "seed", "seed_id": seed_id, "policy": "refine"})`

**Compile check** → no errors.

---

### Step 1.5 — `random_param_set_refine()`
Add after `sample_from_seed()`:

```python
def random_param_set_refine(seed_pool: List[Dict]) -> Tuple[Dict, Dict]:
    """80/20 dispatcher: seed-local vs wide fallback.
    Returns (params, provenance).
    Wide provenance = {"source": "wide", "seed_id": None, "policy": "refine"}
    """
```

Implementation rules:
- `mix_pct = float(os.environ.get("MEGA_REFINE_MIX_PCT", "0.20"))`
- If `random.random() < mix_pct` (wide branch):
  - Call `random_param_set_typical()` if `TYPICAL_RANGES is not None`, else `random_param_set_default()`
  - Return `(params, {"source": "wide", "seed_id": None, "policy": "refine"})`
- Else (seed-local branch):
  - Pick seed uniformly: `seed = random.choice(seed_pool)`
  - `sigma_map, band_map = build_default_sigma_and_band_maps()`
  - Return `sample_from_seed(seed["params"], sigma_map, band_map, seed["combo_id"])`
- After building `provenance`, store in thread-local and assert parent thread (Fix 2.2):
  ```python
  import threading as _threading
  if _threading.current_thread().name != "MainThread":
      raise RuntimeError(
          "random_param_set_refine() must run on MainThread; "
          "thread-local provenance will not be visible otherwise.")
  _threading.current_thread().__dict__["_rps_provenance"] = provenance
  ```
- Also add the same MainThread assertion at the top of `_merged_csv_segment_tags()` when `_REFINE_ACTIVE` is True
- **No call to `random_param_set()`** — avoids circular dispatch

**Compile check** → no errors.

---

### Step 1.6 — Refactor `random_param_set()` into thin dispatcher
Replace the current `random_param_set()` body with:

```python
def random_param_set():
    policy = current_sampling_policy()
    if policy == "refine":
        params, _prov = random_param_set_refine(_REFINE_SEED_POOL)
        return params
    elif policy == "discovery_typical":
        return random_param_set_typical()
    else:
        return random_param_set_default()
```

Move existing `random_param_set()` body into two helpers:
- `random_param_set_typical()` — the `TYPICAL_RANGES is not None` branch (currently `if TYPICAL_RANGES is not None:`)
- `random_param_set_default()` — the `elif wide:` + `else:` branches (the conservative default)

The 70/30 wide-explore split already in `random_param_set_typical()` stays unchanged.

**Compile check** → no errors.

### CHECKPOINT 1 ✓
- `py -3 -m py_compile Optimizer_Anti_2.py` → clean
- With `MEGA_REFINE_FROM` **unset**: `current_sampling_policy()` returns `"discovery_typical"` or `"discovery_default"` — **not** `"refine"` (because `_REFINE_ACTIVE=False`)
- `build_default_sigma_and_band_maps()` returns two non-empty dicts with all 17 params

---

## PHASE 2 — Provenance & metadata
_File: `Optimizer_Anti_2.py`. Wire refine state into tags, runmeta, sidecar, checkpoint._

### Step 2.1 — Module-level globals + startup initialisation

**First**, add these at module top-level (near `TYPICAL_RANGES`, `DATAPATH`, etc.):

```python
# Refine mode globals — set once at startup, read-only thereafter
_REFINE_ACTIVE: bool      = False
_REFINE_CSV_HASH: str     = ""
_REFINE_SEED_IDS: list    = []
_REFINE_RUN_ID: str       = ""
_REFINE_SEED_POOL: list   = []
_refine_from: str         = ""
_top_n: int               = 0
_rank_by: str             = "score"
_strict: bool             = True
```

In any function that **assigns** to these (init block, checkpoint writer/loader), declare `global _REFINE_ACTIVE, _REFINE_CSV_HASH, ...` at the top of that function.

**Then**, find where `TYPICAL_RANGES` is loaded at run start. Add immediately after:

```python
_refine_from = os.environ.get("MEGA_REFINE_FROM", "").strip()
if _refine_from:
    _top_n    = int(os.environ.get("MEGA_REFINE_TOPN", "10"))
    _rank_by  = os.environ.get("MEGA_REFINE_SEED_RANK", "score").strip()
    _strict   = os.environ.get("MEGA_REFINE_STRICT_ONLY", "1").strip() in ("1","true","yes")
    _REFINE_SEED_POOL = load_refine_seed_pool(_refine_from, _top_n, _rank_by, _strict)
    if not _REFINE_SEED_POOL:
        print("[refine] ERROR: no seeds loaded — check predicate / CSV path. Aborting.", flush=True)
        sys.exit(1)
    _REFINE_ACTIVE   = True
    _REFINE_CSV_HASH = hashlib.sha256(open(_refine_from,'rb').read()).hexdigest()[:16]
    _REFINE_SEED_IDS = [s["combo_id"] for s in _REFINE_SEED_POOL]
    _mix = float(os.environ.get("MEGA_REFINE_MIX_PCT", "0.20"))
    _variants = int(os.environ.get("MEGA_REFINE_VARIANTS", "80"))
    print(f"[Sampling] policy=refine  seeds={len(_REFINE_SEED_POOL)}  "
          f"mix_pct={_mix}  rank={_rank_by}  dist=gaussian", flush=True)
    print(f"[refine] TOPN={_top_n}, VARIANTS={_variants} => nominal "
          f"~{int((1-_mix)*_variants*_top_n)} seed-local draws", flush=True)
    # Sanity: warn if --samples too low
    # (actual samples checked in run loop when args.samples is known)

    # Parity seal — HARD GATE (Fix 1.2 + 1.3 + 1.4)
    _parity_seal_path = os.path.join(os.path.dirname(__file__) or ".", "parity_seal.json")
    if not os.path.exists(_parity_seal_path):
        print("FATAL: Refine requires parity_seal.json (TV<>Python certified). "
              "Run Phase 0.B first.", flush=True)
        sys.exit(1)
    _seal = json.load(open(_parity_seal_path, encoding="utf-8"))
    if not _seal.get("ok"):
        print("FATAL: parity_seal.json ok=false — re-run Phase 0.B.", flush=True)
        sys.exit(1)
    # Simulator identity check — stale seal after code changes
    _cur_sim_hash = hashlib.sha256(
        open("Optimizer_Anti_2.py", "rb").read() +
        open("Analyzer_Anti_2.py", "rb").read()
    ).hexdigest()[:16]
    if _seal.get("sim_hash") and _seal["sim_hash"] != _cur_sim_hash:
        print(f"FATAL: parity_seal.json sim_hash mismatch "
              f"(seal={_seal['sim_hash']} current={_cur_sim_hash}). "
              f"Simulator changed — re-run Phase 0.B.", flush=True)
        sys.exit(1)
    # Allowed results check — prevents using a banned/wrong CSV as seed source
    _allowed = _seal.get("allowed_results", "")
    if _allowed and os.path.basename(_refine_from) != _allowed:
        print(f"FATAL: MEGA_REFINE_FROM={os.path.basename(_refine_from)!r} not allowed. "
              f"Seal permits only {_allowed!r}. Re-seal after Run 6.", flush=True)
        sys.exit(1)
    # Hard ban on Run 5
    if os.path.basename(_refine_from) == "mega_results_20260420_003538_all.csv":
        print("FATAL: Run 5 CSV is banned as a refine seed source "
              "(parity failure confirmed). Use RUN6_ALL.", flush=True)
        sys.exit(1)
    # Override escape hatch (emergency only)
    if os.environ.get("MEGA_ALLOW_UNCERTIFIED_REFINE","").strip() in ("1","true"):
        print("[refine] WARNING: MEGA_ALLOW_UNCERTIFIED_REFINE override active — "
              "parity gates bypassed.", flush=True)
else:
    if TYPICAL_RANGES is not None:
        print(f"[Sampling] policy=discovery_typical", flush=True)
    else:
        print(f"[Sampling] policy=discovery_default  (built-in ranges)", flush=True)
```

Also add `import hashlib` near the top of the file if not already present.

> `parity_seal.json` schema: see Checkpoint 0.B. **Refine init hard-aborts** if seal is missing, `ok=false`, `sim_hash` mismatches, or `allowed_results` doesn't match `MEGA_REFINE_FROM`. Override only with `MEGA_ALLOW_UNCERTIFIED_REFINE=1` (emergency use only).

**Compile check** → no errors.

---

### Step 2.2 — SegTags injection
In `_merged_csv_segment_tags()`, add after the existing `wide_explore` injection block:

```python
# Refine mode tags — injected per combo via thread-local provenance
if _REFINE_ACTIVE:
    import threading as _threading
    if _threading.current_thread().name != "MainThread":
        raise RuntimeError("_merged_csv_segment_tags() must run on MainThread in refine mode.")
try:
    import threading as _threading
    _prov = _threading.current_thread().__dict__.get("_rps_provenance", {})
    if _prov.get("policy") == "refine":
        if _prov.get("source") == "seed":
            env_tags.append("refine")
            sid = _prov.get("seed_id", "")
            csv6 = os.path.basename(_refine_from)[:6] if _refine_from else ""
            env_tags.append(f"seed_{sid}_{csv6}")
        else:
            # wide branch — only add wide_explore if not already present
            # (avoids double-add from existing 70/30 wide-explore logic)
            if "wide_explore" not in env_tags:
                env_tags.append("wide_explore")
        if _REFINE_RUN_ID:
            env_tags.append(f"refine_run_{_REFINE_RUN_ID}")
except Exception:
    pass
# Final dedup — _merged_csv_segment_tags already calls sorted(set(...)); confirm it does
```

Thread-local is written in `random_param_set_refine()` (Step 1.5 above). Both calls happen on the parent process thread — do not move param generation into workers.

**Compile check** → no errors.

---

### Step 2.3 — `run_meta.json` additions
Find where `run_meta.json` is written (search for `run_meta` or `runmeta`). Add refine fields to the dict:

```python
if _REFINE_ACTIVE:
    meta["refine_mode"]             = True
    meta["refine_from"]             = _refine_from
    meta["refine_from_hash"]        = _REFINE_CSV_HASH
    meta["refine_topn"]             = _top_n
    meta["refine_seed_count_actual"]= len(_REFINE_SEED_POOL)
    meta["refine_seed_rank"]        = _rank_by
    meta["refine_mix_pct"]          = float(os.environ.get("MEGA_REFINE_MIX_PCT","0.20"))
    meta["refine_strict_only"]      = _strict
    meta["refine_seed_ids"]         = _REFINE_SEED_IDS
    meta["refine_seed_predicate"]   = "base_strict AND PF>=2.0 AND TrL>=4 AND TrS>=4"
    meta["sampling_policy"]         = "refine"
```

**Compile check** → no errors.

---

### Step 2.4 — Sidecar seed file
Find run startup (where RUN_ID / timestamp is established). After `_REFINE_SEED_POOL` is populated and RUN_ID is known, write:

```python
if _REFINE_ACTIVE and RUN_ID:
    _REFINE_RUN_ID = RUN_ID
    _sidecar_path = os.path.join(BASEDIR, f"mega_refine_seeds_{RUN_ID}.json")
    import json as _json
    with open(_sidecar_path, "w", encoding="utf-8") as _sf:
        _json.dump({
            "run_id": RUN_ID,
            "refine_from": _refine_from,
            "refine_from_hash": _REFINE_CSV_HASH,
            "seeds": _REFINE_SEED_POOL,
        }, _sf, indent=2)
    print(f"[refine] Seed sidecar written: {_sidecar_path}", flush=True)
```

**Compile check** → no errors.

---

### Step 2.5 — Checkpoint: save refine state
Find where the checkpoint JSON is written. Add:

```python
if _REFINE_ACTIVE:
    ckpt["refine_from"]       = _refine_from
    ckpt["refine_from_hash"]  = _REFINE_CSV_HASH
    ckpt["refine_seed_ids"]   = _REFINE_SEED_IDS   # ordered list
    ckpt["refine_seed_rank"]  = _rank_by
    ckpt["refine_mix_pct"]    = float(os.environ.get("MEGA_REFINE_MIX_PCT","0.20"))
    ckpt["refine_strict_only"]= _strict
```

---

### Step 2.6 — Checkpoint: resume consistency checks
Find where the checkpoint is loaded on resume. Add after loading:

```python
if ckpt.get("refine_from"):
    # Was a refine run — enforce strict env match
    env_rf = os.environ.get("MEGA_REFINE_FROM","").strip()
    if not env_rf:
        print("FATAL: Resume failed — checkpoint was a refine run but MEGA_REFINE_FROM not set.", flush=True)
        sys.exit(1)
    if env_rf != ckpt["refine_from"]:
        print(f"FATAL: Refine resume mismatch: env MEGA_REFINE_FROM={env_rf!r} "
              f"!= checkpoint {ckpt['refine_from']!r}. Aborting.", flush=True)
        sys.exit(1)
    # Hash check
    cur_hash = hashlib.sha256(open(env_rf,'rb').read()).hexdigest()[:16]
    if cur_hash != ckpt.get("refine_from_hash",""):
        print(f"FATAL: Seed CSV has changed since checkpoint (hash mismatch). Aborting.", flush=True)
        sys.exit(1)
    # Seed set check (unordered)
    if set(_REFINE_SEED_IDS) != set(ckpt.get("refine_seed_ids",[])):
        print("FATAL: Refine seed set differs from checkpoint. Aborting.", flush=True)
        sys.exit(1)
    # Seed order check (warn only)
    if _REFINE_SEED_IDS != ckpt.get("refine_seed_ids",[]):
        print("[refine] WARNING: seed order differs from checkpoint (set is identical — continuing).", flush=True)
elif _REFINE_ACTIVE:
    # Current run is refine but checkpoint was not
    print("WARNING: Resuming non-refine checkpoint in refine mode. Seeds will not match prior run.", flush=True)
```

**Compile check** → no errors.

---

### Step 2.7 — Stage 2 suppression
Find where Stage 2 is triggered (search for `stage2` or `Stage 2` in run loop). Add guard (Fix 9 — both messages wired explicitly):

```python
_stage2_disabled = _REFINE_ACTIVE and os.environ.get(
    "MEGA_STAGE2_DISABLED_ON_REFINE", "1").strip() in ("1","true","yes")
if _stage2_disabled:
    print("[refine] Stage 2 suppressed by default in refine mode "
          "(set MEGA_STAGE2_DISABLED_ON_REFINE=0 to override).", flush=True)
elif _REFINE_ACTIVE:
    print("[refine] WARNING: Stage 2 + refine mode both active — "
          "double-tuning SL/age/TP risk.", flush=True)
```

Wrap Stage 2 entry point with `if not _stage2_disabled:`.

**Compile check** → no errors.

---

### Step 2.8 — Post-run summary
At end of run (after results CSV is written), if `_REFINE_ACTIVE`:

```python
# Collect per-group stats from results CSV
# Group rows by SegTags: "refine" vs "wide_explore"
# Print: seed-local count, strict winner count, median PF/WR/TC
# Print: wide count, strict winner count, median PF/WR/TC
# Print: per-seed usage count (from sidecar or in-memory counter)
```

Use the same CSV parsing logic already in `sort_results_csv()` or `_sweep_report()`.

**Compile check** → no errors.

### CHECKPOINT 2 ✓
- `py -3 -m py_compile Optimizer_Anti_2.py` → clean
- Set `MEGA_REFINE_FROM=RUN6_ALL` (after Phase 0.C) and run import test:
  `py -3 -c "import Optimizer_Anti_2"` → see `[Sampling] policy=refine  seeds=N` in output
- Setting `MEGA_REFINE_FROM=mega_results_20260420_003538_all.csv` → must FATAL with Run 5 ban message
- Deleting `parity_seal.json` then running → must FATAL immediately
- Editing `Optimizer_Anti_2.py` (changing one char, reverting) → sim_hash changes → must FATAL until re-sealed
- `mega_refine_seeds_<runid>.json` written to BASEDIR → inspect manually, all seed IDs plausible

---

## PHASE 3 — Test harness
_Add three test entry points. Triggered only by CLI flags or env vars — never active in production._

### Step 3.1 — `--test-refine-loader` flag
In CLI argument parsing, add `--test-refine-loader` action. When set (parity-check re-uses `strict_profitable_combo_from_agg` — no simplified thresholds):

```python
def _test_refine_seed_loader() -> None:
    csv_path  = os.environ.get("MEGA_REFINE_FROM","").strip()
    top_n     = int(os.environ.get("MEGA_REFINE_TOPN","10"))
    rank_by   = os.environ.get("MEGA_REFINE_SEED_RANK","score")
    strict    = os.environ.get("MEGA_REFINE_STRICT_ONLY","1") in ("1","true","yes")
    seeds = load_refine_seed_pool(csv_path, top_n, rank_by, strict)
    print(f"SEED_LOADER_TEST: loaded {len(seeds)} seeds (requested {top_n})")
    for i, s in enumerate(seeds[:5]):
        p = s["params"]
        print(f"  seed[{i}] id={s['combo_id']}  sll={p.get('sll')}  "
              f"agel={p.get('agel')}  ages={p.get('ages')}  "
              f"PF={s['pf']:.3f}  WR={s['wr']:.3f}  "
              f"TrL={s['trl']}  TrS={s['trs']}  Score={s['score']:.4f}")
    # Cross-check: re-run strict_profitable_combo_from_agg() on each seed
    # (same function used by load_refine_seed_pool — verifies no divergence)
    fails = 0
    for s in seeds:
        res, testres, segbundle = make_agg_tuple_from_row_dict(s)
        ok = strict_profitable_combo_from_agg(
            res, testres, segbundle,
            mintrades=MIN_TRADES, targetwr=TARGET_WR, targetpf=TARGET_PF,
            segment_strict_min_trades=parse_segment_strict_min_trades_env(),
        )
        if not ok:
            print(f"  PREDICATE_MISMATCH: {s['combo_id']} "
                  f"PF={s['pf']:.3f} WR={s['wr']:.3f} — failed strict gate")
            fails += 1
    print(f"SEED_LOADER_TEST: predicate mismatches={fails}")
```

Exit after test. **Compile check** → no errors.

---

### Step 3.2 — `--test-refine-sampler` flag

```python
def _test_refine_sampler(n_samples: int = 200) -> None:
    import random
    from collections import Counter
    random.seed(123456)
    seeds = _REFINE_SEED_POOL
    if not seeds:
        print("REFINE_SAMPLER_TEST: no seeds loaded"); return
    sigma_map, band_map = build_default_sigma_and_band_maps()
    seed_count = 0; wide_count = 0
    stats = {k: [] for k in sigma_map}
    seed_ids = []
    for _ in range(n_samples):
        params, prov = random_param_set_refine(seeds)
        if prov["source"] == "seed":
            seed_count += 1
            seed_ids.append(prov["seed_id"])
            for k in sigma_map:
                if k in params: stats[k].append(params[k])
        else:
            wide_count += 1
    mix = float(os.environ.get("MEGA_REFINE_MIX_PCT","0.20"))
    print(f"REFINE_SAMPLER_TEST: n={n_samples}  seed_local={seed_count} ({seed_count/n_samples:.1%})"
          f"  wide={wide_count} ({wide_count/n_samples:.1%})  expected_wide~{mix:.0%}")
    for k, vals in stats.items():
        if not vals: continue
        lo, hi = band_map[k]
        print(f"  {k:<12} min={min(vals):.4f}  max={max(vals):.4f}  "
              f"mean={sum(vals)/len(vals):.4f}  band=[{lo},{hi}]")
    print(f"  seed_usage: {dict(Counter(seed_ids))}")
```

Exit after test. **Compile check** → no errors.

---

### Step 3.3 — `MEGA_TEST_REFINE_TAGS=1` assertion hook
In `_merged_csv_segment_tags()` (or wherever tags are finalised before `build_csv_row()`), add:

```python
if os.environ.get("MEGA_TEST_REFINE_TAGS","").strip() in ("1","true","yes"):
    if _REFINE_ACTIVE:
        tag_set = set(result_tags)
        if "refine" not in tag_set and "wide_explore" not in tag_set:
            raise AssertionError(
                f"[TAG_ASSERT FATAL] combo missing refine/wide_explore tag. Tags={result_tags}")
        if "refine" in tag_set:
            if not any(t.startswith("seed_") for t in tag_set):
                raise AssertionError(
                    f"[TAG_ASSERT FATAL] refine combo missing seed_* tag. Tags={result_tags}")
            if not any(t.startswith("refine_run_") for t in tag_set):
                raise AssertionError(
                    f"[TAG_ASSERT FATAL] refine combo missing refine_run_* tag. Tags={result_tags}")
```

**Compile check** → no errors.

### CHECKPOINT 3 ✓
Run each harness test (all use `RUN6_ALL` — never Run 5):

```powershell
# T1 — loader
$env:MEGA_REFINE_FROM='<RUN6_ALL>'
$env:MEGA_REFINE_TOPN='10'; $env:MEGA_REFINE_STRICT_ONLY='1'
py -3 Optimizer_Anti_2.py --test-refine-loader
```
**Pass**: K seeds printed, 0 predicate mismatches

```powershell
# T2 — sampler
py -3 Optimizer_Anti_2.py --test-refine-sampler
```
**Pass**: seed_local ≈ 80% (±5%), wide ≈ 20% (±5%), all param values within band_map, no single seed >40% usage

```powershell
# T3 — tags (50-combo run, aborts on first tag failure)
$env:MEGA_TEST_REFINE_TAGS='1'
py -3 Optimizer_Anti_2.py --samples 50
```
**Pass**: run completes with 0 `[TAG_ASSERT FATAL]` lines

---

## PHASE 4 — Resume & Stage 2 validation
_Manual procedural tests. No new code — validates Phase 2 code._

### Step 4.1 — Checkpoint/resume test (T4)

```powershell
# Start 60-combo run, kill after ~25 combos
$env:MEGA_REFINE_FROM='<RUN6_ALL>'
$env:MEGA_REFINE_TOPN='10'; $env:MEGA_REFINE_STRICT_ONLY='1'
py -3 Optimizer_Anti_2.py --samples 60
# Ctrl+C after ~25 combos
```

1. Open checkpoint JSON → verify all `refine_*` fields present
2. Resume with identical env → completes cleanly from saved count
3. Resume with changed `MEGA_REFINE_FROM=something_else.csv` → **must hard abort**
4. Unset `MEGA_REFINE_FROM`, resume → **must hard abort**

**Pass criteria**: steps 3 and 4 abort with clear FATAL messages.

---

### Step 4.2 — Stage 2 suppression test

```powershell
# $env:MEGA_REFINE_FROM='<RUN6_ALL>' must still be set
# With default (Stage 2 suppressed)
py -3 Optimizer_Anti_2.py --samples 60
# Check log: "[refine] Stage 2 suppressed by default..."
# Stage 2 block should not execute

# With override
$env:MEGA_STAGE2_DISABLED_ON_REFINE='0'
py -3 Optimizer_Anti_2.py --samples 60
# Check log: "[refine] Stage 2 + refine mode both active — double-tuning risk"
```

### CHECKPOINT 4 ✓
- Resume hard-aborts work correctly
- Stage 2 suppressed by default, override works

---

## PHASE 5 — First real refine run (validation)
_Only run after Checkpoints 0–4 all pass. `MEGA_REFINE_FROM` must be `RUN6_ALL`._

```powershell
$env:MEGA_WF_STEP='1500'
$env:MEGA_REFINE_FROM='<RUN6_ALL>'
$env:MEGA_REFINE_TOPN='5'
$env:MEGA_REFINE_SEED_RANK='score'
$env:MEGA_REFINE_VARIANTS='80'
$env:MEGA_REFINE_STRICT_ONLY='1'
$env:MEGA_REFINE_MIX_PCT='0.25'
$env:MEGA_STAGE2_DISABLED_ON_REFINE='1'
py -3 Optimizer_Anti_2.py --samples 150
```

After run:
```powershell
py -3 Analyzer_Anti_2.py --sweep-report mega_results_<runid>_all.csv
```

### CHECKPOINT 5 ✓
Compare `refine` group vs `wide_explore` group in sweep report:
- **Pass**: `refine` group has higher median PF, more strict winners per sample → proceed to 800-combo run
- **Fail**: groups are statistically identical → sigma/bands need adjustment; do **not** scale up

---

## PHASE 6 — Full 800-combo refine run
_Only after Checkpoint 5 passes. `MEGA_REFINE_FROM` must be `RUN6_ALL`._

```powershell
$env:MEGA_WF_STEP='1500'
$env:MEGA_REFINE_FROM='<RUN6_ALL>'
$env:MEGA_REFINE_TOPN='10'
$env:MEGA_REFINE_SEED_RANK='score'
$env:MEGA_REFINE_VARIANTS='80'
$env:MEGA_REFINE_STRICT_ONLY='1'
$env:MEGA_REFINE_MIX_PCT='0.20'
$env:MEGA_STAGE2_DISABLED_ON_REFINE='1'
py -3 Optimizer_Anti_2.py --samples 800
```

Expected output:
- ~640 combos tagged `refine` + `seed_<ID>_<csv6>` + `refine_run_<runid>`
- ~160 combos tagged `wide_explore`
- `mega_refine_seeds_<runid>.json` written at start
- Post-run summary printed: seed-local vs wide stats + per-seed usage

---

## Deferred to v2
- Two-tier Gaussian perturbation (50% tight / 50% 2× sigma)
- Weak-mutate parameter category
- Boundary-hit diagnostic (log when param hits band edge >30% of draws)
- Adaptive mix (auto-increase wide if seed-local viability < 2%)
- Combined refine + Stage 2 mode
- T5 deterministic replay harness
- Exit-template architecture (tagged sampling by exit style family)

---

## Quick reference: all env vars

| Env var | Default | Meaning |
|---|---|---|
| `MEGA_REFINE_FROM` | — | Path to `RUN6_ALL`; activates refine mode. Run 5 CSV hard-banned. |
| `MEGA_REFINE_TOPN` | `10` | Max seeds to load |
| `MEGA_REFINE_SEED_RANK` | `score` | Seed ranking: `score`,`pf`,`eq`,`oospf` (oospf FATAL if T_PF absent) |
| `MEGA_REFINE_VARIANTS` | `80` | Advisory only — no runtime effect. Used to log nominal expected draws and warn if `--samples < VARIANTS*TOPN*0.75` |
| `MEGA_REFINE_MIX_PCT` | `0.20` | Fraction of wide fallback samples |
| `MEGA_REFINE_STRICT_ONLY` | `1` | `1`=strict seeds only, `0`=near-miss allowed |
| `MEGA_STAGE2_DISABLED_ON_REFINE` | `1` | `1`=suppress Stage 2, `0`=allow with warning |
| `MEGA_TEST_REFINE_TAGS` | — | `1`=abort on tag assertion failure |
| `MEGA_ALLOW_UNCERTIFIED_REFINE` | — | `1`=bypass parity seal gates (emergency only) |

---

## Parity battery: three required combos

Do not seal with only one combo. Pick three structurally different styles:

| Slot | Style | Why |
|---|---|---|
| Battery[0] | `ID_03740` — balanced | Initial reference target |
| Battery[1] | a trail-heavy combo (large `agel`, `ages`) | Exercises trailing stop logic |
| Battery[2] | a fast-scalp / small SL combo (small `sll`, `sls`) | Exercises tight stop trigger |

All three must reach zero `MISMATCH` rows before `parity_seal.json` gets `ok=true`.

---

## Step 0.B.0 — Data alignment sanity (run before 0.B.1)

Before diffing trades, confirm the OHLCV datasets are identical:

```powershell
py -3 Analyzer_Anti_2.py --data-align-check tv_trades_ID_03740.csv
```

Print:
- First 3 and last 3 OHLCV bars from Python dataset (timestamp, O, H, L, C)
- Earliest and latest timestamp from the TV trade export
- Confirm Python data covers TV's full date range
- Compute and print `dataset_hash = sha256(ohlcv_file)[:16]`

Store `dataset_hash` in `parity_seal.json`. If Python and TV date ranges don't align, **stop** — OHLCV mismatch is a separate root cause from simulator bugs.

---

## parity_check.ps1 — lightweight CI script

Create once, run after any simulator code change:

```powershell
# parity_check.ps1
$ErrorActionPreference = 'Stop'
Write-Host "[parity] Running battery..."
py -3 Analyzer_Anti_2.py --parity-diff ID_03740 tv_trades_ID_03740.csv
py -3 Analyzer_Anti_2.py --parity-diff <ID_trail_heavy> tv_trades_<ID_trail_heavy>.csv
py -3 Analyzer_Anti_2.py --parity-diff <ID_fast_scalp> tv_trades_<ID_fast_scalp>.csv
Write-Host "[parity] All battery combos passed."
```

If any exits non-zero → do not proceed. Fix simulator, re-run, re-seal.
Update `sim_hash` in `parity_seal.json` after any successful battery run.

---

## --parity-diff alignment contract

Trade rows are aligned by **composite key `(Side, EBar)`** — not by sequential index.

Alignment rules:
- Build two maps: `TV_map[(Side, EBar)] = row`, `PY_map[(Side, EBar)] = row`
- For each key in `union(TV_map, PY_map)`:
  - Present in both: compare `XBar`, `EPx`, `XPx`, `Qty`, `PnL` — flag any delta as `MISMATCH`
  - Present only in TV: print as `EXTRA_TV`
  - Present only in PY: print as `EXTRA_PY`
- Print raw row indices alongside composite key for every mismatched line
- Assert `len(TV_map) == len(PY_map)` first; if unequal, print count diff and continue (don't abort)
- Exit code: 0 if zero MISMATCH/EXTRA rows; 1 otherwise (so `parity_check.ps1` catches it)
