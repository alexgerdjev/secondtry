# SIGNAL PARITY PLAN — v2.4 (Consolidated)
# v2.4 – 2026-04-24
# Consolidates v2.3 and the v2.4 delta patch.
# Adds: structural producer matrix, hardened PredictiveBarView,
# exit precedence contract, analyzer-based strict cert reconciliation,
# proof metadata hardening, and stronger checkpoints.

---

## Overall Intent
This plan separates **signal provenance**, **simulation independence**, and **certification enforcement**.

The target operating modes are:

| Mode | Signal Source | Cert Kind | PredictiveBarView | cert_eligible |
|---|---|---|---|---|
| parity | tv_drow | forensic | Off | No |
| autonomous | py_recalc | none | Off | No |
| compare | compare | forensic diag | Off | No |
| predictive_cert | py_recalc | predictive | On | Yes |

Key principle:
- **Forensic parity** = TV-computed signal-state inputs may be used, but simulation/exits remain Python-driven.
- **Predictive certification** = Python must generate signals and trades without reading TV snapshot keys.

---

## PHASE 0 — Rename & Constants (~20 lines)
**Step 0.1** — In `Optimizer_Anti_2.py`, rename `PINE_TV_FIELD_MAP` → `TV_SIGNAL_FIELD_MAP`.
Find all references in both files and replace. Add comment: "Scalar indicator scalars only — structural fields are separate."

**Step 0.2** — Fix the `conf` key collision:
```python
TV_SIGNAL_FIELD_MAP = {
    "rsi": "brsipy", "zscore": "bzscorepy", "adxz": "badxzpy",
    "velocity": "bvelocitypy", "regime": "bregimepy", "conf": "bconfpy",
}
_PY_FIELD_KEYS = {
    "rsi": "rsi_py", "zscore": "z_py", "adxz": "adx_z_py",
    "velocity": "velocity_py", "regime": "regime_py", "conf": "conf_py",
}
REQUIRED_TV_SIGNAL_FIELDS = list(TV_SIGNAL_FIELD_MAP.values())
```

**CHECKPOINT 0**:
- `grep -n "PINE_TV_FIELD_MAP\|bconfpy" Optimizer_Anti_2.py` returns no stale non-comment hits for the old map name.
- `grep -n "TV_SIGNAL_FIELD_MAP\|conf_py" Optimizer_Anti_2.py` confirms the new names exist.

---

## PHASE 1 — Structural Field Contract (~40 lines)
**Step 1.1** — Add `PYTHON_STRUCTURAL_FIELDS` and `TV_STRUCTURAL_FIELDS` near `TV_SIGNAL_FIELD_MAP`:
```python
PYTHON_STRUCTURAL_FIELDS = {
    "vwap_squeeze":    "vwap_squeeze_py",
    "pullback_long":   "pullback_long_logic_py",
    "pullback_short":  "pullback_short_logic_py",
    "prev_fvg_long":   "prev_fvg_py",
    "prev_fvg_short":  "prev_fvg_s_py",
    "sweep_long":      "sweep_long_py",
    "sweep_short":     "sweep_short_py",
    "nuc_long":        "nuc_l_py",
    "nuc_short":       "nuc_s_py",
    "obv_roc5":        "bobvroc5py",
}
TV_STRUCTURAL_FIELDS = {
    "fvg_long_tv":  "fvg_l_tv",
    "fvg_short_tv": "fvg_s_tv",
    "ob_long_tv":   "ob_l_tv",
    "ob_short_tv":  "ob_s_tv",
}
```

**Step 1.2** — Add strict validation pass after uplift in `precompute_forensic_bars()`:
```python
STRICT_STRUCT_FIELDS = bool(os.getenv("STRICT_STRUCT_FIELDS", "1"))

for bi, bar in enumerate(bars):
    missing = [v for v in PYTHON_STRUCTURAL_FIELDS.values() if v not in bar]
    if STRICT_STRUCT_FIELDS and missing:
        raise ValueError(f"[STRUCT_FIELD_MISSING] bi={bi} missing: {missing}")
    if PREDICTIVE_CERTIFICATION:
        for tv_key in TV_STRUCTURAL_FIELDS.values():
            if bar.get(tv_key) is not None:
                raise RuntimeError(f"[CERT_VIOLATION] TV structural field {tv_key!r} present on bar in predictive mode")
```

Refinement note:
- `STRICT_STRUCT_FIELDS=0` is allowed only for legacy-deck debugging.
- It must remain enabled for certification runs.

---

## PHASE 1A — Structural Producer Matrix
**Purpose** — remove circularity by declaring where each structural field is produced and what default it must have.

**Step 1A.1** — Add:
```python
STRUCTURAL_FIELD_SPECS = {
    "vwap_squeeze_py": {"producer": "precompute_forensic_bars/full_uplift", "required": True, "gate_critical": True, "default": False},
    "pullback_long_logic_py": {"producer": "build_combo_state_deck", "required": True, "gate_critical": True, "default": False},
    "pullback_short_logic_py": {"producer": "build_combo_state_deck", "required": True, "gate_critical": True, "default": False},
    "prev_fvg_py": {"producer": "forensic uplift / lagged structural stamp", "required": True, "gate_critical": True, "default": False},
    "prev_fvg_s_py": {"producer": "forensic uplift / lagged structural stamp", "required": True, "gate_critical": True, "default": False},
    "sweep_long_py": {"producer": "build_combo_state_deck", "required": True, "gate_critical": True, "default": False},
    "sweep_short_py": {"producer": "build_combo_state_deck", "required": True, "gate_critical": True, "default": False},
    "nuc_l_py": {"producer": "build_combo_state_deck", "required": True, "gate_critical": True, "default": 0.0},
    "nuc_s_py": {"producer": "build_combo_state_deck", "required": True, "gate_critical": True, "default": 0.0},
    "bobvroc5py": {"producer": "indicator uplift", "required": True, "gate_critical": True, "default": 0.0},
}
```

**Step 1A.2** — Stamp defaults before validation:
```python
for bar in bars:
    for field_name, spec in STRUCTURAL_FIELD_SPECS.items():
        if spec["required"] and field_name not in bar:
            bar[field_name] = spec["default"]
```

**Step 1A.3** — Validate against `STRUCTURAL_FIELD_SPECS`, not only field-map values.

**CHECKPOINT 1 / 1A**:
- Positive test: `precompute_forensic_bars()` completes and all required structural fields are present.
- Negative test: delete one required structural field from a test bar and confirm `[STRUCT_FIELD_MISSING]` fires.

---

## PHASE 2 — SignalState + Router (~40 lines)
**Step 2.1** — Finalize `SignalState`:
```python
@dataclass
class SignalState:
    source_mode: str
    rsi: float | None = None
    zscore: float | None = None
    adxz: float | None = None
    velocity: float | None = None
    regime: float | None = None
    conf: float | None = None
    tv_fields: dict = field(default_factory=dict)
    py_fields: dict = field(default_factory=dict)
```

**Step 2.2** — `build_py_signal_state()` must use `_PY_FIELD_KEYS`, including `conf_py`.

**Step 2.3** — `get_signal_state()` router must assert:
```python
assert mode in {SIGNAL_SOURCE_TV_DROW, SIGNAL_SOURCE_PY_RECALC, SIGNAL_SOURCE_COMPARE}
```

**CHECKPOINT 2**:
- Unit test all 3 modes on a synthetic bar.
- Confirm `state.source_mode` matches the mode.
- Confirm `state.conf == bconfpy` in TV mode and `state.conf == conf_py` in Py mode.
- Negative test: invalid mode raises immediately.

---

## PHASE 3 — Gate Provenance Cleanup (~50 lines)
**Step 3.1** — Audit `evaluate_long_signal()` and `evaluate_short_signal()`.
Classify every field read:
- `state.*` → OK.
- `PYTHON_STRUCTURAL_FIELDS` values → OK.
- `TV_STRUCTURAL_FIELDS` values → forbidden in predictive gate path.

**Step 3.2** — Replace TV structural reads with Python structural equivalents:
```python
# BEFORE
fvg_bull_lag = bar.get("fvg_l_tv", False)
# AFTER
fvg_bull_lag = bar.get("prev_fvg_py", False)
```
Do the same for short side.

**Step 3.3** — Replace composite `sig_long_py` / `sig_short_py` reads with explicit structural fields.

**Step 3.4** — Remove all `*_tv` reads from gate functions.
Any remaining TV read must be inside a `forensic_` function or guarded by `not PREDICTIVE_CERTIFICATION`.

**CHECKPOINT 3**:
```bash
grep -n "_tv" Optimizer_Anti_2.py | grep -v "forensic_\|#\|PREDICTIVE_CERTIFICATION"
```
must return zero lines inside gate functions.

---

## PHASE 4 — Oracle-Blind Enforcement (~30 lines)
**Step 4.1** — Add `PREDICTIVE_CERTIFICATION` and `PredictiveBarView` base guard.

**Step 4.2** — In `simulate()`, wrap bars only in certification mode:
```python
bar_iter = [PredictiveBarView(b) for b in bars] if PREDICTIVE_CERTIFICATION else bars
```
Performance note: wrap once before the hot loop.

**Step 4.3** — Add provenance label:
```python
label = "[PREDICTIVE — ORACLE-BLIND]" if PREDICTIVE_CERTIFICATION else "[FORENSIC — TV-ASSISTED]"
print(label)
```

---

## PHASE 4A — Hardened PredictiveBarView
**Step 4A.1** — Expand `PredictiveBarView` to protect:
- `__getitem__`
- `get`
- `__contains__`
- `keys`
- `items`
- `values`
- `update`
- `setdefault`
- `pop`

Reference implementation:
```python
class PredictiveBarView(dict):
    def _guard(self, k):
        if PREDICTIVE_CERTIFICATION and k in TV_SNAPSHOT_KEYS:
            raise RuntimeError(f"[CERT_VIOLATION] TV key {k!r} accessed in predictive mode")

    def __getitem__(self, k):
        self._guard(k)
        return super().__getitem__(k)

    def get(self, k, default=None):
        self._guard(k)
        return super().get(k, default)

    def __contains__(self, k):
        self._guard(k)
        return super().__contains__(k)

    def keys(self):
        if PREDICTIVE_CERTIFICATION:
            return [k for k in super().keys() if k not in TV_SNAPSHOT_KEYS]
        return super().keys()

    def items(self):
        if PREDICTIVE_CERTIFICATION:
            return [(k, v) for k, v in super().items() if k not in TV_SNAPSHOT_KEYS]
        return super().items()

    def values(self):
        if PREDICTIVE_CERTIFICATION:
            return [v for k, v in super().items() if k not in TV_SNAPSHOT_KEYS]
        return super().values()

    def update(self, other=None, **kwargs):
        payload = {}
        if other:
            payload.update(dict(other))
        payload.update(kwargs)
        if PREDICTIVE_CERTIFICATION:
            bad = [k for k in payload if k in TV_SNAPSHOT_KEYS]
            if bad:
                raise RuntimeError(f"[CERT_VIOLATION] attempted TV key inject: {bad}")
        return super().update(payload)

    def setdefault(self, k, default=None):
        self._guard(k)
        return super().setdefault(k, default)

    def pop(self, k, default=None):
        self._guard(k)
        return super().pop(k, default)
```

**CHECKPOINT 4 / 4A**:
- `bar["fvg_l_tv"]` raises.
- `bar.get("fvg_l_tv")` raises.
- `"fvg_l_tv" in bar` raises.
- `list(bar.keys())` excludes TV keys.
- `bar.update({"fvg_l_tv": 1})` raises.

---

## PHASE 5A — RSI/EXH Exit Queue Semantics (~30 lines)
**Step 5A.1** — Confirm an indicator-exit queue exists. Prefer reusing the existing `pendingindicatorexit` path if already present.

**Step 5A.2** — At the top of each bar’s processing, resolve eligible queued indicator exits at the current open.

**Step 5A.3** — When RSI/EXH triggers, queue for next-bar execution instead of same-bar fill.

Golden rule:
- indicator-triggered close on bar N → fill at earliest eligible bar N+1 open,
- unless the position was already closed by a higher-precedence protective exit first.

---

## PHASE 5B — Protective Order Exit (Pointer)
Add comment block in exit engine:
```python
# PROTECTIVE ORDER EXITS (SL / TP / TRAIL):
# Governed by Master Plan Phase 5 (intrabar path, O→H/L→L/H→C).
# Precedence defined in Phase 5C.
# Trail activation: arm at bar close, first eligible hit on NEXT bar.
# See: process_exit_for_bar() — not redefined in this phase.
```

No direct SL/TP/Trail logic change in this phase unless needed to align with Phase 5C.

---

## PHASE 5C — Exit Precedence Contract
**Purpose** — define interaction between protective exits and queued indicator exits.

**Step 5C.1** — One authoritative order must be codified after reviewing current `process_exit_for_bar()` and `pendingindicatorexit` flow:
1. Protective exits (`SL`, `TP`, `TRAIL`) for the current bar
2. Previously queued indicator exit fill at current bar open
3. New indicator exit detection on current bar
4. Session liquidation

If the current engine already implements a slightly different but Pine-faithful ordering, preserve it and document it explicitly. Do not create a second contradictory queue model.

**Step 5C.2** — Use a structured queue payload:
```python
pending_exit = {
    "reason": "RSI",
    "origin_bi": bi,
    "effective_bi": bi + 1,
    "priority": 10,
}
```

**Step 5C.3** — Define indicator precedence:
```python
INDICATOR_EXIT_PRIORITY = {
    "EXH": 10,
    "RSI": 20,
}
```
Keep only the highest-priority queued indicator exit per open position.

**Step 5C.4** — Cancellation rule:
- No cancellation once queued.
- If a protective exit closes the position first, clear the queued indicator exit.

**CHECKPOINT 5A / 5B / 5C**:
- Bar N RSI → fills at bar N+1 open, not same-bar.
- Same-bar RSI + EXH → deterministic winner.
- Queued RSI + protective SL before execution → one close only, queue cleared.
- No double-exit possible.

---

## PHASE 6 — Analyzer Strict Cert Mode (~40 lines)
**Step 6.1** — Add `--mode strict_predictive_cert` to Analyzer parser.

**Step 6.2** — When mode is `strict_predictive_cert`, set:
```python
os.environ["MEGA_SIGNAL_SOURCE"] = "py_recalc"
optimizer.PREDICTIVE_CERTIFICATION = True
optimizer.PARITY_MODE = False
```

---

## PHASE 6A — Replace Naive Cert Matching
**Purpose** — certification must use Analyzer reconciliation, not positional `zip()`.

**Step 6A.1** — Reuse analyzer reconciliation:
```python
py_trades = results[-1] if isinstance(results, (list, tuple)) else []
matches, scorecard, ghosttrades, targetcount = analyzer.reconcile(py_trades, "strict_predictive_cert")
```

**Step 6A.2** — Oracle selection:
- primary = `analyzer.tvledger`
- fallback = mapped external trade list
- fail closed if neither exists

**Step 6A.3** — PASS condition:
```python
clean = (
    targetcount > 0 and
    matches == targetcount and
    not ghosttrades and
    all(not str(r.get("status", "")).startswith(("EXTRA-TV", "GHOST")) for r in scorecard)
)
```

**Step 6A.4** — On fail, print first mismatch row from scorecard.

**CHECKPOINT 6A**:
- count mismatch → explicit fail,
- side mismatch → explicit fail,
- shuffled PY trade order still reconciles correctly,
- chart-local/UTC normalization works.

---

## PHASE 6B — Proof Metadata Hardening
**Step 6B.1** — On PASS, write proof JSON with version/config metadata:
```python
proof = {
    "combo_id": combo_id,
    "signal_source": "py_recalc",
    "certification_kind": "predictive",
    "predictive_certification": True,
    "oracle_kind": oracle_kind,
    "schema_id": getattr(analyzer, "schema_id", None),
    "optimizer_version": OPTIMIZER_VERSION,
    "analyzer_version": getattr(analyzer, "ANALYZER_VERSION", None),
    "ohlcv_hash": hash_file(ohlcv_path),
    "params_hash": hash_dict(params),
    "config_hash": hash_dict({
        "signal_source": "py_recalc",
        "predictive_certification": True,
        "process_orders_on_close": False,
        "timezone": "Europe/Sofia",
        "strict_struct_fields": bool(optimizer.STRICT_STRUCT_FIELDS),
    }),
    "tolerance_profile": {
        "entry_price_abs": max(float(getattr(optimizer, "TICKSIZE", 0.01)), 1e-6),
        "exit_price_abs": max(float(getattr(optimizer, "TICKSIZE", 0.01)), 1e-6),
        "entry_time_seconds": 0,
        "exit_time_seconds": 0,
        "pnl_abs": 1e-6,
    },
    "timezone": "Europe/Sofia",
    "process_orders_on_close": False,
    "tv_trades": len(analyzer.tvledger) if analyzer.tvledger else len(tv_trades),
    "py_trades": len(py_trades),
    "target_count": targetcount,
    "matches": matches,
    "ghost_trades": len(ghosttrades),
    "first_mismatch": bad,
    "cert_timestamp": datetime.utcnow().isoformat(),
}
```

**Step 6B.2** — Fail closed if timezone metadata is absent or inconsistent unless an intentional fallback policy is documented.

**CHECKPOINT 6 / 6A / 6B**:
- `--mode strict_predictive_cert` prints `[PREDICTIVE — ORACLE-BLIND]`.
- PASS only when reconciliation and proof writing both succeed.
- FAIL prints a meaningful first mismatch payload.

---

## PHASE 7 — Mode Table Fix (~5 lines)
Update docs/comments to keep the authoritative mode table in sync:

| Mode | Signal Source | Cert Kind | PredictiveBarView | cert_eligible |
|---|---|---|---|---|
| parity | tv_drow | forensic | Off | No |
| autonomous | py_recalc | none | Off | No |
| compare | compare | forensic diag | Off | No |
| predictive_cert | py_recalc | predictive | On | Yes |

**CHECKPOINT 7**:
- No call site may set `certification_kind="predictive"` without also setting `PREDICTIVE_CERTIFICATION=True`.

---

## PHASE 8 — Gate Provenance Matrix (Appendix)
Maintain a gate provenance declaration.

```python
# GATE_PROVENANCE_MATRIX — every input to evaluate_long/short_signal()
# state.rsi               | SignalState
# state.zscore            | SignalState
# state.adxz              | SignalState
# state.velocity          | SignalState
# state.regime            | SignalState
# state.conf              | SignalState
# vwap_squeeze_py         | Py structural
# pullback_long_logic_py  | Py structural
# pullback_short_logic_py | Py structural
# sweep_long_py           | Py structural
# sweep_short_py          | Py structural
# prev_fvg_py             | Py structural
# prev_fvg_s_py           | Py structural
# nuc_l_py                | Py structural
# nuc_s_py                | Py structural
# bobvroc5py              | Py structural
# fvg_l_tv (REMOVED)      | TV snapshot | replaced by prev_fvg_py
```

---

## PHASE 8A — Runtime Gate Provenance Check
Optional CI enforcement:
```python
GATE_PROVENANCE_MATRIX = {
    "state.rsi": "SignalState",
    "state.zscore": "SignalState",
    "state.adxz": "SignalState",
    "state.velocity": "SignalState",
    "state.regime": "SignalState",
    "state.conf": "SignalState",
    "vwap_squeeze_py": "Py structural",
    "pullback_long_logic_py": "Py structural",
    "pullback_short_logic_py": "Py structural",
    "sweep_long_py": "Py structural",
    "sweep_short_py": "Py structural",
    "prev_fvg_py": "Py structural",
    "prev_fvg_s_py": "Py structural",
    "nuc_l_py": "Py structural",
    "nuc_s_py": "Py structural",
    "bobvroc5py": "Py structural",
}
ENFORCE_GATE_MATRIX = os.getenv("ENFORCE_GATE_MATRIX", "0").strip() in ("1", "true", "yes")
```

Rule:
- Any new gate input must be added to this matrix first.

**CHECKPOINT 8 / 8A**:
- PR review rule: no new gate input without provenance entry.
- Optional CI runtime assertion in certification builds.

---

## WHAT THIS PLAN DOES NOT COVER
- SL/TP/Trail intrabar path construction (Master Plan Phase 5)
- Checkpoint prefix invariance (Master Plan Phase 2)
- Regression wall / CI gates (Master Plan Phase 7)
- Performance sweep optimization
- Batch certification orchestration across many combos
- Resume/checkpoint mid-bar simulation semantics

---

## EXECUTION ORDER
```text
Phase 0
→ Phase 1
→ Phase 1A
→ Phase 2
→ CHECKPOINT 2
→ Phase 3
→ CHECKPOINT 3
→ Phase 4
→ Phase 4A
→ CHECKPOINT 4A
→ Phase 5A
→ Phase 5B
→ Phase 5C
→ CHECKPOINT 5C
→ Phase 6
→ Phase 6A
→ Phase 6B
→ CHECKPOINT 6A
→ Phase 7
→ Phase 8
→ Phase 8A
→ DONE: [CERT: PASS] only when reconciliation + proof metadata both pass
```

---

## Final Standard
The plan is complete when all of the following are true:
- predictive mode cannot read or inject TV snapshot keys,
- gate decisions are sourced only from declared SignalState or Python structural fields,
- exit precedence is explicitly documented and single-path,
- certification uses analyzer reconciliation rather than positional trade pairing,
- proof artifacts include version, schema, config, oracle, and tolerance metadata.
