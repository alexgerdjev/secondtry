# SIGNAL PARITY PLAN — v2.3 (Actionable)

# v2.3 – 2026-04-23

# Changes from v2.2: added STRICT_STRUCT_FIELDS flag note (Phase 1)

# confirmed PredictiveBarView wrap-once pattern (Phase 4)

# noted trade-matcher placeholder (Phase 6); added runtime matrix check option (Phase 8)

# v2.2 changes: renamed TV_SIGNAL_FIELD_MAP; fixed conf key collision

# added structural field contract; completed gate provenance; added Phase 5B

# fixed mode table; added "not covered" section; added Gate Provenance Matrix

---

## PHASE 0 — Rename & Constants (~20 lines)

**Step 0.1** — In `Optimizer_Anti_2.py`, rename `PINE_TV_FIELD_MAP` → `TV_SIGNAL_FIELD_MAP`.
Find all references in both files and replace. Add comment: "Scalar indicator scalars only — structural fields are separate."

**Step 0.2** — Fix the `conf` key collision (~10 lines):

```python
TV_SIGNAL_FIELD_MAP = {
    "rsi": "brsipy", "zscore": "bzscorepy", "adxz": "badxzpy",
    "velocity": "bvelocitypy", "regime": "bregimepy", "conf": "bconfpy",
}
_PY_FIELD_KEYS = {
    "rsi": "rsi_py", "zscore": "z_py", "adxz": "adx_z_py",
    "velocity": "velocity_py", "regime": "regime_py", "conf": "conf_py",  # NOT bconfpy
}
```

`REQUIRED_TV_SIGNAL_FIELDS = list(TV_SIGNAL_FIELD_MAP.values())`

**CHECKPOINT 0**: `grep -n "PINE_TV_FIELD_MAP\|bconfpy" Optimizer_Anti_2.py` returns zero hits in non-comment code.

---

## PHASE 1 — Structural Field Contract (~40 lines)

**Step 1.1** — Add `PYTHON_STRUCTURAL_FIELDS` dict near `TV_SIGNAL_FIELD_MAP`:

```python
PYTHON_STRUCTURAL_FIELDS = {
    # key: bar dict key, computed by Python only, all modes
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
    # TV-origin structural fields — diagnostic/forensic only, never in gate decisions
    "fvg_long_tv":  "fvg_l_tv",
    "fvg_short_tv": "fvg_s_tv",
    "ob_long_tv":   "ob_l_tv",
    "ob_short_tv":  "ob_s_tv",
}
```

**Step 1.2** — In `precompute_forensic_bars()`, after existing uplift, add a validation pass (~15 lines):

```python
for bi, bar in enumerate(bars):
    missing = [v for v in PYTHON_STRUCTURAL_FIELDS.values() if v not in bar]
    if missing:
        raise ValueError(f"[STRUCT_FIELD_MISSING] bi={bi} missing: {missing}")
    # In predictive cert mode: confirm no TV structural key was read
    if PREDICTIVE_CERTIFICATION:
        for tv_key in TV_STRUCTURAL_FIELDS.values():
            if bar.get(tv_key) is not None:
                raise RuntimeError(f"[CERT_VIOLATION] TV structural field {tv_key!r} present on bar in predictive mode")
```

> **Refinement note**: If legacy decks legitimately omit some structural fields, gate
> this validation behind `STRICT_STRUCT_FIELDS = bool(os.getenv("STRICT_STRUCT_FIELDS", "1"))`.  
> Default is strict (raises). Set to `0` only for legacy deck debugging — never in certification runs.

**CHECKPOINT 1**: Run `precompute_forensic_bars()` on known OHLCV. Confirm no `ValueError` fires. Confirm all structural fields present.

---

## PHASE 2 — SignalState + Router (~40 lines)

**Step 2.1** — Finalize `SignalState` (already exists, just confirm fields):

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

**Step 2.2** — Fix `build_py_signal_state()` to use `_PY_FIELD_KEYS` (now with `conf_py`). No other changes needed.

**Step 2.3** — Confirm `get_signal_state()` router produces TV state in `tv_drow`/`compare`, Python state in `py_recalc`. Add assertion:

```python
assert mode in {SIGNAL_SOURCE_TV_DROW, SIGNAL_SOURCE_PY_RECALC, SIGNAL_SOURCE_COMPARE}
```

**CHECKPOINT 2**: Unit test — call `get_signal_state(bar, ...)` in each of 3 modes on a synthetic bar. Confirm `state.source_mode` matches. Confirm `state.conf` maps to `bconfpy` in TV mode and `conf_py` in Py mode.

---

## PHASE 3 — Gate Provenance Cleanup (~50 lines)

**Step 3.1** — Audit `evaluate_long_signal()` and `evaluate_short_signal()`. For each field read, classify:

- Via `state.*` → OK (SignalState).
- Via `PYTHON_STRUCTURAL_FIELDS` keys → OK (stamped by precompute).
- Via `TV_STRUCTURAL_FIELDS` keys (`fvg_l_tv` etc.) → **REMOVE from gate path**.

**Step 3.2** — Replace `fvg_l_tv` reads in gate functions with `prev_fvg_py`:

```python
# BEFORE (TV-origin, forbidden in predictive mode):
fvg_bull_lag = bar.get("fvg_l_tv", False)
# AFTER (Python-origin, always available):
fvg_bull_lag = bar.get("prev_fvg_py", False)
```

Same for short side. Confirm `prev_fvg_py` is stamped in `precompute_forensic_bars()`.

**Step 3.3** — Replace composite `sig_long_py` / `sig_short_py` reads with explicit structural fields:

```python
# BEFORE:
if bar.get("sig_long_py"):
# AFTER:
sweep_ok = bar.get("sweep_long_py", False)
pullback_ok = bar.get("pullback_long_logic_py", False)
if sweep_ok or pullback_ok:
```

**Step 3.4** — Remove all `*_tv` reads from gate functions. Any remaining `*_tv` read must be inside a function prefixed `forensic_` or guarded by `not PREDICTIVE_CERTIFICATION`.

**CHECKPOINT 3**: `grep -n "_tv" Optimizer_Anti_2.py | grep -v "forensic_\|#\|PREDICTIVE_CERTIFICATION"` returns zero lines inside gate functions.

---

## PHASE 4 — Oracle-Blind Enforcement (~30 lines)

**Step 4.1** — Add `PREDICTIVE_CERTIFICATION` flag and `PredictiveBarView`:

```python
PREDICTIVE_CERTIFICATION: bool = False

TV_SNAPSHOT_KEYS: frozenset = frozenset({
    "z_tv","rsi_tv","velocity_tv","adxz_tv","regime_tv",
    "atr_tv","atr20_tv","obv_tv","fvg_l_tv","fvg_s_tv","ob_l_tv","ob_s_tv",
})

class PredictiveBarView(dict):
    def __getitem__(self, k):
        if PREDICTIVE_CERTIFICATION and k in TV_SNAPSHOT_KEYS:
            raise RuntimeError(f"[CERT_VIOLATION] TV key {k!r} accessed in predictive mode")
        return super().__getitem__(k)
    def get(self, k, default=None):
        if PREDICTIVE_CERTIFICATION and k in TV_SNAPSHOT_KEYS:
            raise RuntimeError(f"[CERT_VIOLATION] TV key {k!r} accessed in predictive mode")
        return super().get(k, default)
```

**Step 4.2** — In `simulate()`, wrap bars only in certification mode:

```python
bar_iter = [PredictiveBarView(b) for b in bars] if PREDICTIVE_CERTIFICATION else bars
```

> **Performance note**: The list comprehension wraps all bars **once before the hot loop**, not per-bar inside it.
> Overhead is O(N) dict subclass construction — acceptable for targeted cert runs, never enabled in sweep/optimize mode.

**Step 4.3** — Add provenance label to all output:

```python
label = "[PREDICTIVE — ORACLE-BLIND]" if PREDICTIVE_CERTIFICATION else "[FORENSIC — TV-ASSISTED]"
print(label)
```

**CHECKPOINT 4**: Set `PREDICTIVE_CERTIFICATION=True`, run simulate on a bar with `fvg_l_tv` in the bar dict. Confirm `RuntimeError` fires. Set `False`, confirm no error.

---

## PHASE 5A — RSI/EXH Exit Queue Semantics (~30 lines)

**Step 5A.1** — Confirm exit state machine has a `pending_close` queue. If not, add:

```python
# In position state, track queued exits:
pending_exit: dict | None = None  # {"reason": "RSI", "bar_i": N}
```

**Step 5A.2** — In the simulation bar loop, at the TOP of each bar's processing:

```python
# Step 1: Resolve any pending prior-bar queued exit at current open
if pending_exit and pending_exit["bar_i"] == bi - 1:
    fill_price = bar["open"]
    close_position(fill_price, reason=pending_exit["reason"], bi=bi)
    pending_exit = None
```

**Step 5A.3** — When RSI/EXH condition fires during bar evaluation, do NOT close immediately. Queue it:

```python
if rsi_exit_condition and position_open:
    pending_exit = {"reason": "RSI", "bar_i": bi}
    # Fill will happen at open of bi+1
```

**CHECKPOINT 5A**: Golden test — bar N fires RSI condition. Assert position closed at bar N+1 open. Assert no same-bar close.

---

## PHASE 5B — Protective Order Exit (Pointer)

**Step 5B.1** — Add comment block in exit engine:

```python
# PROTECTIVE ORDER EXITS (SL / TP / TRAIL):
# Governed by Master Plan Phase 5 (intrabar path, O→H/L→L/H→C).
# Precedence: SL first, then TP, then Trail (per Pine tie-break).
# Trail activation: arm at bar close, first eligible hit on NEXT bar.
# See: process_exit_for_bar() — not modified in this phase.
```

No code changes to SL/TP/Trail in this phase. Keep existing logic. Verify consistency with RSI/EXH queue by checking no double-exit possible.

**CHECKPOINT 5B**: Confirm that a bar with both RSI queue and SL hit resolves correctly — pending RSI fill at next open, then if SL is also hit during that bar's intrabar walk, the first to fill wins (SL intrabar precedes RSI-at-open). Document the tie-break decision.

---

## PHASE 6 — Analyzer Strict Cert Mode (~40 lines)

**Step 6.1** — Add `--mode strict_predictive_cert` to Analyzer argument parser.

**Step 6.2** — When mode is `strict_predictive_cert`, set:

```python
os.environ["MEGA_SIGNAL_SOURCE"] = "py_recalc"
optimizer.PREDICTIVE_CERTIFICATION = True
optimizer.PARITY_MODE = False
```

**Step 6.3** — Run simulate, collect `py_trades`. Load TV trades from `--trades_csv`. Compare:

```python
for i, (py, tv) in enumerate(zip(py_trades, tv_trades)):
    for field in ["side","entry_bar","exit_bar","entry_price","exit_price","pnl"]:
        if not matches(py[field], tv[field], field):
            print(f"[CERT: FAIL] Trade {i} field={field} py={py[field]} tv={tv[field]}")
            return
print("[CERT: PASS]")
```

> **Placeholder note**: `zip()` assumes equal length and same ordering. For the real implementation,
> use the existing `emit_trade_comparison_table()` reconciliation function (side + time matching)
> rather than positional zip. The stub above is correct for a first cert run but must be replaced
> before treating results as production-grade proof.

**Step 6.4** — On PASS, write proof JSON:

```python
proof = {
    "combo_id": combo_id, "signal_source": "py_recalc",
    "certification_kind": "predictive", "predictive_certification": True,
    "ohlcv_hash": hash_file(ohlcv_path), "params_hash": hash_dict(params),
    "optimizer_version": OPTIMIZER_VERSION,
    "timezone": "Europe/Sofia", "process_orders_on_close": False,
    "tv_trades": len(tv_trades), "py_trades": len(py_trades),
    "first_mismatch": None, "cert_timestamp": datetime.utcnow().isoformat(),
}
```

**CHECKPOINT 6**: Run `--mode strict_predictive_cert` on ID_00779. Confirm `[PREDICTIVE — ORACLE-BLIND]` prints. Confirm `[CERT: PASS]` or meaningful `[CERT: FAIL]` with exact field/trade identified.

---

## PHASE 7 — Mode Table Fix (~5 lines)

**Step 7.1** — Update the mode table in docs/comments to add `cert_eligible` column:

| Mode | Signal Source | Cert Kind | PredictiveBarView | cert_eligible |
|---|---|---|---|---|
| parity | tv_drow | forensic | Off | No |
| autonomous | py_recalc | none | Off | **No** |
| compare | compare | forensic diag | Off | No |
| predictive_cert | py_recalc | predictive | **On** | **Yes** |

**CHECKPOINT 7**: Code review — confirm no call site sets `certification_kind="predictive"` without also setting `PREDICTIVE_CERTIFICATION=True`.

---

## PHASE 8 — Gate Provenance Matrix (Appendix)

**Step 8.1** — Create `GATE_PROVENANCE_MATRIX` dict in Optimizer as a comment block:
> **Runtime check option**: For stronger enforcement, maintain `GATE_PROVENANCE_MATRIX` as a live
> Python dict (not just comments) and assert at simulation start that every field key present in
> `evaluate_long_signal` / `evaluate_short_signal` locals has an entry. This is a nice-to-have
> for CI — not required for first cert run.

```python
# GATE_PROVENANCE_MATRIX — every input to evaluate_long/short_signal()
# Field                  | Source       | Phase
# ---------------------- | ------------ | ------
# state.rsi              | SignalState  | Phase 2
# state.zscore           | SignalState  | Phase 2
# state.adxz             | SignalState  | Phase 2
# state.velocity         | SignalState  | Phase 2
# state.regime           | SignalState  | Phase 2
# state.conf             | SignalState  | Phase 2
# vwap_squeeze_py        | Py structural| Phase 1
# pullback_long_logic_py | Py structural| Phase 1
# sweep_long_py          | Py structural| Phase 1
# prev_fvg_py            | Py structural| Phase 1
# nuc_l_py               | Py structural| Phase 1
# bobvroc5py             | Py structural| Phase 1
# fvg_l_tv (REMOVED)     | TV snapshot  | Phase 3 — replaced by prev_fvg_py
```

**CHECKPOINT 8**: Any new field added to gate functions must be added to this matrix first. PR review rule.

---

## WHAT THIS PLAN DOES NOT COVER

- SL/TP/Trail intrabar path construction (Master Plan Phase 5)
- Checkpoint prefix invariance (Master Plan Phase 2)
- Regression wall / CI gates (Master Plan Phase 7)
- Performance sweep optimization

---

## EXECUTION ORDER

```
Phase 0 → Phase 1 → Phase 2 → CHECKPOINT 2 (unit test)
→ Phase 3 → CHECKPOINT 3 (grep audit)
→ Phase 4 → CHECKPOINT 4 (crash test)
→ Phase 5A → CHECKPOINT 5A (golden test)
→ Phase 5B (doc only)
→ Phase 6 → CHECKPOINT 6 (first cert run on ID_00779)
→ Phase 7 → Phase 8
→ DONE: [CERT: PASS] on ID_00779
```
