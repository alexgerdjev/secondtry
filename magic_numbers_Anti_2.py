#!/usr/bin/env python3
"""
magic_numbers â€” single entry point: mega_results CSV row â†’ Trading_strategy_Cursor.pine inputs.

Usage:
  py -3 magic_numbers.py --combo ID_05444
  py -3 magic_numbers.py --combo ID_05444 --csv path/to/mega_results_*.csv
  py -3 magic_numbers.py --combo ID_05444 --dry-run          # no write; still verifies vs CSV
  py -3 magic_numbers.py --combo ID_05444 --no-verify       # patch without verification
  py -3 magic_numbers.py --verify-only --combo ID_05444     # full GS66 audit (49 params + parity tag)
  py -3 magic_numbers.py --verify-only --loose-floats ...   # tolerate float formatting drift

Replaces scattered scripts (update_pine.py, update_pine_fixed.py): use only this for transfers.
"""

from __future__ import annotations

import argparse
import csv
import glob
import os
import re
import sys
import json
from typing import Any, Dict, List, Optional, Set, Tuple

# Add Script Dir to path for optional optimizer import (trade reporting).
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(SCRIPT_DIR)
try:
    import importlib.util
    _spec = importlib.util.spec_from_file_location("optimizer", os.path.join(SCRIPT_DIR, "Optimizer_Anti_2.py"))
    optimizer = importlib.util.module_from_spec(_spec)
    sys.modules["optimizer"] = optimizer  # must register before exec_module (mirrors Analyzer_Anti_2.py)
    _spec.loader.exec_module(optimizer)
except Exception as _e:
    print(f"[!] Warning: Could not import Optimizer: {_e}")
    optimizer = None
DEFAULT_PINE = os.path.join(SCRIPT_DIR, "Trading_strategy_Anti_2.pine")

import zenith_schema  # noqa: E402 - after SCRIPT_DIR on sys.path

# --- GS66: one Pine transfer target per zenith_schema.CSV_PARAM_KEYS entry (49 params) ---
MAGIC_PARAM_COUNT = 0  # assigned after MAGIC_MAP is declared
MAGIC_PARAMS_DOC = """
GS66: MAGIC_MAP mirrors zenith_schema.CSV_PARAM_KEYS (49 params, exact set enforced at import).
Call verify_all_gs66_params_transferred() to audit non-empty CSV cells, Pine input defaults,
Section L PRO literals, and the optional PARITY ACTIVE banner versus ComboID.

The optimizer writes strategy-tuned values per combo after the metric block.
Legacy mega_results used Pascal headers below; new sweeps use zenith_schema GS66 lowercase
canonical names (e.g. sll, slfloorpct). _mega_csv_cell reads both lowercase and Pascal cells.

SLL, SLS, FloorPct, CapPct,
ModeAR, ModeBR_L, ModeBR_S,
TrailActL, TrailActS, TLv, TMv, THv,
NucL, NucS, ConfL, ConfS,
AdxL, AdxS, VelHigh, VelMed,
RsiExL, RsiExS, CdL, CdS,
ChopM, AdxD, UseA, UseB, AdxG, VelG,
MaxRsiL, MaxRsiS, MaxZL, MaxZS,
AgeL, AgeS,
zL, zS, rL, rS,
SwpTol, UseExh,
ExhVelL, ExhZL, ExhVelS, ExhZS, ExhRegime,
RsiLMild, RsiSMild

The exact mapped count is derived from len(MAGIC_MAP).
Inputs not represented in the live CSV schema remain unchanged unless explicitly mapped.
"""

# Pine var â†’ (csv column, kind, scale)
# kind: "float" | "int" | "bool"
# scale: None | "pct_x100" (CSV is 0â€“1 fraction, Pine input shows percent Ã— 100 before /100)
PineField = Tuple[str, str, Optional[str]]

# Legacy Pascal headers -> canonical GS66 CSV keys (shared with Optimizer zenith_schema.CSV_PARAM_KEYS).
MEGA_PASCAL_PARAM_ALIASES: List[Tuple[str, str, str]] = [
    ("RiskL", "riskl", "float"),
    ("RiskS", "risks", "float"),
    ("SLL", "sll", "float"),
    ("SLS", "sls", "float"),
    ("FloorPct", "slfloorpct", "float"),
    ("CapPct", "slcappct", "float"),
    ("ModeAR", "modear", "float"),
    ("ModeBR_L", "modebrlong", "float"),
    ("ModeBR_S", "modebrshort", "float"),
    ("TrailActL", "trailactivationlong", "float"),
    ("TrailActS", "trailactivationshort", "float"),
    ("TLv", "traillv", "float"),
    ("TMv", "trailmv", "float"),
    ("THv", "trailhv", "float"),
    ("NucL", "nucl", "float"),
    ("NucS", "nucs", "float"),
    ("ConfL", "confl", "int"),
    ("ConfS", "confs", "int"),
    ("AdxL", "adxl", "float"),
    ("AdxS", "adxs", "float"),
    ("VelHigh", "velhigh", "float"),
    ("VelMed", "velmed", "float"),
    ("RsiExL", "rsiexl", "float"),
    ("RsiExS", "rsiexs", "float"),
    ("CdL", "cdl", "int"),
    ("CdS", "cds", "int"),
    ("ChopM", "chopmult", "float"),
    ("AdxD", "adxdec", "float"),
    ("UseA", "usea", "bool"),
    ("UseB", "useb", "bool"),
    ("AdxG", "adxgate", "float"),
    ("VelG", "velgate", "float"),
    ("MaxRsiL", "maxrsil", "int"),
    ("MaxRsiS", "maxrsis", "int"),
    ("MaxZL", "maxzl", "float"),
    ("MaxZS", "maxzs", "float"),
    ("AgeL", "agel", "int"),
    ("AgeS", "ages", "int"),
    ("zL", "zl", "float"),
    ("zS", "zs", "float"),
    ("rL", "rl", "float"),
    ("rS", "rs", "float"),
    ("SwpTol", "sweeptolatr", "float"),
    ("UseExh", "useexhaustionexit", "bool"),
    ("ExhVelL", "exhvell", "float"),
    ("ExhZL", "exhzl", "float"),
    ("ExhVelS", "exhvels", "float"),
    ("ExhZS", "exhzs", "float"),
    ("ExhRegime", "exhregime", "bool"),
    ("RsiLMild", "rsilmild", "float"),
    ("RsiSMild", "rsismild", "float"),
    ("StrictRegimeSync", "strictregimesync", "bool"),
    ("UseChopFilter", "usechopfilter", "bool"),
    ("EMAPersistBars", "emapersistbars", "int"),
]

_P2C = {p: c for p, c, _ in MEGA_PASCAL_PARAM_ALIASES}

_LEGACY_MEGA_ROW_WARNED = False


def _detect_csv_column_shift(row: Dict[str, str]) -> Dict[str, str]:
    """Detect and fix column shift corruption for ID_02353.
    
    Issue: agel/ages values (21, 13) appear in cdl/cds columns.
    Detection: agel < ages OR agel < 10 indicates corruption.
    Fix: Swap agel <-> cdl, ages <-> cds if pattern detected.
    """
    fixes = {}
    try:
        agel = int(row.get("agel", "0") or "0")
        ages = int(row.get("ages", "0") or "0")
        cdl = int(row.get("cdl", "0") or "0")
        cds = int(row.get("cds", "0") or "0")
        
        # Column shift heuristic disabled â€” GS66 canonical CSV headers store values correctly.
        pass
    except (ValueError, TypeError):
        pass
    return fixes


def _mega_csv_cell(row: Dict[str, str], canon_csv_key: str) -> str:
    """Read param cell for GS66 header (canon key) or legacy mega_results (Pascal alias).
    Includes auto-fix for known CSV corruption (ID_02353 column shift)."""
    
    # Check for column shift fix first
    fixes = _detect_csv_column_shift(row)
    if canon_csv_key in fixes:
        return fixes[canon_csv_key]
    
    raw = row.get(canon_csv_key)
    if raw is not None and str(raw).strip() != "":
        return str(raw)
    for pascal, c, _ in MEGA_PASCAL_PARAM_ALIASES:
        if c != canon_csv_key:
            continue
        alt = row.get(pascal)
        if alt is not None and str(alt).strip() != "":
            return str(alt)
    return ""


_GS66_CSV_TO_PINE: Dict[str, Tuple[str, Optional[str]]] = {
    "riskl": ("f_risk_long", None),
    "risks": ("f_risk_short", None),
    "sll": ("i_sl_atr_mult_long", None),
    "sls": ("i_sl_atr_mult_short", None),
    "slfloorpct": ("f_sl_floor_pct", "pct_x100"),
    "slcappct": ("f_sl_cap_pct", "pct_x100"),
    "modear": ("i_mode_a_r", None),
    "modebrlong": ("i_mode_b_r_long", None),
    "modebrshort": ("i_mode_b_r_short", None),
    "trailactivationlong": ("i_trail_activation_long", None),
    "trailactivationshort": ("i_trail_activation_short", None),
    "traillv": ("i_trail_lv", None),
    "trailmv": ("i_trail_mv", None),
    "trailhv": ("i_trail_hv", None),
    "nucl": ("i_nuc_threshold", None),
    "nucs": ("i_nuc_threshold_s", None),
    "confl": ("i_confluence_min", None),
    "confs": ("i_confluence_min_s", None),
    "usea": ("i_use_reversal", None),
    "useb": ("i_use_continuation", None),
    "adxl": ("i_min_adx_z_long", None),
    "adxs": ("i_min_adx_z_short", None),
    "velhigh": ("i_velocity_high", None),
    "velmed": ("i_velocity_med", None),
    "chopmult": ("i_chop_threshold", None),
    "adxdec": ("i_adx_decel_thresh", None),
    "adxgate": ("i_min_adx_gate", None),
    "velgate": ("i_min_vel_gate", None),
    "rsiexl": ("i_rsi_ex_l", None),
    "rsiexs": ("i_rsi_ex_s", None),
    "maxrsil": ("i_max_rsi_long", None),
    "maxrsis": ("i_max_rsi_short", None),
    "maxzl": ("i_max_z_l", None),
    "maxzs": ("i_max_z_s", None),
    "zl": ("i_z_long_zone", None),
    "zs": ("i_z_short_zone", None),
    "rl": ("i_rsi_long_extreme", None),
    "rs": ("i_rsi_short_extreme", None),
    "rsilmild": ("i_rsi_long_mild", None),
    "rsismild": ("i_rsi_short_mild", None),
    "cdl": ("i_cd_l", None),
    "cds": ("i_cd_s", None),
    "agel": ("i_min_trend_age_long", None),
    "ages": ("i_min_trend_age_short", None),
    "sweeptolatr": ("i_sweep_tol_atr", None),
    "strictregimesync": ("i_strict_regime_sync", None),
    "usechopfilter": ("i_use_chop_filter", None),
    "emapersistbars": ("i_ema_persist_bars", None),
    "useexhaustionexit": ("i_use_exh_exit", None),
}


# Pine uses input.int for max RSI; zenith stores fractional sweep values â€” round for transfer parity.
_GS66_KIND_OVERRIDES: Dict[str, str] = {"maxrsil": "int", "maxrsis": "int"}


def _gs66_csv_param_kind(csv_key: str) -> str:
    if csv_key in _GS66_KIND_OVERRIDES:
        return _GS66_KIND_OVERRIDES[csv_key]
    if csv_key in zenith_schema.PARAM_IS_BOOL:
        return "bool"
    if csv_key in zenith_schema.PARAM_IS_INT:
        return "int"
    return "float"


_missing_gs66 = set(zenith_schema.CSV_PARAM_KEYS) - set(_GS66_CSV_TO_PINE.keys())
_extra_gs66 = set(_GS66_CSV_TO_PINE.keys()) - set(zenith_schema.CSV_PARAM_KEYS)
assert not _missing_gs66, f"GS66 Pine map missing keys: {sorted(_missing_gs66)}"
assert not _extra_gs66, f"GS66 Pine map has unknown keys: {sorted(_extra_gs66)}"

MAGIC_MAP: List[Tuple[str, PineField]] = [
    (_GS66_CSV_TO_PINE[k][0], (k, _gs66_csv_param_kind(k), _GS66_CSV_TO_PINE[k][1]))
    for k in zenith_schema.CSV_PARAM_KEYS
]
MAGIC_PARAM_COUNT = len(MAGIC_MAP)


def mega_results_row_to_canonical_params(row: Dict[str, str]) -> Dict[str, Any]:
    """
    Convert one mega_results DictReader row to keys `simulate()` expects (lowercase, bool/int/float).
    Supports legacy Pascal headers (SLL, â€¦) and GS66 lowercase headers (sll, â€¦).
    """
    global _LEGACY_MEGA_ROW_WARNED
    out: Dict[str, Any] = {}
    if row.get("sll") is not None and str(row.get("sll", "")).strip() != "":
        for k, kind in [
            ("riskl", "float"),
            ("risks", "float"),
            ("sll", "float"),
            ("sls", "float"),
            ("slfloorpct", "float"),
            ("slcappct", "float"),
            ("modear", "float"),
            ("modebrlong", "float"),
            ("modebrshort", "float"),
            ("trailactivationlong", "float"),
            ("trailactivationshort", "float"),
            ("traillv", "float"),
            ("trailmv", "float"),
            ("trailhv", "float"),
            ("nucl", "float"),
            ("nucs", "float"),
            ("confl", "int"),
            ("confs", "int"),
            ("usea", "bool"),
            ("useb", "bool"),
            ("adxl", "float"),
            ("adxs", "float"),
            ("velhigh", "float"),
            ("velmed", "float"),
            ("chopmult", "float"),
            ("adxdec", "float"),
            ("adxgate", "float"),
            ("velgate", "float"),
            ("rsiexl", "float"),
            ("rsiexs", "float"),
            ("maxrsil", "int"),
            ("maxrsis", "int"),
            ("maxzl", "float"),
            ("maxzs", "float"),
            ("zl", "float"),
            ("zs", "float"),
            ("rl", "float"),
            ("rs", "float"),
            ("rsilmild", "float"),
            ("rsismild", "float"),
            ("cdl", "int"),
            ("cds", "int"),
            ("agel", "int"),
            ("ages", "int"),
            ("sweeptolatr", "float"),
            ("strictregimesync", "bool"),
            ("usechopfilter", "bool"),
            ("emapersistbars", "int"),
            ("useexhaustionexit", "bool"),
        ]:
            raw = row.get(k)
            if raw is None or str(raw).strip() == "":
                continue
            s = str(raw).strip().lower()
            try:
                if kind == "bool":
                    out[k] = s in ("true", "1", "yes")
                elif kind == "int":
                    out[k] = int(round(float(s)))
                else:
                    out[k] = float(s)
            except Exception:
                continue
        return out

    if not _LEGACY_MEGA_ROW_WARNED:
        print(
            "[magic_numbers] DEPRECATED: legacy Pascal mega_results row; prefer GS66 headers (zenith_schema).",
            flush=True,
        )
        _LEGACY_MEGA_ROW_WARNED = True

    for csv_k, canon_k, kind in MEGA_PASCAL_PARAM_ALIASES:
        raw = row.get(csv_k)
        if raw is None or str(raw).strip() == "":
            continue
        s = str(raw).strip().lower()
        try:
            if kind == "bool":
                out[canon_k] = s in ("true", "1", "yes")
            elif kind == "int":
                out[canon_k] = int(round(float(s)))
            else:
                out[canon_k] = float(s)
        except Exception:
            continue

    out.setdefault("riskl", float(row.get("RiskL", 4.0) or 4.0))
    out.setdefault("risks", float(row.get("RiskS", 4.0) or 4.0))
    return out


# Parameters with no USE_PRO_OVERRIDE ternary in Section L (inputs only).
INPUT_ONLY_VARS: Set[str] = set()

# Mapping from Input Var -> Logic Zone Var (for Ternary Map patching)
LOGIC_MAP: Dict[str, str] = {
    # Cursor Pine uses v_* names (see Trading_strategy_Cursor.pine Section L)
    "f_risk_long": "v_risk_l",
    "f_risk_short": "v_risk_s",
    "i_use_chop_filter": "v_use_chop",
    "i_use_continuation": "v_use_b",
    "i_use_reversal": "v_use_a",

    "i_z_long_zone": "v_zl_ign",
    "i_z_short_zone": "v_zs_ign",
    "i_rsi_long_extreme": "v_rl_ign",
    "i_rsi_short_extreme": "v_rs_ign",
    "i_rsi_long_mild": "v_rsi_l_mild",
    "i_rsi_short_mild": "v_rsi_s_mild",

    "i_velocity_high": "v_vel_high",
    "i_velocity_med": "v_vel_med",

    "i_nuc_threshold": "v_nuc_thresh",
    "i_nuc_threshold_s": "v_nuc_thresh_s",
    "i_confluence_min": "v_conf_min",
    "i_confluence_min_s": "v_conf_min_s",

    "i_mode_a_r": "v_mode_a_r",
    "i_mode_b_r_long": "v_mode_b_r_l",
    "i_mode_b_r_short": "v_mode_b_r_s",

    "i_sl_atr_mult_long": "v_sl_l",
    "i_sl_atr_mult_short": "v_sl_s",
    "f_sl_floor_pct": "v_sl_floor",
    "f_sl_cap_pct": "v_sl_cap",

    "i_trail_activation_long": "v_trail_act_l",
    "i_trail_activation_short": "v_trail_act_s",
    "i_trail_lv": "v_trail_lv",
    "i_trail_mv": "v_trail_mv",
    "i_trail_hv": "v_trail_hv",

    "i_rsi_ex_l": "v_rsi_ex_l",
    "i_rsi_ex_s": "v_rsi_ex_s",
    "i_use_exh_exit": "v_use_exh",

    "i_cd_l": "v_cd_l",
    "i_cd_s": "v_cd_s",

    "i_adx_decel_thresh": "v_adx_dec",

    "i_max_rsi_long": "v_max_rsi_l",
    "i_max_rsi_short": "v_max_rsi_s",
    "i_max_z_l": "v_max_z_l",
    "i_max_z_s": "v_max_z_s",

    "i_min_trend_age_long": "v_age_l",
    "i_min_trend_age_short": "v_age_s",

    "i_min_adx_z_long": "v_adx_z_l",
    "i_min_adx_z_short": "v_adx_z_s",

    "i_sweep_tol_atr": "v_sweep_tol",
    "i_chop_threshold": "v_chop_threshold",
    "i_min_adx_gate": "v_adx_gate",
    "i_min_vel_gate": "v_vel_gate",
}

# Inputs that exist in Pine but have no v_* PRO branch (runtime uses input directly).
VARS_WITHOUT_PRO_TERNARY: frozenset[str] = frozenset({"i_strict_regime_sync", "i_ema_persist_bars"})


def find_latest_data_csv(base_dir: str) -> Optional[str]:
    pattern = os.path.join(base_dir, "*.csv")
    # Exclude results files to prevent misusing them as bar data
    files = [p for p in glob.glob(pattern) 
             if "mega_results_" not in os.path.basename(p) 
             and "results (" not in os.path.basename(p)
             and "results_" not in os.path.basename(p)]
    return max(files, key=os.path.getmtime) if files else None


def remap_forensic_bars(bars: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Step 9.2: Complete Forensic Bridge (OHLCV + Indicators).
    Bridges the DATA12 telemetry layout to the simulation's sovereign keys.
    This resolves the 0.00 price failure and the 959-trade divergence.
    """
    for b in bars:
        # Bridge Core BarIndex
        if "BarIndex" in b: 
            b["bar_index"] = int(float(b["BarIndex"]))
            b["bi"] = b["bar_index"]
            
        # Bridge Core OHLCV Prices (Mandatory for non-zero trade reporting)
        if "Open" in b:  b["o"] = float(b["Open"])
        if "High" in b:  b["h"] = float(b["High"])
        if "Low" in b:   b["l"] = float(b["Low"])
        if "Close" in b: b["c"] = float(b["Close"])
        if "Vol" in b:   b["v"] = float(b["Vol"])
        
        # Bridge Indicators (Telemetry -> Simulation)
        if "ZScore" in b: b["bzscorepy"] = float(b["ZScore"])
        if "RSI" in b:    b["brsipy"] = float(b["RSI"])
        if "ADXZS" in b:  b["badxzpy"] = float(b["ADXZS"])
        if "Velocity" in b: b["bvelocitypy"] = float(b["Velocity"])
        if "ATR" in b:    b["batrpy"] = float(b["ATR"])
        if "OBVSlope20" in b: b["bobvslope20py"] = float(b["OBVSlope20"])
        if "VWAP" in b:   b["bvwappy"] = float(b["VWAP"])
        if "BAVW" in b:   b["bavwpy"] = float(b["BAVW"])
        if "BBVW" in b:   b["bbvwpy"] = float(b["BBVW"])
        
        # Bridge Regime State
        if "Regime" in b: b["bregimepy"] = int(float(b["Regime"]))
        if "RegAge" in b: b["bagepy"] = int(float(b["RegAge"]))
        
        # Bridge Persistence Counters
        if "EMA_A" in b: b["bemaapy"] = int(float(b["EMA_A"]))
        if "EMA_B" in b: b["bemabpy"] = int(float(b["EMA_B"]))
        
    return bars


def find_latest_results_csv(base_dir: str) -> Optional[str]:
    pattern = os.path.join(base_dir, "mega_results_*.csv")
    files = glob.glob(pattern)
    return max(files, key=os.path.getmtime) if files else None


def load_combo_row(csv_path: str, combo_id: str) -> Dict[str, str]:
    target_id = combo_id.strip().replace("_", "")
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row_id = (row.get("ComboID") or "").strip().replace("_", "")
            if row_id == target_id:
                return row
    raise SystemExit(f"ComboID {combo_id!r} not found in {csv_path}")


def _parse_csv_scalar(raw: str, kind: str) -> Any:
    s = (raw or "").strip().lower()
    if kind == "bool":
        return s in ("true", "1", "yes")
    if kind == "int":
        return int(round(float(s)))
    return float(s)


def expected_pine_first_arg(row: Dict[str, str], csv_col: str, kind: str, scale: Optional[str]) -> Any:
    # Allow pseudo columns like CONST:4.0 to force a value.
    if (csv_col or "").startswith("CONST:"):
        raw_const = csv_col.split(":", 1)[1]
        v = _parse_csv_scalar(raw_const, kind)
        if scale == "pct_x100":
            return float(v) * 100.0
        return v
    raw = _mega_csv_cell(row, csv_col)
    if not raw or not raw.strip():
        # Missing column: return sensible default
        if kind == "bool": return False
        if kind == "int": return 0
        return 0.0
    v = _parse_csv_scalar(raw, kind)
    if scale == "pct_x100":
        return float(v) * 100.0
    return v


def format_pine_literal(val: Any, kind: str) -> str:
    if kind == "bool":
        return "true" if val else "false"
    if kind == "int":
        return str(int(val))
    # float â€” trim trailing zeros lightly
    s = f"{float(val):.10f}".rstrip("0").rstrip(".")
    return s if s else "0"


def patch_pine_content(content: str, row: Dict[str, str]) -> Tuple[str, int]:
    # Split content to prevent accidental logic corruption (Zoned Patching)
    SENTINEL = "// SECTION L: DIRECT INPUT USAGE"
    if SENTINEL in content:
        input_zone, logic_zone = content.split(SENTINEL, 1)
        logic_zone = SENTINEL + logic_zone
    else:
        input_zone, logic_zone = content, ""

    replacements = 0

    for var, (csv_col, kind, scale) in MAGIC_MAP:
        expect = expected_pine_first_arg(row, csv_col, kind, scale)
        lit = format_pine_literal(expect, kind)
        # override value lives in "raw" internal space: e.g. 0â€“1 for pct_x100
        expect_override = (expect / 100.0) if scale == "pct_x100" else expect
        lit_override = format_pine_literal(expect_override, kind)

        # Determine the actual Pine variable name to search for
        # Use INPUT_ONLY_VARS mapping if available, otherwise use MAGIC_MAP var
        pine_var = INPUT_ONLY_VARS.get(csv_col, (var, None))[0] if csv_col in INPUT_ONLY_VARS else var

        # 1. Patch Input Defaults or simple assignments (ONLY in input_zone)
        # Support both:
        #   i_var = input.float(val, ...)
        #   float i_var = input.float(val, ...)
        #   i_var = val
        pat = rf"""(?mx)
        ^(?P<indent>\s*
           (?:(?:float|int|bool)\s+)?)
        {re.escape(pine_var)}
        (?P<equals>\s*=\s*)?
        (?P<content>[^\n]*)
        $
        """

        def _repl(m: re.Match, target_var: str = pine_var) -> str:
            indent = m.group("indent")
            equals = m.group("equals") or " = "
            content_line = m.group("content")
            
            if csv_col in ("agel", "ages"):
                print(f"[DEBUG _repl] target_var={target_var}, lit={lit}")
                print(f"[DEBUG _repl] content_line={content_line[:60]}...")

            if "input." in content_line:
                # Replace the first argument inside the input call
                inner_pat = r"""(?P<head>input\.(?:float|int|bool)\(\s*)[^,)]+(?P<tail>.*)"""
                def _inner_repl(im: re.Match) -> str:
                    return im.group("head") + lit + im.group("tail")
                new_content = re.sub(inner_pat, _inner_repl, content_line, count=1)
                result = indent + target_var + equals + new_content
                if csv_col in ("agel", "ages"):
                    print(f"[DEBUG _repl] Result: {result[:80]}...")
                return result

            # Simple assignment: var = val  // comment
            comment_split = content_line.split("//", 1)
            new_line = indent + target_var + equals + lit
            if len(comment_split) > 1:
                new_line += " //" + comment_split[1]
            return new_line

        # Find which line matches for debugging
        if csv_col in ("agel", "ages"):
            for i, line in enumerate(input_zone.split('\n'), 1):
                if pine_var in line:
                    print(f"[DEBUG] Line {i}: {line[:80]}")
                    if re.search(rf'\b{re.escape(pine_var)}\b', line):
                        print(f"[DEBUG]   -> Pattern would match this line")
        
        input_zone, n = re.subn(pat, _repl, input_zone, count=1)
        if csv_col in ("agel", "ages"):
            print(f"[DEBUG] Patching {csv_col} -> {pine_var}: pattern matches = {n}")
        replacements += n

        # 2. Patch Overrides (ONLY in logic_zone, matching real T-map style)
        if logic_zone and var not in INPUT_ONLY_VARS:
            logic_var = LOGIC_MAP.get(var)
            if not logic_var:
                continue

            # Pattern for lines like:
            #   v_sl_l = USE_PRO_OVERRIDE ? 0.877744 : i_sl_atr_mult_long
            #   v_conf_min = int(USE_PRO_OVERRIDE ? 0 : i_confluence_min)
            ov_pat = rf"""(?mx)
            ^(?P<indent>\s*)
            \b{re.escape(logic_var)}\b
            \s*=\s*
            (?P<prefix>int\()?\bUSE_PRO_OVERRIDE\b
            \s*\?
            \s*(?P<old_val>[^:]+?)
            \s*:
            \s*(?P<fallback>[a-zA-Z_][a-zA-Z0-9_]*)
            \s*\)?\s*$
            """

            def _ov_repl(om: re.Match) -> str:
                indent = om.group("indent")
                prefix = "int(" if om.group("prefix") else ""
                fallback = om.group("fallback")
                # Ensure we don't double-prefix: exactly one prefix + USE_PRO_OVERRIDE
                close_paren = ")" if prefix else ""
                return f"{indent}{logic_var} = {prefix}USE_PRO_OVERRIDE ? {lit_override} : {fallback}{close_paren}"

            logic_zone, ov_n = re.subn(ov_pat, _ov_repl, logic_zone, count=1)
            replacements += ov_n

            # Legacy catch-all: vvar := literal (only if T-map not found)
            if ov_n == 0:
                if kind == "bool":
                    legacy_pat = rf"""(?mx)
                    ^(?P<indent>\s*)
                    {re.escape(logic_var)}
                    \s*:?=\s*
                    (?:true|false)
                    [^\n]*$
                    """
                elif kind == "int":
                    legacy_pat = rf"""(?mx)
                    ^(?P<indent>\s*)
                    {re.escape(logic_var)}
                    \s*:?=\s*
                    (-?\d+)
                    [^\n]*$
                    """
                else:
                    legacy_pat = rf"""(?mx)
                    ^(?P<indent>\s*)
                    {re.escape(logic_var)}
                    \s*:?=\s*
                    (-?\d*\.?\d+(?:[eE][-+]?\d+)?)
                    [^\n]*$
                    """
                legacy_repl = rf"\g<indent>{logic_var} := {lit_override}"
                logic_zone, legacy_n = re.subn(legacy_pat, legacy_repl, logic_zone, count=1)
                replacements += legacy_n

    # 3. Patch Strategy Label (handle paritylbl / parity_lbl, and any text)
    lbl_pat = r'''(?mx)
    ^(\s*)
    table\.cell\(
        (?:paritylbl|parity_lbl)
        \s*,\s*0\s*,\s*0\s*,
        \s*"[^"]*"
    '''
    combo = row.get("ComboID", "ID_XXXXX")
    lbl_repl = rf'\1table.cell(parity_lbl, 0, 0, "PARITY ACTIVE {combo}"'
    logic_zone, _ = re.subn(lbl_pat, lbl_repl, logic_zone, count=1)
    
    # 4. Patch Metric Comment
    metric_pat = r'// \[SOURCE: [^|]+ \| WR: [^%]+% \| PF: [^|]+ \| Trades: [^|]+ \| Eq: [^\]]+\]'
    wr = float(row.get("WR", 0)) * 100
    pf = row.get("PF", "0")
    tr = row.get("Trades", "0")
    eq = row.get("Eq", "0")
    metric_repl = f'// [SOURCE: {combo} | WR: {wr:.1f}% | PF: {pf} | Trades: {tr} | Eq: {eq}]'
    input_zone = re.sub(metric_pat, metric_repl, input_zone, count=1)

    return input_zone + logic_zone, replacements


_DOUBLE_COMMA_INPUT_RE = re.compile(
    r"input\.[a-zA-Z_]+\(\s*[^\n]*,,[^\n]*\)", re.MULTILINE
)

def assert_no_double_commas_in_inputs(content: str) -> None:
    """Fail fast if patching accidentally generates invalid Pine syntax like input.float(x,, 'label', ...)."""
    m = _DOUBLE_COMMA_INPUT_RE.search(content)
    if m:
        # Keep the message short; user only needs to know it can't compile.
        raise RuntimeError(f"[magic_numbers] Detected invalid Pine input call with double comma near: {m.group(0)[:80]}...")


_INPUT_LINE_RE = re.compile(
    r"""(?mx)
    ^\s*
    (?:(?:float|int|bool)\s+)?
    (?P<var>[a-zA-Z_][a-zA-Z0-9_]*)
    \s*
    (?:=\s*)?           # optional equals
    input\.(?P<kind>float|int|bool)\(
        \s*(?P<val>[^,)]+)\s*,
    """,
)


def parse_pine_inputs(content: str) -> Dict[str, Tuple[str, Any]]:
    """Return var -> (kind, parsed value)."""
    out: Dict[str, Tuple[str, Any]] = {}
    for m in _INPUT_LINE_RE.finditer(content):
        var = m.group("var")
        kind = m.group("kind")
        raw = m.group("val").strip()
        if kind == "bool":
            out[var] = ("bool", raw.lower() == "true")
        elif kind == "int":
            out[var] = ("int", int(round(float(raw))))
        else:
            out[var] = ("float", float(raw))
    return out


def _close(a: float, b: float, rtol: float = 1e-5, atol: float = 1e-6) -> bool:
    return abs(a - b) <= atol + rtol * max(1.0, abs(a), abs(b))


def _float_transfer_match(pv: float, exp: float, *, strict: bool) -> bool:
    """Strict mode: same canonical literal formatting as the patcher; else numeric tolerance."""
    if strict:
        return format_pine_literal(float(pv), "float") == format_pine_literal(float(exp), "float")
    return _close(float(pv), float(exp))


def _verify_parity_label_matches_combo(content: str, row: Dict[str, str]) -> List[str]:
    """If the Pine file contains a PARITY ACTIVE banner, it must match CSV ComboID (normalized)."""
    if '"PARITY ACTIVE' not in content:
        return []
    m = re.search(r'"PARITY ACTIVE\s+([^"]+)"', content)
    if not m:
        return ['parity label: expected "PARITY ACTIVE â€¦" string in Pine, but pattern not found']
    lbl = (m.group(1) or "").strip()
    cid = (row.get("ComboID") or "").strip()
    if not cid:
        return ["parity label: CSV row has no ComboID"]
    if lbl.replace("_", "") != cid.replace("_", ""):
        return [f"parity label: Pine shows {lbl!r} but CSV ComboID is {cid!r}"]
    return []


def verify_row_vs_pine(content: str, row: Dict[str, str], *, strict: bool = True) -> List[str]:
    """Compare mapped inputs + Section L PRO ternaries to the mega_results row."""
    parsed = parse_pine_inputs(content)
    errors: List[str] = []

    for var, (csv_col, kind, scale) in MAGIC_MAP:
        exp = expected_pine_first_arg(row, csv_col, kind, scale)
        exp_override = (exp / 100.0) if scale == "pct_x100" else exp

        # -------- Input checks --------
        if var not in parsed:
            errors.append(f"missing in Pine: {var} (csv {csv_col})")
            continue

        pk, pv = parsed[var]
        if kind == "bool":
            if pk != "bool" or bool(pv) != bool(exp):
                errors.append(f"{var}: expected bool {exp!r}, got {pk} {pv!r}")
        elif kind == "int":
            if int(pv) != int(exp):
                errors.append(f"{var}: expected int {exp}, got {pv}")
        else:
            if not _float_transfer_match(float(pv), float(exp), strict=strict):
                errors.append(f"{var}: expected float {exp!r}, got {pv!r} (csv {csv_col})")

        # -------- Override checks (T-map) --------
        if var in INPUT_ONLY_VARS:
            continue

        logic_var = LOGIC_MAP.get(var)
        if not logic_var:
            if var not in VARS_WITHOUT_PRO_TERNARY:
                errors.append(
                    f"{var}: no LOGIC_MAP v_* entry â€” cannot verify PRO override (csv {csv_col})"
                )
            continue

        # Use the same structure as patcher: look only at the USE_PRO_OVERRIDE ternary
        if kind == "bool":
            ov_re = rf'''(?mx)
            ^\b{re.escape(logic_var)}\b
            \s*=\s*(?:int\()?\bUSE_PRO_OVERRIDE\b
            \s*\?
            \s*(true|false)
            \s*:
            '''
            m = re.search(ov_re, content)
            if m:
                pine_val = (m.group(1).lower() == "true")
                if bool(pine_val) != bool(exp_override):
                    errors.append(
                        f"override {logic_var}: expected {bool(exp_override)!r}, got {pine_val!r}"
                    )
        elif kind == "int":
            ov_re = rf'''(?mx)
            ^\b{re.escape(logic_var)}\b
            \s*=\s*(?:int\()?\bUSE_PRO_OVERRIDE\b
            \s*\?
            \s*(-?\d+)
            \s*:
            '''
            m = re.search(ov_re, content)
            if m:
                pine_val = int(m.group(1))
                if pine_val != int(exp_override):
                    errors.append(
                        f"override {logic_var}: expected {int(exp_override)}, got {pine_val}"
                    )
        else:
            ov_re = rf'''(?mx)
            ^\b{re.escape(logic_var)}\b
            \s*=\s*(?:int\()?\bUSE_PRO_OVERRIDE\b
            \s*\?
            \s*(-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?)
            \s*:
            '''
            m = re.search(ov_re, content)
            if m:
                pine_val = float(m.group(1))
                if strict:
                    if format_pine_literal(pine_val, "float") != format_pine_literal(
                        float(exp_override), "float"
                    ):
                        errors.append(
                            f"override {logic_var}: expected {float(exp_override)!r}, got {pine_val!r}"
                        )
                elif abs(pine_val - float(exp_override)) > 1e-6:
                    errors.append(
                        f"override {logic_var}: expected {float(exp_override)!r}, got {pine_val!r}"
                    )

    return errors


def verify_all_gs66_params_transferred(
    content: str,
    row: Dict[str, str],
    *,
    strict: bool = True,
    check_parity_label: bool = True,
) -> List[str]:
    """
    Full transfer audit against zenith_schema:
    - every GS66 param cell is present in the CSV row;
    - every mapped Pine input default matches (strict float formatting when strict=True);
    - every Section L PRO ternary literal matches where applicable;
    - optional parity banner ComboID check.
    """
    errs: List[str] = []
    combo = row.get("ComboID", "?")
    for k in zenith_schema.CSV_PARAM_KEYS:
        if not str(_mega_csv_cell(row, k)).strip():
            errs.append(f"csv: empty GS66 param {k!r} (ComboID={combo!r})")
    errs.extend(verify_row_vs_pine(content, row, strict=strict))
    if check_parity_label:
        errs.extend(_verify_parity_label_matches_combo(content, row))
    return errs


def main() -> None:
    parser = argparse.ArgumentParser(description="Transfer mega_results combo â†’ Pine strategy")
    parser.add_argument("--combo", required=True, help="e.g. ID_05444")
    parser.add_argument("--csv", default="", help="mega_results CSV (default: newest mega_results_*.csv)")
    parser.add_argument("--pine", default=DEFAULT_PINE, help="Path to Pine file")
    parser.add_argument("--dry-run", action="store_true", help="Do not write Pine file")
    parser.add_argument("--no-verify", action="store_true", help="Skip post-patch verification (default is verify)")
    parser.add_argument("--verify-only", action="store_true", help="Only verify current Pine vs CSV (no write)")
    parser.add_argument(
        "--loose-floats",
        action="store_true",
        help="Allow small numeric tolerance on floats instead of literal formatting match",
    )
    parser.add_argument(
        "--skip-parity-label",
        action="store_true",
        help="Do not require PARITY ACTIVE banner to match ComboID",
    )
    parser.add_argument("--list-params", action="store_true", help="Print the mapped CSV->Pine parameter list and exit")
    parser.add_argument(
        "--report-trades",
        action="store_true",
        help=(
            "Print the expected trade list the Python engine predicts TradingView will show. "
            "IMPORTANT: This uses the patched Pine params + independent OHLCV simulation path (same engine as Analyzer parity)."
        ),
    )
    parser.add_argument(
        "--export-trades",
        metavar="FILE",
        help="Export expected trade list to CSV (entry_time,side,entry_px,exit_time,exit_px,pnl)",
    )
    parser.add_argument(
        "--data",
        help=(
            "OHLCV forensic chain to simulate on for expected trades. "
            "Pass the same comma-separated chain you used for TV exports, e.g. "
            "\"d:\\ToTheMoon\\ohlcv5 (1).csv,d:\\ToTheMoon\\ohlcv5 (2).csv,d:\\ToTheMoon\\ohlcv5 (3).csv\""
        ),
    )
    args = parser.parse_args()

    if args.list_params:
        print(MAGIC_PARAMS_DOC)
        for i, (var, (col, kind, sc)) in enumerate(MAGIC_MAP, 1):
            scs = f" scale={sc}" if sc else ""
            print(f"{i:2d}. {col:12} -> {var} [{kind}{scs}]")
        print(f"{MAGIC_PARAM_COUNT} mapped values per combo.")
        return

    # Search for CSV in D:\ToTheMoon first, then SCRIPT_DIR
    csv_path = args.csv.strip() or find_latest_results_csv(r"D:\ToTheMoon") or find_latest_results_csv(SCRIPT_DIR) or ""
    if not csv_path or not os.path.isfile(csv_path):
        sys.exit(f"No results CSV. Pass --csv or place mega_results_*.csv in {SCRIPT_DIR}")

    row = load_combo_row(csv_path, args.combo)
    print(f"[+] Loaded {args.combo} from {os.path.basename(csv_path)}")
    print(f"    Eq={row.get('Eq')} PF={row.get('PF')} WR={row.get('WR')} Trades={row.get('Trades')} Score={row.get('Score')}")

    with open(args.pine, "r", encoding="utf-8") as f:
        original = f.read()

    _strict = not args.loose_floats
    _chk_lbl = not args.skip_parity_label

    if args.verify_only:
        errs = verify_all_gs66_params_transferred(
            original, row, strict=_strict, check_parity_label=_chk_lbl
        )
        if errs:
            print(f"[FAIL] {len(errs)} mismatch(es):")
            for e in errs[:40]:
                print("   ", e)
            if len(errs) > 40:
                print(f"    ... +{len(errs) - 40} more")
            sys.exit(1)
        print(
            f"[OK] Full GS66 transfer verified: {MAGIC_PARAM_COUNT} params + "
            f"parity label={'on' if _chk_lbl else 'skipped'} (strict_floats={_strict})."
        )
        return

    new_content, n = patch_pine_content(original, row)
    print(f"[*] Patched {n} / {MAGIC_PARAM_COUNT} input lines.")

    # Safety net: prevents reintroducing invalid syntax like input.float(x,, "label"...).
    assert_no_double_commas_in_inputs(new_content)

    if args.dry_run:
        print("[dry-run] Pine file not written.")
    else:
        with open(args.pine, "w", encoding="utf-8", newline="\n") as f:
            f.write(new_content)
        print(f"[+] Wrote {args.pine}")

    body = new_content
    if args.dry_run or not args.no_verify:
        errs = verify_all_gs66_params_transferred(
            body, row, strict=_strict, check_parity_label=_chk_lbl
        )
        if errs:
            print(f"[VERIFY FAIL] {len(errs)} issue(s):")
            for e in errs[:25]:
                print("   ", e)
            sys.exit(1)
        print(
            f"[VERIFY OK] GS66 transfer: {MAGIC_PARAM_COUNT} params consistent "
            f"(strict_floats={_strict}, parity_label={'on' if _chk_lbl else 'skipped'})."
        )

    if args.report_trades or args.export_trades:
        if not optimizer:
            print("[!] Error: mega_optimizer_new.py not found. Cannot report trades.")
            sys.exit(1)

        data_path = (args.data or "").strip()
        if not data_path:
            raise SystemExit(
                "[magic_numbers] --report-trades/--export-trades requires --data with the OHLCV chain "
                "(comma-separated). We must simulate on the same exported bars TV used."
            )

        print(f"\n[*] Generating Expected Trade List using OHLCV: {data_path}...")

        # Load full bar deck + meta exactly like Analyzer parity path.
        bars, ledger_rows, meta, schema_id, h_all = optimizer.load_data(data_path)
        if not bars:
            raise SystemExit(f"[magic_numbers] Failed to load bars from {data_path!r}")

        # Load full 49-param set from the patched Pine file for maximum fidelity
        # (the whole point is: expected list must match the Pine strategy run in TV).
        try:
            pine_parsed = parse_pine_inputs(body)
        except Exception as e:
            raise SystemExit(f"[magic_numbers] Failed to parse Pine inputs for expected trades: {e}")

        # Build optimizer params dict the same way Analyzer parity does:
        # start from optimizer.FORENSIC_PARAMS defaults, then overlay the 49 GS66 keys from Pine.
        # This avoids accidentally zeroing non-GS66 params (slippage, fees, gates, etc.).
        p: Dict[str, Any] = dict(getattr(optimizer, "FORENSIC_PARAMS", {}) or {})
        inv: Dict[str, Tuple[str, Optional[str]]] = {v: (k, sc) for k, (v, sc) in _GS66_CSV_TO_PINE.items()}
        for pine_var, (kind, val) in pine_parsed.items():
            if pine_var not in inv:
                continue
            csv_key, scale = inv[pine_var]
            v2: Any = val
            if scale == "pct_x100":
                try:
                    v2 = float(v2) / 100.0
                except Exception:
                    pass
            # Coerce types to match optimizer expectations.
            try:
                if csv_key in zenith_schema.PARAM_IS_BOOL:
                    p[csv_key] = bool(v2)
                elif csv_key in zenith_schema.PARAM_IS_INT:
                    p[csv_key] = int(round(float(v2)))
                else:
                    p[csv_key] = float(v2)
            except Exception:
                p[csv_key] = v2

        # Ensure all GS66 keys exist (fallback to optimizer defaults; never force zero if missing).
        for k in zenith_schema.CSV_PARAM_KEYS:
            if k not in p:
                if k in getattr(optimizer, "FORENSIC_PARAMS", {}):
                    p[k] = optimizer.FORENSIC_PARAMS[k]
                else:
                    p[k] = False if k in zenith_schema.PARAM_IS_BOOL else (0 if k in zenith_schema.PARAM_IS_INT else 0.0)

        # Ensure the engine is in the certified sovereign signal posture for ID_* combos.
        p.setdefault("minimal_test", False)
        if str(args.combo).strip().upper().startswith("ID_"):
            p["use_sovereign_signal"] = True
            # Parity posture: TV is oracle only after-the-fact, never for decisions.
            p["use_tv_guidance"] = False
            p["autonomous_indicators"] = True

        combo_id = str(args.combo).strip().upper()

        # Tick size: authoritative from forensic meta when present, else optimizer default.
        tick_meta = None
        try:
            tick_meta = float((meta or {}).get("MINTICK", 0.0) or 0.0)
        except Exception:
            tick_meta = None
        tick_size = tick_meta if tick_meta and tick_meta > 0 else float(getattr(optimizer, "TICKSIZE", 0.1) or 0.1)

        # Precompute autonomous indicator fields on the bar deck (independent path).
        bars2, _, _, _, _ = optimizer.precompute_forensic_bars(
            bars,
            ledger_rows or [],
            meta or {},
            schema_id or "",
            h_all or [],
            combo_id=combo_id,
            signal_params=p,
        )

        # ======================================================================
        # PHASE 9.1 â€” Signal source + run_meta (SIGNAL_PARITY_PLAN.md v3)
        # ======================================================================
        os.environ.setdefault("MEGA_SIGNAL_SOURCE", "py_recalc")
        _run_meta = {
            "sim_version": getattr(optimizer, "SIM_VERSION", "unknown"),
            "signal_source_mode": optimizer.get_signal_source_mode(),
            "indicator_provenance": "tradingview_export",
            "combo_id": combo_id,
        }
        print(f"  [RUN META] {_run_meta}")
        # ======================================================================
        # END PHASE 9.1
        # ======================================================================
        sim_res = optimizer.simulate(
            bars2,
            p,
            return_trades=True,
            effective_start_bi=0,
            combo_id=combo_id,
            tick_size=tick_size,
            bars_mode="full",
        )
        trades = sim_res[12] or []

        def _ts_chart_from_bar_index(bi: int) -> str:
            try:
                t = bars2[int(bi)].get("time")
            except Exception:
                return "N/A"
            try:
                if hasattr(optimizer, "_utc_to_chart_ts"):
                    return (optimizer._utc_to_chart_ts(t) or "")[:16].replace("T", " ")
            except Exception:
                pass
            return str(t).replace("T", " ")[:16]

        if args.report_trades:
            print(f"\n--- EXPECTED TRADINGVIEW REPORT FOR {combo_id} ---")
            print(f"{'#':<3} | {'SIDE':<5} | {'ENTRY TIME':<16} | {'ENTRY PX':<10} | {'EXIT TIME':<16} | {'EXIT PX':<10} | {'PnL'}")
            print("-" * 95)
            for i, pos in enumerate(trades, 1):
                ep = float(getattr(pos, "fill_price", 0.0) or 0.0)
                xp = float(getattr(pos, "exit_price", 0.0) or 0.0)
                pnl = getattr(pos, "net_pnl", None)
                try:
                    pnl_f = float(pnl) if pnl is not None else 0.0
                except Exception:
                    pnl_f = 0.0
                side = "LONG" if getattr(pos, "side", 0) == 1 else ("SHORT" if getattr(pos, "side", 0) == -1 else str(getattr(pos, "side", "")))
                et = _ts_chart_from_bar_index(int(getattr(pos, "entry_bi", 0)))
                xt = _ts_chart_from_bar_index(int(getattr(pos, "exit_bi", 0)))
                print(f"{i:<3} | {side:<5} | {et:<16} | {ep:<10.2f} | {xt:<16} | {xp:<10.2f} | {pnl_f:+.6g}")
            print("-" * 95)
            final_eq = sim_res[0] if isinstance(sim_res, (list, tuple)) else 0.0
            print(f"[*] Final Equity: {final_eq:.2f}")
            print(f"[*] Total Trades: {len(trades)}")

        if args.export_trades:
            os.makedirs(os.path.dirname(os.path.abspath(args.export_trades)), exist_ok=True)
            with open(args.export_trades, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["entry_time", "side", "entry_px", "exit_time", "exit_px", "pnl"])
                for t in trades:
                    ep = float(getattr(t, "fill_price", 0.0) or 0.0)
                    xp = float(getattr(t, "exit_price", 0.0) or 0.0)
                    pnl = getattr(t, "net_pnl", None)
                    try:
                        pnl_f = float(pnl) if pnl is not None else 0.0
                    except Exception:
                        pnl_f = 0.0
                    side_raw = getattr(t, "side", 0)
                    side = "LONG" if side_raw == 1 else ("SHORT" if side_raw == -1 else str(side_raw))
                    ebi = int(getattr(t, "entry_bi", 0))
                    xbi = int(getattr(t, "exit_bi", 0))
                    et = _ts_chart_from_bar_index(ebi)
                    xt = _ts_chart_from_bar_index(xbi)
                    w.writerow([et, side, ep, xt, xp, pnl_f])
            print(f"[*] Exported {len(trades)} trades to {args.export_trades}")


if __name__ == "__main__":
    main()