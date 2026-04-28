"""
zenithnew.py

Single source of truth for the Zenith parity-certification stack.

MIGRATION NOTE
--------------
This file is based on the authoritative `zenith_schema.py` contract and extends it
only with additive migration helpers needed for analyzer/optimizer transition work.
The proof/runtime contract must remain semantically identical to the authoritative
schema. No existing contract fields, proof semantics, or certification invariants
are weakened here.

Step 0 expansion on schema v2.4 backward-compatible field additions:
- SignalSourceSummary added `signalsource` field
- ReconciliationStats added price/time/pnl mismatch counts
- MismatchDetail added `kind`, `field`, `detail` generic descriptors
- CertificationProof added `referenceoraclekind`, `predictedtrades`,
  `referencetrades`, `mismatches`
- assert_valid_proof_dict raising validator wrapper
- SignalSourceSummary.from_runtime
- ReconciliationStats.from_legacy_counts
- CertificationProof.from_reconciliation factory helpers

No existing field was renamed. All new fields default to None/0 so existing
constructors and `to_dict()` consumers continue to work unchanged.

Layer 1: CSV parameter schema (`SCHEMA_MEGA_V1027`, `CSV_PARAM_KEYS`, helpers)
Layer 2: Certification proof contract (`CertificationProof`, `TradeRecord`, etc.)

Authoritative proof schema:
- SCHEMA_ID = "zenith.parity.proof.v24"
- SCHEMA_VERSION = "2.4"
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

PARAM_IS_BOOL = frozenset(
    {
        "usea",
        "useb",
        "strictregimesync",
        "usechopfilter",
        "useexhaustionexit",
    }
)

PARAM_IS_INT = frozenset(
    {
        "confl",
        "confs",
        "maxrsil",
        "maxrsis",
        "cdl",
        "cds",
        "agel",
        "ages",
        "emapersistbars",
        "rsilmild",
        "rsismild",
    }
)

PARAM_BOOL_TRUE = "true"
PARAM_BOOL_FALSE = "false"
PARAM_BOOL_TRUE_SET = {"true", "1", "yes"}
PARAM_BOOL_FALSE_SET = {"false", "0", "no"}

CSV_PARAM_KEYS: Tuple[str, ...] = (
    "riskl",
    "risks",
    "sll",
    "sls",
    "slfloorpct",
    "slcappct",
    "modear",
    "modebrlong",
    "modebrshort",
    "trailactivationlong",
    "trailactivationshort",
    "traillv",
    "trailmv",
    "trailhv",
    "nucl",
    "nucs",
    "confl",
    "confs",
    "usea",
    "useb",
    "adxl",
    "adxs",
    "velhigh",
    "velmed",
    "chopmult",
    "adxdec",
    "adxgate",
    "velgate",
    "rsiexl",
    "rsiexs",
    "maxrsil",
    "maxrsis",
    "maxzl",
    "maxzs",
    "zl",
    "zs",
    "rl",
    "rs",
    "rsilmild",
    "rsismild",
    "cdl",
    "cds",
    "agel",
    "ages",
    "sweeptolatr",
    "strictregimesync",
    "usechopfilter",
    "emapersistbars",
    "useexhaustionexit",
)
assert len(CSV_PARAM_KEYS) == 49

METRIC_COLS: Tuple[str, ...] = (
    "ComboID",
    "Equity",
    "PF",
    "WR",
    "Trades",
    "TrL",
    "TrS",
    "Sharpe",
    "DD",
    "Exp",
    "Score",
    "Dur",
    "TWR",
    "TExp",
    "TPF",
)
assert len(METRIC_COLS) == 15

INCLUDE_METADATA_TAIL: bool = True
DEFAULT_SCHEMA_ID: str = "GS66v1"
DEFAULT_CONTRACT_TOKEN: str = "Diamond21Build"

METADATA_COLS: Tuple[str, ...] = (
    "SchemaID",
    "ContractToken",
    "SegTags",
    "SegTB",
)

SCHEMA_MEGA_V1027: Tuple[str, ...] = (
    *METRIC_COLS,
    *CSV_PARAM_KEYS,
    *METADATA_COLS,
)
SCHEMA_MEGA_V10_27 = SCHEMA_MEGA_V1027  # backward-compat alias for optimizer import

EXPECTED_SCHEMA_FIELD_COUNT: int = 68
EXPECTED_ROW_WIDTH: int = 68
assert len(SCHEMA_MEGA_V1027) == EXPECTED_SCHEMA_FIELD_COUNT

PASCAL_TO_CANONICAL: Dict[str, str] = {
    "RiskL": "riskl",
    "RiskS": "risks",
    "SLL": "sll",
    "SLS": "sls",
    "FloorPct": "slfloorpct",
    "CapPct": "slcappct",
    "ModeAR": "modear",
    "ModeBRL": "modebrlong",
    "ModeBRS": "modebrshort",
    "ModeBR_L": "modebrlong",
    "ModeBR_S": "modebrshort",
    "TrailActL": "trailactivationlong",
    "TrailActS": "trailactivationshort",
    "TLv": "traillv",
    "TMv": "trailmv",
    "THv": "trailhv",
    "NucL": "nucl",
    "NucS": "nucs",
    "ConfL": "confl",
    "ConfS": "confs",
    "UseA": "usea",
    "UseB": "useb",
    "AdxL": "adxl",
    "AdxS": "adxs",
    "VelHigh": "velhigh",
    "VelMed": "velmed",
    "ChopM": "chopmult",
    "AdxD": "adxdec",
    "AdxG": "adxgate",
    "VelG": "velgate",
    "RsiExL": "rsiexl",
    "RsiExS": "rsiexs",
    "MaxRsiL": "maxrsil",
    "MaxRsiS": "maxrsis",
    "MaxZL": "maxzl",
    "MaxZS": "maxzs",
    "zL": "zl",
    "zS": "zs",
    "rL": "rl",
    "rS": "rs",
    "RsiLMild": "rsilmild",
    "RsiSMild": "rsismild",
    "CdL": "cdl",
    "CdS": "cds",
    "AgeL": "agel",
    "AgeS": "ages",
    "SwpTol": "sweeptolatr",
    "StrictRegimeSync": "strictregimesync",
    "UseChopFilter": "usechopfilter",
    "EMAPersistBars": "emapersistbars",
    "UseExh": "useexhaustionexit",
}

class UnrecognizedHeaderError(ValueError):
    pass

def sanitize_csv_fieldnames(fieldnames: List[str]) -> List[str]:
    return [str(f or "").strip().lstrip("\ufeff").lstrip("#").strip() for f in (fieldnames or [])]


def normalize_dict_row_keys(row: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in row.items():
        clean = str(k or "").strip().lstrip("#").strip()
        out[PASCAL_TO_CANONICAL.get(clean, clean)] = v
    return out


def classify_mega_header(hdr: List[str]) -> str:
    hdrset = {h.strip() for h in hdr if h}
    if len({"riskl", "sll", "adxgate", "usea", "useb"} & hdrset) >= 4:
        return "gs66"
    if len({"RiskL", "SLL", "ModeAR", "AdxG", "UseA"} & hdrset) >= 3:
        return "legacy"
    lower = {h.lower() for h in hdrset}
    if {"riskl", "adxgate", "usea"}.issubset(lower):
        return "gs66"
    raise UnrecognizedHeaderError(
        f"Cannot classify mega-results header. Sample={sorted(hdrset)[:10]}"
    )


def parse_param_cells_from_full_row(row_list: List[str], header: List[str]) -> Dict[str, Any]:
    minlen = min(len(row_list), len(header))
    bycol: Dict[str, str] = {
        PASCAL_TO_CANONICAL.get(h.strip(), h.strip()): str(v).strip()
        for h, v in zip(header[:minlen], row_list[:minlen])
        if h and v is not None
    }

    result: Dict[str, Any] = {}
    for key in CSV_PARAM_KEYS:
        raw = bycol.get(key, "")
        if not raw:
            continue
        try:
            if key in PARAM_IS_BOOL:
                result[key] = raw.lower() in PARAM_BOOL_TRUE_SET
            elif key in PARAM_IS_INT:
                result[key] = int(round(float(raw)))
            else:
                result[key] = float(raw)
        except (ValueError, TypeError):
            result[key] = raw
    return result


def full_result_header() -> Tuple[str, ...]:
    return SCHEMA_MEGA_V1027


def segment_tags_for_walkforward_layout(
    windowidx: Optional[int] = None,
    role: str = "train",
    extratags: Optional[Iterable[str]] = None,
) -> List[str]:
    tags: List[str] = []
    if windowidx is not None:
        tags.append(f"w{windowidx}")
    if role:
        tags.append(str(role))
    if extratags:
        tags.extend(str(t) for t in extratags if t)
    return tags


def format_segment_tags_cell(tags: Iterable[str]) -> str:
    return "|".join(str(t).strip() for t in (tags or []) if str(t).strip())

def normalize_full_results_row(row_list: List[str], header: List[str]) -> Dict[str, Any]:
    """
    Normalize a full mega-results row: sanitize header, classify schema, canonicalize
    keys (metrics, params, metadata), and type-cast CSV_PARAM_KEYS.

    Returns a full-row dict plus `schema_kind`.
    """
    hdr = sanitize_csv_fieldnames(header)
    kind = classify_mega_header(hdr)
    minlen = min(len(row_list), len(hdr))

    raw: Dict[str, Any] = {
        PASCAL_TO_CANONICAL.get(h.strip(), h.strip()): str(v).strip()
        for h, v in zip(hdr[:minlen], row_list[:minlen])
        if h
    }

    out: Dict[str, Any] = dict(raw)
    out["schema_kind"] = kind

    for key in CSV_PARAM_KEYS:
        rawv = raw.get(key, "")
        if not rawv:
            continue
        try:
            if key in PARAM_IS_BOOL:
                out[key] = rawv.lower() in PARAM_BOOL_TRUE_SET
            elif key in PARAM_IS_INT:
                out[key] = int(round(float(rawv)))
            else:
                out[key] = float(rawv)
        except (ValueError, TypeError):
            out[key] = rawv

    return out


def extract_params_from_normalized_row(row_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract canonical CSV params from a normalized row dict.
    """
    return {k: row_dict[k] for k in CSV_PARAM_KEYS if k in row_dict}

TEST_METRIC_COLS: Tuple[str, ...] = (
    "Eq", "PF", "WR", "Trades", "TrL", "TrS",
    "Sharpe", "DD", "Exp", "Score", "Dur", "TWR", "TExp", "TPF",
)

TEST_METADATA_COLS: Tuple[str, ...] = (
    "SCHEMAID", "CONTRACTTOKEN", "SegTags", "SegTB",
)


def test_result_header() -> Tuple[str, ...]:
    """Return full test-results header matching mega-results schema shape."""
    return ("ComboID", *TEST_METRIC_COLS, *CSV_PARAM_KEYS, *TEST_METADATA_COLS)


def extract_test_metrics(stats: Dict[str, Any]) -> Dict[str, Any]:
    """Extract mega-style metrics from a stats dict with canonical aliases."""
    stats = stats or {}
    alias = {
        "Eq": ("Eq", "Equity", "equity"),
        "PF": ("PF", "pf", "ProfitFactor"),
        "WR": ("WR", "wr", "WinRate"),
        "Trades": ("Trades", "tradecount", "tc"),
        "TrL": ("TrL", "longtrades", "tcl"),
        "TrS": ("TrS", "shorttrades", "tcs"),
        "Sharpe": ("Sharpe", "sharpe"),
        "DD": ("DD", "dd", "maxdd", "Drawdown"),
        "Exp": ("Exp", "exp", "Expectancy"),
        "Score": ("Score", "score"),
        "Dur": ("Dur", "dur", "Duration"),
        "TWR": ("TWR", "twr"),
        "TExp": ("TExp", "texp"),
        "TPF": ("TPF", "tpf"),
    }

    out: Dict[str, Any] = {}
    for col, keys in alias.items():
        val = None
        for k in keys:
            if k in stats and stats[k] is not None:
                val = stats[k]
                break
        out[col] = val
    return out


def build_test_result_row(
    comboid: str,
    stats: Dict[str, Any],
    params: Dict[str, Any],
    schemaid: str = DEFAULT_SCHEMA_ID,
    contracttoken: str = DEFAULT_CONTRACT_TOKEN,
    segtags: str = "",
    segtb: str = "",
) -> Dict[str, Any]:
    """Build a mega-style test result row dict."""
    row: Dict[str, Any] = {"ComboID": str(comboid or "").strip()}
    row.update(extract_test_metrics(stats))

    params = params or {}
    for k in CSV_PARAM_KEYS:
        row[k] = params.get(k, "")

    row["SCHEMAID"] = schemaid
    row["CONTRACTTOKEN"] = contracttoken
    row["SegTags"] = segtags
    row["SegTB"] = segtb
    return row

SCHEMA_ID = "zenith.parity.proof.v24"
SCHEMA_VERSION = "2.4"

CERT_KIND_STRICT_PREDICTIVE = "strict_predictive_cert"
CERT_KIND_FORENSIC = "forensic"
CERT_KIND_FORENSIC_DIAG = "forensic_diag"
CERT_KIND_NONE = "none"

VALID_CERT_KINDS = frozenset({
    CERT_KIND_STRICT_PREDICTIVE,
    CERT_KIND_FORENSIC,
    CERT_KIND_FORENSIC_DIAG,
    CERT_KIND_NONE,
})


@dataclass
class VersionStamp:
    """Version metadata. schema_id lives on CertificationProof, NOT here."""
    optimizer_version: str
    analyzer_version: str
    strategy_version: str = "unknown"
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InputFingerprint:
    ohlcv_hash: str
    params_hash: str
    config_hash: str
    combo_id: str
    symbol: Optional[str] = None
    timeframe: Optional[str] = None
    date_range: Optional[str] = None
    timezone: str = "Europe/Sofia"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ToleranceProfile:
    entry_price_abs: float = 1e-6
    exit_price_abs: float = 1e-6
    entry_time_seconds: int = 0
    exit_time_seconds: int = 0
    pnl_abs: float = 1e-6

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class SignalSourceSummary:
    """
    Describes which signal provenance path was active.

    Step 0 addition: signalsource is the runtime mode string
    ("tvdrow", "pyrecalc", "compare"), kept separate from oraclekind
    which describes the semantic oracle governing decision logic.
    Backward-compatible: signalsource defaults to None.
    """
    mode: str
    oraclekind: str
    signalsource: Optional[str] = None
    predictivecertification: bool = False
    oracleblindenforced: bool = False
    tvsignalreadsblocked: bool = False
    comparedfields: List[str] = field(default_factory=list)
    driftfields: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.setdefault("signal_source", d.get("signalsource"))
        d.setdefault("oracle_kind", d.get("oraclekind"))
        d.setdefault("predictive_certification", d.get("predictivecertification"))
        d.setdefault("oracle_blind_enforced", d.get("oracleblindenforced"))
        d.setdefault("tv_signal_reads_blocked", d.get("tvsignalreadsblocked"))
        return d

    @classmethod
    def from_runtime(
        cls,
        signalsource: str,
        predictivecertification: bool = False,
        oracleblindenforced: Optional[bool] = None,
        tvsignalreadsblocked: Optional[bool] = None,
    ) -> "SignalSourceSummary":
        """
        Factory build from raw runtime mode string.

        oracleblindenforced and tvsignalreadsblocked default to
        predictivecertification if not explicitly provided, but can be
        overridden to reflect actual runtime enforcement state rather
        than just the requested mode.
        """
        oracle = schema_oracle_from_signal_source(signalsource)
        mode = schema_mode_from_runtime(
            "predictivecert" if predictivecertification else signalsource
        )
        return cls(
            mode=mode,
            oraclekind=oracle,
            signalsource=signalsource,
            predictivecertification=predictivecertification,
            oracleblindenforced=(
                predictivecertification
                if oracleblindenforced is None
                else bool(oracleblindenforced)
            ),
            tvsignalreadsblocked=(
                predictivecertification
                if tvsignalreadsblocked is None
                else bool(tvsignalreadsblocked)
            ),
        )


@dataclass
class ReconciliationStats:
    """
    Trade reconciliation counters.

    Step 0 additions: pricemismatchcount, timemismatchcount,
    pnlmismatchcount. Existing fields pythontradecount, tvtradecount,
    etc. are unchanged.
    """
    pythontradecount: int = 0
    tvtradecount: int = 0
    matchedcount: int = 0
    mismatchedcount: int = 0
    ghostpythoncount: int = 0
    ghosttvcount: int = 0
    unmatchedcount: int = 0
    perfectmatch: bool = False
    pricemismatchcount: int = 0
    timemismatchcount: int = 0
    pnlmismatchcount: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_legacy_counts(
        cls,
        pythoncount: int = 0,
        tvcount: int = 0,
        matches: int = 0,
        ghostpython: int = 0,
        ghosttv: int = 0,
        mismatchedcount: Optional[int] = None,
        unmatchedcount: Optional[int] = None,
        perfectmatch: Optional[bool] = None,
        pricemismatches: int = 0,
        timemismatches: int = 0,
        pnlmismatches: int = 0,
    ) -> "ReconciliationStats":
        """
        Factory build from legacy scorecard counter names.

        If exact mismatch/unmatched/perfectmatch values are known from
        the analyzer reconciliation pass, pass them explicitly; the
        derived defaults below are conservative approximations only.
        """
        derivedmismatched = max(0, tvcount - matches)
        derivedunmatched = max(0, tvcount - matches - ghosttv)
        derivedperfect = (
            tvcount > 0 and
            matches == tvcount and
            ghostpython == 0 and
            ghosttv == 0
        )
        return cls(
            pythontradecount=pythoncount,
            tvtradecount=tvcount,
            matchedcount=matches,
            mismatchedcount=(
                derivedmismatched if mismatchedcount is None else int(mismatchedcount)
            ),
            ghostpythoncount=ghostpython,
            ghosttvcount=ghosttv,
            unmatchedcount=(
                derivedunmatched if unmatchedcount is None else int(unmatchedcount)
            ),
            perfectmatch=(
                derivedperfect if perfectmatch is None else bool(perfectmatch)
            ),
            pricemismatchcount=pricemismatches,
            timemismatchcount=timemismatches,
            pnlmismatchcount=pnlmismatches,
        )

@dataclass
class TradeRecord:
    """Portable single-trade representation."""
    entrytime: str
    side: str
    entrypx: float
    exittime: Optional[str] = None
    exitpx: Optional[float] = None
    pnl: Optional[float] = None
    qty: Optional[float] = None
    tradeid: Optional[str] = None
    barsheld: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MismatchDetail:
    """
    Single trade mismatch record.

    Step 0 additions: kind, field, detail generic descriptors so this
    class can represent both the first-mismatch payload (existing usage)
    and items in a structured mismatch list (new usage).

    All new fields default to None for backward compatibility.
    """
    status: str
    reason: str
    pythonindex: Optional[int] = None
    tvindex: Optional[int] = None
    pythontrade: Optional[TradeRecord] = None
    tvtrade: Optional[TradeRecord] = None
    entrydelta: Optional[float] = None
    exitdelta: Optional[float] = None
    pnldelta: Optional[float] = None
    timestampdeltaseconds: Optional[float] = None
    kind: Optional[str] = None
    field: Optional[str] = None
    detail: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_scorecard_row(cls, row: Dict[str, Any]) -> "MismatchDetail":
        """
        Factory build from a legacy analyzer scorecard dict row.

        Preserves any structured fields present in the row (deltas, indices).
        Marked transitional; replace with direct field mapping once analyzer
        emits typed trade objects natively.
        """
        status = str(row.get("status", "MISMATCH"))
        sl = status.lower()
        kind = (
            "price"
            if ("ep" in sl or "xp" in sl or "price" in sl)
            else "time"
            if ("ebar" in sl or "xbar" in sl or "time" in sl)
            else "pnl"
            if ("profit" in sl or "pnl" in sl)
            else "tradereconciliation"
        )
        return cls(
            status=status,
            reason=str(row.get("reason", status)),
            pythonindex=row.get("pythonindex", row.get("pyindex")),
            tvindex=row.get("tvindex"),
            entrydelta=row.get("entrydelta"),
            exitdelta=row.get("exitdelta"),
            pnldelta=row.get("pnldelta"),
            timestampdeltaseconds=row.get("timestampdeltaseconds"),
            kind=kind,
            field=str(row.get("field", status)),
            detail=str(row.get("detail", status)),
        )


@dataclass
class SignalStateSnapshot:
    """Per-bar signal state container for diagnostics-proof consumers."""
    sourcemode: str
    rsi: Optional[float] = None
    zscore: Optional[float] = None
    adxz: Optional[float] = None
    velocity: Optional[float] = None
    regime: Optional[float] = None
    conf: Optional[float] = None
    tvfields: Dict[str, Any] = field(default_factory=dict)
    pyfields: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CompareDriftRow:
    """Per-bar, per-field drift record for compare mode."""
    barindex: int
    comboid: str
    fieldname: str
    tvvalue: Optional[float]
    pyvalue: Optional[float]
    delta: Optional[float]
    exceedseps: bool = False
    eps: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class CertificationProof:
    """
    Top-level certification artifact.
    Written by analyzer after reconciliation.

    Step 0 additions (all optional/defaulted for backward compatibility):
      - referenceoraclekind: the external comparison source ("tvledger",
        "externallist"), distinct from source.oraclekind (decision oracle)
      - predictedtrades: typed TradeRecord list from optimizer
      - referencetrades: typed TradeRecord list from TV/external oracle
      - mismatches: typed MismatchDetail list (structured, not just first)
    """
    certificationkind: str
    passed: bool
    version: VersionStamp
    inputs: InputFingerprint
    tolerance: ToleranceProfile
    source: SignalSourceSummary
    reconciliation: ReconciliationStats

    firstmismatch: Optional[MismatchDetail] = None
    runid: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)
    schemaid: str = SCHEMA_ID
    certtimestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    referenceoraclekind: Optional[str] = None
    predictedtrades: List[TradeRecord] = field(default_factory=list)
    referencetrades: List[TradeRecord] = field(default_factory=list)
    mismatches: List[MismatchDetail] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "schemaid": self.schemaid,
            "schemaversion": self.version.schema_version,
            "certtimestamp": self.certtimestamp,
            "certificationkind": self.certificationkind,
            "passed": self.passed,
            "runid": self.runid,
            "notes": list(self.notes),
            "version": self.version.to_dict(),
            "inputs": self.inputs.to_dict(),
            "tolerance": self.tolerance.to_dict(),
            "source": self.source.to_dict(),
            "reconciliation": self.reconciliation.to_dict(),
            "firstmismatch": self.firstmismatch.to_dict() if self.firstmismatch else None,
            "referenceoraclekind": self.referenceoraclekind,
            "predictedtrades": [t.to_dict() for t in self.predictedtrades or []],
            "referencetrades": [t.to_dict() for t in self.referencetrades or []],
            "mismatches": [m.to_dict() for m in self.mismatches or []],
            "extra": dict(self.extra),
        }
        d.setdefault("schema_id", d.get("schemaid"))
        d.setdefault("schema_version", d.get("schemaversion"))
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_reconciliation(
        cls,
        certificationkind: str,
        passed: bool,
        version: VersionStamp,
        inputs: InputFingerprint,
        tolerance: ToleranceProfile,
        source: SignalSourceSummary,
        reconciliation: ReconciliationStats,
        predictedtrades: Optional[List[TradeRecord]] = None,
        referencetrades: Optional[List[TradeRecord]] = None,
        mismatches: Optional[List[MismatchDetail]] = None,
        firstmismatch: Optional[MismatchDetail] = None,
        referenceoraclekind: Optional[str] = None,
        runid: Optional[str] = None,
        notes: Optional[List[str]] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> "CertificationProof":
        """
        Factory build from a reconciliation payload.
        Preferred over direct constructor.
        """
        return cls(
            certificationkind=certificationkind,
            passed=passed,
            version=version,
            inputs=inputs,
            tolerance=tolerance,
            source=source,
            reconciliation=reconciliation,
            firstmismatch=firstmismatch,
            runid=runid,
            notes=list(notes or []),
            extra=dict(extra or {}),
            referenceoraclekind=referenceoraclekind,
            predictedtrades=list(predictedtrades or []),
            referencetrades=list(referencetrades or []),
            mismatches=list(mismatches or []),
        )

def validate_proof_dict(payload: Dict[str, Any]) -> List[str]:
    """
    Validate a proof dict.
    Returns list of error strings (empty == valid).
    Does NOT raise; callers must check the returned list.
    Use assert_valid_proof_dict for fail-closed write paths.
    """
    errors: List[str] = []

    if not isinstance(payload, dict):
        return ["payload is not a dict"]

    sid = payload.get("schemaid", "")
    if not str(sid).startswith("zenith.parity.proof"):
        errors.append(f"schemaid mismatch: {sid!r}")

    kind = str(payload.get("certificationkind", ""))
    if kind and kind not in VALID_CERT_KINDS:
        errors.append(
            f"certificationkind {kind!r} not in valid set {sorted(VALID_CERT_KINDS)}"
        )

    if kind == CERT_KIND_NONE and payload.get("passed") is True:
        errors.append("certificationkind 'none' is invalid when passed=True")

    version = payload.get("version") or {}
    for vf in ("optimizer_version", "analyzer_version"):
        if not str(version.get(vf, "")).strip():
            errors.append(f"version.{vf} is empty")

    inputs = payload.get("inputs") or {}
    for hf in ("ohlcv_hash", "params_hash", "config_hash"):
        if not str(inputs.get(hf, "")).strip():
            errors.append(f"inputs.{hf} is empty")

    if kind == CERT_KIND_STRICT_PREDICTIVE:
        source = payload.get("source") or {}
        recon = payload.get("reconciliation") or {}

        if not source.get("predictivecertification"):
            errors.append(
                f"{kind}: source.predictivecertification must be True"
            )
        if not source.get("oracleblindenforced"):
            errors.append(
                f"{kind}: source.oracleblindenforced must be True"
            )
        if source.get("oraclekind") != "pyrecalc":
            errors.append(
                f"{kind}: oraclekind must be 'pyrecalc', got {source.get('oraclekind')!r}"
            )
        if source.get("mode") != "predictivecert":
            errors.append(
                f"{kind}: mode must be 'predictivecert', got {source.get('mode')!r}"
            )
        if not source.get("tvsignalreadsblocked"):
            errors.append(
                f"{kind}: source.tvsignalreadsblocked must be True"
            )
        if int(recon.get("tvtradecount") or 0) == 0:
            errors.append(
                f"{kind}: tvtradecount must be > 0 (reference oracle not loaded)"
            )

        refok = payload.get("referenceoraclekind")
        if refok not in ("tvledger", "externallist"):
            errors.append(
                f"{kind}: referenceoraclekind must be 'tvledger' or 'externallist', got {refok!r}"
            )

        for hf in ("ohlcv_hash", "params_hash", "config_hash"):
            hv = str(inputs.get(hf, "")).strip()
            if not hv or hv == "unknown":
                errors.append(
                    f"{kind}: inputs.{hf} must be a real hash, got {hv!r}"
                )

    recon = payload.get("reconciliation") or {}
    predicted = payload.get("predictedtrades") or []
    reference = payload.get("referencetrades") or []
    mismatches = payload.get("mismatches") or []

    pycount = recon.get("pythontradecount")
    tvcount_r = recon.get("tvtradecount")

    if pycount is not None and len(predicted) > 0 and len(predicted) != pycount:
        errors.append(
            f"predictedtrades length {len(predicted)} != "
            f"reconciliation.pythontradecount {pycount}"
        )

    if tvcount_r is not None and len(reference) > 0 and len(reference) != tvcount_r:
        errors.append(
            f"referencetrades length {len(reference)} != "
            f"reconciliation.tvtradecount {tvcount_r}"
        )

    mismatchcount = recon.get("mismatchedcount", 0) or 0
    if len(mismatches) > 0 and mismatchcount == 0:
        errors.append(
            f"mismatches list has {len(mismatches)} entries but "
            f"reconciliation.mismatchedcount == 0"
        )

    source = payload.get("source") or {}
    certkindval = str(payload.get("certificationkind", ""))
    sigsrc = source.get("signalsource") or source.get("mode")

    if certkindval == CERT_KIND_FORENSIC and sigsrc and sigsrc not in ("tvdrow", "parity"):
        errors.append(
            f"certificationkind='forensic' requires signalsource='tvdrow', got {sigsrc!r}"
        )

    if certkindval == CERT_KIND_FORENSIC_DIAG:
        compared = source.get("comparedfields") or []
        if not compared:
            errors.append(
                "certificationkind='forensic_diag' compare mode must populate "
                "source.comparedfields; empty compare metadata is invalid evidence"
            )

    return errors


def assert_valid_proof_dict(payload: Dict[str, Any]) -> None:
    """
    Fail-closed validator: raises ValueError if any errors are found.
    Use this on all analyzer proof write paths.
    """
    errors = validate_proof_dict(payload)
    if errors:
        raise ValueError("Invalid certification proof: " + " | ".join(errors))

def build_default_tolerance(tick_size: float = 0.01) -> ToleranceProfile:
    tol = max(float(tick_size), 1e-6)
    return ToleranceProfile(
        entry_price_abs=tol,
        exit_price_abs=tol,
        entry_time_seconds=0,
        exit_time_seconds=0,
        pnl_abs=1e-6,
    )


def hash_dict(d: Dict[str, Any]) -> str:
    serialized = json.dumps(d, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()[:16]


def hash_file(path: str) -> str:
    try:
        with open(path, "rb") as f:
            data = f.read(65536)
        return hashlib.sha256(data).hexdigest()[:16]
    except Exception:
        return "unknown"


def schema_mode_from_runtime(mode: str) -> str:
    return {
        "parity": "parity",
        "autonomous": "autonomous",
        "compare": "compare",
        "predictivecert": "predictivecert",
        "strictpredictivecert": "predictivecert",
        "barscan": "barscan",
    }.get(str(mode), "autonomous")


def normalize_signal_source(value: Optional[str]) -> str:
    v = str(value or "").strip().lower()
    aliases = {
        "tv_drow": "tvdrow",
        "tvdrow": "tvdrow",
        "py_recalc": "pyrecalc",
        "pyrecalc": "pyrecalc",
        "compare": "compare",
        "parity": "tvdrow",
        "autonomous": "pyrecalc",
        "barscan": "pyrecalc",
        "strict_predictive_cert": "pyrecalc",
        "strictpredictivecert": "pyrecalc",
        "predictivecert": "pyrecalc",
    }
    out = aliases.get(v)
    if out is None:
        raise ValueError(f"Unknown signal source/runtime label: {value!r}")
    return out


def schema_oracle_from_signal_source(signal_source_mode: str) -> str:
    """
    Map a signal-source mode string to canonical oraclekind.

    Accepts both legacy spellings (tv_drow, py_recalc) and new compact
    spellings (tvdrow, pyrecalc) via normalize_signal_source().
    """
    src = normalize_signal_source(signal_source_mode)
    return {
        "tvdrow": "tvdrow",
        "pyrecalc": "pyrecalc",
        "compare": "compare",
    }.get(src, "unknown")


def schema_oracle_from_runtime(signal_source_mode: str) -> str:
    """
    Backward-compatible alias for schema_oracle_from_signal_source().

    Input must still be a signal-source mode, not a high-level runtime label.
    """
    return schema_oracle_from_signal_source(signal_source_mode)


def default_certification_kind_from_source(
    signal_source_summary: SignalSourceSummary,
    requested_certification: Optional[str] = None,
) -> str:
    """
    Return the default certification kind implied by runtime/source state.

    This is a policy convenience helper, not a proof authority primitive.
    Callers should not rely on this as a substitute for explicit
    certification-kind declaration in the proof payload.
    """
    if requested_certification in ("strictpredictivecert", "predictive"):
        if not signal_source_summary.predictivecertification:
            raise RuntimeError(
                f"certification kind {requested_certification!r} requested "
                f"but signal_source_summary.predictivecertification is False"
            )
        return CERT_KIND_STRICT_PREDICTIVE

    src = signal_source_summary.signalsource or signal_source_summary.mode
    if src == "compare":
        return CERT_KIND_FORENSIC_DIAG
    if src in ("tvdrow", "parity"):
        return CERT_KIND_FORENSIC
    return CERT_KIND_NONE


def resolve_certification_kind(
    signal_source_summary: SignalSourceSummary,
    requested_certification: Optional[str] = None,
) -> str:
    """
    Backward-compatible alias for default_certification_kind_from_source().
    """
    return default_certification_kind_from_source(
        signal_source_summary,
        requested_certification,
    )


def _env_first(*names: str, default: str = "") -> str:
    import os
    for name in names:
        val = os.getenv(name)
        if val is not None and str(val).strip() != "":
            return str(val).strip()
    return default


def _env_bool(*names: str, default: bool = False) -> bool:
    raw = _env_first(*names, default="1" if default else "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class RuntimeContract:
    """
    Single frozen certification contract resolved once at startup.

    Nothing in the engine reads env vars directly after this object is built.
    All behavioral decisions flow through RuntimeContract, not os.environ.

    Resolve once via RuntimeContract.from_env() or RuntimeContract.from_args()
    at the entry point (CLI main, test harness, or analyzer main).
    Pass as an argument through the call stack; do not re-read env in hot paths.
    """
    execution_mode: str
    signal_source: str
    predictive_certification: bool = False
    parity_mode: bool = False
    allow_tv_signal_reads: bool = True
    allow_tv_structural_reads: bool = True
    allow_forced_trade_injection: bool = False
    strict_scalar_validation: bool = False
    strict_structural_validation: bool = False
    enforce_gate_matrix: bool = False

    @classmethod
    def from_env(cls) -> "RuntimeContract":
        """
        Resolve RuntimeContract once from environment variables at startup.
        """
        signal_source = normalize_signal_source(
            _env_first("MEGASIGNALSOURCE", "MEGA_SIGNAL_SOURCE", default="tvdrow")
        )
        predictive = _env_bool(
            "MEGAPREDICTIVECERT",
            "MEGA_PREDICTIVE_CERT",
            "PREDICTIVE_CERTIFICATION",
            default=False,
        )
        parity = _env_bool("PARITYMODE", "PARITY_MODE", default=False)
        enforce_gate = _env_bool(
            "ENFORCEGATEMATRIX",
            "ENFORCE_GATE_MATRIX",
            default=False,
        )
        strict_struct = _env_bool(
            "STRICTSTRUCTFIELDS",
            "STRICT_STRUCT_FIELDS",
            default=True,
        )

        if predictive:
            execution_mode = "predictivecert"
        elif signal_source == "compare":
            execution_mode = "compare"
        elif signal_source == "tvdrow":
            execution_mode = "parity"
        else:
            execution_mode = "autonomous"

        if predictive:
            enforce_gate = True
            strict_struct = True

        return cls(
            execution_mode=execution_mode,
            signal_source=signal_source,
            predictive_certification=predictive,
            parity_mode=parity,
            allow_tv_signal_reads=signal_source in ("tvdrow", "compare") and not predictive,
            allow_tv_structural_reads=not predictive,
            allow_forced_trade_injection=False,
            strict_scalar_validation=predictive or signal_source == "tvdrow",
            strict_structural_validation=strict_struct,
            enforce_gate_matrix=enforce_gate,
        )

    @classmethod
    def for_mode(
        cls,
        mode: str,
        *,
        predictive_certification: bool = False,
        enforce_gate_matrix: bool = False,
    ) -> "RuntimeContract":
        """
        Build RuntimeContract from a named mode string for test harnesses.
        """
        mode_to_source = {
            "parity": "tvdrow",
            "autonomous": "pyrecalc",
            "compare": "compare",
            "barscan": "pyrecalc",
            "strict_predictive_cert": "pyrecalc",
            "strictpredictivecert": "pyrecalc",
            "predictivecert": "pyrecalc",
            "perfdebug": "tvdrow",
        }
        mode_norm = str(mode or "").strip().lower()
        signal_source = normalize_signal_source(
            mode_to_source.get(mode_norm, mode_norm or "tvdrow")
        )
        predictive = predictive_certification or mode_norm in {
            "strict_predictive_cert",
            "strictpredictivecert",
            "predictivecert",
        }

        return cls(
            execution_mode=mode_norm,
            signal_source=signal_source,
            predictive_certification=predictive,
            parity_mode=(mode_norm == "parity"),
            allow_tv_signal_reads=signal_source in ("tvdrow", "compare") and not predictive,
            allow_tv_structural_reads=not predictive,
            allow_forced_trade_injection=False,
            strict_scalar_validation=predictive or signal_source == "tvdrow",
            strict_structural_validation=predictive,
            enforce_gate_matrix=predictive or enforce_gate_matrix,
        )


def assert_cert_run_clean(contract: RuntimeContract) -> None:
    """
    The single certification gate: raises if ANY Bundle A invariant is violated.

    Call this once at the entry of every cert-labeled run, before any
    simulation, bar processing, or proof building.

    If this passes, the run is under contract. This is the lock.
    Everything else is metalwork around it.
    """
    violations: List[str] = []

    if contract.predictive_certification:
        if contract.signal_source != "pyrecalc":
            violations.append(
                f"predictive_certification=True requires signal_source='pyrecalc', "
                f"got {contract.signal_source!r}"
            )
        if contract.allow_tv_signal_reads:
            violations.append(
                "predictive_certification=True: allow_tv_signal_reads must be False"
            )
        if contract.allow_tv_structural_reads:
            violations.append(
                "predictive_certification=True: allow_tv_structural_reads must be False"
            )
        if not contract.strict_structural_validation:
            violations.append(
                "predictive_certification=True: strict_structural_validation must be True "
                "(gate-critical structural fields may not silently default)"
            )
        if not contract.strict_scalar_validation:
            violations.append(
                "predictive_certification=True: strict_scalar_validation must be True "
                "(missing Python scalar fields must fail closed, not silently return None)"
            )
        if not contract.enforce_gate_matrix:
            violations.append(
                "predictive_certification=True: enforce_gate_matrix must be True"
            )

    if contract.allow_forced_trade_injection:
        violations.append(
            "allow_forced_trade_injection=True is never permitted in contract-bound runs; "
            "this field exists only to detect misconfiguration"
        )

    if violations:
        raise RuntimeError(
            "CERTRUNVIOLATION: assert_cert_run_clean failed: " + " | ".join(violations)
        )

def py_trade_to_record(
    trade,
    *,
    bars_by_bi: Optional[Dict[int, Any]] = None,
    utc_to_chart_ts=None,
) -> TradeRecord:
    """
    Convert a Python Position trade object or dict into a typed TradeRecord.

    Uses actual optimizer Position field names:
    .entrybi, .exitbi, .fillprice, .exitprice, .netpnl, .qty, .side, .tradeid

    bars_by_bi: optional dict {bar_index: bar_dict} used to resolve timestamps.
    utc_to_chart_ts: optional callable(utc_int) -> str for timestamp formatting.
    """
    def g(*attr, default=None):
        for name in attr:
            if hasattr(trade, name):
                v = getattr(trade, name)
                if v is not None:
                    return v
            if isinstance(trade, dict):
                v = trade.get(name)
                if v is not None:
                    return v
        return default

    side_raw = g("side", default=0)
    side_str = "long" if int(side_raw or 0) > 0 else "short"

    ebi = g("entrybi", "ebar", default=None)
    xbi = g("exitbi", "xbar", default=None)
    epx = g("fillprice", "entryprice", "ep", default=None)
    xpx = g("exitprice", "xp", default=None)
    pnl = g("netpnl", "pl", "profit", "pnl", default=None)
    qty = g("qty", default=None)
    tid = g("tradeid", default=None)

    def chart_ts(bi) -> Optional[str]:
        if bi is None:
            return None
        if bars_by_bi is not None:
            b = bars_by_bi.get(int(bi))
            if b:
                tval = b.get("time")
                if tval is not None:
                    if utc_to_chart_ts is not None:
                        try:
                            return utc_to_chart_ts(tval)[:16] or None
                        except Exception:
                            pass
                    return str(tval).replace("T", " ")[:16] or None
        return None

    bars_held = None
    if ebi is not None and xbi is not None:
        try:
            bars_held = int(xbi) - int(ebi)
        except Exception:
            pass

    return TradeRecord(
        entrytime=chart_ts(ebi) or "",
        side=side_str,
        entrypx=float(epx) if epx is not None else 0.0,
        exittime=chart_ts(xbi),
        exitpx=float(xpx) if xpx is not None else None,
        pnl=float(pnl) if pnl is not None else None,
        qty=float(qty) if qty is not None else None,
        tradeid=str(tid) if tid is not None else None,
        barsheld=bars_held,
    )


def tv_trade_to_record(trade: Dict[str, Any]) -> TradeRecord:
    """
    Convert a TV T-ledger dict into a typed TradeRecord.

    TV ledger field names: et, xt, ep, xp, profit, side (int),
    ebar, xbar, qty, tradeid
    """
    side_raw = trade.get("side", 0)
    side_str = "long" if int(side_raw or 0) > 0 else "short"

    ebar = trade.get("ebar")
    xbar = trade.get("xbar")
    bars_held = None
    if ebar is not None and xbar is not None:
        try:
            bars_held = int(xbar) - int(ebar)
        except Exception:
            pass

    epx = trade.get("ep")
    xpx = trade.get("xp")
    pnl = trade.get("profit")
    qty = trade.get("qty")
    tid = trade.get("tradeid")

    return TradeRecord(
        entrytime=str(trade.get("et") or ""),
        side=side_str,
        entrypx=float(epx) if epx is not None else 0.0,
        exittime=str(trade.get("xt")) if trade.get("xt") else None,
        exitpx=float(xpx) if xpx is not None else None,
        pnl=float(pnl) if pnl is not None else None,
        qty=float(qty) if qty is not None else None,
        tradeid=str(tid) if tid is not None else None,
        barsheld=bars_held,
    )


def normalize_py_trades(
    trades,
    *,
    bars_by_bi: Optional[Dict[int, Any]] = None,
    utc_to_chart_ts=None,
) -> List[TradeRecord]:
    """
    Batch convert Python trade list to TradeRecord list.
    """
    return [
        py_trade_to_record(
            t,
            bars_by_bi=bars_by_bi,
            utc_to_chart_ts=utc_to_chart_ts,
        )
        for t in trades or []
        if t is not None
    ]


def normalize_tv_trades(trades) -> List[TradeRecord]:
    """
    Batch convert TV ledger list to TradeRecord list.
    """
    return [tv_trade_to_record(t) for t in trades or [] if t is not None]


# ---------------------------------------------------------------------------
# Public compatibility aliases
# ---------------------------------------------------------------------------

schema_oracle_from_runtime_signal_source = schema_oracle_from_signal_source

if not hasattr(RuntimeContract, "from_mode"):
    RuntimeContract.from_mode = RuntimeContract.for_mode

if not hasattr(RuntimeContract, "fromenv"):
    RuntimeContract.fromenv = RuntimeContract.from_env
