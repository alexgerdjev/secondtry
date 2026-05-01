"""
Discovery sweep — 1000-combo run targeting PF >= 1.8, both sides, trades >= 8.

Usage (Windows PowerShell):
    $env:N_SAMPLES='1000'; $env:N_WORKERS='8'
    python run_discovery.py

Environment variables:
    N_SAMPLES       Combos to evaluate (default 1000)
    RANDOM_SEED     Reproducibility (default 42)
    RESUME_FROM     Path to existing _all.csv to resume from

    DISCOVERY_MIN_TRADES   Min trades for discovery gate (default 8)
    DISCOVERY_PF_GATE      Min PF for discovery gate (default 1.8)
    HIGH_WR_MIN_TRADES     Min trades for high-WR shortlist (default 10)
    HIGH_WR_MIN_WR         Min WR for high-WR shortlist (default 0.60)
    HIGH_WR_MIN_PF         Min PF for high-WR shortlist (default 1.8)

Labels written to strict_label column:
    strict_winner    — passes discovery gate (trades>=8, PF>=1.8, both sides)
    high_wr_winner   — also passes WR>=60% AND trades>=10 (TV candidate shortlist)
    below_threshold  — everything else

Architecture:
    MEGA_FULL_RANGE_SIM=1 — one simulate() per combo, no window aggregation.
    MEGA_WIDE_RANGES=0    — all samples inside TYPICAL_RANGES_WINNERS basin.
    Metrics are single-run, identical to what TV Strategy Tester will show.

Separation of concerns:
    Discovery gate  = run-local acceptance for THIS sweep (PF>=1.8, trades>=8)
    Certification   = TV-match verification, done separately after shortlisting
    Global target   = WR>70%, PF>2.0 — final aspirational goal, not a filter here
"""

import sys, os, time, random, csv, gc

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Environment — set BEFORE importing optimizer ───────────────────────
os.environ['MEGA_SIGNAL_SOURCE']             = 'py_recalc'
os.environ['ALLOW_TV_EXPORT_PARAM_OVERRIDE'] = '1'
os.environ['MEGA_FAST_SWEEP']                = '1'
os.environ['MEGA_FULL_RANGE_SIM']            = '1'   # single-run, no window aggregation
os.environ['MEGA_WIDE_RANGES']               = '0'   # stay inside winner basin — no 70/30 split

import Optimizer_Anti_2 as opt

opt.PARITY_MODE   = False
opt.FORENSIC_LOCK = False

# ── Configuration ──────────────────────────────────────────────────────
N_SAMPLES   = int(os.environ.get('N_SAMPLES',   '1000'))
RANDOM_SEED = int(os.environ.get('RANDOM_SEED', '42'))
RESUME_FROM = os.environ.get('RESUME_FROM', '')

# Discovery gate (run-local — does not override global certification standards)
DISC_MIN_TRADES = int(os.environ.get('DISCOVERY_MIN_TRADES', '8'))
DISC_PF_GATE    = float(os.environ.get('DISCOVERY_PF_GATE',  '1.8'))

# High-WR shortlist (secondary label — TV verification candidates)
HWR_MIN_TRADES  = int(os.environ.get('HIGH_WR_MIN_TRADES', '10'))
HWR_MIN_WR      = float(os.environ.get('HIGH_WR_MIN_WR',   '0.60'))
HWR_MIN_PF      = float(os.environ.get('HIGH_WR_MIN_PF',   '1.8'))

CAPITAL = 10000.0

RUN_ID      = time.strftime('%Y%m%d_%H%M%S')
OUT_DIR     = r'D:\ToTheMoon'
OUT_ALL     = os.path.join(OUT_DIR, f'mega_results_{RUN_ID}_all.csv')
OUT_STRICT  = os.path.join(OUT_DIR, f'mega_results_{RUN_ID}_strict.csv')
OUT_HIGH_WR = os.path.join(OUT_DIR, f'mega_results_{RUN_ID}_highwr.csv')

random.seed(RANDOM_SEED)

# ── Data files ─────────────────────────────────────────────────────────
# ohlcv30: genesis Oct 1 2025, 20,314 bars through Apr 30 2026
OHLCV_FILES = [
    r'D:\ToTheMoon\ohlcv30 (1).csv',
    r'D:\ToTheMoon\ohlcv30 (2).csv',
    r'D:\ToTheMoon\ohlcv30 (3).csv',
]

# ── Stale override guard ────────────────────────────────────────────────
_zone_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          'zone_analysis_ranges.json')
if os.path.exists(_zone_file):
    print(f'[WARNING] zone_analysis_ranges.json found — this would silently override')
    print(f'  TYPICAL_RANGES_WINNERS. Rename or delete it before running.')
    print(f'  Path: {_zone_file}')
    raise SystemExit('zone_analysis_ranges.json must be removed before discovery run.')

# ── Metric helpers ──────────────────────────────────────────────────────
# agg = (Eq, WR, DD, Exp, Trades, Dur, Sharpe, PF, wins, losses, TrL, TrS)
def _pf(agg):  return float(agg[7])  if agg and len(agg) > 7  else 0.0
def _wr(agg):  return float(agg[1])  if agg and len(agg) > 1  else 0.0
def _eq(agg):  return float(agg[0])  if agg and len(agg) > 0  else CAPITAL
def _dd(agg):  return float(agg[2])  if agg and len(agg) > 2  else 0.0
def _trl(agg): return int(agg[10])   if agg and len(agg) > 10 else 0
def _trs(agg): return int(agg[11])   if agg and len(agg) > 11 else 0
def _trades(seg_bundle): return int(seg_bundle.get('trades', 0)) if seg_bundle else 0

def classify(full_agg, seg_bundle):
    """
    Returns label string. Three tiers:
      high_wr_winner  - WR>=60%, PF>=1.8, trades>=10, both sides -> TV candidate shortlist
      strict_winner   - PF>=1.8, trades>=8, both sides -> discovery pass
      below_threshold - everything else
    """
    n   = _trades(seg_bundle)
    pf  = _pf(full_agg)
    wr  = _wr(full_agg)
    trl = _trl(full_agg)
    trs = _trs(full_agg)
    both_sides = trl > 0 and trs > 0

    if not both_sides:
        return 'below_threshold'   # single-direction = not robust
    if pf >= HWR_MIN_PF and wr >= HWR_MIN_WR and n >= HWR_MIN_TRADES:
        return 'high_wr_winner'    # best candidates for TV cert
    if pf >= DISC_PF_GATE and n >= DISC_MIN_TRADES:
        return 'strict_winner'     # discovery pass
    return 'below_threshold'

def score(full_agg):
    return round(_pf(full_agg) * _wr(full_agg), 4)

# ── Resume ─────────────────────────────────────────────────────────────
done_ids = set()
if RESUME_FROM and os.path.exists(RESUME_FROM):
    with open(RESUME_FROM, encoding='utf-8-sig') as f:
        for row in csv.DictReader(f):
            done_ids.add(row.get('combo_id', ''))
    print(f'[resume] Found {len(done_ids)} already-evaluated combos in {RESUME_FROM}')
    OUT_ALL = RESUME_FROM

# ── Load and precompute ────────────────────────────────────────────────
print(f'[run_discovery] Loading {len(OHLCV_FILES)} OHLCV files...', flush=True)
bars, t_rows, meta, schema_id, h_rows = opt.load_data(OHLCV_FILES)

if len(t_rows) != 0:
    raise RuntimeError(f'Expected 0 T-rows for discovery but got {len(t_rows)}.')

print(f'[run_discovery] {len(bars)} bars '
      f'[{bars[0]["time"]} -> {bars[-1]["time"]}]. '
      f'Precomputing indicators...', flush=True)

result   = opt.precompute_forensic_bars(bars, t_rows, meta, schema_id, h_rows)
uplifted = result[0]

opt.init_worker([], opt.TICKSIZE, opt.COMMISSIONPCT, opt.INITIALCAPITAL,
                '', full_data=uplifted)

# Force-load TYPICAL_RANGES_WINNERS if not already set (bypasses run_sweep() path)
import Optimizer_Anti_2 as _o
if _o.TYPICAL_RANGES is None:
    _o.TYPICAL_RANGES = _o.TYPICAL_RANGES_WINNERS
    print(f'[run_discovery] Loaded TYPICAL_RANGES_WINNERS '
          f'({len(_o.TYPICAL_RANGES)} params) directly.', flush=True)
if _o.TYPICAL_RANGES is None:
    raise SystemExit('[FATAL] TYPICAL_RANGES is None after force-load — check Optimizer_Anti_2.py')
print(f'[run_discovery] TYPICAL_RANGES active: {len(_o.TYPICAL_RANGES)} params '
      f'(TYPICAL_RANGES_WINNERS basin).', flush=True)
print(f'[run_discovery] MEGA_WIDE_RANGES=0 -> 100% basin sampling, no 70/30 split.', flush=True)
print(f'[run_discovery] Discovery gate: PF>={DISC_PF_GATE}, trades>={DISC_MIN_TRADES}, both sides.', flush=True)
print(f'[run_discovery] High-WR shortlist: WR>={HWR_MIN_WR}, PF>={HWR_MIN_PF}, trades>={HWR_MIN_TRADES}.', flush=True)
print(f'[run_discovery] Global cert target (WR>70%, PF>2.0) is separate — applied post-run.', flush=True)

# ── CSV schema ─────────────────────────────────────────────────────────
dummy_params = opt.random_param_set()
FIELDNAMES = (
    ['combo_id', 'strict_label',
     'full_trades', 'full_pf', 'full_wr', 'full_eq', 'full_dd',
     'trl', 'trs', 'score', 'time_s']
    + sorted(dummy_params.keys())
)

def _open_csv(path, append=False):
    mode = 'a' if append else 'w'
    f = open(path, mode, newline='', encoding='utf-8')
    w = csv.DictWriter(f, fieldnames=FIELDNAMES, extrasaction='ignore')
    if not append:
        w.writeheader()
    return f, w

if RESUME_FROM and os.path.exists(RESUME_FROM):
    all_f, all_w = _open_csv(OUT_ALL, append=True)
else:
    all_f, all_w = _open_csv(OUT_ALL)

strict_f,  strict_w  = _open_csv(OUT_STRICT)
highwr_f,  highwr_w  = _open_csv(OUT_HIGH_WR)

# ── Main sweep ─────────────────────────────────────────────────────────
n_strict   = 0
n_highwr   = 0
t0_all     = time.perf_counter()
evaluated  = 0

print(f'\n[run_discovery] Starting {N_SAMPLES}-combo sweep '
      f'(seed={RANDOM_SEED}, FULL_RANGE_SIM=1, WIDE_RANGES=0)...\n', flush=True)

for combo_i in range(1, N_SAMPLES + 1):
    params = opt.random_param_set()
    cid    = f'ID_{combo_i:05d}'

    if cid in done_ids:
        print(f'  [{combo_i:4d}] {cid} -- already done, skipping', flush=True)
        continue

    t0 = time.perf_counter()

    try:
        _, full_agg, _, wf_tags, seg_bundle = opt.run_worker(params)
        if full_agg is None:
            print(f'  [{combo_i:4d}] {cid}  SKIPPED (null agg)', flush=True)
            continue
    except Exception as exc:
        print(f'  [{combo_i:4d}] {cid}  ERROR: {exc}', flush=True)
        continue

    dt = time.perf_counter() - t0

    pf_full = _pf(full_agg)
    wr_full = _wr(full_agg)
    eq_full = _eq(full_agg)
    dd_full = _dd(full_agg)
    n_full  = _trades(seg_bundle)
    trl     = _trl(full_agg)
    trs     = _trs(full_agg)
    label   = classify(full_agg, seg_bundle)
    sc      = score(full_agg)

    if label in ('strict_winner', 'high_wr_winner'):
        n_strict += 1
    if label == 'high_wr_winner':
        n_highwr += 1

    row = {
        'combo_id':     cid,
        'strict_label': label,
        'full_trades':  n_full,
        'full_pf':      round(pf_full, 6),
        'full_wr':      round(wr_full, 6),
        'full_eq':      round(eq_full, 2),
        'full_dd':      round(dd_full, 6),
        'trl':          trl,
        'trs':          trs,
        'score':        sc,
        'time_s':       round(dt, 2),
        **{k: round(v, 6) if isinstance(v, float) else v for k, v in params.items()},
    }
    all_w.writerow(row); all_f.flush()
    if label in ('strict_winner', 'high_wr_winner'):
        strict_w.writerow(row); strict_f.flush()
    if label == 'high_wr_winner':
        highwr_w.writerow(row); highwr_f.flush()

    evaluated += 1
    elapsed = time.perf_counter() - t0_all
    rate    = evaluated / elapsed
    eta     = (N_SAMPLES - combo_i) / rate if rate > 0 else 0

    marker = '*' if label == 'high_wr_winner' else ('+' if label == 'strict_winner' else ' ')
    print(f'  [{combo_i:4d}/{N_SAMPLES}] {marker} {label:<16}  '
          f'pf={pf_full:5.3f}  wr={wr_full:.3f}  '
          f'n={n_full:3d}({trl}L+{trs}S)  eq={eq_full:.2f}  '
          f'{dt:.2f}s  ETA={eta:.0f}s', flush=True)

all_f.close(); strict_f.close(); highwr_f.close()

elapsed_total = time.perf_counter() - t0_all
print(f'\n{"="*70}')
print(f'Run {RUN_ID} complete')
if evaluated:
    print(f'  Combos evaluated : {evaluated}/{N_SAMPLES}')
    print(f'  Strict winners   : {n_strict}  ({n_strict/evaluated*100:.1f}%)  [PF>={DISC_PF_GATE}, trades>={DISC_MIN_TRADES}, both sides]')
    print(f'  High-WR shortlist: {n_highwr}  ({n_highwr/evaluated*100:.1f}%)  [WR>={HWR_MIN_WR}, PF>={HWR_MIN_PF}, trades>={HWR_MIN_TRADES}]')
    print(f'  Time             : {elapsed_total:.0f}s  ({elapsed_total/evaluated:.2f}s/combo)')
    print(f'  Speed estimate   : {3600//(elapsed_total/evaluated):.0f} combos/hour per worker')
print(f'  All results      : {OUT_ALL}')
print(f'  Strict winners   : {OUT_STRICT}')
print(f'  High-WR shortlist: {OUT_HIGH_WR}')
print(f'{"="*70}')
print()
print('NEXT STEPS:')
print(f'  1. Sort {OUT_HIGH_WR} by score (PF*WR) descending')
print(f'  2. Top 5-10 -> magic_numbers -> load into TV -> export OHLCV_PASS x3 + LEDGER_PASS')
print(f'  3. Run parity check - combos hitting WR>=70% on TV are certified winners')
print(f'  4. Global target (WR>70%, PF>2.0) applied here at cert stage, not discovery')
