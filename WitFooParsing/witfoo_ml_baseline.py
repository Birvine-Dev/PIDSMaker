#!/usr/bin/env python3
"""witfoo_ml_baseline.py — conventional unsupervised ML baseline (Isolation Forest).

PURPOSE (Mengmeng's suggestion, scope pending supervisor confirmation):
PIDS sit at the END of a SOC pipeline; conventional detection strips obvious
attacks upstream. This baseline tests whether the WitFoo test-day attacks are
catchable by a deliberately SIMPLE unsupervised detector — no graph, no deep
learning — trained on a benign day. If yes, these attacks would plausibly
never reach a PIDS in deployment.

DESIGN NOTES:
 * Entity = EVENT (the natural upstream/SIEM granularity). Metrics are
   computed by the SAME functions as the PIDS extraction (spliced verbatim):
   headline P/R/F1, framework-exact ADP, entity AP, bootstrap CIs,
   per-incident coverage. Granularity caveat travels with any comparison.
 * The signature field is EXCLUDED from features: malicious events carry
   empty signatures in this dataset, so using it would be label leakage.
 * Features per event: train-day rarity of src host / dst host / src->dst
   pair (+unseen flags), same-second burst count for the src, time-of-day.
 * GT: Disrupted events; attacks = union-find merge of co-listed incident
   ids (same rule as witfoo_incident_stats_v3), indexed by first event time
   so attack numbering matches attack_idx / per_incident.csv.

USAGE (dates are placeholders — set the real benign training day):
  python3 WitFooParsing/witfoo_ml_baseline.py --edges ~/WitFoo84M/graph \\
      --org ORG-0004 --train-date 2024-07-22 --test-date 2024-07-29 \\
      --out-dir analysis_out
"""
import argparse, collections, csv, glob as globmod, gzip, json, math, os, pickle
import numpy as np

p = argparse.ArgumentParser()
p.add_argument("--edges", required=True)
p.add_argument("--org", default="ORG-0004")
p.add_argument("--train-date", action="append", required=True,
               help="benign day(s) to train on; repeatable")
p.add_argument("--test-date", default="2024-07-29")
p.add_argument("--dispositions", default="Disrupted")
p.add_argument("--n-estimators", type=int, default=200)
p.add_argument("--seed", type=int, default=0)
p.add_argument("--bootstrap", type=int, default=20)
p.add_argument("--out-dir", default="analysis_out")
a = p.parse_args()
DISP = set(a.dispositions.split(","))

from datetime import datetime, timezone

def edge_files(path):
    if os.path.isdir(path):
        fs = sorted(globmod.glob(os.path.join(path, "edges-*.jsonl.gz"))) or \
             sorted(globmod.glob(os.path.join(path, "*.jsonl*")))
    else:
        fs = sorted(globmod.glob(path)) or [path]
    if not fs:
        raise SystemExit(f"no edge files found at {path}")
    return fs

def stream_day(dates, want_labels):
    """Yield (src, dst, ts, hour, is_mal, iids) for org events on the dates."""
    dates = set(dates)
    for f in edge_files(a.edges):
        opener = gzip.open if f.endswith(".gz") else open
        for line in opener(f, "rt"):
            e = json.loads(line)
            if e.get("type") == "INCIDENT_LINK":
                continue
            at = e.get("attrs") or {}
            if a.org and at.get("org_id") != a.org:
                continue
            ts = e.get("timestamp", 0)
            if ts < 1_500_000_000:
                continue
            d = datetime.fromtimestamp(ts, tz=timezone.utc)
            if d.strftime("%Y-%m-%d") not in dates:
                continue
            is_mal, iids = 0, ()
            if want_labels:
                lab = e.get("labels") or {}
                if lab.get("label_binary") == "malicious" and \
                   lab.get("disposition") in DISP:
                    is_mal = 1
                    iids = tuple(sorted(set(lab.get("incident_ids") or
                        ([lab["incident_id"]] if lab.get("incident_id") else ()))))
            yield (e.get("src") or "?", e.get("dst") or "?", ts, d.hour + d.minute/60.0,
                   is_mal, iids)
        print(f"...{os.path.basename(f)} done", flush=True)

def featurize(rows, src_cnt, dst_cnt, pair_cnt):
    """rows: list of (src, dst, ts, hour, ...). Burst from the rows' own day."""
    burst = collections.Counter((r[0], int(r[2])) for r in rows)
    X = np.empty((len(rows), 9), dtype=np.float32)
    for i, r in enumerate(rows):
        s, d, ts, hr = r[0], r[1], r[2], r[3]
        cs, cd, cp = src_cnt.get(s, 0), dst_cnt.get(d, 0), pair_cnt.get((s, d), 0)
        X[i] = (math.log1p(cs), math.log1p(cd), math.log1p(cp),
                float(cs == 0), float(cd == 0), float(cp == 0),
                math.log1p(burst[(s, int(ts))]),
                math.sin(2*math.pi*hr/24.0), math.cos(2*math.pi*hr/24.0))
    return X

# ---------------- train ----------------
print(f"== pass 1: training day(s) {a.train_date} ==", flush=True)
train_rows = list(stream_day(a.train_date, want_labels=True))
n_mal_train = sum(r[4] for r in train_rows)
print(f"train events: {len(train_rows):,} ({n_mal_train:,} labelled malicious "
      f"on the training day{'s' if len(a.train_date)>1 else ''} — "
      f"{'WARNING: train day not clean!' if n_mal_train else 'clean'})")
src_cnt = collections.Counter(r[0] for r in train_rows)
dst_cnt = collections.Counter(r[1] for r in train_rows)
pair_cnt = collections.Counter((r[0], r[1]) for r in train_rows)
Xtr = featurize(train_rows, src_cnt, dst_cnt, pair_cnt)
del train_rows

from sklearn.ensemble import IsolationForest
clf = IsolationForest(n_estimators=a.n_estimators, random_state=a.seed,
                      max_samples=min(262144, len(Xtr)), n_jobs=-1)
clf.fit(Xtr)
print("IsolationForest fitted.", flush=True)

# ---------------- test ----------------
print(f"== pass 2: test day {a.test_date} ==", flush=True)
test_rows = list(stream_day([a.test_date], want_labels=True))
print(f"test events: {len(test_rows):,}")
Xte = featurize(test_rows, src_cnt, dst_cnt, pair_cnt)
ys = -clf.score_samples(Xte)                       # higher = more anomalous
yp = (clf.predict(Xte) == -1).astype(int)          # IF's own decision rule
yt = np.array([r[4] for r in test_rows], dtype=int)
print(f"positives on test day: {int(yt.sum()):,}; IF flags: {int(yp.sum()):,}")

# ---------------- GT attacks: union-find merge of incident ids ----------------
parent = {}
def find(x):
    parent.setdefault(x, x)
    while parent[x] != x:
        parent[x] = parent[parent[x]]; x = parent[x]
    return x
def union(x, y):
    rx, ry = find(x), find(y)
    if rx != ry: parent[ry] = rx
first_ts = {}
for r in test_rows:
    if r[4] and r[5]:
        for other in r[5][1:]:
            union(r[5][0], other)
for r in test_rows:
    if r[4] and r[5]:
        root = find(r[5][0])
        first_ts[root] = min(first_ts.get(root, 1e18), r[2])
roots_in_order = [k for k, _ in sorted(first_ts.items(), key=lambda kv: kv[1])]
root2idx = {root: i for i, root in enumerate(roots_in_order)}
ids = list(range(len(test_rows)))                  # entity id = event index
amap = {}
for i, r in enumerate(test_rows):
    if r[4] and r[5]:
        amap[i] = [root2idx[find(r[5][0])]]
print(f"merged attacks: {len(roots_in_order)} (expect 54)")

# ---------------- metrics (spliced verbatim from the extraction script) -------
def ap_entity(ys, yt):
    """Entity-level Average Precision: area under precision-recall over the
    ranking, counting each positive ENTITY individually. NOT the framework's
    ADP (which is incident-granular) -- kept as a complementary column; the
    gap between the two is itself informative (ADP can be high while most
    attack events are never ranked highly)."""
    order = np.argsort(-ys, kind="stable")
    ytr = yt[order]
    tp_cum = np.cumsum(ytr)
    npos = yt.sum()
    if npos == 0:
        return 0.0
    prec = tp_cum / np.arange(1, len(ytr) + 1)
    newtp = ytr == 1
    return float(np.sum(prec[newtp]) / npos)

def adp_incident(ys, yt, ids, amap):
    """Exact replication of the framework's plot_detected_attacks_vs_precision:
    walk the ranking (tie order = np.argsort(scores)[::-1], as the framework does);
    at each entity record precision and %attacks-detected (attack detected once
    any of its mapped entities has passed); start the curve at (0,0); collapse
    duplicate precision values by MAX detected-%; ADP = trapz(%detected, precision)
    / 100. total_attacks is taken from the mapping, matching the framework."""
    if amap is None or yt.sum() == 0:
        return ""
    order = np.argsort(ys)[::-1]           # framework's exact tie order
    yto = np.asarray(yt)[order]
    n = len(yto)
    tp_cum = np.cumsum(yto)
    prec = tp_cum / np.arange(1, n + 1, dtype=float)
    total = len(set(a for v in amap.values()
                    for a in (v if isinstance(v, (list, set, tuple)) else [v])))
    pct = np.zeros(n)
    det = set()
    cur = 0.0
    last = 0
    for p_i in np.where(yto == 1)[0]:
        pct[last:p_i] = cur
        i = order[p_i]
        key = ids[i] if ids is not None else i
        v = amap.get(key)
        if v:
            det.update(v if isinstance(v, (list, set, tuple)) else [v])
        cur = 100.0 * len(det) / max(total, 1)
        pct[p_i] = cur
        last = p_i + 1
    pct[last:] = cur
    prec = np.concatenate(([0.0], prec))
    pct = np.concatenate(([0.0], pct))
    o = np.argsort(prec, kind="stable")
    ps, cs = prec[o], pct[o]
    uniq, idx = np.unique(ps, return_index=True)
    maxs = np.maximum.reduceat(cs, idx)
    _trapz = getattr(np, "trapz", None) or np.trapezoid
    return round(float(_trapz(maxs, uniq)) / 100.0, 4)

def headline(yp, yt):
    tp = int(((yp == 1) & (yt == 1)).sum()); fp = int(((yp == 1) & (yt == 0)).sum())
    fn = int(yt.sum()) - tp
    P = tp / max(tp + fp, 1); R = tp / max(tp + fn, 1)
    F1 = 2 * P * R / max(P + R, 1e-12)
    return tp, fp, fn, P, R, F1

def bootstrap_ci(yp, yt, B, seed=0):
    rng = np.random.default_rng(seed)
    n = len(yt); Ps, Rs = [], []
    for _ in range(B):
        idx = rng.integers(0, n, n)
        tp, fp, fn, P, R, _ = headline(yp[idx], yt[idx])
        Ps.append(P); Rs.append(R)
    return (float(np.percentile(Ps, 2.5)), float(np.percentile(Ps, 97.5)),
            float(np.percentile(Rs, 2.5)), float(np.percentile(Rs, 97.5)))

def incident_rows(ys, yp, yt, ids, amap, tag):
    # percentile of each score among all scored (0..100, higher = more anomalous)
    order = np.argsort(np.argsort(ys))
    pctl = 100.0 * order / max(len(ys) - 1, 1)
    per = collections.defaultdict(lambda: {"tot": 0, "caught": 0, "pctls": []})
    for i in np.where(yt == 1)[0]:
        key = ids[i] if ids is not None else i
        attacks = amap.get(key, ["?"]) if hasattr(amap, "get") else ["?"]
        if not isinstance(attacks, (list, set, tuple)):
            attacks = [attacks]
        for a in attacks:
            r = per[a]; r["tot"] += 1; r["pctls"].append(pctl[i])
            if yp[i] == 1:
                r["caught"] += 1
    rows = []
    for a, r in sorted(per.items(), key=lambda x: str(x[0])):
        rows.append(tag + [a, r["tot"], r["caught"], round(r["caught"] / max(r["tot"], 1), 4),
                           round(max(r["pctls"]), 3), round(float(np.median(r["pctls"])), 3)])
    return rows


tp, fp, fn, P, R, F1 = headline(yp, yt)
ci = bootstrap_ci(yp, yt, a.bootstrap)
a_inc = adp_incident(ys, yt, ids, amap)
a_ent = ap_entity(ys, yt)
inc_hit = len(set(x for i in np.where((yp == 1) & (yt == 1))[0] for x in amap.get(i, ())))
print(f"\n== iforest baseline, IF decision rule ==")
print(f"flags {int(yp.sum()):,}  tp {tp:,}  P {P:.3f} [{ci[0]:.3f},{ci[1]:.3f}]  "
      f"R {R:.3f} [{ci[2]:.3f},{ci[3]:.3f}]  F1 {F1:.3f}  "
      f"ADP {a_inc}  AP {a_ent:.3f}  incidents {inc_hit}/{len(roots_in_order)}")

print(f"\n== quantile sweep (ranking quality independent of the rule) ==")
print(f"{'cut':<10}{'flags':>10}{'tp':>7}{'P':>8}{'R':>8}{'F1':>8}{'FDR':>8}{'inc':>6}")
sweep_rows = []
for q in (0.90, 0.95, 0.97, 0.99, 0.995, 0.999):
    cut = np.quantile(ys, q)
    fl = int((ys >= cut).sum()); tpq = int(((ys >= cut) & (yt == 1)).sum())
    Pq = tpq / fl if fl else 0.0; Rq = tpq / max(int(yt.sum()), 1)
    F1q = 2*Pq*Rq/(Pq+Rq) if Pq+Rq else 0.0
    incq = len(set(x for i in np.where((ys >= cut) & (yt == 1))[0]
                   for x in amap.get(i, ())))
    sweep_rows.append([f"q{q}", cut, fl, tpq, round(Pq,4), round(Rq,4),
                       round(F1q,4), round(1-Pq,4) if fl else "", incq])
    print(f"q{q:<9}{fl:>10,}{tpq:>7,}{Pq:>8.3f}{Rq:>8.3f}{F1q:>8.3f}"
          f"{(1-Pq if fl else 0):>8.3f}{incq:>6}")

# budget-matched points (compare directly with the PIDS at D8)
print(f"\n== budget-matched incident coverage ==")
order = np.argsort(ys)[::-1]
for budget in (272, 1204, 26422):
    top = order[:budget]
    incb = len(set(x for i in top if yt[i] == 1 for x in amap.get(i, ())))
    tpb = int(yt[top].sum())
    print(f"budget {budget:>7,}: tp {tpb:>6,}  incidents {incb}/{len(roots_in_order)}")

# ---------------- artifacts ----------------
os.makedirs(a.out_dir, exist_ok=True)
art = {"pred_scores": ys, "y_preds": yp, "y_truth": yt,
       "edges": ids, "edge2attack": amap}
pkl_path = os.path.join(a.out_dir, f"baseline_iforest_{a.test_date}.pkl")
with open(pkl_path, "wb") as f:
    pickle.dump(art, f)
with open(os.path.join(a.out_dir, "baseline_iforest_summary.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["system","dataset","hash8","verified_from","level","epoch",
                "n_scored","n_pos","flags","tp","fp","fn","precision","recall",
                "f1","fdr","adp_incident","ap_entity","P_ci_lo","P_ci_hi",
                "R_ci_lo","R_ci_hi"])
    w.writerow(["iforest_baseline", f"WITFOO_84M_{a.test_date}", "baseline",
                f"train={'+'.join(a.train_date)}", "event", 0, len(yt),
                int(yt.sum()), int(yp.sum()), tp, fp, fn, round(P,5), round(R,5),
                round(F1,5), round(1-P,5) if tp+fp else "", a_inc, round(a_ent,4),
                *[round(x,5) for x in ci]])
with open(os.path.join(a.out_dir, "baseline_iforest_sweep.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["cut_label","score_cut","flags","tp","precision","recall","f1","fdr","incidents"])
    w.writerows(sweep_rows)
irows = incident_rows(ys, yp, yt, ids, amap,
                      ["iforest_baseline", f"WITFOO_84M_{a.test_date}", "baseline", 0])
with open(os.path.join(a.out_dir, "baseline_iforest_per_incident.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["system","dataset","hash8","epoch","incident","n_events",
                "caught_configured","recall_configured","best_event_pctl","median_event_pctl"])
    for r in irows:
        w.writerow(r[:4] + [r[4], r[5], r[6], r[7], r[8], r[9]])
print(f"\nartifacts -> {pkl_path} + summary/sweep/per_incident CSVs in {a.out_dir}")
