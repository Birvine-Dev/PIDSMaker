#!/usr/bin/env python3
"""witfoo_extract_perincident.py — hash-pinned extraction of headline + per-incident
metrics from PIDSMaker scores pickles, with semantic validation and bootstrap CIs.

Two modes:
  probe:    fingerprint candidate eval dirs (identify runs by their configured output)
      python3 witfoo_extract_perincident.py probe [DATASET ...]
  extract:  run the verified manifest, write per_run_summary.csv + per_incident.csv
      python3 witfoo_extract_perincident.py extract [--bootstrap 20] [--out-dir analysis_out]

Provenance rules (non-negotiable):
  * hash -> system comes ONLY from the MANIFEST below, which records where each
    hash was verified (run-log scores_file lines). Never from folder dates/positions.
  * every pickle is semantically validated on load: positives must match the
    dataset's known GT size (3,062 @ 2M_V2; 3,040 @ 84M D8/D4) or the run is SKIPPED
    with a loud warning.

Run inside a batch job for D8/D4 pickles (~48GB); 2M-only is login-safe.
"""
import sys, os, glob, csv, collections
import numpy as np
import torch

ART = "artifacts/evaluation/evaluation"

# ---- VERIFIED MANIFEST -------------------------------------------------------
# (system, dataset, hash, verified_from)
MANIFEST = [
    ("nodlink",       "WITFOO_84M_D8", "c3231d6a181f9b2905466bb172e6b1ed92c4ba073dfc44d506a63b846c65072f", "slurm-498164"),
    ("nodlink",       "WITFOO_84M_D4", "e62a7368a6b663c9d1c1813f17954786cfd15d403605f43e5eb5faa9e2cb4875", "slurm-498603"),
    ("velox",         "WITFOO_2M_V2",  "eb26a2db4289febec997d07366751fdb6c0cc818eecc9be4096dafdc43c6fd4c", "slurm-498573"),
    ("velox",         "WITFOO_84M_D8", "eb26a2db4289febec997d07366751fdb6c0cc818eecc9be4096dafdc43c6fd4c", "slurm-499000"),
    ("rcaid",         "WITFOO_2M_V2",  "e7b74f99a14bff3d75e081c0034a33103d70dec80e9537b4fbce1b594f762150", "slurm-498573"),
    ("rcaid",         "WITFOO_84M_D8", "e7b74f99a14bff3d75e081c0034a33103d70dec80e9537b4fbce1b594f762150", "slurm-498562"),
    ("orthrus_edge",  "WITFOO_84M_D8", "bad5b7a2ac342079711e75dcb641fb74b1859498dac613fdc77d83b707612395", "slurm-498540"),
    ("orthrus_edge",  "WITFOO_84M_D4", "bad5b7a2ac342079711e75dcb641fb74b1859498dac613fdc77d83b707612395", "slurm-498603"),
    ("orthrus_node",  "WITFOO_2M_V2",  "75e19314b356d8fa44532d994aa9af7c2c396dce9d16a8e8f496ac14969ec561", "cache/499670"),
    ("orthrus_node",  "WITFOO_84M_D8", "75e19314b356d8fa44532d994aa9af7c2c396dce9d16a8e8f496ac14969ec561", "slurm-499670"),
    ("orthrus_node",  "WITFOO_84M_D4", "75e19314b356d8fa44532d994aa9af7c2c396dce9d16a8e8f496ac14969ec561", "slurm-499670"),
    ("nodlink",       "WITFOO_2M_V2",  "9468d443c11f385c4b4f62ea1de62dcac710baedd6ae47eeb3cf01eb768e46fc", "probe:flags=23603,tp=3062"),
    ("orthrus_edge",  "WITFOO_2M_V2",  "46d392aabc53313a8d6124b9fa04e1bc51dc523abaae4e134eabf360265ad261", "probe:flags=5007,tp=1257"),
]

EXPECTED_POS = {"WITFOO_2M_V2": 3062, "WITFOO_84M_D8": 3040, "WITFOO_84M_D4": 3040}

def load(pkl):
    d = torch.load(pkl, map_location="cpu")
    ys = np.asarray(d["pred_scores"], dtype=float)
    yp = np.asarray(d["y_preds"]).astype(int)
    yt = np.asarray(d["y_truth"]).astype(int)
    ids = d.get("nodes", d.get("edges"))
    amap = d.get("node2attacks") or d.get("edge2attack")
    kind = "node" if "nodes" in d else "edge"
    return ys, yp, yt, ids, amap, kind

def adp(ys, yt):
    """Pinned definition: rank all entities by score desc; walking down, track
    precision and %attacks-detected (attack counted once >=1 of its entities has
    passed) -- here at entity granularity, attacks==positive entities, so the
    curve is precision vs recall over the ranking; area under it / 1.0.
    Cross-check against the framework's printed adp_score per epoch."""
    order = np.argsort(-ys, kind="stable")
    ytr = yt[order]
    tp_cum = np.cumsum(ytr)
    npos = yt.sum()
    if npos == 0:
        return 0.0
    prec = tp_cum / np.arange(1, len(ytr) + 1)
    rec = tp_cum / npos
    # area under precision as a function of recall (step integration at each new tp)
    newtp = ytr == 1
    return float(np.sum(prec[newtp]) / npos)

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

def probe(datasets):
    for ds_dir in sorted(glob.glob(f"{ART}/*/*/")):
        h, ds = ds_dir.rstrip("/").split("/")[-2:]
        if datasets and ds not in datasets:
            continue
        pkls = sorted(glob.glob(os.path.join(ds_dir, "precision_recall_dir", "scores_model_epoch_*.pkl")))
        if not pkls:
            continue
        try:
            ys, yp, yt, ids, amap, kind = load(pkls[-1])
            known = next((s for s, d, hh, _ in MANIFEST if hh == h and d == ds), "?")
            print(f"{h[:8]} {ds:<16} {kind}-level  n={len(yt):>9,}  pos={int(yt.sum()):>5,}  "
                  f"flags={int(yp.sum()):>8,}  tp={int(((yp==1)&(yt==1)).sum()):>5,}  "
                  f"epochs={len(pkls)}  manifest={known}")
        except Exception as e:
            print(f"{h[:8]} {ds:<16} UNREADABLE: {e}")

def extract(B, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    srows, irows = [], []
    for system, ds, h, src in MANIFEST:
        ddir = f"{ART}/{h}/{ds}/precision_recall_dir"
        pkls = sorted(glob.glob(os.path.join(ddir, "scores_model_epoch_*.pkl")),
                      key=lambda p: int(p.split("_")[-1].split(".")[0]))
        if not pkls:
            print(f"!! {system}/{ds}: no pickles at {ddir}"); continue
        for pkl in pkls:
            ep = int(pkl.split("_")[-1].split(".")[0])
            ys, yp, yt, ids, amap, kind = load(pkl)
            npos = int(yt.sum())
            if npos != EXPECTED_POS.get(ds, npos):
                print(f"!! SKIP {system}/{ds} ep{ep}: positives {npos} != expected "
                      f"{EXPECTED_POS[ds]} — WRONG PICKLE?"); continue
            tp, fp, fn, P, R, F1 = headline(yp, yt)
            a = adp(ys, yt)
            ci = bootstrap_ci(yp, yt, B) if B else ("", "", "", "")
            srows.append([system, ds, h[:8], src, kind, ep, len(yt), npos,
                          int(yp.sum()), tp, fp, fn, round(P, 5), round(R, 5),
                          round(F1, 5), round(1 - P if tp + fp else "", 5) if tp + fp else "",
                          round(a, 4), *[round(x, 5) if x != "" else "" for x in ci]])
            if amap is not None:
                irows.extend(incident_rows(ys, yp, yt, ids, amap,
                                           [system, ds, h[:8], ep]))
            print(f"ok {system:<13} {ds:<14} ep{ep}: tp {tp:>6,} fp {fp:>8,} "
                  f"P {P:.3f} R {R:.3f} ADP {a:.3f}")
    with open(os.path.join(out_dir, "per_run_summary.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["system", "dataset", "hash8", "verified_from", "level", "epoch",
                    "n_scored", "n_pos", "flags", "tp", "fp", "fn", "precision",
                    "recall", "f1", "fdr", "adp_computed",
                    "P_ci_lo", "P_ci_hi", "R_ci_lo", "R_ci_hi"])
        w.writerows(srows)
    with open(os.path.join(out_dir, "per_incident.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["system", "dataset", "hash8", "epoch", "incident", "n_events",
                    "caught_configured", "recall_configured",
                    "best_event_pctl", "median_event_pctl"])
        w.writerows(irows)
    print(f"\nwrote {len(srows)} summary rows, {len(irows)} incident rows -> {out_dir}/")

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "probe"
    if mode == "probe":
        probe(sys.argv[2:])
    elif mode == "extract":
        B = int(sys.argv[sys.argv.index("--bootstrap") + 1]) if "--bootstrap" in sys.argv else 20
        out = sys.argv[sys.argv.index("--out-dir") + 1] if "--out-dir" in sys.argv else "analysis_out"
        extract(B, out)
    else:
        sys.exit("mode must be 'probe' or 'extract'")
