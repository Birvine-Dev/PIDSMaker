#!/usr/bin/env python3
"""nodlink_threshold_sweep.py — threshold sensitivity from saved scores.

Post-processing only: no retraining, no change to the published configuration.
Loads a PIDSMaker scores pickle, introspects its structure, and sweeps
thresholds over the score distribution, printing precision / recall / F1 /
FPR / flag-count at each operating point.

Usage:
  python3 nodlink_threshold_sweep.py <scores_model_epoch_NN.pkl> [--gt <ground_truth_nodes.csv>]

If the pickle already pairs scores with labels, --gt is unneeded; otherwise
supply translate's GT file and the script will try to join on node ids.
"""
import argparse, pickle, sys
import numpy as np

p = argparse.ArgumentParser()
p.add_argument("scores_pkl")
p.add_argument("--gt", default=None)
a = p.parse_args()

try:
    with open(a.scores_pkl, "rb") as f:
        obj = pickle.load(f)
except Exception:
    import torch
    obj = torch.load(a.scores_pkl, map_location="cpu")
    def _unwrap(x):
        if torch.is_tensor(x): return x.numpy()
        if isinstance(x, dict): return {k: _unwrap(v) for k, v in x.items()}
        if isinstance(x, (list, tuple)): return type(x)(_unwrap(v) for v in x)
        return x
    obj = _unwrap(obj)
    print("(loaded via torch.load)")

print(f"pickle type: {type(obj).__name__}")
y_score, y_true, ids = None, None, None

if isinstance(obj, dict):
    if "pred_scores" in obj and "y_truth" in obj:
        y_score = np.asarray(obj["pred_scores"], dtype=float); y_true = np.asarray(obj["y_truth"]).astype(int); ids = list(obj.get("nodes", []))
        print("  -> PIDSMaker scores dict: pred_scores + y_truth (authoritative)")
    print("keys:", list(obj.keys())[:12])
    for k in obj:
        v = obj[k]
        kl = str(k).lower()
        if hasattr(v, "__len__") and len(v) > 1000:
            if any(s in kl for s in ("score", "loss", "pred")) and y_score is None:
                y_score = np.asarray(v, dtype=float)
                print(f"  -> using '{k}' as scores ({len(v)} entries)")
            elif any(s in kl for s in ("label", "true", "y", "gt", "malic")) and y_true is None:
                y_true = np.asarray(v).astype(int)
                print(f"  -> using '{k}' as labels ({len(v)} entries)")
            elif any(s in kl for s in ("id", "node", "uuid")) and ids is None:
                ids = list(v)
                print(f"  -> using '{k}' as ids ({len(v)} entries)")
elif isinstance(obj, (tuple, list)) and len(obj) in (2, 3):
    print(f"sequence of {len(obj)}; element sizes: {[len(x) if hasattr(x,'__len__') else '?' for x in obj]}")
    arrs = [np.asarray(x) for x in obj if hasattr(x, "__len__")]
    for arr in arrs:
        if arr.dtype.kind == "f" and y_score is None: y_score = arr.astype(float)
        elif arr.dtype.kind in "iub" and set(np.unique(arr)) <= {0, 1} and y_true is None: y_true = arr.astype(int)
        elif ids is None: ids = list(arr)
else:
    try:
        import pandas as pd
        if isinstance(obj, pd.DataFrame):
            print("DataFrame columns:", list(obj.columns))
            for c in obj.columns:
                cl = c.lower()
                if any(s in cl for s in ("score", "loss")) and y_score is None: y_score = obj[c].to_numpy(float)
                elif any(s in cl for s in ("label", "true", "malic", "y")) and y_true is None: y_true = obj[c].to_numpy(int)
                elif any(s in cl for s in ("id", "node", "uuid")) and ids is None: ids = list(obj[c])
    except ImportError:
        pass

if y_score is None:
    sys.exit("Could not identify a score array - paste the printed structure to Claude.")

if y_true is None and a.gt and ids is not None:
    gt = set(l.split(",")[0].strip() for l in open(a.gt) if l.strip())
    y_true = np.array([1 if str(i) in gt else 0 for i in ids])
    print(f"labels joined from GT file: {int(y_true.sum())} positives of {len(y_true)}")
if y_true is None:
    sys.exit("No labels found and no usable --gt join - paste the printed structure to Claude.")

n, npos = len(y_score), int(y_true.sum())
print(f"\n{n:,} scored nodes, {npos:,} positives ({100*npos/n:.2f}%)\n")
print(f"{'quantile':>9} {'threshold':>12} {'flags':>9} {'tp':>6} {'fp':>8} {'precision':>10} {'recall':>8} {'F1':>7} {'FPR':>8}")
for q in [0.90, 0.925, 0.95, 0.96, 0.97, 0.98, 0.99, 0.995, 0.999, 0.9995]:
    thr = float(np.quantile(y_score, q))
    flag = y_score >= thr
    tp = int((flag & (y_true == 1)).sum()); fp = int((flag & (y_true == 0)).sum())
    fn = npos - tp
    prec = tp / max(tp + fp, 1); rec = tp / max(npos, 1)
    f1 = 2 * prec * rec / max(prec + rec, 1e-12)
    fpr = fp / max((y_true == 0).sum(), 1)
    print(f"{q:>9} {thr:>12.5g} {tp+fp:>9,} {tp:>6,} {fp:>8,} {prec:>10.3f} {rec:>8.3f} {f1:>7.3f} {100*fpr:>7.2f}%")
print("\nRead: each row = one alarm-budget choice over the SAME trained model/scores.")
