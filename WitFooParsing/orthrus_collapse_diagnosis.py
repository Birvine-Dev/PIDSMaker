#!/usr/bin/env python3
"""orthrus_collapse_diagnosis.py - why does enriched training kill ORTHRUS?

Walks every scores_model_epoch_*.pkl in a precision_recall_dir and, per epoch,
reports where attack scores sit relative to benign scores and what the alarm
rule did. Separates two failure modes:
  RANKING DEATH: attack scores sink into the benign mass (AUC -> 0.5)
  POLICY DEATH:  ranking stays healthy but the threshold overshoots (AUC high,
                 flags ~0)

Usage:
  python3 orthrus_collapse_diagnosis.py <precision_recall_dir> [more dirs...]
e.g. the enriched (collapsing) run and the thin (healthy) run side by side.
"""
import sys, glob, os, re
import torch
import numpy as np

def auc_rank(scores, labels):
    """AUC via rank statistic (fast, exact up to ties)."""
    order = np.argsort(scores, kind="mergesort")
    ranks = np.empty(len(scores)); ranks[order] = np.arange(1, len(scores) + 1)
    pos = labels == 1
    n1, n0 = int(pos.sum()), int((~pos).sum())
    if n1 == 0 or n0 == 0: return float("nan")
    return (ranks[pos].sum() - n1 * (n1 + 1) / 2) / (n1 * n0)

for d in sys.argv[1:]:
    files = sorted(glob.glob(os.path.join(d, "scores_model_epoch_*.pkl")),
                   key=lambda p: int(re.search(r"epoch_(\d+)", p).group(1)))
    print(f"\n===== {d}  ({len(files)} epochs) =====")
    print(f"{'ep':>3} {'AUC':>6} {'atk_med':>9} {'ben_med':>9} {'ben_p999':>9} "
          f"{'atk>p999%':>9} {'flags':>7} {'tp':>6}")
    for f in files:
        ep = int(re.search(r"epoch_(\d+)", f).group(1))
        dd = torch.load(f, map_location="cpu")
        s = np.asarray(dd["pred_scores"], dtype=float)
        y = np.asarray(dd["y_truth"]).astype(int)
        yp = np.asarray(dd["y_preds"]).astype(int)
        atk, ben = s[y == 1], s[y == 0]
        p999 = float(np.quantile(ben, 0.999))
        above = 100 * float((atk > p999).mean())
        print(f"{ep:>3} {auc_rank(s, y):>6.3f} {np.median(atk):>9.3g} "
              f"{np.median(ben):>9.3g} {p999:>9.3g} {above:>8.1f}% "
              f"{int(yp.sum()):>7,} {int((yp[y==1]==1).sum()):>6,}")
    print("READ: AUC ~0.5 + atk_med ~ ben_med  -> RANKING DEATH (model unlearns)")
    print("      AUC high + flags ~0           -> POLICY DEATH (threshold overshoots)")
    print("      atk>p999% = share of attacks above the 99.9th benign percentile")
