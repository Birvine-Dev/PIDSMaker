#!/usr/bin/env python3
"""incidents_from_scores.py — incidents-detected + per-incident recall from a
PIDSMaker scores pickle. Handles both dialects:
  node-level: {pred_scores, y_preds, y_truth, nodes, node2attacks}
  edge-level: {pred_scores, y_preds, y_truth, edges, edge2attack}
Falls back to joining Ground_Truth CSVs if no attack mapping is present.

Usage: python3 incidents_from_scores.py <scores_model_epoch_NN.pkl>
"""
import sys, collections
import torch
import numpy as np

path = sys.argv[1]
d = torch.load(path, map_location="cpu")

yp = np.asarray(d["y_preds"]).astype(int)
yt = np.asarray(d["y_truth"]).astype(int)
ids = d.get("nodes", d.get("edges"))
amap = d.get("node2attacks") or d.get("edge2attack")
kind = "node" if "nodes" in d else "edge"
print(f"dialect: {kind}-level; {len(yt):,} scored; mapping: "
      f"{'in-pickle' if amap else 'GT-CSV fallback'}")

if amap is None:
    import glob, csv, os
    amap = {}
    for f in sorted(glob.glob("Ground_Truth/orthrus/witfoo/2m_v2_incidents/2m_v2_inc_*.csv")):
        short = os.path.basename(f).split("_")[-1].split(".")[0]
        for row in csv.reader(open(f)):
            if row:
                amap.setdefault(row[0].strip(), []).append(short)

def lookup(i):
    """attack(s) for position i: try by id, then by index."""
    for key in ((ids[i] if ids is not None else None), i):
        if key is None:
            continue
        try:
            v = amap.get(key) if hasattr(amap, "get") else None
        except TypeError:  # unhashable id (e.g. list) -> try tuple
            v = amap.get(tuple(key)) if hasattr(amap, "get") else None
        if v is not None and v != []:
            return v if isinstance(v, (list, set, tuple)) else [v]
    return ["?"]

per = collections.defaultdict(lambda: [0, 0])  # attack -> [caught, total]
for i in range(len(yt)):
    if yt[i] != 1:
        continue
    for a in lookup(i):
        per[a][1] += 1
        if yp[i] == 1:
            per[a][0] += 1

det = sum(1 for c, t in per.values() if c > 0)
print(f"{path.split('/')[-1]}: {len(per)} incidents in GT; DETECTED (>=1 flagged): {det}")
print(f"{'incident':<44}{'caught/total':>14}{'recall':>9}")
for a, (c, t) in sorted(per.items(), key=lambda x: x[1][0] / max(x[1][1], 1)):
    print(f"{str(a)[:42]:<44}{c:>7}/{t:<6}{c / max(t, 1):>8.2f}")
if "?" in per:
    print("\nNOTE: '?' bucket = some GT positives had no attack mapping; paste this output.")
