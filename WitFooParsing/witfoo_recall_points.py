#!/usr/bin/env python3
"""witfoo_recall_points.py — hindsight cost of fixed recall, every run, every epoch.

For each locked pickle: sort scores descending (framework tie order) and find
the minimum number of flags needed to reach recall 0.95 and 1.00. This is the
hindsight-vs-hindsight comparison: what each RANKING could deliver if the
threshold were chosen with perfect knowledge, independent of the configured
rule. Reads pickles only; no training, no re-evaluation.

  python3 WitFooParsing/witfoo_recall_points.py --out-dir analysis_out
"""
import argparse, csv, glob, os
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
    yt = np.asarray(d["y_truth"]).astype(int)
    return ys, yt

ap = argparse.ArgumentParser()
ap.add_argument("--out-dir", default="analysis_out")
a = ap.parse_args()
os.makedirs(a.out_dir, exist_ok=True)

rows = []
print(f"{'run':<34}{'ep':>3}{'flags@R.95':>12}{'P@R.95':>8}{'flags@R1.0':>12}{'P@R1.0':>8}{'FDR@R1.0':>9}")
for system, ds, h, src in MANIFEST:
    ddir = f"{ART}/{h}/{ds}/precision_recall_dir"
    pkls = sorted(glob.glob(os.path.join(ddir, "scores_model_epoch_*.pkl")),
                  key=lambda p: int(p.split("_")[-1].split(".")[0]))
    if not pkls:
        print(f"!! {system}/{ds}: no pickles at {ddir}"); continue
    for pkl in pkls:
        ep = int(pkl.split("_")[-1].split(".")[0])
        ys, yt = load(pkl)
        npos = int(yt.sum())
        if npos != EXPECTED_POS.get(ds, npos):
            print(f"!! SKIP {system}/{ds} ep{ep}: pos {npos} != expected"); continue
        order = np.argsort(ys)[::-1]            # framework's exact tie order
        pos_ranks = np.where(yt[order] == 1)[0]
        out = [system, ds, h[:8], ep, len(yt), npos]
        line = f"{system+'/'+ds:<34}{ep:>3}"
        for R in (0.95, 1.00):
            need = int(np.ceil(R * npos))
            k = int(pos_ranks[need - 1]) + 1    # flags to include the need-th positive
            P = need / k
            out += [k, round(P, 5), round(1 - P, 5)]
            line += f"{k:>12,}{P:>8.4f}" + (f"{1-P:>9.4f}" if R == 1.0 else "")
        rows.append(out)
        print(line)

with open(os.path.join(a.out_dir, "recall_points.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["system","dataset","hash8","epoch","n_scored","n_pos",
                "flags_R095","P_R095","FDR_R095","flags_R100","P_R100","FDR_R100"])
    w.writerows(rows)
print("\n-> recall_points.csv")
