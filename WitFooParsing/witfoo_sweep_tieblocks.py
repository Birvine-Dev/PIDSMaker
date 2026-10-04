#!/usr/bin/env python3
"""witfoo_sweep_tieblocks.py — (1) Velox D8 threshold sweep, (2) tie-block census.

Runs on the locked evaluation pickles only (hash-pinned manifest, semantic
validation). No training, no re-evaluation.

  python3 WitFooParsing/witfoo_sweep_tieblocks.py --out-dir analysis_out
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
    yp = np.asarray(d["y_preds"]).astype(int)
    yt = np.asarray(d["y_truth"]).astype(int)
    ids = d.get("nodes", d.get("edges"))
    amap = d.get("node2attacks") or d.get("edge2attack")
    kind = "node" if "nodes" in d else "edge"
    return ys, yp, yt, ids, amap, kind


def incidents_above(ys, ids, amap, cut):
    """Incidents with >=1 mapped entity scoring >= cut."""
    if amap is None:
        return ""
    hit = set()
    for i, e in enumerate(ids):
        if ys[i] >= cut:
            for a in amap.get(e, ()):
                hit.add(a)
    return len(hit)


def total_attacks(amap):
    if amap is None:
        return ""
    s = set()
    for v in amap.values():
        s.update(v)
    return len(s)


def velox_d8_sweep(out_dir):
    h = next(hh for s, d, hh, _ in MANIFEST if s == "velox" and d == "WITFOO_84M_D8")
    ddir = f"{ART}/{h}/WITFOO_84M_D8/precision_recall_dir"
    rows = []
    for ep in (7, 9):
        pkl = os.path.join(ddir, f"scores_model_epoch_{ep}.pkl")
        if not os.path.exists(pkl):
            print(f"!! missing {pkl}"); continue
        ys, yp, yt, ids, amap, kind = load(pkl)
        npos = int(yt.sum())
        assert npos == EXPECTED_POS["WITFOO_84M_D8"], f"wrong pickle: pos={npos}"
        ta = total_attacks(amap)
        print(f"\n=== Velox D8 ep{ep} sweep (n={len(ys):,}, pos={npos:,}, attacks={ta}) ===")
        print(f"{'cut':<22}{'flags':>9}{'tp':>7}{'P':>8}{'R':>8}{'F1':>8}{'FDR':>8}{'inc':>6}")
        for q in (0.90, 0.925, 0.95, 0.97, 0.99, 0.995, 0.999):
            cut = np.quantile(ys, q)
            fl = int((ys >= cut).sum()); tp = int(((ys >= cut) & (yt == 1)).sum())
            P = tp / fl if fl else 0.0; R = tp / npos
            F1 = 2 * P * R / (P + R) if P + R else 0.0
            inc = incidents_above(ys, ids, amap, cut)
            rows.append(["velox", "WITFOO_84M_D8", ep, f"q{q}", cut, fl, tp,
                         round(P, 4), round(R, 4), round(F1, 4),
                         round(1 - P, 4) if fl else "", inc, ta])
            print(f"q{q:<21}{fl:>9,}{tp:>7,}{P:>8.3f}{R:>8.3f}{F1:>8.3f}"
                  f"{(1-P if fl else 0):>8.3f}{inc!s:>6}")
        # minimum flags for recall 1.0
        order = np.argsort(ys)[::-1]
        pos_ranks = np.where(yt[order] == 1)[0]
        k = int(pos_ranks[-1]) + 1          # flags needed to include last positive
        cut = ys[order][k - 1]
        P = npos / k
        print(f"recall-1.0 point: flags={k:,}  P={P:.4f}  FDR={1-P:.4f}  "
              f"(score cut {cut:.6g})")
        rows.append(["velox", "WITFOO_84M_D8", ep, "recall1.0", cut, k, npos,
                     round(P, 4), 1.0, round(2*P/(P+1), 4), round(1-P, 4), ta, ta])
    with open(os.path.join(out_dir, "velox_d8_sweep.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["system", "dataset", "epoch", "cut_label", "score_cut", "flags",
                    "tp", "precision", "recall", "f1", "fdr", "incidents", "total_attacks"])
        w.writerows(rows)


def tieblock_census(out_dir):
    rows = []
    print("\n=== tie-block census (all runs, all saved epochs) ===")
    print(f"{'run':<34}{'ep':>3}{'n':>10}{'uniq':>9}{'maxblk':>9}{'maxblk%':>9}"
          f"{'blk>=100':>9}{'pop>=100%':>10}{'posUniq':>8}{'maxPosBlk':>10}")
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
                print(f"!! SKIP {system}/{ds} ep{ep}: pos {npos} != expected"); continue
            vals, counts = np.unique(ys, return_counts=True)
            n = len(ys); mx = int(counts.max())
            big = counts >= 100
            pv, pc = np.unique(ys[yt == 1], return_counts=True)
            rows.append([system, ds, h[:8], ep, n, len(vals), mx,
                         round(mx / n, 4), int(big.sum()),
                         round(counts[big].sum() / n, 4),
                         len(pv), int(pc.max())])
            print(f"{system+'/'+ds:<34}{ep:>3}{n:>10,}{len(vals):>9,}{mx:>9,}"
                  f"{mx/n:>9.3f}{int(big.sum()):>9}{counts[big].sum()/n:>10.3f}"
                  f"{len(pv):>8,}{int(pc.max()):>10,}")
    with open(os.path.join(out_dir, "tieblock_census.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["system", "dataset", "hash8", "epoch", "n_scored",
                    "n_distinct_scores", "largest_block", "largest_block_frac",
                    "n_blocks_ge100", "pop_frac_in_blocks_ge100",
                    "n_distinct_pos_scores", "largest_pos_block"])
        w.writerows(rows)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="analysis_out")
    a = ap.parse_args()
    os.makedirs(a.out_dir, exist_ok=True)
    velox_d8_sweep(a.out_dir)
    tieblock_census(a.out_dir)
    print("\ndone.")
