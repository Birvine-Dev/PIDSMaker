"""Reload a saved epoch checkpoint and re-run inference + evaluation N times
under different random seeds.

Usage (inside the pids container, same args as the original run + extras)
--------------------------------------------------------------------------
  python scripts/rerun_checkpoint.py nodlink CADETS_E3 \
      --ckpt-epoch 31 --n-seeds 10 --base-seed 100 \
      [--training.num_epochs=50 ... any overrides used in the original run]

IMPORTANT: pass the same config overrides as the original training run.
The artifact cache is keyed on config values, so differing overrides would
resolve to a different task path and the checkpoint would not be found.

Outputs
-------
  * Per-seed losses under   <edge_losses_dir>_reseed/seed_<s>/
  * Per-seed eval artifacts under <precision_recall_dir>_reseed/seed_<s>/
  * A CSV summary (reseed_results_epoch<E>.csv) + mean/std printed per metric.
"""

import argparse
import copy
import csv
import os
import sys

import numpy as np
import torch
import wandb

extra_parser = argparse.ArgumentParser(add_help=False)
extra_parser.add_argument("--ckpt-epoch", type=int, required=True,
                          help="Epoch number of the checkpoint to reload")
extra_parser.add_argument("--n-seeds", type=int, default=10,
                          help="Number of reseeded inference passes")
extra_parser.add_argument("--base-seed", type=int, default=100,
                          help="First seed; passes use base, base+1, ...")
extra_args, remaining = extra_parser.parse_known_args()
sys.argv = [sys.argv[0]] + remaining

from pidsmaker.config import get_runtime_required_args, get_yml_cfg  # noqa: E402
from pidsmaker.detection.training_methods import inference_loop  # noqa: E402
from pidsmaker.factory import build_model  # noqa: E402
from pidsmaker.tasks import evaluation  # noqa: E402
from pidsmaker.tasks.batching import get_preprocessed_graphs  # noqa: E402
from pidsmaker.utils.data_utils import load_model  # noqa: E402
from pidsmaker.utils.utils import get_device, log, set_seed  # noqa: E402


def main():
    args, unknown = get_runtime_required_args(return_unknown_args=True)
    if unknown:
        raise argparse.ArgumentTypeError(f"Unknown args {unknown}")

    # No experiment tracking for re-runs; evaluation.py calls wandb.log().
    wandb.init(mode="disabled")

    cfg = get_yml_cfg(args)

    epoch = extra_args.ckpt_epoch
    ckpt_dir = os.path.join(cfg.training._trained_models_dir, f"model_epoch_{epoch}")
    if not os.path.isdir(ckpt_dir):
        available = (
            sorted(os.listdir(cfg.training._trained_models_dir))
            if os.path.isdir(cfg.training._trained_models_dir)
            else []
        )
        raise FileNotFoundError(
            f"No checkpoint at {ckpt_dir}\n"
            f"Available checkpoints: {available or 'none — was the run made with checkpointing enabled?'}\n"
            f"Also verify you passed the same config overrides as the original run."
        )

    device = get_device(cfg)

    # Same data/model construction path as training_loop.main
    train_data, val_data, test_data, max_node_num = get_preprocessed_graphs(cfg)
    model = build_model(
        data_sample=train_data[0][0], device=device, cfg=cfg, max_node_num=max_node_num
    )

    base_losses_dir = cfg.training._edge_losses_dir.rstrip("/")
    base_pr_dir = cfg.evaluation._precision_recall_dir.rstrip("/")

    rows = []
    for i in range(extra_args.n_seeds):
        seed = extra_args.base_seed + i
        log(f"===== Reseeded pass {i + 1}/{extra_args.n_seeds} (seed={seed}) =====",
            pre_return_line=True)

        # Fresh weights (and TGN memory/neighbor state, if any) every pass —
        # inference mutates TGN memory, so reloading guarantees each seed
        # starts from the identical checkpointed state.
        load_model(model, ckpt_dir, cfg)
        model.to_device(device)

        # Redirect outputs so passes don't overwrite each other. Everything
        # else (ground truth, preprocessed graphs, thresholds config) is
        # shared and read-only.
        cfg_i = copy.deepcopy(cfg)
        cfg_i.training._edge_losses_dir = f"{base_losses_dir}_reseed/seed_{seed}/"
        cfg_i.evaluation._precision_recall_dir = f"{base_pr_dir}_reseed/seed_{seed}/"
        os.makedirs(cfg_i.training._edge_losses_dir, exist_ok=True)
        os.makedirs(cfg_i.evaluation._precision_recall_dir, exist_ok=True)

        # The seed is set immediately before inference — BUT inference_loop.main
        # internally calls set_seed(cfg) at its start (inference_loop.py:258),
        # which silently re-seeds every pass back to cfg.training.seed (identical
        # across passes, since the checkpoint path is hashed from it). Override
        # that internal call so it re-seeds with THIS pass's seed instead.
        set_seed(cfg_i, seed=seed)
        inference_loop.set_seed = (
            lambda s: (lambda cfg, seed=None: set_seed(cfg, seed=s))
        )(seed)

        # Harness self-check: this value MUST differ between passes. Identical
        # probes across passes mean the seeding is broken and results are void.
        log(f"[seed {seed}] RNG probe (must differ per pass): {torch.rand(1).item():.10f}")

        # split="all" regenerates val losses under the same seed too, so
        # validation-derived thresholds (e.g. Grubbs) see this pass's noise —
        # faithful to how a full run computes them.
        inference_loop.main(
            cfg=cfg_i,
            model=model,
            val_data=val_data,
            test_data=test_data,
            epoch=epoch,
            split="all",
        )

        stats = evaluation.main(cfg_i) or {}
        stats = {k: v for k, v in stats.items() if isinstance(v, (int, float))}
        stats["seed"] = seed
        rows.append(stats)
        log(f"[seed {seed}] " + ", ".join(f"{k}={v}" for k, v in sorted(stats.items())))


    metrics = sorted({k for r in rows for k in r} - {"seed"})
    out_csv = f"reseed_results_{args.model}_{args.dataset}_epoch{epoch}.csv"
    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["seed"] + metrics)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

    log("=" * 60)
    log(f"Reseeded evaluation of {args.model} / {args.dataset} @ epoch {epoch} "
        f"({extra_args.n_seeds} seeds)")
    log("=" * 60)
    for m in metrics:
        vals = np.array([r[m] for r in rows if m in r], dtype=float)
        if len(vals) == 0:
            continue
        log(f"{m:>25s}: mean={vals.mean():.4f}  std={vals.std(ddof=1) if len(vals) > 1 else 0.0:.4f}  "
            f"min={vals.min():.4f}  max={vals.max():.4f}")
    log(f"Per-seed results written to {out_csv}")
    log("std == 0 on every metric ==> the model is deterministic at inference; "
        "the seed has nothing to vary. Expected for ORTHRUS/Velox/R-CAID.")


if __name__ == "__main__":
    main()
