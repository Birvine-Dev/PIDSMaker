# Fork guide: checkpointing and the WitFoo pipeline

This fork of [ubc-provenance/PIDSMaker](https://github.com/ubc-provenance/PIDSMaker) carries the artefacts from the SENG402 research project *Evaluating Provenance-Based Intrusion Detection Systems on Real Security Operations Data* (Ben Irvine, University of Canterbury, 2026). All project work lives on the **`checkpointing`** branch; `main` tracks upstream.

It adds three things to the upstream framework:

1. **Per-epoch checkpointing** of trained models, plus a script to reload any checkpoint and re-run inference and evaluation under fresh seeds, so a result can be handed over and verified without retraining.
2. **A WitFoo ingestion pipeline** that translates WitFoo's openly published SOC telemetry (the Precinct 6 datasets) into PIDSMaker's database tables, so every system in the framework can run on real security operations data.
3. **Evaluation tooling**: threshold sweeps, per-incident analysis, and a classical ML baseline used to contextualise the deep-learning systems' results.

For installing and running the framework itself, follow upstream's [ten-minute install](https://ubc-provenance.github.io/PIDSMaker/ten-minute-install/). Everything below assumes that setup works (the Postgres container and the `pids` environment).

---

## 1. Checkpointing

### What it does

During training, the framework now saves the model after **every epoch** to the run's trained-models directory (`cfg.training._trained_models_dir/model_epoch_<N>`). Upstream only kept the final/best model, which meant a result could not be re-examined at a given epoch without a full retrain.

Controlled by one config flag (default on):

```
--training.save_checkpoints=False   # disable to save disk on large graphs
```

Defined in `pidsmaker/config/config.py` (`training.save_checkpoints`); the save itself is in `pidsmaker/detection/training_methods/training_loop.py`.

### Re-running from a checkpoint

`scripts/rerun_checkpoint.py` reloads a saved epoch and re-runs inference + evaluation N times under different seeds:

```
python scripts/rerun_checkpoint.py nodlink CADETS_E3 \
    --ckpt-epoch 31 --n-seeds 10 --base-seed 100 \
    [...the same config overrides as the original run]
```

**Important:** pass the same config overrides as the original training run. The artifact cache is keyed on config values; different overrides resolve to a different task path and the checkpoint will not be found.

Outputs: per-seed losses and evaluation artifacts under `<dir>_reseed/seed_<s>/`, plus a CSV summary (`reseed_results_epoch<E>.csv`) with mean/std per metric.

### Why this matters for hand-off

A checkpoint plus this script is a verification package: someone else can take the trained model and confirm the reported numbers (or probe seed sensitivity) without access to the original training run or the hours it took.

---

## 2. The WitFoo pipeline

### The data

WitFoo's Precinct 6 telemetry is published openly on Hugging Face. All project results are pinned to exact dataset revisions, recorded in `WitFooParsing/DATA_VERSIONS.txt`. Re-fetch with `revision=<sha>`:

| Dataset | Pinned revision (v2, current) |
|---|---|
| `witfoo/precinct6-cybersecurity` (2M) | `cc7123d1...` |
| `witfoo/precinct6-cybersecurity-100m` (100M) | `f63ffdbc...` |

(The v1 revisions in that file remain the clean-benign baseline; v2 is Charles Herring's corrected re-export of 2026-09-09.)

### Step 1: translate (`WitFooParsing/witfoo_translate.py`)

Converts WitFoo node/edge JSONL into PIDSMaker's table CSVs. Three graph mappings are implemented (the report discusses the choice):

- **Mapping A**: no reification; events stay edges, hosts carry ground truth
- **Mapping B**: full reification, typed stubs (`NETWORK_FLOW_SRC`/`_DST`, ...) **(used for all reported results)**
- **Mapping C**: full reification, generic stubs (`SRC_OF`/`DST_OF`)

```
# Toy example (9 entities, 12 events; good first run):
python witfoo_translate.py --toy --mapping B -o out_toy_B

# Real data:
python witfoo_translate.py --nodes nodes.jsonl --edges edges.jsonl \
    --mapping B --shift-benign-to 2024-07-08T11:00:00 -o out_2m_B
```

`--shift-benign-to` offsets benign/suspicious timestamps so the live-capture hour overlaps the attack era (ordering and gaps preserved exactly).

Outputs one CSV per PIDSMaker table (`subject_node_table.csv`, `file_node_table.csv`, `netflow_node_table.csv`, `event_table.csv`, `ground_truth_nodes.csv`) plus a `summary.txt` of counts.

### Step 2: load into Postgres (`WitFooParsing/load_witfoo_db.sh`)

```
./WitFooParsing/load_witfoo_db.sh witfoo_toy /path/to/out_toy_B/
```

Creates the database, the four tables, and COPYs the CSVs in. Prints row counts at the end as a sanity check.

### Step 3: ground truth (`WitFooParsing/witfoo_emit_incident_gt.py`)

Emits per-incident ground truth files and `attack_to_time_window` config entries from the labelled edges:

```
python3 witfoo_emit_incident_gt.py \
    --edges ~/WitFoo2M-v2/graph/edges.jsonl \
    --org ORG-0004 --gt-date 2024-07-29 \
    --out-dir Ground_Truth/orthrus/witfoo/2m_v2_incidents \
    --prefix 2m_v2_inc --pad-min 2
```

**Caution:** event uuids are assigned by the translate script in edge-file order over org-filtered rows, and this script replicates that numbering. If the translate filters change, regenerate the ground truth.

### Step 4: run any system on it

The WitFoo datasets are registered in the framework (`witfoo_toy`, `witfoo_2m`, `witfoo_2m_v2`, `witfoo_84m_d8`, `witfoo_84m_d4`, ... see `witfoo_datasets` in `pidsmaker/utils/dataset_utils.py`; dataset definitions in `pidsmaker/config/config.py`). Then it is a normal framework run:

```
python pidsmaker/main.py orthrus WITFOO_TOY \
    --construction.time_window_size=600.0 \
    --featurization.emb_dim=32 --featurization.epochs=2 \
    --restart_from_scratch --database_host localhost --artifact_dir ./artifacts/
```

`witfoo_toy_ingest.slurm` at the repo root is a complete end-to-end example (translate output -> DB load -> ORTHRUS run) as submitted on the UC RCH cluster.

### Adding a new system (e.g. integrating your own PIDS)

Nothing in the WitFoo pipeline is system-specific. Follow upstream's documentation for integrating a new system into PIDSMaker; once your system runs on a framework dataset such as CADETS_E3, the WitFoo datasets are available to it exactly like any other (steps 1 to 3 above populate the database; step 4's command takes your system's name).

---

## 3. Evaluation tooling (`WitFooParsing/`)

The scripts behind the report's analysis, in rough pipeline order:

| Script | What it does |
|---|---|
| `witfoo_event_type_census.py` | Census of event/message types in the raw data |
| `census3_per_org_daymap.py` | Per-organisation, per-day event volumes (sampling decisions) |
| `witfoo_extract_perincident.py` | Per-incident statistics from framework outputs |
| `incidents_from_scores.py` | Maps node scores back to labelled incidents |
| `witfoo_incident_stats_v3.py` | Per-attack statistics. **v3 is current**: it union-finds incident ids that co-occur on an event, so one row = one merged attack group, matching the 54-way ground truth. v2 fanned events out per incident id (~7x double-counting); v1/v2 kept for provenance |
| `nodlink_threshold_sweep.py` | Full threshold sweep for NodLink (lowest threshold at recall 1.0) |
| `witfoo_sweep_tieblocks.py` | Threshold sweep aware of tied score blocks |
| `witfoo_recall_points.py` | Alarm-budget curves (alarms needed per recall level) |
| `orthrus_collapse_diagnosis.py` | Diagnoses ORTHRUS's tied-score collapse |
| `witfoo_ml_baseline.py` | Isolation Forest baseline (5 features) for context |

---

## 4. Tests

Two layers:

- **`tests/test_witfoo_parser.py`** (this fork): pure-Python unit tests of the WitFoo pipeline. No GPU, no database, no torch; they run anywhere in under a second:

  ```
  pytest tests/test_witfoo_parser.py -v
  ```

  They cover the field rules (doc tables 4a-4e), all three mappings on the built-in toy graph, the hygiene filters (INCIDENT_LINK exclusion, corrupt timestamps, `--gt-date`, `--org`), the benign time shift (ordering and gaps preserved, malicious timestamps untouched), the relation registry round-trip, and the checkpointing wiring.

- **`tests/test_framework.py`** (upstream): functional tests that run the full pipeline (real training and evaluation) across system/component combinations. These need the complete environment: GPU, the Postgres container, and datasets loaded. Run them on the cluster, not a laptop, and target the parser file explicitly on machines without that environment (bare `pytest tests/` will fail to collect `test_framework.py` there).

---

## 5. Infrastructure notes (UC RCH cluster)

Full runs were executed on the University of Canterbury RCH cluster via SLURM: the large WitFoo days reach 12M events and runs needed nodes with hundreds of GB of memory and scheduled GPU access. `witfoo_toy_ingest.slurm` shows the job shape (module load, conda env, apptainer Postgres instance, then the run). The toy dataset runs on a laptop; the 2M and larger datasets do not.

---

## Contact

Ben Irvine · bir17@uclive.ac.nz · github.com/Birvine-Dev
Project supervised by Etienne Borde, Mengmeng Ge, and Maria Kainat (UC CSSE), with data from WitFoo (Charles Herring).
