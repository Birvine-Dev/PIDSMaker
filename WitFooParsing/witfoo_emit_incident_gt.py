#!/usr/bin/env python3
"""witfoo_emit_incident_gt.py — per-incident ground truth for PIDSMaker.

Groups confirmed-malicious events by their primary incident_id and emits:
  - one 3-column GT CSV per incident (event-node uuids, matching translate's
    e-NNNNNNNNN numbering, which is position-stable given identical filters)
  - a ready-to-paste config fragment: ground_truth_relative_path list +
    attack_to_time_window entries (windows in US/Eastern, because PIDSMaker
    parses config datetimes via datetime_to_ns_time_US)

Usage:
  python3 witfoo_emit_incident_gt.py \
      --edges ~/WitFoo2M-v2/graph/edges.jsonl \
      --org ORG-0004 --gt-date 2024-07-29 \
      --out-dir Ground_Truth/orthrus/witfoo/2m_v2_incidents \
      --prefix 2m_v2_inc --pad-min 2

IMPORTANT: event uuids (e-NNNNNNNNN) are assigned by translate in edge-file
order over org-filtered rows. This script replicates that numbering exactly:
same file, same org filter, same INCIDENT_LINK skip => same counters. If the
translate filters ever change, regenerate GT with it.
"""
import argparse, csv, os, collections
import json
from datetime import datetime, timezone, timedelta

US_EASTERN_JULY_OFFSET = timedelta(hours=-4)  # EDT (July): UTC-4

p = argparse.ArgumentParser()
p.add_argument("--edges", required=True)
p.add_argument("--org", required=True)
p.add_argument("--gt-date", required=True)
p.add_argument("--out-dir", required=True)
p.add_argument("--prefix", default="inc")
p.add_argument("--pad-min", type=float, default=2.0)
p.add_argument("--gt-file", default=None,
               help="translate's ground_truth_nodes.csv; only uuids present there are emitted (authoritative)")
a = p.parse_args()
gt_allow = None
if a.gt_file:
    gt_allow = set(l.split(",")[0].strip() for l in open(a.gt_file) if l.strip())

os.makedirs(a.out_dir, exist_ok=True)
inc = collections.defaultdict(lambda: {"uuids": [], "ts": []})
edge_counter = -1  # replicates translate's e-counter over org-filtered, non-INCIDENT_LINK rows

def _iter_edge_lines(path):
    import glob as _g, gzip as _gz
    if os.path.isdir(path):
        paths = sorted(_g.glob(os.path.join(path, "edges-*.jsonl*")) or _g.glob(os.path.join(path, "*.jsonl*")))
    elif any(c in path for c in "*?["):
        paths = sorted(_g.glob(path))
    else:
        paths = [path]
    if not paths:
        raise SystemExit(f"no edge files match: {path}")
    for p_ in paths:
        opener = _gz.open if p_.endswith(".gz") else open
        with opener(p_, "rt") as f_:
            for line_ in f_:
                yield line_

for line in _iter_edge_lines(a.edges):
    e = json.loads(line)
    if (e.get("attrs") or {}).get("org_id") != a.org:
        continue  # translate's iterator-level org filter
    if e.get("type") == "INCIDENT_LINK":
        continue
    edge_counter += 1
    native_id = e.get("edge_id")  # v2 exports carry authoritative edge ids; translate uses them verbatim
    lab = e.get("labels") or {}
    if lab.get("label_binary") != "malicious" or lab.get("disposition") != "Disrupted":
        continue
    t = e.get("timestamp", 0)
    if t < 1_500_000_000:
        continue
    d = datetime.fromtimestamp(t, tz=timezone.utc)
    if d.strftime("%Y-%m-%d") != a.gt_date:
        continue
    iid = lab.get("incident_id") or "no-primary-id"
    u = native_id if native_id else f"e-{edge_counter:09d}"
    if gt_allow is not None and u not in gt_allow:
        continue  # translate excluded this event from GT; follow its lead
    inc[iid]["uuids"].append(u)
    inc[iid]["ts"].append(t)

# emit CSVs + config fragments
gt_paths, windows, rows = [], [], []
for iid, r in sorted(inc.items(), key=lambda x: min(x[1]["ts"])):
    short = iid.split("-")[0]
    fname = f"{a.prefix}_{short}.csv"
    with open(os.path.join(a.out_dir, fname), "w", newline="") as f:
        w = csv.writer(f)
        w.writerows((u, "malicious", "") for u in r["uuids"])
    t0, t1 = min(r["ts"]), max(r["ts"])
    w0 = datetime.fromtimestamp(t0, tz=timezone.utc) + US_EASTERN_JULY_OFFSET - timedelta(minutes=a.pad_min)
    w1 = datetime.fromtimestamp(t1, tz=timezone.utc) + US_EASTERN_JULY_OFFSET + timedelta(minutes=a.pad_min)
    rel = f"witfoo/2m_v2_incidents/{fname}"
    gt_paths.append(rel)
    windows.append((rel, w0.strftime("%Y-%m-%d %H:%M:%S"), w1.strftime("%Y-%m-%d %H:%M:%S")))
    rows.append((short, len(r["uuids"]), round(t1 - t0, 1)))

print(f"{len(inc)} incidents -> {a.out_dir}/  (total GT events: {sum(n for _, n, _ in rows)})")
print(f"{'incident':<12}{'events':>7}{'dur_s':>9}")
for s, n, d in rows:
    print(f"{s:<12}{n:>7}{d:>9}")

cfg = "        \"ground_truth_relative_path\": [\n"
for gp in gt_paths:
    cfg += f"            \"{gp}\",\n"
cfg += "        ],\n        \"attack_to_time_window\": [\n"
for rel, w0, w1 in windows:
    cfg += f"            [\n                \"{rel}\",\n                \"{w0}\",\n                \"{w1}\",\n            ],\n"
cfg += "        ],\n"
with open(os.path.join(a.out_dir, "_config_fragment.txt"), "w") as f:
    f.write(cfg)
print(f"\nconfig fragment written to {a.out_dir}/_config_fragment.txt")
print("Paste it over the ground_truth_relative_path + attack_to_time_window entries of WITFOO_2M_V2.")
