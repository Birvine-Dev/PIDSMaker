#!/usr/bin/env python3
"""witfoo_incident_stats_v2.py — per-incident statistics for confirmed-malicious events.

v2: reads gz-sharded exports (directory or glob), adds --org filter, and defaults
to Disrupted-only so the incident set matches the emitter's GT exactly.

Writes a per-incident CSV for joining incident characteristics with per-tool
detection results (join key: attack_idx = rank by first event time, which matches
the framework's attack numbering since the emitter emits GT files in that order).

Usage (84M, ORG-0004, test day):
  python3 witfoo_incident_stats_v2.py --edges ~/WitFoo84M/graph --org ORG-0004 \
      --date 2024-07-29 -o incidents_84m_0729.csv
  (--edges takes a directory of edges-*.jsonl.gz shards, a glob, or a single file)
"""
import argparse, csv, glob as globmod, gzip, json, os, statistics
from datetime import datetime, timezone

p = argparse.ArgumentParser()
p.add_argument("--edges", required=True,
               help="edges file, directory of edges-*.jsonl.gz shards, or glob")
p.add_argument("--org", default=None, help="attrs.org_id filter (e.g. ORG-0004)")
p.add_argument("--date", default=None, help="UTC date filter YYYY-MM-DD (default: all)")
p.add_argument("--dispositions", default="Disrupted",
               help="comma-separated; default Disrupted (matches GT). Use "
                    "'Disrupted,Resolved' for the wider confirmed set")
p.add_argument("-o", "--out", default="incidents.csv")
a = p.parse_args()

DISP = set(a.dispositions.split(","))

def edge_files(path):
    if os.path.isdir(path):
        fs = sorted(globmod.glob(os.path.join(path, "edges-*.jsonl.gz"))) or \
             sorted(globmod.glob(os.path.join(path, "*.jsonl*")))
    else:
        fs = sorted(globmod.glob(path)) or [path]
    if not fs:
        raise SystemExit(f"no edge files found at {path}")
    return fs

inc = {}
for f in edge_files(a.edges):
    opener = gzip.open if f.endswith(".gz") else open
    for line in opener(f, "rt"):
        e = json.loads(line)
        if e.get("type") == "INCIDENT_LINK":
            continue
        lab = e.get("labels") or {}
        if lab.get("label_binary") != "malicious" or lab.get("disposition") not in DISP:
            continue
        at = e.get("attrs") or {}
        if a.org and at.get("org_id") != a.org:
            continue
        ts = e.get("timestamp", 0)
        if ts < 1_500_000_000:
            continue
        d = datetime.fromtimestamp(ts, tz=timezone.utc)
        if a.date and d.strftime("%Y-%m-%d") != a.date:
            continue
        iids = lab.get("incident_ids") or \
               ([lab["incident_id"]] if lab.get("incident_id") else ["(no-incident-id)"])
        for iid in iids:
            r = inc.setdefault(iid, {"ts": [], "stages": set(), "sigs": set(),
                                     "types": set(), "hosts": set()})
            r["ts"].append(ts)
            if lab.get("lifecycle_stage"): r["stages"].add(lab["lifecycle_stage"])
            if at.get("signature"): r["sigs"].add(str(at["signature"])[:60])
            if e.get("type"): r["types"].add(e["type"])
            for h in (e.get("src"), e.get("dst")):
                if h: r["hosts"].add(h)
    print(f"...{os.path.basename(f)} done", flush=True)

rows = []
for rank, (iid, r) in enumerate(sorted(inc.items(), key=lambda x: min(x[1]["ts"]))):
    ts = sorted(r["ts"])
    gaps = [b - a_ for a_, b in zip(ts, ts[1:])]
    rows.append({
        "attack_idx": rank,                 # join key to per_incident.csv 'incident'
        "incident_id": iid,
        "n_events": len(ts),
        "first_utc": datetime.fromtimestamp(ts[0], tz=timezone.utc).isoformat(),
        "last_utc": datetime.fromtimestamp(ts[-1], tz=timezone.utc).isoformat(),
        "duration_s": round(ts[-1] - ts[0], 3),
        "gap_mean_s": round(statistics.mean(gaps), 3) if gaps else "",
        "gap_std_s": round(statistics.stdev(gaps), 3) if len(gaps) > 1 else "",
        "n_hosts": len(r["hosts"]),
        "lifecycle_stages": ";".join(sorted(r["stages"])),
        "event_types": ";".join(sorted(r["types"])),
        "signatures": ";".join(sorted(r["sigs"])),
    })

with open(a.out, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=rows[0].keys())
    w.writeheader(); w.writerows(rows)

print(f"\n{len(rows)} incidents -> {a.out}")
print(f"{'idx':>4} {'incident':<15}{'events':>7}{'dur_s':>10}{'hosts':>6}  stages")
for r in rows:
    print(f"{r['attack_idx']:>4} {str(r['incident_id'])[:13]:<15}{r['n_events']:>7}"
          f"{r['duration_s']:>10}{r['n_hosts']:>6}  {r['lifecycle_stages']}")
