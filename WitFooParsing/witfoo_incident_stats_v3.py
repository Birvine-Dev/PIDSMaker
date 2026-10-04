#!/usr/bin/env python3
"""witfoo_incident_stats_v3.py — per-attack statistics for confirmed-malicious events.

v3: merges overlapping incident records. WitFoo events carry a LIST of incident
ids; v2 fanned each event out into every id it listed (260 rows, ~7x event
double-counting). v3 counts each event once and union-finds incident ids that
co-occur on any event, so one row = one merged attack group — matching the
54-way GT splice. Use --no-merge to get the raw per-incident-id fan-out view.

Join key: attack_idx = rank of merged group by first event time (framework
attack numbering follows GT emission order, which is time order).

Usage (84M, ORG-0004, test day):
  python3 witfoo_incident_stats_v3.py --edges ~/WitFoo84M/graph --org ORG-0004 \
      --date 2024-07-29 -o incidents_84m_0729.csv
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
p.add_argument("--no-merge", action="store_true",
               help="v2 behaviour: one row per incident id, events fanned out")
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

# --- union-find over incident ids -------------------------------------------
parent = {}
def find(x):
    parent.setdefault(x, x)
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x
def union(x, y):
    rx, ry = find(x), find(y)
    if rx != ry:
        parent[ry] = rx

def new_rec():
    return {"ts": [], "stages": set(), "sigs": set(), "types": set(),
            "hosts": set(), "iids": set()}

inc = {}          # key: incident id (merge mode: stats land on iids[0], merged later)
n_events_total = 0
memberships_total = 0

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
        iids = sorted(set(iids))
        n_events_total += 1
        memberships_total += len(iids)
        targets = iids if a.no_merge else iids[:1]   # merge mode: count event ONCE
        if not a.no_merge:
            for other in iids[1:]:
                union(iids[0], other)
        for iid in targets:
            r = inc.setdefault(iid, new_rec())
            r["ts"].append(ts)
            r["iids"].update(iids)
            if lab.get("lifecycle_stage"): r["stages"].add(lab["lifecycle_stage"])
            if at.get("signature"): r["sigs"].add(str(at["signature"])[:60])
            if e.get("type"): r["types"].add(e["type"])
            for h in (e.get("src"), e.get("dst")):
                if h: r["hosts"].add(h)
    print(f"...{os.path.basename(f)} done", flush=True)

# --- merge per-id records into union-find components -------------------------
if a.no_merge:
    groups = inc
else:
    groups = {}
    for iid, r in inc.items():
        root = find(iid)
        g = groups.setdefault(root, new_rec())
        g["ts"].extend(r["ts"])
        for k in ("stages", "sigs", "types", "hosts", "iids"):
            g[k].update(r[k])

rows = []
for rank, (key, r) in enumerate(sorted(groups.items(), key=lambda x: min(x[1]["ts"]))):
    ts = sorted(r["ts"])
    gaps = [b - a_ for a_, b in zip(ts, ts[1:])]
    rows.append({
        "attack_idx": rank,                 # join key to per_incident.csv 'incident'
        "incident_id": key,                 # representative id (merge: component root)
        "n_incident_ids": len(r["iids"]),
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

mode = "raw per-id" if a.no_merge else "merged"
print(f"\n{len(rows)} {mode} groups -> {a.out}")
print(f"events: {n_events_total} unique confirmed events; "
      f"{memberships_total} incident-id memberships "
      f"(mean {memberships_total/max(n_events_total,1):.1f} ids/event)")
print(f"{'idx':>4} {'incident':<15}{'n_ids':>6}{'events':>7}{'dur_s':>10}{'hosts':>6}  stages")
for r in rows:
    print(f"{r['attack_idx']:>4} {str(r['incident_id'])[:13]:<15}{r['n_incident_ids']:>6}"
          f"{r['n_events']:>7}{r['duration_s']:>10}{r['n_hosts']:>6}  {r['lifecycle_stages']}")
