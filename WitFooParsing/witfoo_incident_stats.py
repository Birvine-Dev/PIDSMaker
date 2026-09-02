#!/usr/bin/env python3
"""witfoo_incident_stats.py — per-incident statistics for confirmed-malicious events.

Answers: how many independent incidents, their duration, size, event-rate
(mean/std inter-event gap), lifecycle stages (kill-chain), signatures/techniques,
hosts involved. Writes a per-incident CSV reusable for per-incident ground truth
and for correlating incident characteristics with per-tool detection.

Usage:
  python3 witfoo_incident_stats.py --edges ~/WitFoo2M/witfoo-2m/graph/edges.jsonl \
      --date 2024-07-08 -o incidents_2024-07-08.csv
  (omit --date for all confirmed incidents in the file)
"""
import argparse, csv, json, statistics
from datetime import datetime, timezone

p = argparse.ArgumentParser()
p.add_argument("--edges", required=True)
p.add_argument("--date", default=None, help="UTC date filter YYYY-MM-DD (default: all)")
p.add_argument("-o", "--out", default="incidents.csv")
a = p.parse_args()

inc = {}
for line in open(a.edges):
    e = json.loads(line)
    if e.get("type") == "INCIDENT_LINK":
        continue
    lab = e.get("labels") or {}
    if lab.get("label_binary") != "malicious" or lab.get("disposition") not in ("Disrupted", "Resolved"):
        continue
    ts = e.get("timestamp", 0)
    if ts < 1_500_000_000:
        continue
    d = datetime.fromtimestamp(ts, tz=timezone.utc)
    if a.date and d.strftime("%Y-%m-%d") != a.date:
        continue
    at = e.get("attrs") or {}
    for iid in lab.get("incident_ids") or ["(no-incident-id)"]:
        r = inc.setdefault(iid, {"ts": [], "stages": set(), "sigs": set(), "types": set(), "hosts": set()})
        r["ts"].append(ts)
        if lab.get("lifecycle_stage"): r["stages"].add(lab["lifecycle_stage"])
        if at.get("signature"): r["sigs"].add(str(at["signature"])[:60])
        if e.get("type"): r["types"].add(e["type"])
        for h in (e.get("src"), e.get("dst")):
            if h: r["hosts"].add(h)

rows = []
for iid, r in sorted(inc.items(), key=lambda x: min(x[1]["ts"])):
    ts = sorted(r["ts"])
    gaps = [b - a_ for a_, b in zip(ts, ts[1:])]
    rows.append({
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

print(f"{len(rows)} incidents -> {a.out}\n")
print(f"{'incident':<15}{'events':>7}{'dur_s':>10}{'hosts':>6}  stages")
for r in rows:
    print(f"{r['incident_id'][:13]:<15}{r['n_events']:>7}{r['duration_s']:>10}{r['n_hosts']:>6}  {r['lifecycle_stages']}")
