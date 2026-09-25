#!/usr/bin/env python3
"""census3_per_org_daymap.py - per-org experiment-design map for the 84M export.

For every org: monthly label histogram for the archive (pre Jul 2024), daily
label counts for the live window (Jul-Aug 2024), and distinct malicious
incidents per day. Answers, per org: do attack days overlap benign capture
(natural run viable?), are there clean days to train on, and at what volumes.

Usage: python3 census3_per_org_daymap.py /home/bir17/WitFoo84M/graph
"""
import sys, json, gzip, glob, os, collections
from datetime import datetime, timezone

root = sys.argv[1] if len(sys.argv) > 1 else "/home/bir17/WitFoo84M/graph"
paths = sorted(glob.glob(os.path.join(root, "edges-*.jsonl.gz")) or
               glob.glob(os.path.join(root, "*.jsonl*")))

day = collections.Counter()      # (org, bucket, label) -> n   bucket = YYYY-MM or MM-DD
inc = collections.defaultdict(set)  # (org, bucket) -> {incident_id}
disp = collections.Counter()     # (org, bucket) -> n Disrupted

for p in paths:
    opener = gzip.open if p.endswith(".gz") else open
    for line in opener(p, "rt"):
        e = json.loads(line)
        if e.get("type") == "INCIDENT_LINK":
            continue
        lab = e.get("labels") or {}
        org = (e.get("attrs") or {}).get("org_id", "?")
        t = e.get("timestamp", 0)
        if not t or t < 1.5e9:
            continue
        d = datetime.fromtimestamp(t, tz=timezone.utc)
        if d < datetime(2024, 7, 1, tzinfo=timezone.utc) or d >= datetime(2024, 9, 1, tzinfo=timezone.utc):
            bucket = d.strftime("%Y-%m")          # archive / stragglers: monthly
        else:
            bucket = d.strftime("%m-%d")          # live window: daily
        b = lab.get("label_binary", "?")
        day[(org, bucket, b)] += 1
        if b == "malicious":
            iid = lab.get("incident_id") or ""
            if iid:
                inc[(org, bucket)].add(iid)
            if lab.get("disposition") == "Disrupted":
                disp[(org, bucket)] += 1
    print(f"...{os.path.basename(p)} done", flush=True)

orgs = sorted(set(o for (o, _, _) in day))
for org in orgs:
    print(f"\n================ {org} ================")
    print(f"{'bucket':>10} {'benign':>12} {'suspicious':>11} {'malicious':>10} {'Disrupted':>10} {'incidents':>10}")
    buckets = sorted(set(bk for (o, bk, _) in day if o == org))
    for bk in buckets:
        ben = day.get((org, bk, "benign"), 0)
        sus = day.get((org, bk, "suspicious"), 0)
        mal = day.get((org, bk, "malicious"), 0)
        di = disp.get((org, bk), 0)
        ni = len(inc.get((org, bk), set()))
        print(f"{bk:>10} {ben:>12,} {sus:>11,} {mal:>10,} {di:>10,} {ni:>10,}")
    # design verdict helper: live-window days with BOTH benign>0 and Disrupted>0
    both = [bk for bk in buckets if len(bk) == 5 and day.get((org, bk, "benign"), 0) > 0 and disp.get((org, bk), 0) > 0]
    clean = [bk for bk in buckets if len(bk) == 5 and day.get((org, bk, "benign"), 0) > 1000 and day.get((org, bk, "malicious"), 0) == 0]
    print(f"  -> live days with benign AND Disrupted attacks: {both or 'NONE'}")
    print(f"  -> clean candidate train days (benign>1k, zero malicious): {clean or 'NONE'}")
