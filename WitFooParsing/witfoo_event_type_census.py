#!/usr/bin/env python3
"""witfoo_event_type_census.py — event-type and signature-presence census,
split malicious vs benign, for the ML-baseline feature justification.

Answers two claims before they go in writing:
  1. "event type is near-constant in the export" (we only verified attacks)
  2. "malicious events carry empty signature fields" — gives the benign
     signature-coverage % so the leak claim carries a number.

Usage (84M, ORG-0004, test day — same args as the incident stats run):
  python3 witfoo_event_type_census.py --edges ~/WitFoo84M/graph \
      --org ORG-0004 --date 2024-07-29
"""
import argparse, glob as globmod, gzip, json, os
from collections import Counter
from datetime import datetime, timezone

p = argparse.ArgumentParser()
p.add_argument("--edges", required=True)
p.add_argument("--org", default=None)
p.add_argument("--date", default=None, help="UTC date YYYY-MM-DD")
p.add_argument("--dispositions", default="Disrupted",
               help="dispositions counted as malicious (default Disrupted, matches GT)")
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

types = {"mal": Counter(), "ben": Counter()}
sig   = {"mal": Counter(), "ben": Counter()}   # keys: present / empty
n     = Counter()

for f in edge_files(a.edges):
    opener = gzip.open if f.endswith(".gz") else open
    for line in opener(f, "rt"):
        e = json.loads(line)
        if e.get("type") == "INCIDENT_LINK":
            n["incident_link_rows"] += 1
            continue
        at = e.get("attrs") or {}
        if a.org and at.get("org_id") != a.org:
            continue
        ts = e.get("timestamp", 0)
        if ts < 1_500_000_000:
            continue
        if a.date and datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d") != a.date:
            continue
        lab = e.get("labels") or {}
        cls = "mal" if (lab.get("label_binary") == "malicious"
                        and lab.get("disposition") in DISP) else "ben"
        n[cls] += 1
        types[cls][str(e.get("type"))] += 1
        sig[cls]["present" if at.get("signature") else "empty"] += 1
    print(f"...{os.path.basename(f)} done", flush=True)

print(f"\n=== {a.org or 'all orgs'} {a.date or 'all days'} "
      f"(malicious = {','.join(sorted(DISP))}) ===")
print(f"events: malicious {n['mal']:,} | benign {n['ben']:,} "
      f"| INCIDENT_LINK rows skipped {n['incident_link_rows']:,}")
for cls, name in (("mal", "MALICIOUS"), ("ben", "BENIGN")):
    tot = max(n[cls], 1)
    print(f"\n{name} event types ({len(types[cls])} distinct):")
    for t, c in types[cls].most_common(20):
        print(f"  {t:<30}{c:>12,}  {100*c/tot:6.2f}%")
    if len(types[cls]) > 20:
        print(f"  ... and {len(types[cls])-20} more types")
    print(f"{name} signature field: present {sig[cls]['present']:,} "
          f"({100*sig[cls]['present']/tot:.2f}%) | "
          f"empty {sig[cls]['empty']:,} ({100*sig[cls]['empty']/tot:.2f}%)")
