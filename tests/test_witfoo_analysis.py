"""Unit tests for the analysis scripts behind the reported figures:

  * witfoo_incident_stats_v3.py  (the union-find merge that yields the 54 attacks)
  * nodlink_threshold_sweep.py   (the sweep behind the threshold findings)

Both scripts are CLI programs (argparse at module level), so each test runs
them as a subprocess on small synthetic inputs where the right answer is
computable by hand. No GPU, no database; numpy is the only non-stdlib need
(the sweep script imports it).

    pytest tests/test_witfoo_analysis.py -v
"""

import csv
import json
import pickle
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
STATS = REPO / "WitFooParsing" / "witfoo_incident_stats_v3.py"
SWEEP = REPO / "WitFooParsing" / "nodlink_threshold_sweep.py"


def run(script, *args):
    proc = subprocess.run([sys.executable, str(script), *map(str, args)],
                          capture_output=True, text=True, cwd=REPO)
    assert proc.returncode == 0, proc.stderr or proc.stdout
    return proc.stdout


# ---------------------------------------------------------------------------
# witfoo_incident_stats_v3.py
# ---------------------------------------------------------------------------

T0 = 1_720_000_000  # safely past the corrupt-timestamp floor (1.5e9)


def mal_edge(eid, ts, iids, src="h1", dst="h2", disposition="Disrupted",
             stage=None, etype="NETWORK_FLOW"):
    e = {"edge_id": eid, "src": src, "dst": dst, "type": etype,
         "timestamp": float(ts), "attrs": {},
         "labels": {"label_binary": "malicious", "disposition": disposition,
                    "incident_ids": iids}}
    if stage:
        e["labels"]["lifecycle_stage"] = stage
    return e


@pytest.fixture
def edges_file(tmp_path):
    """Two true attack groups plus noise that must all be filtered out.

    Group 1 (earlier): events e1 [A], e2 [A, B], e3 [B].
        Incident ids A and B co-occur on e2, so the merge must union them
        into ONE attack of 3 events spanning 2 incident ids.
    Group 2 (later): event e4 [C]: its own attack of 1 event.
    """
    edges = [
        mal_edge("e1", T0 + 0, ["A"], src="h1", dst="h2", stage="Delivery"),
        mal_edge("e2", T0 + 10, ["A", "B"], src="h1", dst="h3"),
        mal_edge("e3", T0 + 20, ["B"], src="h3", dst="h2"),
        mal_edge("e4", T0 + 1000, ["C"], src="h9", dst="h8"),
        # noise, all excluded:
        {"edge_id": "n1", "src": "h1", "dst": "h2", "type": "INCIDENT_LINK",
         "timestamp": float(T0), "attrs": {},
         "labels": {"label_binary": "malicious", "disposition": "Disrupted",
                    "incident_ids": ["A"]}},                      # link edge
        mal_edge("n2", T0, ["D"], disposition="Open"),            # unconfirmed
        mal_edge("n3", 42, ["E"]),                                # corrupt ts
        {"edge_id": "n4", "src": "h1", "dst": "h2", "type": "NETWORK_FLOW",
         "timestamp": float(T0), "attrs": {},
         "labels": {"label_binary": "benign"}},                   # benign
    ]
    f = tmp_path / "edges.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in edges) + "\n")
    return f


def read_rows(out_csv):
    with open(out_csv, newline="") as f:
        return list(csv.DictReader(f))


class TestIncidentStatsV3Merge:
    def test_overlapping_incident_ids_merge_into_one_attack(self, edges_file, tmp_path):
        out = tmp_path / "merged.csv"
        stdout = run(STATS, "--edges", edges_file, "-o", out)
        rows = read_rows(out)

        assert len(rows) == 2  # A+B merged, C alone

        g1, g2 = rows  # ranked by first event time
        assert g1["attack_idx"] == "0" and g2["attack_idx"] == "1"
        assert int(g1["n_events"]) == 3
        assert int(g1["n_incident_ids"]) == 2        # A and B
        assert int(g1["n_hosts"]) == 3               # h1, h2, h3
        assert g1["duration_s"] == "20.0"
        assert g1["gap_mean_s"] == "10.0"            # gaps 10, 10
        assert g1["lifecycle_stages"] == "Delivery"
        assert int(g2["n_events"]) == 1
        assert int(g2["n_incident_ids"]) == 1

        # each event counted ONCE even when it lists several incident ids
        assert "4 unique confirmed events" in stdout
        assert "5 incident-id memberships" in stdout  # 1 + 2 + 1 + 1

    def test_no_merge_reproduces_the_v2_fan_out(self, edges_file, tmp_path):
        out = tmp_path / "raw.csv"
        run(STATS, "--edges", edges_file, "--no-merge", "-o", out)
        rows = read_rows(out)

        assert len(rows) == 3  # one row per incident id: A, B, C
        by_id = {r["incident_id"]: r for r in rows}
        assert int(by_id["A"]["n_events"]) == 2      # e1, e2
        assert int(by_id["B"]["n_events"]) == 2      # e2 again: double-counted
        assert int(by_id["C"]["n_events"]) == 1
        # 5 fanned rows from 4 events = the double-counting v3 removes
        assert sum(int(r["n_events"]) for r in rows) == 5

    def test_date_filter(self, edges_file, tmp_path):
        out = tmp_path / "dated.csv"
        # T0 = 2024-07-03 UTC; a different date must keep nothing... so use
        # the right one and check everything survives.
        run(STATS, "--edges", edges_file, "--date", "2024-07-03", "-o", out)
        assert len(read_rows(out)) == 2


# ---------------------------------------------------------------------------
# nodlink_threshold_sweep.py
# ---------------------------------------------------------------------------

def sweep_row(stdout, quantile):
    """Return the printed sweep row for a quantile as a list of fields."""
    for line in stdout.splitlines():
        parts = line.split()
        if parts and parts[0] == str(quantile):
            return parts
    raise AssertionError(f"no sweep row for q={quantile} in output:\n{stdout}")


class TestThresholdSweep:
    def test_sweep_on_authoritative_scores_dict(self, tmp_path):
        """1,000 unique scores 0..999; the top 10 are the positives.

        Hand-computed: at q=0.99 the threshold is 989.01, flagging exactly the
        10 positives (precision 1.0, recall 1.0). At q=0.95 it is 949.05,
        flagging 50 nodes: 10 tp + 40 fp (precision 0.2, recall 1.0).
        """
        n = 1000
        obj = {"pred_scores": [float(i) for i in range(n)],
               "y_truth": [1 if i >= n - 10 else 0 for i in range(n)],
               "nodes": [f"n{i}" for i in range(n)]}
        pkl = tmp_path / "scores.pkl"
        pkl.write_bytes(pickle.dumps(obj))

        stdout = run(SWEEP, pkl)
        assert "1,000 scored nodes, 10 positives" in stdout

        q99 = sweep_row(stdout, 0.99)
        # columns: quantile threshold flags tp fp precision recall F1 FPR
        assert q99[2] == "10" and q99[3] == "10" and q99[4] == "0"
        assert q99[5] == "1.000" and q99[6] == "1.000"

        q95 = sweep_row(stdout, 0.95)
        assert q95[2] == "50" and q95[3] == "10" and q95[4] == "40"
        assert q95[5] == "0.200" and q95[6] == "1.000"

    def test_sweep_joins_labels_from_gt_file(self, tmp_path):
        """No y_truth in the pickle: labels come from --gt (translate's format).

        2,000 scores 0..1999, GT names the top 20 ids: q=0.99 flags exactly
        those 20 (precision 1.0, recall 1.0).
        """
        n = 2000
        obj = {"pred_scores": [float(i) for i in range(n)],
               "nodes": [f"n{i}" for i in range(n)]}
        pkl = tmp_path / "scores.pkl"
        pkl.write_bytes(pickle.dumps(obj))

        gt = tmp_path / "ground_truth_nodes.csv"
        gt.write_text("".join(f"n{i},malicious,\n" for i in range(n - 20, n)))

        stdout = run(SWEEP, pkl, "--gt", gt)
        assert "labels joined from GT file: 20 positives of 2000" in stdout
        q99 = sweep_row(stdout, 0.99)
        assert q99[2] == "20" and q99[3] == "20" and q99[4] == "0"
        assert q99[5] == "1.000" and q99[6] == "1.000"
