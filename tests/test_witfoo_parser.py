"""Unit tests for the WitFoo pipeline: translate rules, mappings, filters, and
the relation registry.

These are pure-Python tests: no GPU, no database, no torch. They load the
modules by file path, so they run on any machine from the repo root:

    pytest tests/test_witfoo_parser.py -v

The toy graph (9 entities, 12 events, 5 confirmed-malicious) is the built-in
one from witfoo_translate.py, which mirrors the structure of real incident
9fd6e430. Under mapping B it reifies to 21 nodes.
"""

import csv
import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _load(name, relpath):
    spec = importlib.util.spec_from_file_location(name, REPO / relpath)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


wt = _load("witfoo_translate", "WitFooParsing/witfoo_translate.py")
du = _load("dataset_utils", "pidsmaker/utils/dataset_utils.py")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def run_toy(tmp_path, mapping, **kwargs):
    out = tmp_path / f"toy_{mapping}"
    wt.translate(iter(wt.TOY_NODES), iter(wt.TOY_EDGES), mapping, out=str(out), **kwargs)
    return out


def read_csv(out, name):
    with open(out / name, newline="") as f:
        rows = list(csv.reader(f))
    return rows[0], rows[1:]  # header, data


def read_gt(out):
    """ground_truth_nodes.csv is headerless: (uuid, label, extra)."""
    with open(out / "ground_truth_nodes.csv", newline="") as f:
        return list(csv.reader(f))


def host(node_id, hostname=None, ip=None):
    return {"node_id": node_id, "type": "HOST",
            "attrs": {"hostname": hostname or node_id, "ip": ip or node_id}}


def edge(eid, src, dst, ts, mal=False, etype="NETWORK_FLOW"):
    e = {"edge_id": eid, "src": src, "dst": dst, "type": etype,
         "timestamp": float(ts), "attrs": {"message_type": "flow", "action": "allow"},
         "labels": {"label_binary": "benign"}}
    if mal:
        e["labels"] = {"label_binary": "malicious", "disposition": "Disrupted",
                       "incident_ids": ["inc-1"]}
    return e


# ---------------------------------------------------------------------------
# field rules (doc tables 4a-4e)
# ---------------------------------------------------------------------------

class TestFieldRules:
    def test_host_row_maps_hostname_and_ip(self):
        n = host("10.0.0.1", hostname="HOST-0001", ip="10.0.0.1")
        assert wt.host_row(n) == ("10.0.0.1", "HOST-0001", "10.0.0.1")

    def test_host_row_falls_back_to_node_id(self):
        n = {"node_id": "10.0.0.2", "type": "HOST", "attrs": {}}
        assert wt.host_row(n) == ("10.0.0.2", "10.0.0.2", "10.0.0.2")

    def test_credential_row_adds_user_prefix(self):
        n = {"node_id": "USER-1776", "type": "CREDENTIAL",
             "attrs": {"credential": "USER-1776"}}
        assert wt.credential_row(n) == ("USER-1776", "user:USER-1776")

    def test_credential_row_does_not_double_prefix(self):
        n = {"node_id": "x", "type": "CREDENTIAL",
             "attrs": {"credential": "user:alice"}}
        assert wt.credential_row(n) == ("x", "user:alice")

    def test_stub_type_mapping_b_carries_event_type(self):
        e = edge("e1", "a", "b", 1_700_000_000, etype="DNS_RESOLVE")
        assert wt.stub_type(e, "B") == ("DNS_RESOLVE_SRC", "DNS_RESOLVE_DST")

    def test_stub_type_mapping_c_is_generic(self):
        e = edge("e1", "a", "b", 1_700_000_000, etype="DNS_RESOLVE")
        assert wt.stub_type(e, "C") == ("SRC_OF", "DST_OF")

    @pytest.mark.parametrize("labels,expected", [
        ({"label_binary": "malicious", "disposition": "Disrupted"}, True),
        ({"label_binary": "malicious", "disposition": "Resolved"}, True),
        ({"label_binary": "malicious", "disposition": "Open"}, False),
        ({"label_binary": "benign"}, False),
        ({}, False),
    ])
    def test_is_confirmed_malicious(self, labels, expected):
        assert wt.is_confirmed_malicious({"labels": labels}) is expected


# ---------------------------------------------------------------------------
# toy graph, mapping B (the mapping used for all reported results)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def toy_b(tmp_path_factory):
    return run_toy(tmp_path_factory.mktemp("toy_b"), "B")


@pytest.fixture(scope="module")
def toy_a(tmp_path_factory):
    return run_toy(tmp_path_factory.mktemp("toy_a"), "A")


class TestToyMappingB:
    @pytest.fixture
    def out(self, toy_b):
        return toy_b

    def test_entity_counts(self, out):
        _, subjects = read_csv(out, "subject_node_table.csv")
        _, files = read_csv(out, "file_node_table.csv")
        _, netflows = read_csv(out, "netflow_node_table.csv")
        assert len(subjects) == 8      # the 8 hosts
        assert len(files) == 1         # the credential
        assert len(netflows) == 12     # one reified node per source event
        assert len(subjects) + len(files) + len(netflows) == 21

    def test_each_source_event_becomes_two_edges(self, out):
        _, events = read_csv(out, "event_table.csv")
        assert len(events) == 24  # 12 events x (src stub + dst stub)
        uuids = [r[5] for r in events]
        assert sum(u.endswith(":s") for u in uuids) == 12
        assert sum(u.endswith(":d") for u in uuids) == 12

    def test_operations_are_typed_stubs_known_to_the_framework(self, out):
        _, events = read_csv(out, "event_table.csv")
        ops = {r[2] for r in events}
        assert all(op.endswith("_SRC") or op.endswith("_DST") for op in ops)
        # every operation emitted must be registered in the framework's map
        assert ops <= {k for k in du.rel2id_witfoo if isinstance(k, str)}

    def test_ground_truth_is_the_five_malicious_events(self, out):
        gt = read_gt(out)
        assert [r[0] for r in gt] == [f"e-toy{i:02d}" for i in range(1, 6)]
        assert all(r[1] == "malicious" for r in gt)

    def test_gt_format_is_headerless_three_columns(self, out):
        gt = read_gt(out)
        assert all(len(r) == 3 for r in gt)
        assert gt[0][0] != "node_uuid"  # no header row


# ---------------------------------------------------------------------------
# toy graph, mappings A and C
# ---------------------------------------------------------------------------

class TestToyMappingA:
    @pytest.fixture
    def out(self, toy_a):
        return toy_a

    def test_no_reification(self, out):
        _, netflows = read_csv(out, "netflow_node_table.csv")
        _, events = read_csv(out, "event_table.csv")
        assert len(netflows) == 0
        assert len(events) == 12  # events stay single edges

    def test_ground_truth_is_the_malicious_endpoints(self, out):
        gt = {r[0] for r in read_gt(out)}
        assert gt == {"100.64.10.131", "100.64.10.132",
                      "172.21.61.66", "172.24.247.113"}


class TestToyMappingC:
    def test_operations_are_generic_stubs_only(self, tmp_path):
        out = run_toy(tmp_path, "C")
        _, events = read_csv(out, "event_table.csv")
        assert {r[2] for r in events} == {"SRC_OF", "DST_OF"}


# ---------------------------------------------------------------------------
# hygiene filters
# ---------------------------------------------------------------------------

class TestFilters:
    def test_incident_link_edges_are_excluded(self, tmp_path):
        nodes = [host("a"), host("b")]
        edges = [edge("e1", "a", "b", 1_700_000_000, etype="INCIDENT_LINK")]
        wt.translate(iter(nodes), iter(edges), "B", out=str(tmp_path / "o"))
        _, events = read_csv(tmp_path / "o", "event_table.csv")
        _, subjects = read_csv(tmp_path / "o", "subject_node_table.csv")
        assert events == []
        assert subjects == []  # endpoints only referenced by the link: not emitted

    def test_corrupt_timestamps_are_skipped(self, tmp_path):
        nodes = [host("a"), host("b")]
        edges = [edge("e1", "a", "b", 42),               # year-1300 bug
                 edge("e2", "a", "b", 1_700_000_000)]    # fine
        wt.translate(iter(nodes), iter(edges), "B", out=str(tmp_path / "o"))
        _, events = read_csv(tmp_path / "o", "event_table.csv")
        assert {r[5].rsplit(":", 1)[0] for r in events} == {"e2"}

    def test_gt_date_excludes_dormant_malicious_events(self, tmp_path):
        # 2024-07-08 ~ 1720400000; a malicious event on another day stays in
        # the graph but out of the ground truth.
        on_day = 1_720_440_000    # 2024-07-08 UTC
        off_day = 1_715_695_200   # 2024-05-14 UTC
        nodes = [host("a"), host("b")]
        edges = [edge("e1", "a", "b", on_day, mal=True),
                 edge("e2", "a", "b", off_day, mal=True)]
        wt.translate(iter(nodes), iter(edges), "B",
                     out=str(tmp_path / "o"), gt_date="2024-07-08")
        _, events = read_csv(tmp_path / "o", "event_table.csv")
        gt = {r[0] for r in read_gt(tmp_path / "o")}
        assert len(events) == 4   # both events kept in the graph
        assert gt == {"e1"}       # only the on-date one is ground truth

    def test_org_filter_keeps_only_that_org(self, tmp_path):
        nodes = [host("a"), host("b")]
        for n in nodes:
            n["attrs"]["org_id"] = "ORG-0004"
        other = host("c")
        other["attrs"]["org_id"] = "ORG-0005"
        e1 = edge("e1", "a", "b", 1_700_000_000)
        e1["attrs"]["org_id"] = "ORG-0004"
        e2 = edge("e2", "a", "c", 1_700_000_000)
        e2["attrs"]["org_id"] = "ORG-0005"
        wt.translate(iter(nodes + [other]), iter([e1, e2]), "B",
                     out=str(tmp_path / "o"), org="ORG-0004")
        _, events = read_csv(tmp_path / "o", "event_table.csv")
        assert {r[5].rsplit(":", 1)[0] for r in events} == {"e1"}


# ---------------------------------------------------------------------------
# benign time shift (Etienne's direction, 23 July): ordering and gaps
# must be preserved exactly; malicious timestamps must not move
# ---------------------------------------------------------------------------

class TestBenignShift:
    def test_shift_preserves_order_and_gaps_and_leaves_malicious_alone(self, tmp_path):
        nodes = [host("a"), host("b")]
        b1, b2, b3 = 1_715_000_000, 1_715_000_007, 1_715_003_600
        m1 = 1_720_440_000
        edges = [edge("e1", "a", "b", b1), edge("e2", "a", "b", b2),
                 edge("e3", "a", "b", b3), edge("m1", "a", "b", m1, mal=True)]
        target = "2024-07-08T11:00:00"
        wt.translate(iter(nodes), iter(edges), "A",
                     shift_to=target, out=str(tmp_path / "o"))
        _, events = read_csv(tmp_path / "o", "event_table.csv")
        ts = {r[5]: int(r[6]) for r in events}  # uuid -> ns timestamp
        NS = wt.NS
        # benign start lands exactly on the target
        from datetime import datetime, timezone
        tgt_ns = int(datetime.fromisoformat(target)
                     .replace(tzinfo=timezone.utc).timestamp() * NS)
        assert ts["e1"] == tgt_ns
        # gaps preserved exactly
        assert ts["e2"] - ts["e1"] == (b2 - b1) * NS
        assert ts["e3"] - ts["e2"] == (b3 - b2) * NS
        # malicious untouched
        assert ts["m1"] == m1 * NS


# ---------------------------------------------------------------------------
# framework registration (pidsmaker/utils/dataset_utils.py)
# ---------------------------------------------------------------------------

class TestRelationRegistry:
    def test_rel2id_witfoo_round_trips(self):
        names = {k for k in du.rel2id_witfoo if isinstance(k, str)}
        ids = {k for k in du.rel2id_witfoo if isinstance(k, int)}
        assert len(names) == len(ids) == 17
        for name in names:
            assert du.rel2id_witfoo[du.rel2id_witfoo[name]] == name

    def test_witfoo_datasets_are_registered(self):
        for ds in ("witfoo_toy", "witfoo_2m", "witfoo_84m_d8", "witfoo_84m_d4"):
            assert ds in du.witfoo_datasets


# ---------------------------------------------------------------------------
# checkpointing wiring (source-level: the full config stack needs torch,
# which these tests deliberately avoid)
# ---------------------------------------------------------------------------

class TestCheckpointingWiring:
    def test_save_checkpoints_flag_is_declared_in_config(self):
        src = (REPO / "pidsmaker" / "config" / "config.py").read_text()
        assert '"save_checkpoints"' in src

    def test_training_loop_saves_per_epoch_behind_the_flag(self):
        src = (REPO / "pidsmaker" / "detection" / "training_methods"
               / "training_loop.py").read_text()
        assert "save_checkpoints" in src
        assert "model_epoch_" in src
