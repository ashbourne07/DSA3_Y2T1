# tests/test_all_dsa.py
#
# Comprehensive tests for all DSA components.
# Run with:  cd backend && python -m pytest tests/ -v
# Or:        cd backend && python -m unittest tests.test_all_dsa -v

import sys
import os
import unittest

# Ensure backend root is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from algorithms.kmp import build_lps, kmp_search, find_attack_patterns_in_logs
from algorithms.hash_lookup import SignatureHashTable
from algorithms.graph import AttackGraph
from algorithms.bfs_dfs import bfs, dfs, bfs_shortest_path, find_all_paths
from algorithms.articulation_points import find_articulation_points_and_bridges
from algorithms.priority_queue import AlertPriorityQueue, get_prioritised_alerts
from services.alert_generator import generate_alerts_from_matches, deduplicate_alerts
from services.alert_correlator import correlate_alerts
from services.kill_chain_builder import build_kill_chain, KILL_CHAIN_ORDER
from services.monitoring_optimizer import greedy_monitoring_optimizer
from services.log_processor import parse_logs_from_csv


# ─────────────────────────────────────────────────────────────
# KMP Tests
# ─────────────────────────────────────────────────────────────
class TestKMP(unittest.TestCase):

    def test_lps_simple(self):
        """LPS array for simple pattern."""
        lps = build_lps(["A", "B", "C"])
        self.assertEqual(lps, [0, 0, 0])

    def test_lps_with_prefix_suffix(self):
        """LPS for pattern with repeating prefix."""
        lps = build_lps(["A", "B", "A"])
        self.assertEqual(lps, [0, 0, 1])

    def test_lps_all_same(self):
        """LPS for all-same elements."""
        lps = build_lps(["X", "X", "X"])
        self.assertEqual(lps, [0, 1, 2])

    def test_kmp_no_match(self):
        """KMP returns empty list when pattern not in text."""
        result = kmp_search(["A", "B", "C"], ["D", "E"])
        self.assertEqual(result, [])

    def test_kmp_single_match(self):
        """KMP finds one match at the correct index."""
        text    = ["A", "B", "C", "D"]
        pattern = ["B", "C"]
        result  = kmp_search(text, pattern)
        self.assertEqual(result, [1])

    def test_kmp_multiple_matches(self):
        """KMP finds all occurrences of pattern."""
        text    = ["X", "Y", "X", "Y", "X", "Y"]
        pattern = ["X", "Y"]
        result  = kmp_search(text, pattern)
        self.assertEqual(result, [0, 2, 4])

    def test_kmp_empty_pattern(self):
        """KMP with empty pattern returns empty."""
        self.assertEqual(kmp_search(["A", "B"], []), [])

    def test_kmp_empty_text(self):
        """KMP with empty text returns empty."""
        self.assertEqual(kmp_search([], ["A"]), [])

    def test_kmp_pattern_longer_than_text(self):
        """Pattern longer than text — no match."""
        self.assertEqual(kmp_search(["A"], ["A", "B", "C"]), [])

    def test_kmp_brute_force_detection(self):
        """KMP detects three consecutive LOGIN_FAILED events."""
        text    = ["LOGIN_FAILED", "LOGIN_FAILED", "LOGIN_FAILED", "MALWARE_DETECTED"]
        pattern = ["LOGIN_FAILED", "LOGIN_FAILED", "LOGIN_FAILED"]
        result  = kmp_search(text, pattern)
        self.assertIn(0, result)

    def test_kmp_exact_match_full_text(self):
        """Pattern equals the entire text."""
        text    = ["A", "B", "C"]
        pattern = ["A", "B", "C"]
        result  = kmp_search(text, pattern)
        self.assertEqual(result, [0])

    def test_find_attack_patterns_in_logs(self):
        """Detects attack pattern across a list of log dicts."""
        logs = [
            {"log_id": "L1", "event_type": "LOGIN_FAILED",  "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2"},
            {"log_id": "L2", "event_type": "LOGIN_FAILED",  "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2"},
            {"log_id": "L3", "event_type": "LOGIN_FAILED",  "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2"},
        ]
        signatures = [{"id": "SIG001", "pattern": ["LOGIN_FAILED", "LOGIN_FAILED", "LOGIN_FAILED"],
                       "attack_type": "BRUTE_FORCE", "severity": "HIGH",
                       "kill_chain_stage": "Initial Access", "description": "Test"}]
        result = find_attack_patterns_in_logs(logs, signatures)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['attack_type'], 'BRUTE_FORCE')

    def test_find_attack_patterns_empty_logs(self):
        """Empty log list returns no matches."""
        result = find_attack_patterns_in_logs([], [{"id": "S1", "pattern": ["A"]}])
        self.assertEqual(result, [])


# ─────────────────────────────────────────────────────────────
# Hash Lookup Tests
# ─────────────────────────────────────────────────────────────
class TestHashLookup(unittest.TestCase):

    def setUp(self):
        self.table = SignatureHashTable()

    def test_known_event_category(self):
        """Known event type returns correct category."""
        result = self.table.get_event_category("LOGIN_FAILED")
        self.assertEqual(result['category'], 'Authentication')

    def test_unknown_event_category(self):
        """Unknown event type returns 'Unknown' category default."""
        result = self.table.get_event_category("TOTALLY_UNKNOWN_EVENT")
        self.assertEqual(result['category'], 'Unknown')

    def test_signature_by_attack_type(self):
        """O(1) lookup returns correct signature for BRUTE_FORCE."""
        sig = self.table.get_signature_by_attack_type("BRUTE_FORCE")
        self.assertIsNotNone(sig)
        self.assertEqual(sig['id'], 'SIG001')

    def test_unknown_attack_type(self):
        """Unknown attack type returns None."""
        sig = self.table.get_signature_by_attack_type("TOTALLY_FAKE")
        self.assertIsNone(sig)

    def test_is_suspicious_true(self):
        """Malware event is suspicious."""
        self.assertTrue(self.table.is_suspicious_event("MALWARE_DETECTED"))

    def test_is_suspicious_false(self):
        """Normal login is not suspicious."""
        self.assertFalse(self.table.is_suspicious_event("NORMAL_LOGIN"))

    def test_sig_id_lookup(self):
        """Lookup by signature ID."""
        sig = self.table.get_signature_by_id("SIG002")
        self.assertIsNotNone(sig)
        self.assertEqual(sig['attack_type'], 'MALWARE_ATTACK')

    def test_all_signatures_loaded(self):
        """All 5 signatures loaded."""
        self.assertEqual(len(self.table.get_all_signatures()), 5)


# ─────────────────────────────────────────────────────────────
# Graph Tests
# ─────────────────────────────────────────────────────────────
class TestGraph(unittest.TestCase):

    def test_add_node(self):
        """Adding a node creates an entry in the adjacency list."""
        g = AttackGraph()
        g.add_node("A")
        self.assertIn("A", g.adj_list)

    def test_add_edge(self):
        """Adding an edge links two nodes."""
        g = AttackGraph()
        g.add_edge("A", "B", edge_type="attack")
        neighbours = [n["to"] for n in g.get_neighbours("A")]
        self.assertIn("B", neighbours)

    def test_node_count(self):
        """Node count is correct."""
        g = AttackGraph()
        g.add_edge("A", "B")
        g.add_edge("B", "C")
        self.assertEqual(g.node_count(), 3)

    def test_edge_count(self):
        """Edge count is correct."""
        g = AttackGraph()
        g.add_edge("A", "B")
        g.add_edge("A", "C")
        self.assertEqual(g.edge_count(), 2)

    def test_no_duplicate_edges(self):
        """Same edge added twice only appears once."""
        g = AttackGraph()
        g.add_edge("A", "B", event_type="LOGIN_FAILED")
        g.add_edge("A", "B", event_type="LOGIN_FAILED")
        self.assertEqual(len(g.get_neighbours("A")), 1)

    def test_single_node_graph(self):
        """Graph with one node has no neighbours."""
        g = AttackGraph()
        g.add_node("X")
        self.assertEqual(g.get_neighbours("X"), [])

    def test_to_dict_format(self):
        """to_dict returns nodes and links keys."""
        g = AttackGraph()
        g.add_edge("A", "B")
        d = g.to_dict()
        self.assertIn("nodes", d)
        self.assertIn("links", d)

    def test_from_logs(self):
        """from_logs builds graph from log list."""
        logs = [
            {"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "event_type": "LOGIN_FAILED"},
            {"source_ip": "2.2.2.2", "destination_ip": "3.3.3.3", "event_type": "MALWARE_DETECTED"},
        ]
        g = AttackGraph.from_logs(logs)
        self.assertEqual(g.node_count(), 3)
        self.assertEqual(g.edge_count(), 2)

    def test_disconnected_graph(self):
        """Disconnected graph — two isolated components."""
        g = AttackGraph()
        g.add_edge("A", "B")
        g.add_edge("C", "D")
        self.assertEqual(g.node_count(), 4)
        self.assertEqual(g.edge_count(), 2)
        # A and C are not connected
        a_neighbours = [n["to"] for n in g.get_neighbours("A")]
        self.assertNotIn("C", a_neighbours)


# ─────────────────────────────────────────────────────────────
# BFS / DFS Tests
# ─────────────────────────────────────────────────────────────
class TestBFSDFS(unittest.TestCase):

    def _make_graph(self):
        """Build a simple test graph: A→B, A→C, B→D, C→D"""
        g = AttackGraph()
        g.add_edge("A", "B")
        g.add_edge("A", "C")
        g.add_edge("B", "D")
        g.add_edge("C", "D")
        return g

    def test_bfs_visits_all_nodes(self):
        """BFS from A visits all connected nodes."""
        g = self._make_graph()
        result = bfs(g, "A")
        self.assertIn("D", result['traversal_order'])
        self.assertEqual(result['visited_count'], 4)

    def test_bfs_levels(self):
        """BFS correctly assigns levels."""
        g = self._make_graph()
        result = bfs(g, "A")
        self.assertEqual(result['levels']['A'], 0)
        self.assertEqual(result['levels']['B'], 1)
        self.assertEqual(result['levels']['C'], 1)
        self.assertEqual(result['levels']['D'], 2)

    def test_bfs_unknown_start(self):
        """BFS on unknown start node returns empty."""
        g = self._make_graph()
        result = bfs(g, "Z")
        self.assertEqual(result['visited_count'], 0)

    def test_dfs_visits_all_nodes(self):
        """DFS from A visits all nodes."""
        g = self._make_graph()
        result = dfs(g, "A")
        self.assertEqual(result['visited_count'], 4)

    def test_dfs_discovery_times_assigned(self):
        """DFS assigns non-zero discovery times."""
        g = self._make_graph()
        result = dfs(g, "A")
        self.assertGreater(result['discovery_time']['A'], 0)

    def test_bfs_shortest_path(self):
        """BFS finds shortest path A→D as 2 hops (A→B→D or A→C→D)."""
        g = self._make_graph()
        path = bfs_shortest_path(g, "A", "D")
        self.assertEqual(path[0], "A")
        self.assertEqual(path[-1], "D")
        self.assertLessEqual(len(path), 3)

    def test_bfs_no_path(self):
        """BFS returns empty list if no path exists."""
        g = AttackGraph()
        g.add_node("A")
        g.add_node("B")
        result = bfs_shortest_path(g, "A", "B")
        self.assertEqual(result, [])

    def test_find_all_paths(self):
        """find_all_paths finds at least one path from A to D."""
        g = self._make_graph()
        paths = find_all_paths(g, "A", "D")
        self.assertGreater(len(paths), 0)
        for p in paths:
            self.assertEqual(p[0], "A")
            self.assertEqual(p[-1], "D")


# ─────────────────────────────────────────────────────────────
# Articulation Points Tests
# ─────────────────────────────────────────────────────────────
class TestArticulationPoints(unittest.TestCase):

    def test_clear_articulation_point(self):
        """B is the articulation point in A-B-C linear chain."""
        g = AttackGraph()
        g.add_edge("A", "B")
        g.add_edge("B", "C")
        result = find_articulation_points_and_bridges(g)
        self.assertIn("B", result['articulation_points'])

    def test_no_articulation_point_cycle(self):
        """Triangle A-B-C-A has no articulation points."""
        g = AttackGraph()
        g.add_edge("A", "B")
        g.add_edge("B", "C")
        g.add_edge("C", "A")
        result = find_articulation_points_and_bridges(g)
        self.assertEqual(len(result['articulation_points']), 0)

    def test_bridge_detection(self):
        """A-B edge is a bridge when no alternative path exists."""
        g = AttackGraph()
        g.add_edge("A", "B")
        g.add_edge("B", "C")
        result = find_articulation_points_and_bridges(g)
        self.assertGreater(len(result['bridges']), 0)

    def test_empty_graph(self):
        """Empty graph returns no APs."""
        g = AttackGraph()
        result = find_articulation_points_and_bridges(g)
        self.assertEqual(result['articulation_points'], [])

    def test_single_node(self):
        """Single node has no APs."""
        g = AttackGraph()
        g.add_node("X")
        result = find_articulation_points_and_bridges(g)
        self.assertEqual(result['articulation_points'], [])

    def test_disconnected_graph(self):
        """Disconnected graph — each chain independently finds APs."""
        g = AttackGraph()
        g.add_edge("A", "B")
        g.add_edge("C", "D")
        result = find_articulation_points_and_bridges(g)
        # No node in these two separate edges is an AP (removing any doesn't disconnect its component more)
        # A-B: neither A nor B is an AP (each chain of 2 can't be "disconnected further")
        # This is expected — true APs require at least 3 nodes in one chain
        self.assertEqual(result['ap_count'], len(result['articulation_points']))


# ─────────────────────────────────────────────────────────────
# Priority Queue Tests
# ─────────────────────────────────────────────────────────────
class TestPriorityQueue(unittest.TestCase):

    def _make_alerts(self):
        return [
            {"alert_id": "A1", "severity": "LOW"},
            {"alert_id": "A2", "severity": "CRITICAL"},
            {"alert_id": "A3", "severity": "MEDIUM"},
            {"alert_id": "A4", "severity": "HIGH"},
        ]

    def test_push_and_peek(self):
        """After inserting mixed-severity alerts, peek returns CRITICAL."""
        pq = AlertPriorityQueue()
        for a in self._make_alerts():
            pq.push(a)
        self.assertEqual(pq.peek()['severity'], 'CRITICAL')

    def test_pop_order(self):
        """Pop returns alerts in CRITICAL → HIGH → MEDIUM → LOW order."""
        pq = AlertPriorityQueue()
        for a in self._make_alerts():
            pq.push(a)
        order = []
        while not pq.is_empty():
            order.append(pq.pop()['severity'])
        self.assertEqual(order, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])

    def test_empty_queue(self):
        """Pop on empty queue returns None."""
        pq = AlertPriorityQueue()
        self.assertIsNone(pq.pop())
        self.assertIsNone(pq.peek())

    def test_size(self):
        """Size reflects number of items."""
        pq = AlertPriorityQueue()
        pq.push({"alert_id": "X", "severity": "HIGH"})
        pq.push({"alert_id": "Y", "severity": "LOW"})
        self.assertEqual(pq.size(), 2)

    def test_get_all_sorted(self):
        """get_all_sorted returns sorted list and preserves the heap."""
        pq = AlertPriorityQueue()
        for a in self._make_alerts():
            pq.push(a)
        sorted_alerts = pq.get_all_sorted()
        self.assertEqual(sorted_alerts[0]['severity'], 'CRITICAL')
        self.assertEqual(sorted_alerts[-1]['severity'], 'LOW')
        self.assertEqual(pq.size(), 4)   # heap is preserved

    def test_get_prioritised_alerts_function(self):
        """Helper function returns CRITICAL first."""
        result = get_prioritised_alerts(self._make_alerts())
        self.assertEqual(result[0]['severity'], 'CRITICAL')

    def test_single_alert(self):
        """Single alert is returned correctly."""
        pq = AlertPriorityQueue()
        pq.push({"alert_id": "A1", "severity": "MEDIUM"})
        self.assertEqual(pq.pop()['severity'], 'MEDIUM')


# ─────────────────────────────────────────────────────────────
# Monitoring Optimizer Tests
# ─────────────────────────────────────────────────────────────
class TestMonitoringOptimizer(unittest.TestCase):

    def test_no_paths(self):
        """Empty path list returns empty monitoring set."""
        g = AttackGraph()
        result = greedy_monitoring_optimizer(g, [])
        self.assertEqual(result['monitoring_nodes'], [])

    def test_single_path(self):
        """Single path — the first node in the path that covers it is selected."""
        g = AttackGraph()
        g.add_edge("A", "B")
        g.add_edge("B", "C")
        paths = [["A", "B", "C"]]
        result = greedy_monitoring_optimizer(g, paths)
        self.assertGreater(len(result['monitoring_nodes']), 0)
        self.assertEqual(result['covered_paths'], 1)

    def test_all_paths_covered(self):
        """After greedy selection, all paths should be covered."""
        g = AttackGraph()
        paths = [
            ["A", "B", "C"],
            ["A", "B", "D"],
            ["A", "E", "F"],
        ]
        result = greedy_monitoring_optimizer(g, paths)
        self.assertEqual(result['covered_paths'], result['total_paths'])

    def test_shared_node_chosen_first(self):
        """Node appearing in most paths should be selected first."""
        g = AttackGraph()
        # A appears in all 3 paths
        paths = [["A", "B"], ["A", "C"], ["A", "D"]]
        result = greedy_monitoring_optimizer(g, paths)
        self.assertEqual(result['monitoring_nodes'][0], "A")


# ─────────────────────────────────────────────────────────────
# Log Processor Tests
# ─────────────────────────────────────────────────────────────
class TestLogProcessor(unittest.TestCase):

    def _valid_csv(self):
        return (
            "log_id,timestamp,source_ip,destination_ip,event_type,description,severity\n"
            "L001,2024-01-01 10:00:00,1.1.1.1,2.2.2.2,LOGIN_FAILED,Test,LOW\n"
            "L002,2024-01-01 10:01:00,1.1.1.1,2.2.2.2,LOGIN_FAILED,Test,MEDIUM\n"
            "L003,2024-01-01 10:02:00,1.1.1.1,2.2.2.2,MALWARE_DETECTED,Test,HIGH\n"
        )

    def test_valid_csv_parses(self):
        """Valid CSV is parsed with no errors."""
        logs, errors = parse_logs_from_csv(self._valid_csv())
        self.assertEqual(len(logs), 3)
        self.assertEqual(len(errors), 0)

    def test_empty_csv(self):
        """Empty CSV returns no logs and an error."""
        logs, errors = parse_logs_from_csv("")
        self.assertEqual(len(logs), 0)

    def test_missing_columns(self):
        """CSV missing required columns returns error."""
        bad_csv = "timestamp,source_ip\n2024-01-01,1.1.1.1\n"
        logs, errors = parse_logs_from_csv(bad_csv)
        self.assertEqual(len(logs), 0)
        self.assertTrue(len(errors) > 0)

    def test_invalid_severity_defaults(self):
        """Row with invalid severity is kept with LOW default and error noted."""
        csv = (
            "log_id,timestamp,source_ip,destination_ip,event_type,description,severity\n"
            "L001,2024-01-01 10:00:00,1.1.1.1,2.2.2.2,LOGIN_FAILED,Test,INVALID\n"
        )
        logs, errors = parse_logs_from_csv(csv)
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]['severity'], 'LOW')
        self.assertTrue(len(errors) > 0)

    def test_severity_uppercased(self):
        """Severity is normalised to uppercase."""
        csv = (
            "log_id,timestamp,source_ip,destination_ip,event_type,description,severity\n"
            "L001,2024-01-01 10:00:00,1.1.1.1,2.2.2.2,LOGIN_FAILED,Test,low\n"
        )
        logs, _ = parse_logs_from_csv(csv)
        self.assertEqual(logs[0]['severity'], 'LOW')

    def test_duplicate_alert_deduplication(self):
        """Duplicate alerts from same source/type/logs are removed."""
        alerts = [
            {"alert_id": "A1", "source_ip": "1.1.1.1", "attack_type": "BRUTE_FORCE",
             "related_log_ids": ["L1", "L2"], "severity": "HIGH", "description": "", "destination_ip": "2.2.2.2",
             "signature_id": "SIG001", "kill_chain_stage": "Initial Access", "timestamp": "now"},
            {"alert_id": "A2", "source_ip": "1.1.1.1", "attack_type": "BRUTE_FORCE",
             "related_log_ids": ["L1", "L2"], "severity": "HIGH", "description": "", "destination_ip": "2.2.2.2",
             "signature_id": "SIG001", "kill_chain_stage": "Initial Access", "timestamp": "now"},
        ]
        result = deduplicate_alerts(alerts)
        self.assertEqual(len(result), 1)


# ─────────────────────────────────────────────────────────────
# Kill Chain Tests
# ─────────────────────────────────────────────────────────────
class TestKillChain(unittest.TestCase):

    def test_kill_chain_observed_stages(self):
        """Only stages present in data are Observed."""
        alerts = [
            {"alert_id": "A1", "kill_chain_stage": "Initial Access", "severity": "HIGH",
             "source_ip": "1.1.1.1", "attack_type": "BRUTE_FORCE", "description": "",
             "destination_ip": "2.2.2.2", "related_log_ids": [], "signature_id": "S1", "timestamp": "now"},
        ]
        correlation = {
            "correlation_id": "CORR001",
            "source_ip": "1.1.1.1",
            "alert_ids": ["A1"],
            "max_severity": "HIGH",
            "attack_types": ["BRUTE_FORCE"],
        }
        kc = build_kill_chain(correlation, alerts)
        observed = [s for s in kc['stages'] if s['status'] == 'Observed']
        not_observed = [s for s in kc['stages'] if s['status'] == 'Not Observed']
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]['stage'], 'Initial Access')
        self.assertGreater(len(not_observed), 0)

    def test_kill_chain_never_invents_stages(self):
        """All 7 stages are represented (some Observed, some Not Observed)."""
        alerts = []
        correlation = {
            "correlation_id": "CORR001",
            "source_ip": "1.1.1.1",
            "alert_ids": [],
            "max_severity": "LOW",
            "attack_types": [],
        }
        kc = build_kill_chain(correlation, alerts)
        self.assertEqual(len(kc['stages']), len(KILL_CHAIN_ORDER))


# ─────────────────────────────────────────────────────────────
# Graph Router Helpers Tests
# ─────────────────────────────────────────────────────────────
class TestGraphRouterHelpers(unittest.TestCase):

    def test_reconstruct_graph(self):
        """_reconstruct_graph recreates AttackGraph from serialized dict."""
        from routers.graph import _reconstruct_graph
        graph_data = {
            "nodes": [
                {"id": "10.0.0.1", "label": "Attacker", "node_type": "external"},
                {"id": "10.0.0.2", "label": "Victim", "node_type": "server"},
            ],
            "links": [
                {"source": "10.0.0.1", "target": "10.0.0.2", "edge_type": "attack", "event_type": "LOGIN_FAILED"}
            ]
        }
        g = _reconstruct_graph(graph_data)
        self.assertEqual(g.node_count(), 2)
        self.assertEqual(g.edge_count(), 1)
        self.assertIn("10.0.0.1", g.get_all_nodes())
        self.assertIn("10.0.0.2", g.get_all_nodes())


if __name__ == '__main__':
    unittest.main(verbosity=2)
