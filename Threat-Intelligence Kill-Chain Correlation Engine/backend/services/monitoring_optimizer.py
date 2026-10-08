# services/monitoring_optimizer.py
#
# ─────────────────────────────────────────────────────────────
# DSA CONCEPT: Greedy Algorithm (Set Cover approximation)
#
# USED FOR:
#   Recommending a minimum set of network nodes to monitor so that
#   all known attack paths are covered.
#
# THE PROBLEM:
#   Given a set of attack paths and a set of network nodes,
#   which nodes should we monitor so that every attack path
#   passes through at least one monitored node?
#   This is a variant of the "Set Cover" problem.
#
# WHY GREEDY?
#   The optimal Set Cover is NP-hard (no known polynomial-time solution).
#   The greedy approximation works like this:
#     1. Find which node covers the most uncovered paths.
#     2. Add that node to the monitoring set.
#     3. Mark those paths as covered.
#     4. Repeat until all paths are covered.
#
# IMPORTANT:
#   This greedy approach does NOT always guarantee the mathematically
#   optimal (minimum) set. It is a well-known approximation algorithm
#   with a ln(n) approximation ratio. We clearly state this limitation.
#
# TIME COMPLEXITY: O(P * N) per iteration, at most N iterations
#   P = number of attack paths
#   N = number of nodes
#   Total: O(P * N²) in the worst case
# ─────────────────────────────────────────────────────────────

from algorithms.bfs_dfs import find_all_paths
from algorithms.graph import AttackGraph


def get_attack_paths(graph: AttackGraph, alerts: list) -> list:
    """
    Extract attack paths from the graph using the source/destination IPs
    found in alerts.

    For each alert, we find all paths from source_ip to destination_ip
    using DFS (find_all_paths). This gives us the actual paths an attacker
    could have taken.

    Args:
        graph:  the AttackGraph
        alerts: list of alert dicts (each has source_ip and destination_ip)

    Returns:
        list of paths, each path is a list of node IDs
        e.g. [["192.168.1.10", "192.168.1.50", "192.168.1.100"], ...]
    """
    attack_paths = []
    seen_pairs = set()

    for alert in alerts:
        src = alert.get('source_ip', '')
        dst = alert.get('destination_ip', '')

        if not src or not dst or src == dst:
            continue

        pair = (src, dst)
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)

        # Find all paths from src to dst using DFS
        paths = find_all_paths(graph, src, dst, max_depth=8)
        attack_paths.extend(paths)

    # Deduplicate identical paths
    unique_paths = []
    seen_paths = set()
    for p in attack_paths:
        key = tuple(p)
        if key not in seen_paths:
            seen_paths.add(key)
            unique_paths.append(p)

    return unique_paths


def greedy_monitoring_optimizer(graph: AttackGraph, attack_paths: list) -> dict:
    """
    Greedy Set Cover: select monitoring nodes to cover all attack paths.

    Algorithm:
        1. Build a mapping: node → set of path indices it covers
        2. Greedily pick the node that covers the most uncovered paths
        3. Add it to the monitoring set, mark covered paths
        4. Repeat until all paths are covered (or no more nodes help)

    Args:
        graph:        the AttackGraph
        attack_paths: list of paths (each path = list of node IDs)

    Returns:
        dict with:
            - monitoring_nodes:    list of selected node IDs to monitor
            - coverage_steps:      step-by-step explanation of the greedy choices
            - total_paths:         total attack paths identified
            - covered_paths:       how many paths are covered by recommendation
            - all_nodes_considered: how many candidate nodes were evaluated
            - note:                disclaimer about greedy approximation
    """
    if not attack_paths:
        return {
            "monitoring_nodes":       [],
            "coverage_steps":         [],
            "total_paths":            0,
            "covered_paths":          0,
            "all_nodes_considered":   0,
            "note": "No attack paths found. Nothing to optimise."
        }

    total_paths = len(attack_paths)

    # Step 1: Build a mapping node → which path indices it appears in
    # Key:   node ID
    # Value: set of path indices this node is part of
    node_to_paths: dict = {}
    for path_idx, path in enumerate(attack_paths):
        for node in path:
            if node not in node_to_paths:
                node_to_paths[node] = set()
            node_to_paths[node].add(path_idx)

    # Greedy loop
    monitoring_nodes = []
    coverage_steps   = []
    covered_paths    = set()    # indices of paths already covered

    step = 1
    while len(covered_paths) < total_paths:
        # Find the node that covers the most currently UNCOVERED paths
        best_node   = None
        best_count  = 0
        best_new    = set()

        for node, path_indices in node_to_paths.items():
            if node in monitoring_nodes:
                continue  # already selected

            # How many new (uncovered) paths does this node cover?
            new_coverage = path_indices - covered_paths
            if len(new_coverage) > best_count:
                best_count = len(new_coverage)
                best_node  = node
                best_new   = new_coverage

        if best_node is None or best_count == 0:
            # No node can cover any more paths — stop
            break

        # Select this node
        monitoring_nodes.append(best_node)
        covered_paths.update(best_new)

        coverage_steps.append({
            "step":          step,
            "selected_node": best_node,
            "new_paths_covered": best_count,
            "total_covered": len(covered_paths),
            "paths_covered": [attack_paths[i] for i in sorted(best_new)],
        })
        step += 1

    return {
        "monitoring_nodes":       monitoring_nodes,
        "coverage_steps":         coverage_steps,
        "total_paths":            total_paths,
        "covered_paths":          len(covered_paths),
        "all_nodes_considered":   len(node_to_paths),
        "attack_paths":           attack_paths,
        "note": (
            "Greedy approximation: this is NOT guaranteed to be the "
            "mathematically optimal minimum set. It is a well-known "
            "approximation algorithm for the NP-hard Set Cover problem."
        )
    }


def run_monitoring_analysis(graph: AttackGraph, alerts: list) -> dict:
    """
    Full monitoring analysis pipeline:
      1. Extract attack paths from alerts
      2. Run greedy optimisation
      3. Return combined result

    This is the function called by the FastAPI router.
    """
    attack_paths = get_attack_paths(graph, alerts)
    result       = greedy_monitoring_optimizer(graph, attack_paths)
    return result
