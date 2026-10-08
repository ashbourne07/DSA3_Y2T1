# algorithms/articulation_points.py
#
# ─────────────────────────────────────────────────────────────
# DSA CONCEPT: Articulation Points (Cut Vertices)
#
# DEFINITION:
#   An articulation point is a node whose removal disconnects
#   the graph into two or more separate components.
#
# USED FOR:
#   Identifying "graphically critical nodes" — network hosts that,
#   if removed or isolated, would break connectivity in the attack path.
#   These are potential choke points for monitoring.
#
# IMPORTANT DISCLAIMER:
#   We call these "graphically critical nodes / potential choke points."
#   An articulation point in the mathematical graph sense does NOT
#   automatically mean it is the best security control in a real network.
#   This is a demonstration of the graph algorithm concept.
#
# HOW IT WORKS (Tarjan's algorithm using DFS):
#   During DFS, we track two values for each node:
#     disc[u]  = discovery time (when was u first visited)
#     low[u]   = lowest discovery time reachable from the subtree rooted at u
#                (including back edges)
#
#   A node u is an articulation point if either:
#     1. u is the root of the DFS tree AND has ≥ 2 children in DFS tree, OR
#     2. u is NOT the root AND has a child v where low[v] >= disc[u]
#        (meaning v cannot reach an ancestor of u through back edges)
#
# TIME COMPLEXITY: O(V + E) — single DFS pass
# SPACE COMPLEXITY: O(V) — for disc, low, parent, visited arrays
#
# ALSO INCLUDED: Bridge detection
#   A bridge is an edge whose removal disconnects the graph.
#   An edge (u, v) is a bridge if low[v] > disc[u].
# ─────────────────────────────────────────────────────────────

from algorithms.graph import AttackGraph


def find_articulation_points_and_bridges(graph: AttackGraph) -> dict:
    """
    Find all articulation points and bridges in the graph using Tarjan's algorithm.

    NOTE: This algorithm works on the UNDIRECTED version of the graph.
    We treat all directed edges as undirected for connectivity analysis,
    which is standard practice for finding cut vertices.

    Args:
        graph: the AttackGraph instance

    Returns:
        dict with:
            - articulation_points: list of node IDs that are cut vertices
            - bridges:             list of (u, v) edge pairs that are bridges
            - node_details:        dict with disc/low values for each node
    """
    nodes = graph.get_all_nodes()
    if not nodes:
        return {
            "articulation_points": [],
            "bridges": [],
            "node_details": {}
        }

    # Build an undirected adjacency set for this algorithm
    # (combine forward and backward edges)
    undirected: dict = {node: set() for node in nodes}
    for edge in graph.get_all_edges():
        undirected[edge["from"]].add(edge["to"])
        undirected[edge["to"]].add(edge["from"])

    # DFS state arrays
    visited     = {}    # node_id → bool
    disc        = {}    # node_id → discovery time
    low         = {}    # node_id → lowest reachable disc time
    parent      = {}    # node_id → parent in DFS tree
    timer       = [0]   # mutable counter

    ap_set      = set()   # articulation points found
    bridges     = []       # bridge edges found

    for node in nodes:
        visited[node] = False
        parent[node]  = None

    def dfs_ap(u: str):
        """
        Recursive DFS that fills disc[], low[], and finds APs/bridges.
        """
        # How many children this node has in the DFS tree
        children = 0

        visited[u] = True
        timer[0]  += 1
        disc[u]    = timer[0]
        low[u]     = timer[0]

        for v in undirected.get(u, []):
            if not visited[v]:
                children += 1
                parent[v] = u
                dfs_ap(v)

                # After exploring v's subtree, update low[u]
                low[u] = min(low[u], low[v])

                # ── Articulation Point Check ──────────────────
                # Case 1: u is root of DFS tree with ≥ 2 children
                if parent[u] is None and children > 1:
                    ap_set.add(u)

                # Case 2: u is not root AND low[v] >= disc[u]
                # (v cannot reach above u via a back edge)
                if parent[u] is not None and low[v] >= disc[u]:
                    ap_set.add(u)

                # ── Bridge Check ──────────────────────────────
                # Edge (u,v) is a bridge if low[v] > disc[u]
                # (v cannot reach u or any ancestor of u)
                if low[v] > disc[u]:
                    bridges.append({"from": u, "to": v})

            elif v != parent[u]:
                # Back edge — v is already visited and not the parent
                # Update low[u] to reflect reachability via back edge
                low[u] = min(low[u], disc[v])

    # Run DFS from each unvisited node (handles disconnected graphs)
    for node in nodes:
        if not visited[node]:
            dfs_ap(node)

    # Build node details for API response
    node_details = {
        node: {
            "discovery_time": disc.get(node, 0),
            "low_value":      low.get(node, 0),
            "is_articulation_point": node in ap_set,
        }
        for node in nodes
    }

    return {
        "articulation_points": list(ap_set),
        "bridges":             bridges,
        "node_details":        node_details,
        "ap_count":            len(ap_set),
        "bridge_count":        len(bridges),
    }
