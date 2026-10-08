# algorithms/bfs_dfs.py
#
# ─────────────────────────────────────────────────────────────
# DSA CONCEPT: Graph Traversal — BFS and DFS
#
# BFS — Breadth-First Search
#   USED FOR: Exploring the attack graph level by level.
#             Finding shortest path between two nodes (fewest hops).
#   HOW:      Uses a QUEUE (FIFO). Visit all neighbours at the current
#             level before moving deeper.
#   EXAMPLE:
#     Start: Attacker IP
#     Level 0: Attacker IP
#     Level 1: Compromised Server
#     Level 2: Database
#     BFS finds the shortest route an attacker took.
#   TIME COMPLEXITY: O(V + E)
#
# DFS — Depth-First Search
#   USED FOR: Exploring all possible attack paths deeply.
#             Detecting cycles. Used as the basis for articulation points.
#   HOW:      Uses a STACK (LIFO) or recursion. Go as deep as possible
#             before backtracking.
#   EXAMPLE:
#     Start: Attacker IP → follow one path all the way to the end,
#     then backtrack and explore other branches.
#   TIME COMPLEXITY: O(V + E)
#
# V = number of vertices (nodes)
# E = number of edges
# ─────────────────────────────────────────────────────────────

from collections import deque
from algorithms.graph import AttackGraph


def bfs(graph: AttackGraph, start_node: str) -> dict:
    """
    Breadth-First Search on the AttackGraph.

    Explores the graph level by level starting from start_node.
    Uses a QUEUE (Python deque) for FIFO ordering.

    Args:
        graph:      the AttackGraph instance
        start_node: ID of the starting node

    Returns:
        dict with:
            - traversal_order: list of node IDs in the order visited
            - levels:          dict mapping node_id → level (distance from start)
            - parent:          dict mapping node_id → parent node_id
            - visited_count:   how many nodes were reached from start_node

    Example:
        If graph has: A→B, A→C, B→D
        bfs(graph, "A") → traversal_order = ["A", "B", "C", "D"]
                          levels = {"A": 0, "B": 1, "C": 1, "D": 2}
    """
    if start_node not in graph.adj_list:
        return {
            "traversal_order": [],
            "levels": {},
            "parent": {},
            "visited_count": 0
        }

    visited = set()           # Track visited nodes
    queue   = deque()         # BFS queue (FIFO)
    levels  = {}              # Distance from start
    parent  = {}              # Parent of each node in BFS tree
    traversal_order = []

    # Initialise
    queue.append(start_node)
    visited.add(start_node)
    levels[start_node] = 0
    parent[start_node] = None

    while queue:
        # Dequeue from the front — FIFO
        current = queue.popleft()
        traversal_order.append(current)

        # Visit all unvisited neighbours
        for neighbour in graph.get_neighbours(current):
            nid = neighbour["to"]
            if nid not in visited:
                visited.add(nid)
                queue.append(nid)            # Enqueue neighbour
                levels[nid] = levels[current] + 1
                parent[nid] = current

    return {
        "traversal_order": traversal_order,
        "levels":          levels,
        "parent":          parent,
        "visited_count":   len(traversal_order),
    }


def dfs(graph: AttackGraph, start_node: str) -> dict:
    """
    Depth-First Search on the AttackGraph.

    Explores as deep as possible along each branch before backtracking.
    Uses an explicit STACK (list) for LIFO ordering.

    Args:
        graph:      the AttackGraph instance
        start_node: ID of the starting node

    Returns:
        dict with:
            - traversal_order: list of node IDs in DFS order
            - discovery_time:  dict node_id → when it was first visited
            - finish_time:     dict node_id → when all its paths were explored
            - visited_count:   how many nodes were reached
    """
    if start_node not in graph.adj_list:
        return {
            "traversal_order": [],
            "discovery_time": {},
            "finish_time": {},
            "visited_count": 0
        }

    visited        = set()
    traversal_order = []
    discovery_time  = {}
    finish_time     = {}
    timer           = [0]   # mutable counter (list trick for nested scope)

    def dfs_recursive(node: str):
        """Inner recursive DFS function."""
        visited.add(node)
        timer[0] += 1
        discovery_time[node] = timer[0]
        traversal_order.append(node)

        # Visit all unvisited neighbours (go deep first)
        for neighbour in graph.get_neighbours(node):
            nid = neighbour["to"]
            if nid not in visited:
                dfs_recursive(nid)

        # All paths from this node explored
        timer[0] += 1
        finish_time[node] = timer[0]

    dfs_recursive(start_node)

    return {
        "traversal_order": traversal_order,
        "discovery_time":  discovery_time,
        "finish_time":     finish_time,
        "visited_count":   len(traversal_order),
    }


def find_all_paths(graph: AttackGraph, start: str, end: str,
                   max_depth: int = 10) -> list:
    """
    Find all simple paths from start to end using DFS.
    A "simple path" means no node is visited twice.

    Used to enumerate all possible attack routes between two nodes.

    Args:
        graph:     the AttackGraph instance
        start:     starting node ID
        end:       target node ID
        max_depth: safety limit to prevent extremely long paths

    Returns:
        list of paths, each path is a list of node IDs
        e.g. [["A", "B", "D"], ["A", "C", "D"]]
    """
    if start not in graph.adj_list or end not in graph.adj_list:
        return []

    all_paths = []

    def dfs_path(current: str, path: list, visited: set):
        if len(path) > max_depth:
            return
        if current == end:
            all_paths.append(list(path))
            return
        for neighbour in graph.get_neighbours(current):
            nid = neighbour["to"]
            if nid not in visited:
                path.append(nid)
                visited.add(nid)
                dfs_path(nid, path, visited)
                path.pop()
                visited.remove(nid)

    dfs_path(start, [start], {start})
    return all_paths


def bfs_shortest_path(graph: AttackGraph, start: str, end: str) -> list:
    """
    Find the shortest path (fewest hops) from start to end using BFS.

    BFS always finds the shortest path in an unweighted graph
    because it explores level by level.

    Args:
        graph: the AttackGraph instance
        start: starting node ID
        end:   target node ID

    Returns:
        list of node IDs forming the shortest path,
        or empty list if no path exists.
    """
    if start not in graph.adj_list or end not in graph.adj_list:
        return []
    if start == end:
        return [start]

    result = bfs(graph, start)
    parent = result["parent"]

    # Reconstruct path by walking parent pointers from end → start
    if end not in parent:
        return []   # No path found

    path = []
    current = end
    while current is not None:
        path.append(current)
        current = parent.get(current)

    path.reverse()
    return path
