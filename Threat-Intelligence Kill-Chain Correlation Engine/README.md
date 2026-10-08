# Threat-Intelligence Kill-Chain Correlation Engine

**DSA-3 College Project | Academic Prototype**

> ⚠ This is a simplified academic demonstration of Data Structures and Algorithms applied to cybersecurity concepts. It is NOT a real Security Operations Centre (SOC) tool, does not connect to real systems, and uses only fictional sample data.

---

## 1. Problem Statement

Security teams receive thousands of log events per day. The challenge is:
- How do you find attack patterns hidden in a flood of events?
- How do you connect related alerts into a coherent attack story?
- How do you identify which network nodes are most critical?
- How do you decide where to place the fewest monitoring sensors?

This project demonstrates how classical Data Structures and Algorithms solve each of these problems.

---

## 2. Objectives

- Parse and validate security logs from CSV
- Use **KMP pattern matching** to detect attack signatures in log sequences
- Use **hashing** for O(1) signature lookup
- Generate and **deduplicate** alerts
- **Correlate** related alerts into attack sequences
- Reconstruct the **kill chain** (attack stages) from correlated alerts
- Build an **attack graph** using adjacency list representation
- Traverse the graph using **BFS** and **DFS**
- Identify critical network nodes using **Tarjan's Articulation Point** algorithm
- Recommend monitoring locations using a **greedy set cover** approach
- Prioritise alerts using a **max-heap priority queue**
- Display everything on a **full-stack React dashboard**

---

## 3. Technology Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 18 + Vite + Tailwind CSS |
| Backend API | Python 3.14 + FastAPI |
| Database | MongoDB (via Motor async driver) |
| DSA Engine | Pure Python (no external libraries) |
| Testing | pytest |

---

## 4. Project Structure

```
threat-kill-chain-engine/
├── backend/
│   ├── main.py                        ← FastAPI app entry point
│   ├── config.py                      ← MongoDB settings
│   ├── database.py                    ← Motor async client
│   ├── requirements.txt
│   ├── data/
│   │   ├── sample_logs.csv            ← 30 fictional security logs
│   │   └── attack_signatures.json    ← 5 predefined attack patterns
│   ├── models/
│   │   ├── log_entry.py               ← LogEntry Pydantic model
│   │   └── alert.py                   ← Alert Pydantic model
│   ├── algorithms/                    ← Pure DSA (no DB calls)
│   │   ├── hash_lookup.py             ← Hash table for O(1) lookups
│   │   ├── kmp.py                     ← KMP pattern matching
│   │   ├── graph.py                   ← Adjacency list graph
│   │   ├── bfs_dfs.py                 ← BFS and DFS traversal
│   │   ├── articulation_points.py    ← Tarjan's choke point detection
│   │   └── priority_queue.py         ← Max-heap alert prioritisation
│   ├── services/                      ← Business logic + MongoDB
│   │   ├── log_processor.py           ← Parse CSV + run full pipeline
│   │   ├── alert_generator.py         ← Create alerts from KMP matches
│   │   ├── alert_correlator.py        ← Group alerts by source IP
│   │   ├── kill_chain_builder.py      ← Map alerts to kill chain stages
│   │   └── monitoring_optimizer.py   ← Greedy monitoring coverage
│   ├── routers/
│   │   ├── logs.py                    ← /api/logs endpoints
│   │   ├── alerts.py                  ← /api/alerts endpoints
│   │   ├── graph.py                   ← /api/graph endpoints
│   │   └── analysis.py               ← /api/analysis endpoints
│   └── tests/
│       └── test_all_dsa.py            ← 63 unit tests
└── frontend/
    └── src/
        ├── pages/
        │   ├── Dashboard.jsx
        │   ├── Logs.jsx
        │   ├── Alerts.jsx
        │   ├── AttackGraph.jsx
        │   ├── KillChain.jsx
        │   └── Monitoring.jsx
        └── components/
            ├── NavBar.jsx
            ├── StatCard.jsx
            └── AlertCard.jsx
```

---

## 5. Installation

### Prerequisites
- Python 3.14+
- Node.js 18+
- MongoDB running on localhost:27017

### Backend Setup
```bash
cd threat-kill-chain-engine/backend
python -m pip install -r requirements.txt
```

### Frontend Setup
```bash
cd threat-kill-chain-engine/frontend
npm install
```

---

## 6. How to Run

### Step 1 — Start MongoDB
Make sure MongoDB is running on localhost:27017.
(Open MongoDB Compass or run `mongod` in terminal)

### Step 2 — Start the Backend
```bash
cd threat-kill-chain-engine/backend
uvicorn main:app --reload
```
Backend runs at: http://localhost:8000
API docs at:     http://localhost:8000/docs

### Step 3 — Start the Frontend
```bash
cd threat-kill-chain-engine/frontend
npm run dev
```
Frontend runs at: http://localhost:5173

### Step 4 — Load Sample Data
Open the dashboard at http://localhost:5173 and click **"Load Sample Logs"**.
This runs the entire DSA pipeline and populates MongoDB.

---

## 7. DSA Concepts

### CONCEPT 1: Hashing
**File:** `algorithms/hash_lookup.py`
**Used for:** Fast lookup of attack signatures and event categories.
**Why:** A Python dict (hash table) stores event_type → category. When we see "LOGIN_FAILED", we look it up in O(1) instead of scanning all signatures.
**Complexity:** Average O(1) lookup, O(n) to build.
**Viva question:** *What is the worst case for hash lookup?* — O(n) due to hash collisions, but Python's dict handles this with open addressing.

---

### CONCEPT 2: KMP Pattern Matching
**File:** `algorithms/kmp.py`
**Used for:** Detecting known attack sequences in log event streams.
**Why:** Brute force is O(n×m). KMP preprocesses the pattern to build an LPS (Longest Proper Prefix-Suffix) array, then searches in O(n+m).
**How:**
1. `build_lps(pattern)` — builds the failure function in O(m)
2. `kmp_search(text, pattern)` — slides pattern over text in O(n)
**Complexity:** O(n+m), space O(m) for LPS array.
**Example:**
```
Text:    [LOGIN_FAILED, LOGIN_FAILED, LOGIN_FAILED, MALWARE_DETECTED]
Pattern: [LOGIN_FAILED, LOGIN_FAILED, LOGIN_FAILED]
Result:  Match found at index 0
```

---

### CONCEPT 3: Graph (Adjacency List)
**File:** `algorithms/graph.py`
**Used for:** Representing the network topology and attack movement.
**Why adjacency list (not matrix)?** The network is sparse — most host pairs have no direct connection. Adjacency list uses O(V+E) space vs O(V²) for a matrix.
**Structure:** Python dict where key=node_id, value={label, node_type, neighbours[]}

---

### CONCEPT 4: BFS — Breadth-First Search
**File:** `algorithms/bfs_dfs.py`
**Used for:** Exploring the attack graph level by level. Finding the shortest path (fewest hops) from attacker to target.
**How:** Uses a QUEUE (deque, FIFO). Visit all level-1 neighbours before level-2.
**Complexity:** O(V+E)
**Output:** traversal_order, levels, parent, shortest_path reconstruction.

---

### CONCEPT 5: DFS — Depth-First Search
**File:** `algorithms/bfs_dfs.py`
**Used for:** Deep exploration of attack paths. Finding all possible routes.
**How:** Uses recursion (implicit call stack, LIFO). Go deep before backtracking.
**Complexity:** O(V+E)
**Output:** traversal_order, discovery_time, finish_time.

---

### CONCEPT 6: Articulation Points
**File:** `algorithms/articulation_points.py`
**Used for:** Finding "graphically critical nodes" — nodes whose removal disconnects the graph.
**Algorithm:** Tarjan's DFS-based algorithm using discovery time (disc[]) and low value (low[]) arrays.
**Rule:**
- Root with ≥ 2 DFS children → articulation point
- Non-root u with child v where low[v] ≥ disc[u] → articulation point
**Complexity:** O(V+E)
**Important:** These are mathematical graph properties. They are labelled "potential choke points" for academic demonstration only.

---

### CONCEPT 7: Greedy Algorithm (Set Cover)
**File:** `services/monitoring_optimizer.py`
**Used for:** Recommending the minimum set of network nodes to monitor.
**How:** At each step, pick the node that covers the most uncovered attack paths. Repeat until all paths are covered.
**Important limitation:** This is a greedy approximation. The true optimal Set Cover is NP-hard. The greedy approach has a ln(n) approximation ratio — it is NOT guaranteed to find the minimum possible set.

---

### CONCEPT 8: Priority Queue (Max-Heap)
**File:** `algorithms/priority_queue.py`
**Used for:** Processing CRITICAL alerts before HIGH, then MEDIUM, then LOW.
**How:** Manual max-heap using a Python list. Negated priority used to simulate max-heap with Python's min-heap conventions.
- push: O(log n) — bubble_up
- peek: O(1) — root always has highest priority
- pop:  O(log n) — heapify_down

---

## 8. Time Complexity Summary

| Algorithm | Time Complexity | Space Complexity |
|-----------|----------------|-----------------|
| Hash Lookup (build) | O(n) | O(n) |
| Hash Lookup (query) | O(1) average | O(1) |
| KMP build LPS | O(m) | O(m) |
| KMP search | O(n) | O(1) |
| KMP total | O(n+m) | O(m) |
| Graph build | O(V+E) | O(V+E) |
| BFS | O(V+E) | O(V) |
| DFS | O(V+E) | O(V) |
| Articulation Points | O(V+E) | O(V) |
| Priority Queue push | O(log n) | O(1) |
| Priority Queue pop | O(log n) | O(1) |
| Priority Queue peek | O(1) | O(1) |
| Greedy Set Cover | O(P×N²) | O(P+N) |
| Alert Correlation | O(n) | O(n) |

where: n=logs, m=pattern length, V=vertices, E=edges, P=paths, N=nodes

---

## 9. Sample Input

**sample_logs.csv** contains 30 fictional log entries covering:
- Scenario 1: Brute force → malware → privilege escalation → data exfiltration (L001-L012)
- Scenario 2: Port scan → brute force attempt (L013-L018)
- Scenario 3: Unusual login → privilege escalation → database access (L019-L021)
- Scenario 4: Normal traffic (L022-L025, L030)
- Scenario 5: Ransomware propagation (L026-L029)

---

## 10. API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/logs/import-sample | Import built-in sample logs |
| POST | /api/logs/import | Upload your own CSV |
| GET | /api/logs/ | Get all logs |
| GET | /api/alerts/ | Get all alerts |
| GET | /api/alerts/priority | Alerts sorted by max-heap |
| GET | /api/graph/ | Graph + BFS/DFS + choke points |
| GET | /api/graph/choke-points | Articulation points only |
| GET | /api/analysis/kill-chains | Reconstructed kill chains |
| GET | /api/analysis/correlations | Correlated alert groups |
| GET | /api/analysis/monitoring | Greedy monitoring recommendation |
| GET | /api/analysis/dashboard | All stats in one request |

---

## 11. Testing

```bash
cd backend
python -m pytest tests/ -v
```

**63 tests, all passing.** Coverage:
- KMP: 13 tests (LPS array, search, edge cases, attack detection)
- Hash Lookup: 8 tests (known/unknown events, suspicious check, O(1) lookup)
- Graph: 9 tests (add nodes/edges, node count, duplicate prevention, from_logs)
- BFS/DFS: 8 tests (levels, shortest path, discovery times, unknown start)
- Articulation Points: 6 tests (clear AP, cycle, bridge, empty, single node)
- Priority Queue: 7 tests (push/pop order, peek, empty, size, sorted)
- Monitoring Optimizer: 4 tests (no paths, single path, full coverage, greedy choice)
- Log Processor: 6 tests (valid CSV, empty, missing columns, invalid severity, dedup)
- Kill Chain: 2 tests (Observed stages, never invents stages)

---

## 12. Limitations

This system is an academic prototype. It clearly:
- Works only with predefined/sample attack patterns (5 signatures)
- Does not detect unknown or novel attacks
- Uses simplified correlation (same source IP = same attack)
- Does not replace a real SOC or SIEM system
- Uses fictional sample data only — no real credentials or systems
- Greedy monitoring optimisation does not guarantee the optimal minimum set
- Articulation points are graph-theoretic properties, not automatic security recommendations

---

## 13. Future Scope

(Not implemented — potential future improvements only)
- Real-time log ingestion via WebSocket or Kafka
- Integration with SIEM systems (Splunk, ELK)
- Larger threat intelligence signature databases
- Machine learning for anomaly detection
- External threat intelligence feeds (MITRE ATT&CK)
- Network topology discovery (instead of manual classification)

---

## 14. Viva Questions and Answers

**Q: What is the time complexity of KMP?**
A: O(n+m) where n is the text length and m is the pattern length. The LPS preprocessing is O(m) and the search is O(n). Total O(n+m), which is better than brute force O(n×m).

**Q: Why did you use an adjacency list instead of an adjacency matrix?**
A: A network graph is sparse — most pairs of hosts are not directly connected. An adjacency list uses O(V+E) space, while a matrix uses O(V²). For a network with 100 nodes but only 50 connections, the list is much more efficient.

**Q: What is the difference between BFS and DFS? When would you use each?**
A: BFS uses a queue (FIFO) and explores level by level — it finds the shortest path (fewest hops). DFS uses a stack/recursion (LIFO) and goes deep before backtracking — it's better for finding all possible paths and is the basis for articulation point detection.

**Q: What is an articulation point?**
A: A node whose removal disconnects the graph into two or more separate components. We find them using Tarjan's DFS-based algorithm by tracking discovery time (disc[u]) and low value (low[u]). If low[v] ≥ disc[u] for a child v of node u (where u is not the DFS root), then u is an articulation point.

**Q: Why is the greedy monitoring optimisation not optimal?**
A: The monitoring problem is a variant of Set Cover, which is NP-hard — no known polynomial-time algorithm finds the guaranteed minimum set. The greedy approach has a well-known ln(n) approximation ratio, meaning it could use slightly more nodes than the true minimum. We clearly state this limitation.

**Q: How does the priority queue work internally?**
A: It uses a max-heap — a binary tree where every parent has a higher priority than its children. We store items as (-priority, counter, alert) in a Python list. push() appends and bubbles up — O(log n). pop() swaps root with last item, removes it, then heapifies down — O(log n). peek() just returns the root — O(1).

**Q: What is hashing and why is O(1) not always guaranteed?**
A: Hashing maps a key to a bucket index using a hash function. On average, lookup is O(1) because we jump directly to the bucket. In the worst case, all keys hash to the same bucket (collision), making lookup O(n). Python's dict uses a high-quality hash function that makes collisions very rare in practice.

**Q: Why is the kill chain reconstruction honest about missing stages?**
A: The project requirement says we must never fabricate data. If a log sequence shows only brute force and privilege escalation, the kill chain shows only those two stages as "Observed" and marks the rest as "Not Observed". This is technically honest — a real SOC analyst needs to know what evidence was actually found.

**Q: What is the LPS array in KMP?**
A: LPS stands for Longest Proper Prefix which is also a Suffix. For a pattern like ["A","B","A"], lps=[0,0,1] — the last element has value 1 because "A" is both a prefix and suffix of "ABA". During the search, if a mismatch occurs at position j, we don't restart from 0 — we jump back to lps[j-1], reusing the already-matched portion.

---

## 15. 2-Minute Project Explanation

"This project is called Threat Kill-Chain Correlation Engine. It's a full-stack DSA application that analyses fictional security logs to detect cyberattacks.

Here's what it does step by step:
1. We load security logs from a CSV file into MongoDB.
2. A hash table gives us O(1) lookup for what type of event each log represents.
3. KMP pattern matching — that's O(n+m) — scans the log sequence to find known attack patterns like brute force or malware chains.
4. When a pattern is found, we generate an alert. Duplicate alerts are removed using a hash set.
5. Alerts are grouped into attack sequences using correlation — alerts with the same source IP are grouped together.
6. We reconstruct the kill chain — the ordered attack stages — and only show stages that are actually supported by the data.
7. We build an attack graph as an adjacency list and traverse it with BFS and DFS.
8. Tarjan's algorithm finds articulation points — graphically critical nodes in the network.
9. A greedy algorithm recommends the minimum monitoring points to cover all attack paths — this is a Set Cover approximation.
10. Finally, a max-heap priority queue ensures CRITICAL alerts are processed first.
All of this is displayed on a React dashboard with MongoDB as the database."

---

## 16. Demo Script

1. Open http://localhost:5173
2. Click **"Load Sample Logs"** — watch the pipeline execute
3. Dashboard shows: 30 logs, alerts generated, correlations, kill chains
4. Navigate to **Logs** — show the raw log table, point out suspicious events
5. Navigate to **Alerts** — show the alerts, then click "Sort by Priority (Max-Heap)"
6. Navigate to **Attack Graph** — show the Adjacency List tab (the actual data structure)
7. Click **BFS Traversal** — show levels and shortest path
8. Click **DFS Traversal** — show discovery/finish times
9. Click **Choke Points** — show articulation points found by Tarjan's algorithm
10. Navigate to **Kill Chain** — show Observed vs Not Observed stages
11. Navigate to **Monitoring** — show greedy step-by-step selection and disclaimer
12. Point out: "Every result here was calculated by the actual algorithm — nothing is hardcoded."
