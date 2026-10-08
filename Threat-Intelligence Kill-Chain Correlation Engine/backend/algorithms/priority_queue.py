# algorithms/priority_queue.py
#
# ─────────────────────────────────────────────────────────────
# DSA CONCEPT: Priority Queue (Max-Heap)
#
# USED FOR:
#   Prioritising alerts so CRITICAL alerts are processed first,
#   followed by HIGH, MEDIUM, then LOW.
#
# WHY A HEAP (not just sort)?
#   A simple sort is O(n log n) but is a one-time operation.
#   A priority queue (heap) supports efficient INCREMENTAL operations:
#     - Insert a new alert:       O(log n)
#     - Get highest priority:     O(1)
#     - Remove highest priority:  O(log n)
#   This is useful when alerts arrive continuously — we don't re-sort
#   everything each time a new alert comes in.
#
# IMPLEMENTATION:
#   We implement a MAX-HEAP manually (without using heapq directly as
#   a black box) to clearly show the DSA concept.
#   Python's heapq is a min-heap, so we negate the priority value
#   to simulate max-heap behaviour.
#
# HEAP PROPERTY (max-heap):
#   Every parent node has a priority ≥ its children.
#   The highest priority alert is always at the root (index 0).
#
# TIME COMPLEXITY:
#   Insert (push):    O(log n)  — bubble up
#   Get max (peek):   O(1)      — root is always max
#   Remove max (pop): O(log n)  — heapify down
#   Build from list:  O(n)      — heapify
# ─────────────────────────────────────────────────────────────

# Severity → numeric priority (higher = more urgent)
SEVERITY_PRIORITY = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
}


class AlertPriorityQueue:
    """
    A max-heap based priority queue for Alert objects.

    The heap stores tuples of (priority, counter, alert_dict).
    We negate priority to use Python's min-heap as a max-heap:
        Stored as (-priority, counter, alert)
    The counter breaks ties to preserve insertion order for
    alerts with equal priority.

    Internal heap array (0-indexed):
        Parent of index i:      (i - 1) // 2
        Left child of index i:  2 * i + 1
        Right child of index i: 2 * i + 2
    """

    def __init__(self):
        self._heap: list = []     # Internal array storage
        self._counter: int = 0   # Tie-breaker for equal priorities

    def push(self, alert: dict):
        """
        Insert an alert into the priority queue.
        Time complexity: O(log n)

        The alert's 'severity' field determines its priority.
        """
        priority = SEVERITY_PRIORITY.get(alert.get('severity', 'LOW'), 1)
        # Negate priority so Python's min-heap gives us max-heap behaviour
        entry = (-priority, self._counter, alert)
        self._counter += 1
        self._heap.append(entry)
        self._bubble_up(len(self._heap) - 1)

    def peek(self) -> dict | None:
        """
        Return the highest-priority alert without removing it.
        Time complexity: O(1)
        """
        if not self._heap:
            return None
        return self._heap[0][2]   # The alert dict is at index 2

    def pop(self) -> dict | None:
        """
        Remove and return the highest-priority alert.
        Time complexity: O(log n)
        """
        if not self._heap:
            return None
        if len(self._heap) == 1:
            return self._heap.pop()[2]

        # Swap root with last element, remove last, then heapify down
        root_alert = self._heap[0][2]
        self._heap[0] = self._heap.pop()   # Move last to root
        self._heapify_down(0)
        return root_alert

    def size(self) -> int:
        """Return number of alerts in the queue."""
        return len(self._heap)

    def is_empty(self) -> bool:
        return len(self._heap) == 0

    def get_all_sorted(self) -> list:
        """
        Return all alerts sorted from highest to lowest priority.
        Does NOT modify the heap.
        Time complexity: O(n log n)
        """
        # Make a copy of the heap and drain it
        saved_heap    = list(self._heap)
        saved_counter = self._counter
        result = []
        while not self.is_empty():
            result.append(self.pop())
        # Restore the heap
        self._heap    = saved_heap
        self._counter = saved_counter
        return result

    # ─────────────────────────────────────────────────────────
    # Internal heap operations
    # ─────────────────────────────────────────────────────────

    def _bubble_up(self, idx: int):
        """
        After insertion, bubble the new element up to restore heap property.
        Compare with parent; swap if new element has higher priority (lower value
        in our negated representation).
        """
        while idx > 0:
            parent = (idx - 1) // 2
            # Remember: we stored (-priority, ...) so smaller tuple = higher priority
            if self._heap[idx] < self._heap[parent]:
                self._heap[idx], self._heap[parent] = self._heap[parent], self._heap[idx]
                idx = parent
            else:
                break

    def _heapify_down(self, idx: int):
        """
        After removing the root, push the element at idx down to restore heap property.
        Swap with the smaller child (higher actual priority) until heap order is restored.
        """
        n = len(self._heap)
        while True:
            left  = 2 * idx + 1
            right = 2 * idx + 2
            smallest = idx  # "smallest" in negated = highest actual priority

            if left < n and self._heap[left] < self._heap[smallest]:
                smallest = left
            if right < n and self._heap[right] < self._heap[smallest]:
                smallest = right

            if smallest != idx:
                self._heap[idx], self._heap[smallest] = self._heap[smallest], self._heap[idx]
                idx = smallest
            else:
                break


def build_priority_queue_from_alerts(alerts: list) -> AlertPriorityQueue:
    """
    Build a priority queue from a list of alert dicts.
    Inserts all alerts in O(n log n) total.

    Args:
        alerts: list of alert dicts

    Returns:
        AlertPriorityQueue with all alerts inserted
    """
    pq = AlertPriorityQueue()
    for alert in alerts:
        pq.push(alert)
    return pq


def get_prioritised_alerts(alerts: list) -> list:
    """
    Return all alerts sorted by priority (CRITICAL first, LOW last).
    This is the function called by the FastAPI router.

    Args:
        alerts: list of alert dicts

    Returns:
        sorted list of alert dicts, highest priority first
    """
    pq = build_priority_queue_from_alerts(alerts)
    return pq.get_all_sorted()
