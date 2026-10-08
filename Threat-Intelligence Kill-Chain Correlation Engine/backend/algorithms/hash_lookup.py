# algorithms/hash_lookup.py
#
# ─────────────────────────────────────────────────────────────
# DSA CONCEPT: Hashing
#
# USED FOR:
#   Fast lookup of attack signatures and event type categories.
#
# WHY HASHING?
#   Instead of scanning every signature in a list every time we
#   see an event type, we store signatures in a Python dict (hash map).
#   Python's dict uses a hash table internally.
#   When we ask "what attack type does LOGIN_FAILED belong to?",
#   Python computes hash(key) → finds the bucket → returns the value.
#   This is O(1) average case, regardless of how many signatures exist.
#
# TIME COMPLEXITY:
#   Average lookup:  O(1)
#   Worst case:      O(n)  — rare hash collisions, handled by Python
#   Build time:      O(n)  — one pass to load all signatures
#
# SPACE COMPLEXITY: O(n) — one entry per signature/event type
# ─────────────────────────────────────────────────────────────

import json
import os

# Path to the signatures file
_DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'attack_signatures.json')


class SignatureHashTable:
    """
    A hash-map based lookup table for attack signatures and event types.

    Two hash maps are built on initialisation:
      1. event_to_category  — maps event type string → category info
         e.g. "LOGIN_FAILED" → { "category": "Authentication", "base_severity": "LOW" }

      2. attack_type_to_sig  — maps attack type string → full signature dict
         e.g. "BRUTE_FORCE" → { id, name, pattern, severity, ... }

    Both lookups are O(1) average case.
    """

    def __init__(self):
        # Hash map 1: event type → category/severity info
        # Key:   event type string  (e.g. "LOGIN_FAILED")
        # Value: dict with category and base_severity
        self.event_to_category: dict = {}

        # Hash map 2: attack type → full signature record
        # Key:   attack type string  (e.g. "BRUTE_FORCE")
        # Value: full signature dict from attack_signatures.json
        self.attack_type_to_sig: dict = {}

        # Hash map 3: signature id → full signature record
        # Key:   signature id string  (e.g. "SIG001")
        # Value: full signature dict
        self.sig_id_to_sig: dict = {}

        # Load and build all maps at init time — O(n) one-time cost
        self._load()

    def _load(self):
        """
        Load attack_signatures.json and build all hash maps.
        This runs once at startup.
        """
        with open(_DATA_PATH, 'r') as f:
            data = json.load(f)

        # Build event_to_category map
        for event_type, info in data['event_type_lookup'].items():
            self.event_to_category[event_type] = info
            # Python dict uses hashing internally here

        # Build attack_type_to_sig and sig_id_to_sig maps
        for sig in data['signatures']:
            self.attack_type_to_sig[sig['attack_type']] = sig
            self.sig_id_to_sig[sig['id']] = sig

    def get_event_category(self, event_type: str) -> dict:
        """
        O(1) lookup: what category does this event type belong to?

        Example:
          get_event_category("LOGIN_FAILED")
          → { "category": "Authentication", "base_severity": "LOW" }

        Returns a default dict if event type is unknown.
        """
        return self.event_to_category.get(
            event_type,
            {"category": "Unknown", "base_severity": "LOW"}
        )

    def get_signature_by_attack_type(self, attack_type: str) -> dict | None:
        """
        O(1) lookup: get the full signature for a given attack type.

        Example:
          get_signature_by_attack_type("BRUTE_FORCE")
          → { id: "SIG001", name: "Brute Force Attack", pattern: [...], ... }
        """
        return self.attack_type_to_sig.get(attack_type, None)

    def get_signature_by_id(self, sig_id: str) -> dict | None:
        """
        O(1) lookup: get the full signature by its ID.

        Example:
          get_signature_by_id("SIG001")
          → { id: "SIG001", name: "Brute Force Attack", ... }
        """
        return self.sig_id_to_sig.get(sig_id, None)

    def is_suspicious_event(self, event_type: str) -> bool:
        """
        O(1) check: is this event type in a suspicious category?
        Normal events (NORMAL_LOGIN, NORMAL_TRAFFIC, FILE_ACCESS) return False.
        """
        info = self.get_event_category(event_type)
        return info.get('category', 'Unknown') not in ('Normal', 'Unknown')

    def get_all_signatures(self) -> list:
        """Return all loaded signatures as a list."""
        return list(self.attack_type_to_sig.values())


# ─────────────────────────────────────────────────────────────
# Module-level singleton — built once, reused everywhere.
# Services import this object instead of re-loading the file.
# ─────────────────────────────────────────────────────────────
signature_table = SignatureHashTable()
