# algorithms/kmp.py
#
# ─────────────────────────────────────────────────────────────
# DSA CONCEPT: KMP (Knuth-Morris-Pratt) Pattern Matching
#
# USED FOR:
#   Detecting known attack patterns inside sequences of log events.
#
# WHY KMP?
#   Brute force pattern matching is O(n * m) in the worst case —
#   it re-checks characters it has already seen.
#   KMP avoids this by pre-computing a "failure function" (also called
#   the LPS — Longest Proper Prefix which is also a Suffix array).
#   When a mismatch occurs, KMP uses LPS to skip ahead without
#   re-scanning characters already matched.
#
# EXAMPLE:
#   Text    = ["LOGIN_FAILED", "LOGIN_FAILED", "LOGIN_FAILED", "LOGIN_SUCCESS"]
#   Pattern = ["LOGIN_FAILED", "LOGIN_FAILED", "LOGIN_FAILED"]
#   KMP finds the match at index 0 without unnecessary backtracking.
#
# TIME COMPLEXITY:
#   Build LPS:   O(m)   — m = length of pattern
#   Search:      O(n)   — n = length of text (log sequence)
#   Total:       O(n + m)
#
# SPACE COMPLEXITY: O(m) — for the LPS array
#
# WHY NOT RABIN-KARP HERE?
#   Rabin-Karp uses hash functions on substrings (good for string chars).
#   Our "text" is a list of event type strings, not individual characters.
#   KMP works cleanly on any comparable sequence — more appropriate here.
# ─────────────────────────────────────────────────────────────


def build_lps(pattern: list) -> list:
    """
    Build the LPS (Longest Proper Prefix which is also Suffix) array.

    This is the preprocessing step of KMP.

    For pattern = ["LOGIN_FAILED", "LOGIN_FAILED", "LOGIN_FAILED"]:
      lps = [0, 1, 2]
      Meaning: if a mismatch happens at index 2, we can jump back to index 2
               (re-use the first 2 matched elements).

    Args:
        pattern: list of event type strings (the attack signature pattern)

    Returns:
        lps: list of integers, same length as pattern
    """
    m = len(pattern)
    lps = [0] * m      # lps[0] is always 0

    length = 0          # length of previous longest prefix-suffix
    i = 1               # start from second element

    while i < m:
        if pattern[i] == pattern[length]:
            # Characters match — extend the prefix-suffix
            length += 1
            lps[i] = length
            i += 1
        else:
            if length != 0:
                # Fall back using the lps array (key KMP insight)
                # Don't increment i here — try shorter prefix
                length = lps[length - 1]
            else:
                # No prefix-suffix of length > 0
                lps[i] = 0
                i += 1

    return lps


def kmp_search(text: list, pattern: list) -> list:
    """
    Search for all occurrences of pattern inside text using KMP.

    Args:
        text:    list of event type strings from log sequence
                 e.g. ["LOGIN_FAILED", "LOGIN_FAILED", "LOGIN_FAILED", "MALWARE_DETECTED"]
        pattern: list of event type strings to search for
                 e.g. ["LOGIN_FAILED", "LOGIN_FAILED", "LOGIN_FAILED"]

    Returns:
        match_indices: list of starting indices where pattern was found in text
                       e.g. [0]  means the pattern starts at index 0

    Example:
        text    = ["A", "B", "A", "B", "C", "A", "B", "C"]
        pattern = ["A", "B", "C"]
        result  = [2, 5]  ← pattern found starting at index 2 and 5
    """
    n = len(text)
    m = len(pattern)

    # Edge cases
    if m == 0 or n == 0 or m > n:
        return []

    # Step 1: Build the LPS array — O(m)
    lps = build_lps(pattern)

    match_indices = []
    i = 0   # index for text
    j = 0   # index for pattern

    # Step 2: Slide the pattern over the text — O(n)
    while i < n:
        if text[i] == pattern[j]:
            # Current elements match — advance both pointers
            i += 1
            j += 1

        if j == m:
            # Full pattern matched! Record the starting index
            match_indices.append(i - j)
            # Use LPS to find next possible match (don't start from scratch)
            j = lps[j - 1]

        elif i < n and text[i] != pattern[j]:
            # Mismatch after some matches
            if j != 0:
                # Use LPS to skip — the key KMP optimisation
                j = lps[j - 1]
            else:
                # No partial match to fall back on
                i += 1

    return match_indices


def find_attack_patterns_in_logs(log_events: list, signatures: list) -> list:
    """
    Run KMP for each signature pattern against a sequence of log events.

    This is the main function called by the pattern matcher service.

    Args:
        log_events: list of dicts, each with at least 'event_type' and 'log_id'
                    e.g. [{"log_id": "L001", "event_type": "LOGIN_FAILED", ...}, ...]

        signatures: list of signature dicts from attack_signatures.json
                    e.g. [{"id": "SIG001", "pattern": ["LOGIN_FAILED", ...], ...}, ...]

    Returns:
        results: list of match dicts, one per signature that matched
                 Each dict contains:
                   - signature_id
                   - attack_type
                   - severity
                   - kill_chain_stage
                   - match_positions: list of starting positions in log_events
                   - matched_log_ids: list of log_id lists for each match
    """
    # Extract just the event types in order — this is our "text" for KMP
    event_types = [log['event_type'] for log in log_events]

    results = []

    for sig in signatures:
        pattern = sig['pattern']   # e.g. ["LOGIN_FAILED", "LOGIN_FAILED", "LOGIN_FAILED"]

        # Run KMP search — O(n + m)
        match_positions = kmp_search(event_types, pattern)

        if match_positions:
            # Collect which log IDs are involved in each match
            matched_log_ids = []
            for start_pos in match_positions:
                end_pos = start_pos + len(pattern)
                involved_logs = [
                    log_events[i]['log_id']
                    for i in range(start_pos, min(end_pos, len(log_events)))
                ]
                matched_log_ids.append(involved_logs)

            results.append({
                'signature_id':    sig['id'],
                'attack_type':     sig['attack_type'],
                'severity':        sig['severity'],
                'kill_chain_stage': sig['kill_chain_stage'],
                'description':     sig['description'],
                'pattern':         pattern,
                'match_positions': match_positions,
                'matched_log_ids': matched_log_ids,
            })

    return results
