"""
detector.py — Autonomous SOC Detection Engine
FortiSec Operations | Threat Detection Module

Capabilities:
    - Log parsing (Flask access logs + custom application logs)
    - Behavioral detection: brute force, IDOR, XSS, privilege escalation
    - C2 beaconing analysis via interval consistency scoring
    - Severity-ranked reporting with color-coded terminal output

Author  : Solomon James
Version : 2.0.0
"""

import re
import statistics
from collections import defaultdict
from datetime import datetime


# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

LOG_FILE               = "app.log"   # Path to the application log file
BRUTE_FORCE_THRESHOLD  = 5           # Minimum logins to trigger brute force alert
C2_MIN_CONNECTIONS     = 5           # Minimum connections required to evaluate beaconing
C2_JITTER_TOLERANCE    = 0.3         # Max allowed jitter ratio to classify as beaconing
C2_HIGH_CONFIDENCE     = 0.85        # Confidence threshold to escalate from HIGH → CRITICAL


# ─────────────────────────────────────────────
# COMPILED REGEX PATTERNS
# ─────────────────────────────────────────────

# Matches Flask access log lines: timestamp - IP - - [...] "METHOD /path HTTP" status
FLASK_ACCESS = re.compile(
    r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)'
    r' - (\d+\.\d+\.\d+\.\d+)'
    r' - - \[.*?\] "(.*?)" (\d+)'
)

# Matches custom app log lines: timestamp - message body
CUSTOM_LOG = re.compile(
    r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+) - (.+)'
)

# Matches an IP address embedded at the start of a log message body
IP_INLINE = re.compile(r'(\d+\.\d+\.\d+\.\d+) - (.+)')


# ─────────────────────────────────────────────
# LOG PARSER
# ─────────────────────────────────────────────

def parse_logs(path: str) -> list[dict]:
    """
    Parse a mixed-format log file into a structured list of events.

    Handles two log formats:
        Flask access:  timestamp - IP - - [...] "METHOD /path HTTP" status
        Custom app:    timestamp - [IP - ] message

    Args:
        path: Path to the log file.

    Returns:
        List of event dicts with keys: timestamp, ip, message, raw.
    """
    events = []

    try:
        with open(path) as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {path}")
        return events

    # Pass 1: build timestamp → IP lookup from Flask access log lines
    ts_to_ip: dict[str, str] = {}
    for line in lines:
        m = FLASK_ACCESS.match(line.strip())
        if m:
            ts_to_ip[m.group(1)] = m.group(2)

    # Pass 2: parse custom application log lines into structured events
    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Skip pure Flask access lines — already consumed in Pass 1
        if FLASK_ACCESS.match(line):
            continue

        m = CUSTOM_LOG.match(line)
        if not m:
            continue

        timestamp = m.group(1)
        body      = m.group(2)

        # Check if IP is embedded directly in the message body
        ip_in_body = IP_INLINE.match(body)
        if ip_in_body:
            ip      = ip_in_body.group(1)
            message = ip_in_body.group(2).strip()
        else:
            # Fall back to timestamp correlation from Flask access lines
            ip      = ts_to_ip.get(timestamp, "unknown")
            message = body.strip()

        events.append({
            "timestamp": timestamp,
            "ip":        ip,
            "message":   message,
            "raw":       line
        })

    return events


# ─────────────────────────────────────────────
# C2 BEACONING ANALYZER
# ─────────────────────────────────────────────

def detect_c2_beaconing(
    json_logs:        list[dict],
    min_connections:  int   = C2_MIN_CONNECTIONS,
    jitter_tolerance: float = C2_JITTER_TOLERANCE
) -> list[dict]:
    """
    Detect C2 beaconing behavior from connection logs using interval analysis.

    Detection logic (step by step):
        1. Group connections by (src_ip, dst_ip) pair
        2. Sort timestamps chronologically
        3. Compute inter-connection intervals (seconds between each connection)
        4. Measure timing variance via standard deviation
        5. Normalize: jitter_ratio = std_dev / avg_interval
           - Low ratio (~0) = machine-like regularity = suspicious
           - High ratio      = human/random traffic = benign
        6. Flag pairs where jitter_ratio < tolerance threshold
        7. Score confidence: consistency (60%) + connection frequency (40%)

    Args:
        json_logs:        List of connection dicts with src_ip, dst_ip, timestamp.
        min_connections:  Minimum connections before analysis is applied.
        jitter_tolerance: Max normalized std-dev to classify as beaconing.

    Returns:
        List of suspicious beaconing patterns with confidence scores.
    """

    # Step 1: Group connection timestamps by (src_ip, dst_ip) pair
    grouped: dict[tuple, list] = defaultdict(list)
    for log in json_logs:
        key = (log["src_ip"], log["dst_ip"])
        try:
            # Normalize "2026-05-01 04:33:03,071" → "2026-05-01 04:33:03.071"
            ts_str = log["timestamp"].replace(",", ".")
            ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            continue  # skip any malformed timestamps silently
        grouped[key].append(ts)

    suspicious = []

    for (src, dst), timestamps in grouped.items():

        # Skip pairs that don't have enough data points to analyze
        if len(timestamps) < min_connections:
            continue

        # Step 2: sort chronologically so intervals are meaningful
        timestamps.sort()

        # Step 3: calculate time gaps (seconds) between consecutive connections
        intervals = [
            (timestamps[i] - timestamps[i - 1]).total_seconds()
            for i in range(1, len(timestamps))
        ]

        # Need at least 3 intervals for a statistically meaningful variance check
        if len(intervals) < 3:
            continue

        avg_interval = sum(intervals) / len(intervals)   # mean period between beacons

        # Step 4: measure spread of intervals — low std_dev = highly regular = suspicious
        std_dev = statistics.stdev(intervals)

        # Step 5: normalize deviation relative to average (jitter ratio)
        # A jitter_ratio near 0 = very consistent timing = likely beaconing
        jitter_ratio = std_dev / avg_interval if avg_interval > 0 else 1.0

        # Step 6: flag if jitter is below the configured tolerance threshold
        if jitter_ratio < jitter_tolerance:

            # Step 7: score confidence
            # Consistency: closer to 0 jitter = higher score (weight 60%)
            consistency_score = max(0.0, 1.0 - jitter_ratio)

            # Frequency: more connections = more certain (weight 40%, capped at 1)
            frequency_score = min(1.0, len(intervals) / 10)

            confidence = round((consistency_score * 0.6) + (frequency_score * 0.4), 2)

            suspicious.append({
                "src_ip":       src,
                "dst_ip":       dst,
                "connections":  len(timestamps),
                "avg_interval": round(avg_interval, 2),  # seconds between beacons
                "jitter":       round(jitter_ratio, 2),  # normalized timing variance
                "confidence":   confidence               # 0.0 – 1.0 confidence score
            })

    return suspicious


# ─────────────────────────────────────────────
# THREAT DETECTION ENGINE
# ─────────────────────────────────────────────

def detect(events: list[dict]) -> list[dict]:
    """
    Run signature-based and behavioral detections across parsed log events.

    Detections:
        - API IDOR attempts
        - Privilege escalation via admin endpoint
        - Token usage observation
        - IDOR ID enumeration
        - XSS payload injection
        - Brute force login (threshold-based)
        - Admin panel access without authentication
        - C2 beaconing (interval consistency analysis) ← injected into findings

    Args:
        events: Parsed log events from parse_logs().

    Returns:
        Sorted list of finding dicts ready for print_report().
    """
    login_attempts: dict[str, list] = defaultdict(list)  # IP → list of login timestamps
    c2_logs:        list[dict]      = []                  # Raw beacon connection records
    findings:       list[dict]      = []                  # All detection hits

    # XSS indicator strings to match against message content
    XSS_PATTERNS = ["<script>", "javascript:", "onerror=", "onload=", "alert("]

    for ev in events:
        ts  = ev["timestamp"]
        ip  = ev["ip"]
        msg = ev["message"]

        # ── API IDOR: unauthorized access to another user's object ──
        if "API IDOR attempt" in msg:
            findings.append({
                "severity":  "HIGH",
                "type":      "API IDOR",
                "ip":        ip,
                "detail":    "Unauthorized API object access",
                "timestamp": ts
            })

        # ── Privilege escalation: admin endpoint reached via token abuse ──
        if "Admin endpoint accessed" in msg:
            findings.append({
                "severity":  "CRITICAL",
                "type":      "Privilege Escalation",
                "ip":        ip,
                "detail":    "Admin access via token abuse",
                "timestamp": ts
            })

        # ── Token usage: log API token observation for audit trail ──
        if "Token used" in msg:
            findings.append({
                "severity":  "INFO",
                "type":      "Token Usage",
                "ip":        ip,
                "detail":    "API token observed in request",
                "timestamp": ts
            })

        # ── IDOR: user accessing another resource by ID enumeration ──
        if "User accessed ID" in msg:
            id_match = re.search(r'User accessed ID: (\w+)', msg)
            user_id  = id_match.group(1) if id_match else "?"
            findings.append({
                "severity":  "INFO",
                "type":      "IDOR",
                "ip":        ip,
                "detail":    f"ID enumeration — accessed ID {user_id}",
                "timestamp": ts
            })

        # ── XSS: check for common client-side injection payloads ──
        if any(pattern in msg.lower() for pattern in XSS_PATTERNS):
            findings.append({
                "severity":  "HIGH",
                "type":      "XSS",
                "ip":        ip,
                "detail":    f"Possible XSS payload: {msg[:80]}",
                "timestamp": ts
            })

        # ── Brute force: collect login attempts per IP for threshold check ──
        if "Login attempt" in msg:
            login_attempts[ip].append(ts)

        # ── Admin panel: access reached without proper authentication ──
        if "Accessed admin panel" in msg:
            findings.append({
                "severity":  "MEDIUM",
                "type":      "Unauthorized Access",
                "ip":        ip,
                "detail":    "Admin panel accessed without authentication",
                "timestamp": ts
            })

        # ── C2 beaconing: collect outbound connection record for analysis ──
        if "Beaconing to" in msg:
            dst_match = re.search(r'Beaconing to (\d+\.\d+\.\d+\.\d+)', msg)
            dst_ip    = dst_match.group(1) if dst_match else "unknown"
            c2_logs.append({
                "src_ip":    ip,
                "dst_ip":    dst_ip,
                "timestamp": ts   # raw string — normalized inside detect_c2_beaconing
            })

    # ── Brute force: apply threshold after full event pass ──
    for ip, timestamps in login_attempts.items():
        if len(timestamps) >= BRUTE_FORCE_THRESHOLD:
            findings.append({
                "severity":  "CRITICAL",
                "type":      "Brute Force",
                "ip":        ip,
                "detail":    f"{len(timestamps)} login attempts detected",
                "timestamp": timestamps[-1]
            })

    # ── C2 beaconing: run interval analysis and INJECT results into findings ──
    # This was the missing step — without this, beacon analysis ran but never
    # surfaced in the report. Now results are added as proper alert findings.
    beacon_results = detect_c2_beaconing(c2_logs)
    for r in beacon_results:
        # Escalate to CRITICAL if confidence is high, otherwise HIGH
        severity = "CRITICAL" if r["confidence"] >= C2_HIGH_CONFIDENCE else "HIGH"
        findings.append({
            "severity":  severity,
            "type":      "C2 Beaconing",
            "ip":        r["src_ip"],
            "detail":    (
                f"Beaconing to {r['dst_ip']} | "
                f"connections: {r['connections']} | "
                f"avg interval: {r['avg_interval']}s | "
                f"jitter: {r['jitter']} | "
                f"confidence: {r['confidence']}"
            ),
            "timestamp": ""
        })

    return findings


# ─────────────────────────────────────────────
# REPORT PRINTER
# ─────────────────────────────────────────────

def print_report(findings: list[dict]) -> None:
    """
    Print a color-coded, severity-ranked terminal report of all findings.

    Severity order: CRITICAL → HIGH → MEDIUM → INFO
    """
    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}

    COLORS = {
        "CRITICAL": "\033[91m",  # red
        "HIGH":     "\033[93m",  # yellow
        "MEDIUM":   "\033[94m",  # blue
        "INFO":     "\033[92m",  # green
    }
    RESET = "\033[0m"

    # Sort findings by severity priority before printing
    findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))

    print("\n" + "═" * 60)
    print("  FORTISEC OPERATIONS — Detection Report")
    print("═" * 60)

    if not findings:
        print("\n  [✓] No threats detected.\n")
    else:
        print()
        for f in findings:
            sev   = f["severity"]
            color = COLORS.get(sev, "")
            tag   = f"[{sev}]".ljust(10)
            print(f"  {color}{tag}{RESET} {f['type']:<22} IP: {f['ip']:<18} {f['detail']}")

        print(f"\n  Total findings: {len(findings)}")

        print("\n  ─── Summary by Severity ───")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "INFO"]:
            count = sum(1 for f in findings if f["severity"] == sev)
            if count:
                print(f"    {COLORS[sev]}{sev}{RESET}: {count}")

    print("\n" + "═" * 60 + "\n")


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    # Step 1: Parse log file into structured events
    events = parse_logs(LOG_FILE)

    # Step 2: Run all detections (web, API, behavioral, C2)
    findings = detect(events)

    # Step 3: Print color-coded terminal report
    print_report(findings)
