import re
from collections import defaultdict

LOG_FILE = "app.log"
BRUTE_FORCE_THRESHOLD = 5

# Regex patterns
FLASK_ACCESS = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+) - (\d+\.\d+\.\d+\.\d+) - - \[.*?\] "(.*?)" (\d+)')
CUSTOM_LOG   = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+) - (.+)')
IP_INLINE    = re.compile(r'(\d+\.\d+\.\d+\.\d+) - (.+)')

def parse_logs(path):
    """
    Returns list of dicts with keys: timestamp, ip, message, raw
    Handles two formats:
      - Flask access:  timestamp - IP - - [..] "METHOD /path HTTP" status
      - Custom app:    timestamp - [IP - ] message
    """
    events = []
    try:
        with open(path) as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {path}")
        return events

    # First pass: build a timestamp -> IP map from Flask access lines
    ts_to_ip = {}
    for line in lines:
        m = FLASK_ACCESS.match(line.strip())
        if m:
            ts, ip = m.group(1), m.group(2)
            ts_to_ip[ts] = ip

    # Second pass: parse custom app log lines
    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Skip pure Flask access log lines (already used for IP mapping)
        if FLASK_ACCESS.match(line):
            continue

        m = CUSTOM_LOG.match(line)
        if not m:
            continue

        timestamp = m.group(1)
        body = m.group(2)

        # Check if IP is embedded in body (e.g. "192.168.x.x - Login attempt: admin")
        ip_in_body = IP_INLINE.match(body)
        if ip_in_body:
            ip = ip_in_body.group(1)
            message = ip_in_body.group(2).strip()
        else:
            # Fall back to Flask access log timestamp correlation
            ip = ts_to_ip.get(timestamp, "unknown")
            message = body.strip()

        events.append({
            "timestamp": timestamp,
            "ip": ip,
            "message": message,
            "raw": line
        })

    return events


def detect(events):
    login_attempts = defaultdict(list)
    findings = []

    for ev in events:
        ts  = ev["timestamp"]
        ip  = ev["ip"]
        msg = ev["message"]

        # --- API IDOR detection ---
        if "API IDOR attempt" in msg:
            findings.append({
                "severity": "HIGH",
                "type": "API IDOR",
                "ip": ip,
                "detail": "Unauthorized API object access",
                "timestamp": ts
            })

        # --- Privilege escalation (admin bypass) ---
        if "Admin endpoint accessed" in msg:
            findings.append({
                "severity": "CRITICAL",
                "type": "Privilege Escalation",
                "ip": ip,
                "detail": "Admin access via token abuse",
                "timestamp": ts
            })

        # --- Token usage visibility ---
        if "Token used" in msg:
            findings.append({
                "severity": "INFO",
                "type": "Token Usage",
                "ip": ip,
                "detail": "API token observed in request",
                "timestamp": ts
            })

        # --- IDOR detection ---
        if "User accessed ID" in msg:
            id_match = re.search(r'User accessed ID: (\w+)', msg)
            user_id = id_match.group(1) if id_match else "?"
            findings.append({
                "severity": "INFO",
                "type": "IDOR",
                "ip": ip,
                "detail": f"ID enumeration — accessed ID {user_id}",
                "timestamp": ts
            })

        # --- XSS detection ---
        xss_patterns = ["<script>", "javascript:", "onerror=", "onload=", "alert("]
        if any(p in msg.lower() for p in xss_patterns):
            findings.append({
                "severity": "HIGH",
                "type": "XSS",
                "ip": ip,
                "detail": f"Possible XSS payload: {msg[:80]}",
                "timestamp": ts
            })

        # --- Brute force tracking ---
        if "Login attempt" in msg:
            login_attempts[ip].append(ts)

        # --- Admin panel access ---
        if "Accessed admin panel" in msg:
            findings.append({
                "severity": "MEDIUM",
                "type": "Unauthorized Access",
                "ip": ip,
                "detail": "Admin panel accessed without authentication",
                "timestamp": ts
            })

    # --- Brute force detection (behavioral threshold) ---
    for ip, timestamps in login_attempts.items():
        count = len(timestamps)
        if count >= BRUTE_FORCE_THRESHOLD:
            findings.append({
                "severity": "CRITICAL",
                "type": "Brute Force",
                "ip": ip,
                "detail": f"{count} login attempts detected",
                "timestamp": timestamps[-1]
            })

    return findings


def print_report(findings):
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 9))

    colors = {
        "CRITICAL": "\033[91m",   # red
        "HIGH":     "\033[93m",   # yellow
        "MEDIUM":   "\033[94m",   # blue
        "INFO":     "\033[92m",   # green
    }
    reset = "\033[0m"

    print("\n=== Detection Results ===\n")

    if not findings:
        print("  No threats detected.")
        return

    for f in findings:
        sev   = f["severity"]
        color = colors.get(sev, "")
        tag   = f"[{sev}]".ljust(10)
        print(f"{color}{tag}{reset} {f['type']:<22} IP: {f['ip']:<18} {f['detail']}")

    print(f"\n  Total findings: {len(findings)}")

    # Summary by severity
    print("\n--- Summary ---")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "INFO"]:
        count = sum(1 for f in findings if f["severity"] == sev)
        if count:
            color = colors[sev]
            print(f"  {color}{sev}{reset}: {count}")


if __name__ == "__main__":
    events = parse_logs(LOG_FILE)
    findings = detect(events)
    print_report(findings)


