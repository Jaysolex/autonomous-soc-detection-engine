# Autonomous SOC Detection Engine

## Overview

Autonomous DevSecOps-driven SOC detection engine simulating web, API, and C2 beaconing attacks with automated log analysis, behavioral detection, and MITRE ATT&CK-aligned alerting.

---

## 🧱 Architecture

![Architecture](screenshots/architecture.png)

The architecture represents a full detection pipeline from attack simulation to SIEM-style alerting.

---

## 🔄 Attack → Detection Pipeline

![Pipeline](screenshots/pipeline.png)

This pipeline shows how raw attack traffic is transformed into structured security alerts.

---

## ⚔️ Attack Simulation

![Attack](screenshots/attack-simulation.png)

Simulated attacks from Kali Linux:

* Brute force
* XSS
* IDOR
* API abuse
* Token manipulation

---

## 📜 Log Generation & Evidence

![Logs](screenshots/logs.png)

Application logs capture:

* Source IP
* Request behavior
* Payloads
* Authentication attempts

---

## 🚨 Detection Output (SIEM Simulation)

![Detection](screenshots/detection-output.png)

Structured alert output with severity classification:

* CRITICAL
* HIGH
* INFO

---

## 📊 Detection Summary (Analyst View)

![SIEM](screenshots/siem-output.png)

Aggregated findings similar to SIEM dashboards.

---

## 🧠 Detection Capabilities

* Brute force detection (threshold-based)
* XSS payload detection
* IDOR enumeration tracking
* API authorization abuse detection
* Privilege escalation detection
* Token misuse monitoring
* C2 beaconing detection (interval-based pattern recognition)

---

## 🧬 MITRE ATT&CK Mapping

| Technique                         | ID     |
| --------------------------------- | ------ |
| Brute Force                       | T1110  |
| Exploitation of Public-Facing App | T1190  |
| Command and Control (Beaconing)   | T1071  |
| Valid Accounts Abuse              | T1078  |
| Privilege Escalation              | TA0004 |

---

## 💼 Skills Demonstrated

* SOC Alert Triage (L1)
* Threat Investigation (L2 mindset)
* Detection Engineering
* Log Correlation
* Behavioral Analysis
* DevSecOps Automation

---

## ⚙️ Tools & Technologies

* Python (Flask)
* Linux (Ubuntu / Kali)
* Custom Detection Engine
* SIEM Simulation
* curl / API testing

---

## 👤 Author

Solomon James
SOC Analyst | Detection Engineering | DevSecOps
