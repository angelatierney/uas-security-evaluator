# Lab Exercise: Detecting a Spoofed GPS Attack on UAS Telemetry

**Audience:** Junior cybersecurity / flight-systems engineers  
**Duration:** ~45–60 minutes  
**Objective:** Ingest a sample attack log, run the evaluator, interpret findings, and write remediation steps mapped to NIST SP 800-53.

---

## Prerequisites

- Python 3.10+  
- Project cloned locally (`uas-security-evaluator`)  
- Ability to run commands in a terminal

---

## Lab Scenario

During a BVLOS training flight, the Ground Control Station recorded MAVLink telemetry that later looked “wrong” to the pilot: the map jumped, speed spiked, and a second heartbeat source briefly appeared. Security engineering has extracted the window into:

```text
data/spoofed_gps_attack.json
```

Your job is to prove (or disprove) an active cyber attack using **uas-security-evaluator**.

---

## Step 1 — Environment Setup

```bash
cd uas-security-evaluator
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Confirm the sample log exists:

```bash
ls data/spoofed_gps_attack.json
```

---

## Step 2 — Ingest the Attack Log

Run the end-to-end CLI (parser → detector → NIST report):

```bash
python main.py --input data/spoofed_gps_attack.json --output audit_report.md
```

Optional: print findings as JSON for scripting:

```bash
python main.py --input data/spoofed_gps_attack.json --json-findings findings.json
```

### What just happened?

| Stage | Module | Role |
| --- | --- | --- |
| Parse | `src/mavlink_parser.py` | Normalize JSON MAVLink fields into a DataFrame |
| Detect | `src/anomaly_detector.py` | Apply GPS jump, velocity, and sysid heuristics |
| Report | `src/report_builder.py` | Map findings to NIST controls → Markdown |

---

## Step 3 — Analyze the Findings

Open `audit_report.md` and answer:

1. **How many High-severity findings** were raised?  
2. Which alert corresponds to the **impossible position jump** (`GPS_SPOOFING_ALERT`)? Note the distance (m) and time delta (ms).  
3. Which finding shows a **ground_speed** that exceeds the physical envelope?  
4. Which **unauthorized `system_id`** appeared, and why is that dangerous on an unsigned MAVLink bus?

### Expected signals in the sample

| Alert | Approx. Trigger in Sample |
| --- | --- |
| `GPS_SPOOFING_ALERT` | Jump near `14:00:02.050Z` (~1+ km relocation in ~50 ms) |
| `VELOCITY_ANOMALY` | `ground_speed` spike to ~72 m/s |
| `UNAUTHORIZED_SYSTEM_ID` | Heartbeats from `system_id = 99` |

> Tip: You can also inspect the raw log with:
>
> ```bash
> python -m src.mavlink_parser data/spoofed_gps_attack.json
> ```

---

## Step 4 — Write Remediation Steps

Using Section 4 of `audit_report.md` and `docs/THREAT_MODEL.md`, draft a short remediation note (½–1 page) that includes:

1. **Immediate operational action** (e.g., ground the airframe, quarantine the log, notify the PIC).  
2. **Engineering fixes** for each alert type you observed.  
3. **NIST control callouts** — at minimum reference `SI-4`, `SC-8`, and `AC-3` / `IA-2`.  
4. **Verification plan** — how you would re-run this lab after mitigations (e.g., signed MAVLink capture should yield zero High findings).

### Example remediation outline

```markdown
## Remediation Write-Up

### Immediate
- Suspend flight ops until GCS allow-list and link integrity are verified.

### Engineering
- GPS spoofing: enable MAVLink 2.0 signing; fuse GNSS with IMU; reject >100 m jumps.
- Velocity: enforce envelope checks at the companion computer.
- Sysid 99: drop unknown HEARTBEAT/COMMAND at the boundary; require GCS pairing.

### NIST Mapping
- SI-4 continuous monitoring via this evaluator in post-flight CI.
- SC-8 transmission integrity (message signing / encryption).
- AC-3 / IA-2 access enforcement and GCS authentication.

### Verification
- Re-run: `python main.py --input data/spoofed_gps_attack.json`
- Success criteria: zero High findings on a clean signed capture; High findings still
  raised on this attack fixture (detector regression test).
```

---

## Step 5 — Stretch Goals (Optional)

- Tune `--max-speed` / authorize additional sysids via CLI flags and re-run.  
- Add a second JSON fixture with only benign flight data; confirm a clean report.  
- Extend `AnomalyDetector` with a missing-heartbeat DoS heuristic from the STRIDE model.

---

## Acceptance Checklist

- [ ] Environment installed; CLI runs without errors  
- [ ] `audit_report.md` generated with Executive Summary, Findings, NIST Mapping, Mitigations  
- [ ] Trainee can explain each High finding in plain language  
- [ ] Remediation write-up references at least three NIST controls  
- [ ] Trainee can locate the corresponding STRIDE rows in `docs/THREAT_MODEL.md`

---

## Facilitator Notes

The sample is intentionally noisy: one geospatial teleport, one speed spike, and a rogue sysid. Junior engineers should leave the lab able to operate the tool **and** connect alerts back to architecture-level threats (spoofing, tampering, unauthorized identity).
