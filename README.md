# uas-security-evaluator

Cybersecurity assessment toolkit for **Unmanned Aircraft System (UAS)** MAVLink telemetry. Ingest flight logs, detect GPS spoofing / velocity anomalies / unauthorized system IDs, and generate a NIST SP 800-53–mapped Markdown audit report.

## Features

| Component | Path | Role |
| --- | --- | --- |
| Telemetry parser | `src/mavlink_parser.py` | Normalize JSON MAVLink logs → pandas DataFrame |
| Anomaly detector | `src/anomaly_detector.py` | GPS jump, velocity spike, rogue `system_id` heuristics |
| Report builder | `src/report_builder.py` | Executive Markdown report with NIST control mapping |
| STRIDE threat model | `docs/THREAT_MODEL.md` | Architecture + spoofing / tampering / DoS analysis |
| Training lab | `docs/LAB_EXERCISE.md` | Hands-on exercise using `data/spoofed_gps_attack.json` |

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python main.py --input data/spoofed_gps_attack.json --output audit_report.md
```

Exit codes: `0` = no High findings, `2` = one or more High-severity alerts.

### Useful flags

```bash
python main.py \
  --input data/spoofed_gps_attack.json \
  --output audit_report.md \
  --json-findings findings.json \
  --authorized-sysid 1 \
  --max-jump-m 100 \
  --max-speed 45
```

## Detection Rules (defaults)

- **GPS spoofing** — position change `> 100 m` within `< 1 s` → `GPS_SPOOFING_ALERT` (High)
- **Velocity anomaly** — `ground_speed > 45 m/s`, or abrupt delta `≥ 25 m/s`
- **Unauthorized system ID** — HEARTBEAT / traffic from sysids outside the allow-list (default `{1}`)

## NIST Mapping (examples)

| Alert | Example Controls |
| --- | --- |
| `GPS_SPOOFING_ALERT` | SI-4, SC-8, SI-10 |
| `VELOCITY_ANOMALY` | SI-4, SI-10, AU-6 |
| `UNAUTHORIZED_SYSTEM_ID` | AC-3, IA-2, SI-4, SC-7 |

## Project Layout

```text
uas-security-evaluator/
├── main.py
├── requirements.txt
├── data/
│   └── spoofed_gps_attack.json
├── docs/
│   ├── THREAT_MODEL.md
│   └── LAB_EXERCISE.md
└── src/
    ├── mavlink_parser.py
    ├── anomaly_detector.py
    └── report_builder.py
```

## Documentation

- [STRIDE Threat Model](docs/THREAT_MODEL.md)
- [Hands-on Lab Exercise](docs/LAB_EXERCISE.md)

## License

For engineering audit, research, and training use.
