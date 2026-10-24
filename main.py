#!/usr/bin/env python3
"""
uas-security-evaluator CLI

Ingest MAVLink-style telemetry, detect cybersecurity anomalies, and emit a
NIST SP 800-53 mapped Markdown audit report.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from anomaly_detector import AnomalyDetector, findings_to_dicts  # noqa: E402
from mavlink_parser import parse_telemetry, summarize_telemetry  # noqa: E402
from report_builder import write_report  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate UAS MAVLink telemetry for cybersecurity anomalies."
    )
    parser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Path to JSON / JSONL telemetry log (e.g. data/spoofed_gps_attack.json)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="audit_report.md",
        help="Markdown report output path (default: audit_report.md)",
    )
    parser.add_argument(
        "--json-findings",
        default=None,
        help="Optional path to write machine-readable findings JSON",
    )
    parser.add_argument(
        "--authorized-sysid",
        type=int,
        nargs="+",
        default=[1],
        help="Allow-listed MAVLink system_id values (default: 1)",
    )
    parser.add_argument(
        "--max-jump-m",
        type=float,
        default=100.0,
        help="Max allowed position jump in meters within <1s (default: 100)",
    )
    parser.add_argument(
        "--max-speed",
        type=float,
        default=45.0,
        help="Max allowed ground_speed in m/s (default: 45)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    input_path = Path(args.input)

    print(f"[*] Parsing telemetry: {input_path}")
    df = parse_telemetry(input_path)
    summary = summarize_telemetry(df)
    print(
        f"[*] Packets={summary['packet_count']} "
        f"sysids={summary['system_ids']} "
        f"duration={summary['duration_seconds']:.3f}s"
    )

    detector = AnomalyDetector(
        authorized_system_ids=args.authorized_sysid,
        max_position_jump_m=args.max_jump_m,
        max_ground_speed_mps=args.max_speed,
    )
    findings = detector.analyze(df)
    print(f"[*] Findings: {len(findings)}")
    for finding in findings:
        print(
            f"    - [{finding.severity}] {finding.alert_type} "
            f"@ {finding.timestamp} (sysid={finding.system_id})"
        )

    report_path = write_report(
        findings,
        output_path=args.output,
        telemetry_summary=summary,
        source_name=str(input_path),
    )
    print(f"[*] Wrote NIST audit report → {report_path}")

    if args.json_findings:
        out = Path(args.json_findings)
        out.write_text(
            json.dumps(findings_to_dicts(findings), indent=2),
            encoding="utf-8",
        )
        print(f"[*] Wrote findings JSON → {out}")

    return 0 if not any(f.severity == "High" for f in findings) else 2


if __name__ == "__main__":
    raise SystemExit(main())
