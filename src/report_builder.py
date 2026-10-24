"""
NIST & Audit Report Generator

Maps anomaly findings to NIST SP 800-53 controls and emits an
executive-ready Markdown compliance report.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Sequence, Union

from anomaly_detector import Finding

# NIST SP 800-53 control catalog used for mapping & narrative
NIST_CATALOG: dict[str, dict[str, str]] = {
    "SI-4": {
        "title": "System Monitoring",
        "family": "System and Information Integrity",
        "rationale": (
            "Continuous monitoring of MAVLink telemetry for anomalous "
            "position, velocity, and identity signals."
        ),
    },
    "SI-10": {
        "title": "Information Input Validation",
        "family": "System and Information Integrity",
        "rationale": (
            "Validate GPS and speed fields against physical flight envelopes "
            "before accepting them as ground truth."
        ),
    },
    "SC-8": {
        "title": "Transmission Confidentiality and Integrity",
        "family": "System and Communications Protection",
        "rationale": (
            "Protect the wireless command-and-control link so spoofed or "
            "tampered packets cannot be injected unnoticed."
        ),
    },
    "SC-7": {
        "title": "Boundary Protection",
        "family": "System and Communications Protection",
        "rationale": (
            "Enforce a trust boundary that admits only known GCS / UAS "
            "system identifiers onto the MAVLink bus."
        ),
    },
    "AC-3": {
        "title": "Access Enforcement",
        "family": "Access Control",
        "rationale": (
            "Deny command authority to unauthorized system_id values "
            "attempting to inject control traffic."
        ),
    },
    "IA-2": {
        "title": "Identification and Authentication (Organizational Users)",
        "family": "Identification and Authentication",
        "rationale": (
            "Authenticate Ground Control Stations before accepting "
            "HEARTBEAT / COMMAND_LONG traffic."
        ),
    },
    "AU-6": {
        "title": "Audit Record Review, Analysis, and Reporting",
        "family": "Audit and Accountability",
        "rationale": (
            "Review flight telemetry audit trails for velocity spikes and "
            "correlate them with operational events."
        ),
    },
}

ALERT_TO_ATTACK_VECTOR: dict[str, str] = {
    "GPS_SPOOFING_ALERT": (
        "GPS / GNSS spoofing or injected GLOBAL_POSITION_INT frames "
        "producing impossible geospatial relocation."
    ),
    "VELOCITY_ANOMALY": (
        "Telemetry tampering or sensor-feed manipulation causing "
        "non-physical ground_speed excursions."
    ),
    "UNAUTHORIZED_SYSTEM_ID": (
        "Rogue Ground Control Station or replayed HEARTBEAT frames "
        "from an untrusted MAVLink system_id."
    ),
}

MITIGATIONS: dict[str, list[str]] = {
    "GPS_SPOOFING_ALERT": [
        "Enable MAVLink 2.0 message signing (AUTH) between GCS and autopilot.",
        "Cross-check GNSS against IMU / barometer / visual odometry fused estimators.",
        "Reject position updates whose implied velocity exceeds the airframe envelope.",
        "Monitor RF spectrum for GNSS spoofing indicators during BVLOS operations.",
    ],
    "VELOCITY_ANOMALY": [
        "Apply Kalman / complementary filter bounds on reported ground_speed.",
        "Alert operators when consecutive speed deltas exceed configured thresholds.",
        "Hard-limit autopilot acceptance of velocity fields outside certified limits.",
    ],
    "UNAUTHORIZED_SYSTEM_ID": [
        "Maintain an allow-list of GCS and companion-computer system_id values.",
        "Drop HEARTBEAT / COMMAND frames from unknown sysids at the link layer.",
        "Require mutual authentication (certificate or PSK) for new GCS pairing.",
        "Log and page security operations on first sighting of a foreign sysid.",
    ],
}


def _severity_counts(findings: Sequence[Finding]) -> dict[str, int]:
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def _risk_rating(counts: dict[str, int]) -> str:
    if counts.get("High", 0) > 0:
        return "HIGH — Immediate engineering and operational response required."
    if counts.get("Medium", 0) > 0:
        return "MEDIUM — Investigate before next flight authorization."
    if counts.get("Low", 0) > 0:
        return "LOW — Track and remediate in the next hardening cycle."
    return "NONE — No anomalies detected in the evaluated telemetry window."


def build_report(
    findings: Sequence[Finding],
    telemetry_summary: Optional[dict[str, Any]] = None,
    scope: Optional[str] = None,
    source_name: Optional[str] = None,
) -> str:
    """
    Build a Markdown NIST-mapped audit report from detector findings.
    """
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    summary = telemetry_summary or {}
    counts = _severity_counts(findings)
    risk = _risk_rating(counts)

    scope_text = scope or (
        "Cybersecurity assessment of Unmanned Aircraft System (UAS) MAVLink "
        "telemetry for GPS spoofing, velocity envelope violations, and "
        "unauthorized system identity injection."
    )

    lines: list[str] = [
        "# UAS Security Evaluation — Audit Report",
        "",
        f"**Generated:** {generated_at}  ",
        f"**Tool:** uas-security-evaluator  ",
        f"**Source:** {source_name or 'telemetry stream'}  ",
        f"**Overall Risk Rating:** {risk}",
        "",
        "---",
        "",
        "## 1. Executive Summary & Scope",
        "",
        scope_text,
        "",
        "### Telemetry Window",
        "",
        f"| Metric | Value |",
        f"| --- | --- |",
        f"| Packets analyzed | {summary.get('packet_count', 'n/a')} |",
        f"| System IDs observed | {summary.get('system_ids', 'n/a')} |",
        f"| Window start (UTC) | {summary.get('time_start', 'n/a')} |",
        f"| Window end (UTC) | {summary.get('time_end', 'n/a')} |",
        f"| Duration (s) | {summary.get('duration_seconds', 'n/a')} |",
        "",
        "### Finding Counts",
        "",
        f"- **High:** {counts.get('High', 0)}",
        f"- **Medium:** {counts.get('Medium', 0)}",
        f"- **Low:** {counts.get('Low', 0)}",
        f"- **Total:** {len(findings)}",
        "",
        "---",
        "",
        "## 2. Identified Vulnerabilities & Attack Vectors",
        "",
    ]

    if not findings:
        lines.extend(
            [
                "_No security anomalies were detected in the provided telemetry._",
                "",
            ]
        )
    else:
        for idx, finding in enumerate(findings, start=1):
            vector = ALERT_TO_ATTACK_VECTOR.get(
                finding.alert_type, "Unclassified telemetry anomaly."
            )
            evidence_bits = ", ".join(
                f"{k}={v}" for k, v in finding.evidence.items()
            )
            lines.extend(
                [
                    f"### Finding {idx}: `{finding.alert_type}` "
                    f"({finding.severity})",
                    "",
                    f"- **Timestamp:** {finding.timestamp}",
                    f"- **System ID:** {finding.system_id}",
                    f"- **Description:** {finding.description}",
                    f"- **Attack Vector:** {vector}",
                    f"- **Evidence:** {evidence_bits}",
                    "",
                ]
            )

    lines.extend(
        [
            "---",
            "",
            "## 3. NIST SP 800-53 Control Mapping & Risk Ratings",
            "",
            "| Finding | Severity | NIST Controls | Control Titles |",
            "| --- | --- | --- | --- |",
        ]
    )

    if not findings:
        lines.append("| — | — | — | No mappings required |")
    else:
        for finding in findings:
            titles = []
            for control in finding.nist_controls:
                meta = NIST_CATALOG.get(control, {})
                titles.append(f"{control}: {meta.get('title', 'Unknown')}")
            lines.append(
                f"| `{finding.alert_type}` | {finding.severity} | "
                f"{', '.join(finding.nist_controls)} | "
                f"{'; '.join(titles)} |"
            )

    lines.extend(
        [
            "",
            "### Control Rationale",
            "",
        ]
    )

    used_controls: set[str] = set()
    for finding in findings:
        used_controls.update(finding.nist_controls)

    if not used_controls:
        lines.append("_No NIST controls were implicated by this assessment._")
        lines.append("")
    else:
        for control in sorted(used_controls):
            meta = NIST_CATALOG.get(control, {})
            lines.extend(
                [
                    f"**{control} — {meta.get('title', 'Unknown')}** "
                    f"({meta.get('family', 'n/a')})",
                    "",
                    meta.get("rationale", "No rationale available."),
                    "",
                ]
            )

    lines.extend(
        [
            "---",
            "",
            "## 4. Engineering Mitigation Recommendations",
            "",
        ]
    )

    alert_types = {f.alert_type for f in findings}
    if not alert_types:
        lines.extend(
            [
                "- Continue baseline SI-4 monitoring of MAVLink HEARTBEAT and "
                "GLOBAL_POSITION_INT traffic.",
                "- Keep the authorized system_id allow-list under change control.",
                "",
            ]
        )
    else:
        for alert_type in sorted(alert_types):
            lines.append(f"### {alert_type}")
            lines.append("")
            for item in MITIGATIONS.get(
                alert_type, ["Review findings with the flight-security engineering team."]
            ):
                lines.append(f"- {item}")
            lines.append("")

    lines.extend(
        [
            "---",
            "",
            "_This report was generated by **uas-security-evaluator** for "
            "engineering audit and training use. It is not a certification "
            "artifact._",
            "",
        ]
    )
    return "\n".join(lines)


def write_report(
    findings: Sequence[Finding],
    output_path: Union[str, Path] = "audit_report.md",
    telemetry_summary: Optional[dict[str, Any]] = None,
    scope: Optional[str] = None,
    source_name: Optional[str] = None,
) -> Path:
    """Render the Markdown report and write it to disk."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = build_report(
        findings,
        telemetry_summary=telemetry_summary,
        scope=scope,
        source_name=source_name,
    )
    path.write_text(content, encoding="utf-8")
    return path
