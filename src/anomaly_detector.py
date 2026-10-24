"""
Security Rule & Heuristic Engine

Detects GPS spoofing / impossible position jumps, velocity anomalies,
and unauthorized MAVLink system IDs in normalized telemetry.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from math import asin, cos, radians, sin, sqrt
from typing import Any, Iterable, Optional, Sequence

import pandas as pd

# Default physical / policy thresholds
DEFAULT_MAX_POSITION_JUMP_M = 100.0
DEFAULT_MIN_JUMP_DT_S = 0.001  # ignore zero/negative deltas
DEFAULT_MAX_GROUND_SPEED_MPS = 45.0  # ~87 knots; typical small UAS ceiling
DEFAULT_SPEED_SPIKE_DELTA_MPS = 25.0
DEFAULT_AUTHORIZED_SYSTEM_IDS: frozenset[int] = frozenset({1})


@dataclass
class Finding:
    """A single security finding with NIST-ready metadata."""

    alert_type: str
    severity: str  # High | Medium | Low
    timestamp: str
    system_id: Optional[int]
    description: str
    evidence: dict[str, Any]
    nist_controls: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def haversine_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two WGS84 points in meters."""
    r = 6_371_000.0
    phi1, phi2 = radians(lat1), radians(lat2)
    d_phi = radians(lat2 - lat1)
    d_lambda = radians(lon2 - lon1)
    a = sin(d_phi / 2) ** 2 + cos(phi1) * cos(phi2) * sin(d_lambda / 2) ** 2
    return 2 * r * asin(sqrt(a))


def _ts_iso(value: Any) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return "unknown"
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


class AnomalyDetector:
    """Heuristic anomaly detector for UAS MAVLink telemetry streams."""

    def __init__(
        self,
        authorized_system_ids: Optional[Iterable[int]] = None,
        max_position_jump_m: float = DEFAULT_MAX_POSITION_JUMP_M,
        max_ground_speed_mps: float = DEFAULT_MAX_GROUND_SPEED_MPS,
        speed_spike_delta_mps: float = DEFAULT_SPEED_SPIKE_DELTA_MPS,
    ) -> None:
        ids = (
            DEFAULT_AUTHORIZED_SYSTEM_IDS
            if authorized_system_ids is None
            else frozenset(int(x) for x in authorized_system_ids)
        )
        self.authorized_system_ids = ids
        self.max_position_jump_m = max_position_jump_m
        self.max_ground_speed_mps = max_ground_speed_mps
        self.speed_spike_delta_mps = speed_spike_delta_mps

    def analyze(self, df: pd.DataFrame) -> list[Finding]:
        """Run all detection rules and return sorted findings."""
        if df is None or df.empty:
            return []

        findings: list[Finding] = []
        findings.extend(self._detect_gps_spoofing(df))
        findings.extend(self._detect_velocity_anomalies(df))
        findings.extend(self._detect_unauthorized_system_ids(df))

        severity_rank = {"High": 0, "Medium": 1, "Low": 2}
        findings.sort(
            key=lambda f: (severity_rank.get(f.severity, 9), f.timestamp, f.alert_type)
        )
        return findings

    def _detect_gps_spoofing(self, df: pd.DataFrame) -> list[Finding]:
        findings: list[Finding] = []
        geo = df.dropna(subset=["lat", "lon", "timestamp"]).copy()
        if len(geo) < 2:
            return findings

        prev = geo.iloc[0]
        for _, row in geo.iloc[1:].iterrows():
            dt = (row["timestamp"] - prev["timestamp"]).total_seconds()
            if dt < DEFAULT_MIN_JUMP_DT_S:
                prev = row
                continue

            distance_m = haversine_meters(
                float(prev["lat"]),
                float(prev["lon"]),
                float(row["lat"]),
                float(row["lon"]),
            )

            # Impossible instantaneous relocation (e.g. >100 m in tens of ms)
            implied_speed = distance_m / dt if dt > 0 else float("inf")
            if distance_m > self.max_position_jump_m and dt < 1.0:
                findings.append(
                    Finding(
                        alert_type="GPS_SPOOFING_ALERT",
                        severity="High",
                        timestamp=_ts_iso(row["timestamp"]),
                        system_id=int(row["system_id"])
                        if pd.notna(row["system_id"])
                        else None,
                        description=(
                            f"Impossible position jump of {distance_m:.1f} m "
                            f"in {dt * 1000:.1f} ms (implied {implied_speed:.0f} m/s)."
                        ),
                        evidence={
                            "from_lat": float(prev["lat"]),
                            "from_lon": float(prev["lon"]),
                            "to_lat": float(row["lat"]),
                            "to_lon": float(row["lon"]),
                            "distance_m": round(distance_m, 2),
                            "delta_ms": round(dt * 1000, 3),
                            "implied_speed_mps": round(implied_speed, 2),
                        },
                        nist_controls=["SI-4", "SC-8", "SI-10"],
                    )
                )
            prev = row
        return findings

    def _detect_velocity_anomalies(self, df: pd.DataFrame) -> list[Finding]:
        findings: list[Finding] = []
        speed_rows = df.dropna(subset=["ground_speed", "timestamp"]).copy()
        if speed_rows.empty:
            return findings

        prev_speed: Optional[float] = None
        for _, row in speed_rows.iterrows():
            speed = float(row["ground_speed"])
            sid = int(row["system_id"]) if pd.notna(row["system_id"]) else None
            ts = _ts_iso(row["timestamp"])

            if speed > self.max_ground_speed_mps:
                findings.append(
                    Finding(
                        alert_type="VELOCITY_ANOMALY",
                        severity="High",
                        timestamp=ts,
                        system_id=sid,
                        description=(
                            f"Ground speed {speed:.1f} m/s exceeds physical limit "
                            f"of {self.max_ground_speed_mps:.1f} m/s."
                        ),
                        evidence={
                            "ground_speed_mps": speed,
                            "max_allowed_mps": self.max_ground_speed_mps,
                        },
                        nist_controls=["SI-4", "SI-10", "AU-6"],
                    )
                )
            elif (
                prev_speed is not None
                and abs(speed - prev_speed) >= self.speed_spike_delta_mps
            ):
                findings.append(
                    Finding(
                        alert_type="VELOCITY_ANOMALY",
                        severity="Medium",
                        timestamp=ts,
                        system_id=sid,
                        description=(
                            f"Abrupt ground-speed change of "
                            f"{abs(speed - prev_speed):.1f} m/s "
                            f"({prev_speed:.1f} → {speed:.1f} m/s)."
                        ),
                        evidence={
                            "previous_speed_mps": prev_speed,
                            "ground_speed_mps": speed,
                            "delta_mps": round(abs(speed - prev_speed), 2),
                        },
                        nist_controls=["SI-4", "SI-10"],
                    )
                )
            prev_speed = speed
        return findings

    def _detect_unauthorized_system_ids(self, df: pd.DataFrame) -> list[Finding]:
        findings: list[Finding] = []
        heartbeat_mask = df["heartbeat"].fillna(False) | (
            df["msg_type"].astype(str).str.upper() == "HEARTBEAT"
        )
        candidates = df[heartbeat_mask | df["system_id"].notna()]

        seen: set[int] = set()
        for _, row in candidates.iterrows():
            if pd.isna(row["system_id"]):
                continue
            sid = int(row["system_id"])
            if sid in self.authorized_system_ids or sid in seen:
                continue
            seen.add(sid)
            findings.append(
                Finding(
                    alert_type="UNAUTHORIZED_SYSTEM_ID",
                    severity="High",
                    timestamp=_ts_iso(row["timestamp"]),
                    system_id=sid,
                    description=(
                        f"Unauthorized system_id {sid} observed on the MAVLink "
                        f"bus (authorized: {sorted(self.authorized_system_ids)})."
                    ),
                    evidence={
                        "observed_system_id": sid,
                        "authorized_system_ids": sorted(self.authorized_system_ids),
                        "msg_type": str(row.get("msg_type", "UNKNOWN")),
                        "heartbeat": bool(row.get("heartbeat", False)),
                    },
                    nist_controls=["AC-3", "IA-2", "SI-4", "SC-7"],
                )
            )
        return findings


def findings_to_dicts(findings: Sequence[Finding]) -> list[dict[str, Any]]:
    """Serialize Finding objects for JSON / report consumers."""
    return [f.to_dict() for f in findings]
