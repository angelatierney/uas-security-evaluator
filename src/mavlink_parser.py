"""
MAVLink Telemetry Ingestion Engine

Reads structured JSON telemetry logs (portable stand-in for pymavlink /
pcap captures) and normalizes flight metrics into a pandas DataFrame.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Union

import pandas as pd

REQUIRED_COLUMNS = [
    "system_id",
    "timestamp",
    "lat",
    "lon",
    "alt",
    "ground_speed",
    "heartbeat",
    "msg_type",
]


def _load_json_records(path: Path) -> list[dict[str, Any]]:
    """Load a JSON array or newline-delimited JSON object stream."""
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []

    if text.startswith("["):
        data = json.loads(text)
        if not isinstance(data, list):
            raise ValueError(f"Expected a JSON array in {path}")
        return data

    records: list[dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON on line {line_no} of {path}: {exc}") from exc
        if not isinstance(obj, dict):
            raise ValueError(f"Expected JSON objects on each line of {path}")
        records.append(obj)
    return records


def _normalize_record(raw: dict[str, Any]) -> dict[str, Any]:
    """Map common field aliases into the canonical schema."""
    aliases = {
        "sysid": "system_id",
        "sys_id": "system_id",
        "systemId": "system_id",
        "time": "timestamp",
        "ts": "timestamp",
        "latitude": "lat",
        "longitude": "lon",
        "lng": "lon",
        "altitude": "alt",
        "gs": "ground_speed",
        "groundspeed": "ground_speed",
        "speed": "ground_speed",
        "type": "msg_type",
        "message_type": "msg_type",
    }

    record: dict[str, Any] = {col: None for col in REQUIRED_COLUMNS}
    for key, value in raw.items():
        canonical = aliases.get(key, key)
        if canonical in record:
            record[canonical] = value

    if record["heartbeat"] is None:
        msg = str(record.get("msg_type") or "").upper()
        record["heartbeat"] = msg == "HEARTBEAT"

    return record


def parse_telemetry(
    source: Union[str, Path, Iterable[dict[str, Any]]],
) -> pd.DataFrame:
    """
    Parse MAVLink-style telemetry into a normalized DataFrame.

    Parameters
    ----------
    source:
        Path to a ``.json`` log file, or an iterable of packet dictionaries.

    Returns
    -------
    pandas.DataFrame
        Columns: system_id, timestamp, lat, lon, alt, ground_speed,
        heartbeat, msg_type. Rows are sorted by timestamp ascending.
    """
    if isinstance(source, (str, Path)):
        path = Path(source)
        if not path.exists():
            raise FileNotFoundError(f"Telemetry source not found: {path}")
        if path.suffix.lower() not in {".json", ".jsonl"}:
            raise ValueError(
                f"Unsupported file type '{path.suffix}'. "
                "Provide a .json / .jsonl telemetry log."
            )
        raw_records = _load_json_records(path)
    else:
        raw_records = list(source)

    if not raw_records:
        return pd.DataFrame(columns=REQUIRED_COLUMNS)

    normalized = [_normalize_record(r) for r in raw_records]
    df = pd.DataFrame(normalized)

    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    for numeric_col in ("lat", "lon", "alt", "ground_speed"):
        df[numeric_col] = pd.to_numeric(df[numeric_col], errors="coerce")

    df["system_id"] = pd.to_numeric(df["system_id"], errors="coerce").astype("Int64")
    df["heartbeat"] = df["heartbeat"].fillna(False).astype(bool)
    df["msg_type"] = df["msg_type"].fillna("UNKNOWN").astype(str)

    df = df.sort_values("timestamp", kind="mergesort").reset_index(drop=True)
    return df[REQUIRED_COLUMNS]


def summarize_telemetry(df: pd.DataFrame) -> dict[str, Any]:
    """Return a short ingest summary useful for report headers."""
    if df.empty:
        return {
            "packet_count": 0,
            "system_ids": [],
            "time_start": None,
            "time_end": None,
            "duration_seconds": 0.0,
        }

    time_start = df["timestamp"].min()
    time_end = df["timestamp"].max()
    duration = (time_end - time_start).total_seconds() if pd.notna(time_start) else 0.0
    system_ids = sorted({int(sid) for sid in df["system_id"].dropna().unique()})

    return {
        "packet_count": int(len(df)),
        "system_ids": system_ids,
        "time_start": time_start.isoformat() if pd.notna(time_start) else None,
        "time_end": time_end.isoformat() if pd.notna(time_end) else None,
        "duration_seconds": float(duration),
    }


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "data/spoofed_gps_attack.json"
    frame = parse_telemetry(target)
    print(summarize_telemetry(frame))
    print(frame.to_string(index=False))
