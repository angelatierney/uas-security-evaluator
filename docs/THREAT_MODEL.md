# UAS MAVLink Telemetry — STRIDE Threat Model

**System:** uas-security-evaluator target architecture  
**Scope:** Ground Control Station ↔ wireless C2 link ↔ UAS flight controller  
**Protocol:** MAVLink (telemetry + command channel)  
**Audience:** TrustThink architectural / security design reviews

---

## 1. System Architecture

```
 ┌──────────────────────────┐         RF / Wi-Fi / LTE          ┌──────────────────────────┐
 │  Ground Control Station  │  ════════════════════════════════ │   Unmanned Aircraft      │
 │  (GCS / Companion PC)    │                                   │   System (UAS)           │
 │                          │   MAVLink HEARTBEAT               │                          │
 │  • Mission planner UI    │   GLOBAL_POSITION_INT  ─────────► │  • Autopilot / FC        │
 │  • Telemetry display     │   COMMAND_LONG / SET_MODE         │  • GNSS + IMU sensors    │
 │  • system_id (authorized)│ ◄──────────────────────────────── │  • Failsafe logic        │
 └────────────┬─────────────┘                                   └────────────┬─────────────┘
              │                                                              │
              │              ┌─────────────────────────────┐                 │
              └─────────────►│   Wireless Link Threat      │◄────────────────┘
                             │   Surface                   │
                             │  • Spoofed GCS frames       │
                             │  • Tampered GPS telemetry   │
                             │  • Jammed heartbeats (DoS)  │
                             └─────────────────────────────┘
                                          │
                                          ▼
                             ┌─────────────────────────────┐
                             │  uas-security-evaluator     │
                             │  parser → detector → NIST   │
                             │  audit report               │
                             └─────────────────────────────┘
```

**Trust boundaries**

1. **GCS identity** — only allow-listed `system_id` values may issue commands.  
2. **Wireless link** — unauthenticated MAVLink is assumed adversary-reachable.  
3. **Sensor truth** — GNSS reports must be validated against physical envelopes before flight decisions.

---

## 2. STRIDE Threat Matrix

| STRIDE Category | Threat Scenario | Impact on UAS | Detection Hook (`uas-security-evaluator`) | Primary NIST SP 800-53 |
| --- | --- | --- | --- | --- |
| **S**poofing | Unauthorized GCS injects rogue MAVLink `HEARTBEAT` / `COMMAND_LONG` frames using a foreign `system_id`. | Attacker gains command authority; mode changes, RTL, or motor kill. | `UNAUTHORIZED_SYSTEM_ID` | AC-3, IA-2, SC-7, SI-4 |
| **T**ampering | Adversary intercepts and alters telemetry altitude / position packets (`GLOBAL_POSITION_INT`) mid-flight. | False situational awareness; unsafe geofence or landing decisions. | `GPS_SPOOFING_ALERT`, `VELOCITY_ANOMALY` | SC-8, SI-10, SI-4 |
| **R**epudiation | Operator or attacker denies issuing a critical command because unsigned MAVLink lacks non-repudiation. | Incident investigation blocked; accountability gap. | Audit trail via report builder timestamps | AU-6, AU-10 (recommended) |
| **I**nformation Disclosure | Passive eavesdropping of unencrypted telemetry reveals mission waypoints and home location. | Privacy / OPSEC loss; enables follow-on spoofing. | Out of band (link encryption review) | SC-8 |
| **D**enial of Service | RF jamming suppresses `HEARTBEAT` traffic, triggering autopilot failsafe land / RTL protocols. | Forced landing in unsafe area; mission abort. | Missing-heartbeat gaps (future rule); ops runbook | SC-5, SI-4 |
| **E**levation of Privilege | Companion computer on the airframe is compromised and elevates from telemetry relay to full autopilot parameter write. | Persistent control of the aircraft. | Unexpected `system_id` + command mix | AC-3, AC-6, SI-4 |

### Narrative deep-dives (required review items)

#### Spoofing — Unauthorized GCS
Without MAVLink 2.0 signing, any radio that speaks MAVLink can claim an arbitrary `system_id`. A rogue GCS that emits heartbeats with `system_id=99` can appear as a second controller. The evaluator flags every non-allow-listed sysid on first observation.

#### Tampering — Altered altitude / position
An on-path attacker (or GNSS spoofer) can rewrite latitude/longitude so the aircraft appears to jump hundreds of meters in milliseconds. The GPS position-jump heuristic treats `distance > 100 m` within `< 1 s` as `GPS_SPOOFING_ALERT` (High).

#### Denial of Service — Heartbeat jamming
Jamming the C2 link causes the flight controller to lose GCS heartbeats and enter failsafe. While RF jamming itself is physical-layer, the resulting telemetry gap and subsequent failsafe event should be correlated in the audit report and operator runbook.

---

## 3. Assumptions & Residual Risk

| Assumption | Residual Risk if Violated |
| --- | --- |
| Authorized sysids are correctly provisioned | False positives / missed rogue GCS |
| JSON logs faithfully mirror on-wire MAVLink | Blind spots vs. live RF captures |
| Physical speed envelope ≤ 45 m/s | Platform-specific tuning needed for faster airframes |
| MAVLink signing not yet mandatory | Spoofing remains possible until SC-8 is enforced in production |

---

## 4. Recommended Security Controls (Engineering Backlog)

1. **Mandatory MAVLink 2.0 signing** between GCS and autopilot (SC-8).  
2. **System-id allow-list** enforced in the companion computer firewall (AC-3, SC-7).  
3. **GNSS / IMU fusion with envelope checks** before accepting position as truth (SI-10).  
4. **Continuous SI-4 monitoring** via this evaluator in CI and post-flight pipelines.  
5. **Operator playbooks** for High-severity findings before next flight release.

---

## 5. References

- NIST SP 800-53 Rev. 5 — Security and Privacy Controls for Information Systems  
- MAVLink Protocol — https://mavlink.io/en/  
- ASTM F3411 / Remote ID & UAS cybersecurity guidance (contextual)
