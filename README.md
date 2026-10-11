# Detecting Forged UE Reports under Missing and Delayed Telemetry

A research prototype for live, per-cell UE report consistency checks in ns-O-RAN.

**Question:** Can protected UE connection-state history reduce false alarms caused by delayed reports while retaining detection of inserted, never-connected UE IDs?

## Implementation

| Component | Code |
|---|---|
| UE count, UE membership, and time-aware consistency rules | [ran_online_detector.py](scripts/ran_online_detector.py) |
| Live intake and five paired channel views | [ran_live_faults.py](scripts/ran_live_faults.py) |
| Repeated trials | [ran_repeat_trials.py](scripts/ran_repeat_trials.py) |
| Delay/history sensitivity experiments | [ran_window_sweep.py](scripts/ran_window_sweep.py) |
| Forgery overlapping a genuine UE join | [ran_join_attack_trials.py](scripts/ran_join_attack_trials.py) |
| Instrumented simulator source snapshots | [simulator/](simulator/) |

The count baseline compares against the latest received RRC snapshot. Membership also compares UE IDs. The time-aware rule requires count and membership to match the same received snapshot within a recent history window. Generation timestamps and attack labels are used for experiment scheduling and scoring, not by these rules.

## Recorded experiments

The evidence contains **40 distinct simulation runs**, covering 8 conditions and 5 RngRun values (6202, 6203, 6204, 6205, 6206). Conditions reuse those values for pairing. Each physical run feeds normal, missing-whole-report, delayed, forged, and forged-plus-faults views. Packets and views within a run are correlated; conditions and simulation durations are kept separate.

Selected delayed-only results, shown as false alarms / delivered benign reports:

| Condition | Count | Membership | Time-aware |
|---|---:|---:|---:|
| C1 | 15/180 | 15/180 | 0/180 |
| C3 | 15/180 | 15/180 | 10/180 |
| C4 | 15/180 | 15/180 | 10/180 |
| C5 | 15/180 | 15/180 | 0/180 |

Forgery overlapping the genuine UE join, with missing/delayed reports:

| Condition | Method | Detected / delivered forged | Accepted forged (FN) | Unresolved forged |
|---|---|---:|---:|---:|
| J1 | ue_count | 6/16 | 10 | 0 |
| J1 | ue_membership | 16/16 | 0 | 0 |
| J1 | time_aware | 16/16 | 0 | 0 |
| J2 | ue_count | 6/16 | 10 | 0 |
| J2 | ue_membership | 16/16 | 0 | 0 |
| J2 | time_aware | 16/16 | 0 | 0 |

Dropped reports receive no security verdict. Unresolved attacks remain in the delivered-attack denominator. See the [complete condition definitions and interpretation](evidence/README.md), [condition metrics](evidence/condition_metrics.csv), and [per-run metrics](evidence/per_run_metrics.csv).

## Verify the archived results

From the project folder, with Python 3.10+:

```bash
python3 scripts/ran_prepare_github.py --verify-repo .
```

Expected: `GITHUB_VERIFY=PASS`. This checks the frozen source copies, file hashes, accounting, and causality of the original live decisions. PASS describes evidence quality and permits detector errors. Verification needs no original VM paths, simulator installation, or external Python packages.

## Run a fresh simulation

A fresh run requires the complete matching ns-O-RAN repository, its dependencies, and a successful build. This project includes two source snapshots, not the full simulator. Follow the [fresh live trial instructions](evidence/README.md#fresh-live-trial-in-the-matching-lab-repository); set `RAN_HANDOVER_DIR` to this project's `evidence` folder. The frozen batch controllers retain their original checkpoint requirements.

## Scope

Decisions were made while ns3 ran, by tailing local CSV logs. Actual E2 transport, xApp deployment, mitigation, and physical PRB changes were not evaluated. Forgeries insert reserved UE ID 99999 into parsed report copies. The protected reference and reports originate in the same simulator/RRC model; this is an experimental trust assumption. ID reuse, replay, replacement, partial per-UE loss, and faulty reference telemetry require separate evaluation.

A history match is not a direct report-age limit. First-alarm episode offsets use the received simulation-reference clock and are not exact E2 or processing latency. Preliminary related-work screening is included in the handover README; general novelty is not established.

## Repository contents

`scripts/` exposes the frozen experiment code. `simulator/` exposes the two native source snapshots. `evidence/` retains the complete verified handover bundle, including its original scripts, raw logs, live decisions, metrics, provenance, and file index. The duplicate code copies are checked against the archive.

This folder is prepared for a private GitHub repository. Repository creation and upload are separate steps. Existing notices in the simulator source snapshots are retained; no new project-wide license is selected here.
