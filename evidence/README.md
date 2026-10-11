# Forged UE reports: live ns-O-RAN prototype

Research question: Can checking UE report membership against protected RRC connection-state history reduce delay-induced false alarms while retaining detection of inserted, never-connected UE IDs?

This bundle contains 40 distinct simulation runs across 8 conditions, using RngRun values 6202, 6203, 6204, 6205, 6206. The five channel views within each run share one physical simulation: normal, missing whole reports, delayed reports, forged entries, and forgery combined with missing/delayed reports. RngRun values are reused across conditions for pairing. Reused comparison runs and the initial pilot are not additional samples.

## Start here

Extract the ZIP and enter its top-level folder. Verify all recorded decisions and file hashes:

```bash
python3 ran_collect_evidence.py --verify-bundle .
```

Expected: `BUNDLE_VERIFY=PASS`. Verification works without the original VM paths or simulator installation. PASS means that data, causal auditing, and accounting agree; it permits false positives, false negatives, and unresolved verdicts.

| File | Purpose |
|---|---|
| `condition_metrics.csv` / `.json` | Descriptive totals within each condition |
| `per_run_metrics.csv` | Counts for each RngRun, case, and method |
| `packet_examples.json` | Count-rule misses and benign mismatches explained by historical snapshots |
| `runs/` | Raw reference states/events, source CU-CP logs, channel events, receipt times, and live decisions |
| `scripts/` | Frozen detector, harness, and experiment controllers |
| `source_snapshot/` | Two native source files used by the experiments |
| `checkpoints/` | Original batch records; their absolute paths document provenance |
| `handover_metadata.json` | Input evidence hash and repository state observed at handover |

## Conditions

Two real UEs are configured. Native connection for the second starts at 500 ms. RRC snapshots are sampled every 10 ms of simulator time. Delay scheduling follows the latest received complete reference snapshot at report interception.

| Condition | Runs | Simulation seconds | Delay ms | History ms | Forgery generation window ms |
|---|---:|---:|---:|---:|---|
| R1 | 5 | 1.7 | 250 | 300 | 1000–1400 |
| C1 | 5 | 2 | 250 | 300 | 1000–1400 |
| C2 | 5 | 2 | 100 | 300 | 1000–1400 |
| C3 | 5 | 2 | 450 | 300 | 1000–1400 |
| C4 | 5 | 2 | 250 | 100 | 1000–1400 |
| C5 | 5 | 2 | 250 | 500 | 1000–1400 |
| J1 | 5 | 2 | 250 | 300 | 300–700 |
| J2 | 5 | 2 | 250 | 100 | 300–700 |

R1 uses 1.7 s; later conditions use 2.0 s to allow delayed reports to drain. Different durations are kept separate. Generation timestamps and synthetic attack labels support experiment scheduling/metrics; they are not inputs to the three detector rules.

## Results from the audited data

Entries below are false alarms / delivered benign reports in the delayed-only case. Count and membership use the latest received snapshot; time-aware requires count and membership to match one snapshot in recent history.

| Condition | UE count FP/benign | UE membership FP/benign | Time-aware FP/benign |
|---|---:|---:|---:|
| R1 | 15/172 | 15/172 | 0/172 |
| C1 | 15/180 | 15/180 | 0/180 |
| C2 | 5/180 | 5/180 | 0/180 |
| C3 | 15/180 | 15/180 | 10/180 |
| C4 | 15/180 | 15/180 | 10/180 |
| C5 | 15/180 | 15/180 | 0/180 |
| J1 | 15/180 | 15/180 | 0/180 |
| J2 | 15/180 | 15/180 | 10/180 |

Attacks overlapping the genuine UE join, in the forged-plus-faults case:

| Condition | Method | Detected/delivered forged | Accepted forged (FN) | Unresolved forged |
|---|---|---:|---:|---:|
| J1 | ue_count | 6/16 | 10 | 0 |
| J1 | ue_membership | 16/16 | 0 | 0 |
| J1 | time_aware | 16/16 | 0 | 0 |

J1: 34 forged reports were injected; 18 were dropped before delivery. Dropped reports receive no security verdict and are excluded from delivered-attack recall.

| Condition | Method | Detected/delivered forged | Accepted forged (FN) | Unresolved forged |
|---|---|---:|---:|---:|
| J2 | ue_count | 6/16 | 10 | 0 |
| J2 | ue_membership | 16/16 | 0 | 0 |
| J2 | time_aware | 16/16 | 0 | 0 |

J2: 34 forged reports were injected; 18 were dropped before delivery. Dropped reports receive no security verdict and are excluded from delivered-attack recall.

Count-rule miss example (J1, RngRun 6202, cell 1): report generated at 300 ms, decided on reference clock 550 ms. Reported IDs were `[1, 99999]` with count 2; latest reference IDs were `[1, 2]` with count 2. Verdicts: `{"time_aware": "alarm", "ue_count": "consistent", "ue_membership": "alarm"}`.

## Interpretation and limits

The result supports a scoped comparison of connection-state consistency rules under telemetry faults and real UE joins. A history window allows a match to a recent state; it is not a direct report-age check. False alarms can remain when the needed old state has left the window.

Collection and decisions were live while ns3 was running, by tailing local simulator CSV logs. This is a report-plane prototype; actual E2 transport, an xApp deployment, mitigation, and physical PRB changes were not evaluated. The attack changes parsed report copies by inserting reserved new UE ID 99999 and incrementing the count. It does not create physical UEs. ID reuse, replay, replacement, partial per-UE record loss, corrupted reference telemetry, and broader join/leave/handover populations require separate evaluation.

The report and reference paths are separate, but both come from the same simulator/RRC model. Reference completeness and integrity are protected assumptions in this experiment, not demonstrated hardware or cryptographic independence. Checks are per cell against raw RRC context membership, including temporary contexts. A multi-connectivity UE can legitimately appear in both its LTE anchor and a mmWave cell. Raw temporary unknown identities can produce `indeterminate`; an unresolved attack is neither a true positive nor a false negative. FP fractions use all delivered benign reports, and TP fractions use all delivered forged reports, including unresolved ones in those denominators.

First-alarm offsets are measured from the first intercepted forged report to the first alarm on the received simulation reference clock. They describe an episode and are not exact E2 latency, wall-clock processing latency, or per-packet detection delay. Packets and channel views within a run are correlated. These 40 simulation runs use 5 distinct RngRun values, paired across conditions. Use per-run metrics for comparisons and keep conditions separate.

## Fresh live trial in the matching lab repository

Portable verification above needs only this bundle. A fresh simulation additionally needs the original complete ns-O-RAN tree, its dependencies, matching source snapshots, and a successful build. The bundle does not contain the full repository or install its dependencies. Run the following from the matching repository, replacing the handover folder path:

```bash
RAN_HANDOVER_DIR="/absolute/path/to/extracted/handover"
./ns3 build -j 2
RAN_SECURITY_LATE_ATTACH_MS=500 NS_LOG="" python3 "$RAN_HANDOVER_DIR/scripts/ran_live_faults.py" \
  --repo "$PWD" --ues 2 --seed 6202 --sim-seconds 2.0 \
  --delay-ms 250 --grace-ms 300 \
  --fault-start-ms 300 --fault-end-ms 1400 \
  --forge-start-ms 300 --forge-end-ms 700 \
  --drop-times-ms 400,600,1100,1300 --max-wall-seconds 240
```

This is one J1-style live trial, saved into a new result directory. It does not replace the exported evidence. The batch controllers retain their original checkpoint path requirements; their recorded absolute paths are not portable rerun inputs.

## Related work: preliminary positioning

Existing work already covers malicious telemetry detection, state consistency, and protected operational evidence. The contribution proposed here is the scoped comparison around delay, whole-report loss, history-window limits, and a genuine UE join. Priority or general novelty is not established by this screening.

- [Rogue Cell / MARRS](https://arxiv.org/html/2505.01816v1): detects manipulated cell telemetry using LSTM autoencoders; sequence-based detection reduces outlier-induced false positives.
- [INVARAN: Invariant-Guided Logical Testing of Open RAN Controllers](https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_yang-tianchang.pdf): finds semantic controller flaws with inferred invariants, including state inconsistencies and falsified reports; discusses delayed/lost acknowledgments.
- [Closing the Visibility Gap](https://arxiv.org/html/2509.03000v1): monitors O-RU configuration/control state using hardware-rooted signed evidence for policy verification.
