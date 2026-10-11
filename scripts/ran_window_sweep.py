#!/usr/bin/env python3
"""Explore delay and history-window limits using the passed five-run checkpoint.

Use --baseline-batch to select ran_repeat_... with BATCH_STATUS=PASS. Its frozen
scripts are verified and reused. No installer is executed and no RAN source is
edited. Build once, then run five paired channel cases for every condition and
every baseline RngRun. All conditions last 2.0 simulation seconds, allowing
450 ms channel delay to drain before exit. The initial 1.7 s results remain a
separate experiment and are not pooled into this sweep.

A history window permits a payload matching one recent connection-state
snapshot. It is not a direct bound on the age of the report. Forgery here adds
the reserved, never-connected UE ID 99999 to a parsed report copy. The protected
reference remains complete. Real source states and source report membership
are compared across conditions with the same RngRun. PASS is a data-quality and
pairing result, independent of FP, FN, or indeterminate verdict counts.
"""

import argparse
import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path


CONDITIONS = (
    {"id": "C1", "delay_ms": 250, "grace_ms": 300},
    {"id": "C2", "delay_ms": 100, "grace_ms": 300},
    {"id": "C3", "delay_ms": 450, "grace_ms": 300},
    {"id": "C4", "delay_ms": 250, "grace_ms": 100},
    {"id": "C5", "delay_ms": 250, "grace_ms": 500},
)
SOURCE_NAMES = ("scratch/scenario-online-security.cc", "src/mmwave/helper/mmwave-helper.cc")
SCRIPT_NAMES = ("ran_online_detector.py", "ran_live_faults.py",
                "install_ran_late_attach_v2.py", "ran_repeat_trials.py")


def source_fingerprints(folder):
    reports = []
    with (folder / "channel_events.jsonl").open() as source:
        for line in source:
            row = json.loads(line)
            if row["event"] == "source_report":
                reports.append((row["cell_id"], row["source_generation_us"], row["original_count"],
                                sorted(row["original_imsis"])))
    canonical = json.dumps(sorted(reports), separators=(",", ":")).encode()
    return {"source_membership_sha256": hashlib.sha256(canonical).hexdigest(),
            "reference_states_sha256": hashlib.sha256((folder / "ue_events.csv.states.csv").read_bytes()).hexdigest(),
            "source_reports": len(reports)}


def summarize(batch, manifest, controller):
    trials = manifest["trials"]
    valid = [t for t in trials if t["status"] == "PASS"]
    groups, rows, pairing_issues = {}, [], []
    for run in manifest["rng_runs"]:
        fingerprints = [t["fingerprints"] for t in valid if t["rng_run"] == run]
        if len(fingerprints) != len(CONDITIONS):
            pairing_issues.append(f"RngRun {run}: incomplete condition set")
        elif any(f != fingerprints[0] for f in fingerprints[1:]):
            pairing_issues.append(f"RngRun {run}: source membership or RRC state differed across conditions")
    for condition in CONDITIONS:
        selected = [t for t in valid if t["condition_id"] == condition["id"]]
        pooled = {}
        for case in controller.CASES:
            pooled[case] = {}
            for method in controller.METHODS:
                metrics = [t["summary"]["metrics_live_only"][case][method] for t in selected]
                total = {key: sum(m[key] for m in metrics) for key in controller.METRIC_KEYS}
                injected = sum(t["summary"]["channel_stats"][case]["source_forged"] for t in selected)
                dropped = sum(t["summary"]["channel_stats"][case]["dropped_forged"] for t in selected)
                offsets = [t["transition"]["first_alarm_delay_on_observed_reference_clock"].get(case, {}).get(method, {}).get("delay_ms")
                           for t in selected]
                measured = [value for value in offsets if value is not None]
                record = {"condition_id": condition["id"], **condition, "case": case, "method": method,
                          "valid_runs": len(selected), "planned_runs": len(manifest["rng_runs"]), **total,
                          "all_injected_forged": injected, "dropped_forged": dropped,
                          "false_alarm_fraction_of_delivered_benign": total["FP"] / total["live_benign"] if total["live_benign"] else None,
                          "detection_fraction_of_delivered_forged": total["TP"] / total["live_attack"] if total["live_attack"] else None,
                          "runs_with_false_alarms": sum(m["FP"] > 0 for m in metrics),
                          "runs_with_false_negatives": sum(m["FN"] > 0 for m in metrics),
                          "runs_with_indeterminate": sum(m["indeterminate_benign"] + m["indeterminate_attack"] > 0 for m in metrics),
                          "min_first_alarm_observed_delay_ms": min(measured) if measured else None,
                          "max_first_alarm_observed_delay_ms": max(measured) if measured else None}
                rows.append(record)
                pooled[case][method] = record
        groups[condition["id"]] = {**condition, "valid_runs": len(selected), "pooled": pooled}
    planned = len(CONDITIONS) * len(manifest["rng_runs"])
    status = "PASS" if len(valid) == planned and not pairing_issues and not manifest.get("error") else "CHECK_RESULTS"
    report = {"sweep_status": status, "valid_runs": len(valid), "planned_runs": planned,
              "rng_runs": manifest["rng_runs"], "conditions": groups, "pairing_issues": pairing_issues,
              "per_run_results": trials, "experimental_unit": "one simulation per RngRun and condition",
              "previous_1p7_second_runs_pooled": False,
              "interpretation": "Descriptive paired condition comparison; packets within a run are correlated. History tolerance is not report-age verification. Alarm offsets use observed reference ticks."}
    controller.save_json(batch / "window_summary.json", report)
    with (batch / "window_metrics.csv").open("w", newline="") as destination:
        writer = csv.DictWriter(destination, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print("\n=== WINDOW SWEEP SUMMARY ===", flush=True)
    print(f"SWEEP_STATUS={status} VALID_RUNS={len(valid)}/{planned} PAIRED_SOURCE_MATCH={'PASS' if not pairing_issues else 'CHECK_RESULTS'}")
    for condition in CONDITIONS:
        group = groups[condition["id"]]
        print(f"\nCONFIG={condition['id']} DELAY_MS={condition['delay_ms']} GRACE_MS={condition['grace_ms']} VALID_RUNS={group['valid_runs']}/{len(manifest['rng_runs'])}")
        for method in controller.METHODS:
            metrics = {case: group["pooled"][case][method] for case in controller.CASES}
            delayed, mixed, forged = metrics["delayed"], metrics["forged_faults"], metrics["forged"]
            print(f"  METHOD={method} DELAYED_FP={delayed['FP']}/{delayed['live_benign']} "
                  f"MIXED_FP={mixed['FP']}/{mixed['live_benign']} FORGED_TP={forged['TP']}/{forged['live_attack']} "
                  f"MIXED_TP={mixed['TP']}/{mixed['live_attack']} FN_TOTAL={sum(m['FN'] for m in metrics.values())} "
                  f"BENIGN_INDETERMINATE={sum(m['indeterminate_benign'] for m in metrics.values())} "
                  f"ATTACK_INDETERMINATE={sum(m['indeterminate_attack'] for m in metrics.values())} "
                  f"NORMAL_FP={metrics['normal']['FP']} MISSING_FP={metrics['missing']['FP']}")
        temporal = group["pooled"]["forged_faults"]["time_aware"]
        print(f"  MIXED_FORGED_DROPPED={temporal['dropped_forged']} FIRST_ALARM_OBSERVED_DELAY_RANGE_MS="
              f"{temporal['min_first_alarm_observed_delay_ms']}..{temporal['max_first_alarm_observed_delay_ms']}")
    for issue in pairing_issues:
        print("PAIRING_ISSUE=" + issue)
    print("A history window is not a direct report-age limit. Dropped reports have no verdict.")
    print("New UE-ID insertion only; the reference is protected. Offsets are not exact E2 latency.")
    print("Results saved in: " + str(batch), flush=True)
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--baseline-batch", type=Path, required=True)
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()
    repo, baseline = args.repo.expanduser().resolve(), args.baseline_batch.expanduser().resolve()
    previous = json.loads((baseline / "manifest.json").read_text())
    previous_summary = json.loads((baseline / "batch_summary.json").read_text())
    if previous_summary["batch_status"] != "PASS" or previous_summary["valid_runs"] != len(previous["rng_runs"]):
        parser.error("Select a complete, passed repetition batch.")
    for name in SCRIPT_NAMES:
        path = baseline / "scripts" / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != previous["script_sha256"][name]:
            parser.error(f"The baseline script checkpoint is missing or changed: {name}.")
    source_paths = [repo / name for name in SOURCE_NAMES]
    for path, marker in zip(source_paths, ("BEGIN RAN_SECURITY_LATE_ATTACH_V2", "BEGIN RAN_SECURITY_LATE_NAS_V2")):
        if (not path.is_file() or marker not in path.read_text()
                or hashlib.sha256(path.read_bytes()).hexdigest() != previous["source_sha256"][str(path.relative_to(repo))]):
            parser.error("V2 RAN sources differ from the passed checkpoint; stop and inspect before sweeping.")
    (repo / "test_open").mkdir(exist_ok=True)
    batch = Path(tempfile.mkdtemp(prefix="ran_windows_", dir=str(repo / "test_open")))
    frozen = batch / "scripts"
    frozen.mkdir()
    for name in SCRIPT_NAMES:
        shutil.copy2(baseline / "scripts" / name, frozen / name)
    shutil.copy2(Path(__file__).resolve(), frozen / "ran_window_sweep.py")
    for name in SOURCE_NAMES:
        target = batch / "source_snapshot" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(repo / name, target)
    sys.path.insert(0, str(frozen))
    import ran_repeat_trials as controller
    base = controller.load_module("ran_online_detector", frozen / "ran_online_detector.py")
    late = controller.load_module("ran_windows_late", frozen / "install_ran_late_attach_v2.py")
    runs = controller.rng_runs(",".join(str(run) for run in previous["rng_runs"]))
    manifest = {"baseline_batch": str(baseline), "rng_runs": runs, "conditions": CONDITIONS, "trials": [],
                "source_sha256": previous["source_sha256"],
                "script_sha256": {p.name: controller.sha256(p) for p in frozen.iterdir() if p.is_file()},
                "common_parameters": {"sim_seconds": 2.0, "ues": 2, "late_attach_ms": 500,
                                      "fault_window_ms": [300, 1400], "forgery_window_ms": [1000, 1400],
                                      "drop_times_ms": [400, 600, 1100, 1300]},
                "generation_metadata_and_labels_are_rule_inputs": False,
                "same_rng_runs_reused_across_conditions_for_pairing": True,
                "previous_runs_included_in_metrics": False}
    print(f"Sweep results: {batch}\nCONDITIONS={len(CONDITIONS)} RUNS_PER_CONDITION={len(runs)} TOTAL_RUNS={len(CONDITIONS)*len(runs)}", flush=True)
    controller.save_json(batch / "window_manifest.json", manifest)
    try:
        if not args.skip_build:
            print("Building the unchanged V2 scenario once...", flush=True)
            subprocess.run([str(repo / "ns3"), "build", "-j", "2"], cwd=repo, check=True)
        binary = repo / "build/scratch/ns3.42-scenario-online-security-default"
        if binary.is_file():
            manifest["scenario_binary_sha256"] = controller.sha256(binary)
        for condition in CONDITIONS:
            for run in runs:
                if any(controller.sha256(path) != previous["source_sha256"][str(path.relative_to(repo))] for path in source_paths):
                    raise RuntimeError("RAN sources changed during the sweep.")
                if binary.is_file() and controller.sha256(binary) != manifest.get("scenario_binary_sha256"):
                    raise RuntimeError("The scenario executable changed during the sweep.")
                command = [sys.executable, str(frozen / "ran_live_faults.py"), "--repo", str(repo),
                           "--ues", "2", "--seed", str(run), "--sim-seconds", "2.0",
                           "--delay-ms", str(condition["delay_ms"]), "--grace-ms", str(condition["grace_ms"]),
                           "--fault-start-ms", "300", "--fault-end-ms", "1400", "--forge-start-ms", "1000",
                           "--forge-end-ms", "1400", "--drop-times-ms", "400,600,1100,1300", "--max-wall-seconds", "240"]
                trial = {"condition_id": condition["id"], "rng_run": run, "status": "RUNNING", "command": command}
                manifest["trials"].append(trial)
                controller.save_json(batch / "window_manifest.json", manifest)
                print(f"\nTRIAL={len(manifest['trials'])}/{len(CONDITIONS)*len(runs)} CONFIG={condition['id']} RngRun={run} "
                      f"DELAY_MS={condition['delay_ms']} GRACE_MS={condition['grace_ms']}", flush=True)
                log_path = batch / f"{condition['id']}_run_{run}.log"
                code, folder = controller.run_harness(command, repo, dict(os.environ, RAN_SECURITY_LATE_ATTACH_MS="500"), log_path)
                trial.update({"return_code": code, "folder": str(folder) if folder else None})
                if code != 0 or folder is None:
                    raise RuntimeError(f"Live run failed; inspect {log_path.name} and its partial result folder.")
                control = {**manifest["common_parameters"], **condition, "rng_run": run,
                           "command": command, "sweep_folder": str(batch), "source_sha256": previous["source_sha256"],
                           "attach_mode": "V2 PHY startup / delayed native NAS Connect"}
                controller.save_json(folder / "experiment_control.json", control)
                with log_path.open("a") as log, redirect_stdout(log):
                    joined = late.summarize(folder, 500, control)
                if not joined:
                    raise RuntimeError("The genuine UE join did not pass validation.")
                audit = controller.audit_run(folder, base)
                controller.save_json(folder / "decision_audit.json", audit)
                trial.update({"status": "PASS", "audit": audit, "fingerprints": source_fingerprints(folder),
                              "summary": json.loads((folder / "summary.json").read_text()),
                              "transition": json.loads((folder / "transition_validation.json").read_text())})
                controller.save_json(batch / "window_manifest.json", manifest)
                print(f"TRIAL_STATUS=PASS JOIN=PASS AUDIT=PASS SOURCE_REPORTS={trial['fingerprints']['source_reports']}", flush=True)
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        manifest["error"] = f"{type(error).__name__}: {str(error) or 'Interrupted; partial results retained.'}"
        if manifest["trials"] and manifest["trials"][-1]["status"] == "RUNNING":
            manifest["trials"][-1].update({"status": "CHECK_RESULTS", "error": manifest["error"]})
        print("STOP: " + manifest["error"], flush=True)
    finally:
        controller.save_json(batch / "window_manifest.json", manifest)
    return 0 if summarize(batch, manifest, controller) == "PASS" else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, RuntimeError, argparse.ArgumentTypeError) as error:
        raise SystemExit(f"STOP: {error}") from error
