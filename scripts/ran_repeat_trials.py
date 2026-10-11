#!/usr/bin/env python3
"""Repeat the native V2 genuine-join experiment with distinct ns3 RngRun values.

Place beside ran_online_detector.py, ran_live_faults.py, and
install_ran_late_attach_v2.py. The V2 source changes must already be installed.
This controller builds once, freezes the scripts, and runs five paired cases
per fresh simulation. It does not change the scenario or detector rules.

The default five RngRun values exclude the initial 6201 pilot. Reports within
one simulation and its five channel views are paired, not independent samples.
An optional pilot is audited but is not included in the repeat totals.
Post-run auditing uses recorded receipt times and each decision's reference
watermark. Its reconstruction is validation, never an input to live decisions.
Pipeline/audit PASS does not require zero false positives or perfect detection.
"""

import argparse
import csv
import hashlib
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections import Counter
from contextlib import redirect_stdout
from pathlib import Path


CASES = ("normal", "missing", "delayed", "forged", "forged_faults")
METHODS = ("ue_count", "ue_membership", "time_aware")
METRIC_KEYS = ("live_total", "live_benign", "live_attack", "TP", "FP", "TN", "FN",
               "indeterminate_benign", "indeterminate_attack", "outside_live")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def rng_runs(text):
    try:
        values = [int(part.strip()) for part in text.split(",")]
    except ValueError as error:
        raise argparse.ArgumentTypeError("Use comma-separated positive RngRun integers.") from error
    if not values or min(values) <= 0 or len(set(values)) != len(values):
        raise argparse.ArgumentTypeError("RngRun integers must be positive and unique.")
    return values


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def audit_run(folder, base):
    """Validate live accounting and the reference available at each decision."""
    config = json.loads((folder / "config.json").read_text())
    summary = json.loads((folder / "summary.json").read_text())
    if (summary["pipeline_status"] != "PASS" or summary["return_code"] != 0
            or summary["data_issues"] or summary["queued_at_exit"]):
        raise RuntimeError("The live pipeline did not pass; retain this run for diagnosis.")
    if config["rules_sha256"] != sha256(Path(base.__file__)):
        raise RuntimeError("The audit rules differ from the rules used for this run.")
    grace_us = round(config["grace_ms"] * 1000)
    stream, frames = base.StateStream(grace_us, config["forge_imsi"]), {}
    with (folder / "ue_events.csv.states.csv").open() as source:
        for row in csv.DictReader(source):
            frame = stream.accept(row)
            if frame is not None:
                frames[frame.stamp_us] = frame
    if stream.current is not None or len(frames) != summary["reference_frames"]:
        raise RuntimeError("Reference frames are incomplete or disagree with the summary.")
    with (folder / "reference_receipts.csv").open() as source:
        receipts = list(csv.DictReader(source))
    received = {}
    for row in receipts:
        stamp = int(row["sim_time_us"])
        if (stamp not in frames or stamp in received
                or int(row["snapshot_id"]) != frames[stamp].sequence):
            raise RuntimeError("Reference receipt/frame identifiers disagree.")
        received[stamp] = (float(row["received_wall_s"]), row["phase"])
    if set(received) != set(frames):
        raise RuntimeError("Not every complete frame has a recorded receipt.")
    metrics = {case: {method: Counter(dict.fromkeys(METRIC_KEYS, 0))
                     for method in METHODS} for case in CASES}
    packets, seen, decision_rows = {}, set(), 0
    examples = []
    with (folder / "decisions.csv").open() as source:
        for row in csv.DictReader(source):
            case, method = row["case"], row["method"]
            key = (case, int(row["report_id"]), method)
            if case not in CASES or method not in METHODS or key in seen:
                raise RuntimeError("Unknown or duplicate decision.")
            seen.add(key)
            if (row["included_in_live_metrics"] != "1"
                    or row["source_receipt_phase"] != "runner_running"
                    or row["decision_phase"] != "runner_running"):
                raise RuntimeError("A decision was made outside live collection.")
            cell, clock = int(row["cell_id"]), int(row["reference_watermark_us"])
            generation, intercept = int(row["source_generation_us"]), int(row["channel_intercept_us"])
            scheduled, nominal = int(row["scheduled_delivery_us"]), int(row["nominal_delay_us"])
            wall = float(row["decision_wall_s"])
            if (clock not in received or received[clock][1] != "runner_running"
                    or received[clock][0] > wall + 0.000002
                    or float(row["source_received_wall_s"]) > wall + 0.000002
                    or not generation <= intercept <= scheduled <= clock
                    or scheduled != intercept + nominal
                    or int(row["actual_channel_hold_us"]) != clock - intercept
                    or int(row["source_to_decision_offset_us"]) != clock - generation):
                raise RuntimeError("A decision has inconsistent receipt times or channel clocks.")
            history = [frame for stamp, frame in frames.items()
                       if clock - grace_us <= stamp <= clock]
            if not history or history[-1].stamp_us != clock:
                raise RuntimeError("Decision reference window is missing its latest frame.")
            if any(received[f.stamp_us][0] > wall + 0.000002 for f in history):
                raise RuntimeError("A reference used in the decision was received later.")
            count, imsis = int(row["reported_count"]), tuple(json.loads(row["reported_imsis"]))
            if count != len(imsis) or len(set(imsis)) != len(imsis):
                raise RuntimeError("A report payload is incomplete or contains duplicate UE IDs.")
            match = int(row["matching_snapshot_us"]) if row["matching_snapshot_us"] else None
            actual = (row["verdict"], row["reason"], match)
            expected = base.evaluate(cell, count, imsis, history, grace_us)[method]
            if actual != expected:
                raise RuntimeError(f"Recorded verdict differs from its causal reconstruction: {key}.")
            attack = row["synthetic_attack"] == "1"
            signature = (cell, generation, intercept, scheduled, clock, count, imsis, attack)
            packet = packets.setdefault(key[:2], {"signature": signature, "methods": set()})
            if packet["signature"] != signature:
                raise RuntimeError("Methods did not decide the same delivered packet.")
            packet["methods"].add(method)
            metric = metrics[case][method]
            metric["live_total"] += 1
            metric["live_attack" if attack else "live_benign"] += 1
            if row["verdict"] == "indeterminate":
                metric["indeterminate_attack" if attack else "indeterminate_benign"] += 1
            else:
                label = ("TP" if attack else "FP") if row["verdict"] == "alarm" else ("FN" if attack else "TN")
                metric[label] += 1
            if not attack and method == "ue_count" and row["verdict"] == "alarm":
                examples.append({"case": case, "report_id": key[1], "cell_id": cell,
                                 "generation_us": generation, "decision_clock_us": clock,
                                 "reported_imsis": imsis,
                                 "latest_reference_imsis": [u[1] for u in frames[clock].cells[cell]]})
            decision_rows += 1
    if not decision_rows or any(p["methods"] != set(METHODS) for p in packets.values()):
        raise RuntimeError("Missing method decisions for delivered reports.")
    for case in CASES:
        stats = summary["channel_stats"][case]
        if stats["source_packets"] != stats["delivered_live"] + stats["dropped_packets"]:
            raise RuntimeError("Source, dropped, and delivered report counts disagree.")
        if stats["source_forged"] != stats["delivered_forged_live"] + stats["dropped_forged"]:
            raise RuntimeError("Injected, dropped, and delivered forgery counts disagree.")
        if stats["delivered_outside_live"]:
            raise RuntimeError("The channel delivered packets after the live run.")
        for method in METHODS:
            metric = metrics[case][method]
            if (dict(metric) != summary["metrics_live_only"][case][method]
                    or metric["live_total"] != stats["delivered_live"]
                    or metric["live_attack"] != stats["delivered_forged_live"]):
                raise RuntimeError("Decision counts disagree with summary/channel accounting.")
    return {"audit_status": "PASS", "decision_rows": decision_rows,
            "delivered_packets_all_cases": len(packets), "reference_frames": len(frames),
            "receipt_rounding_tolerance_seconds": 0.000002,
            "false_alarm_examples_for_count_rule": examples,
            "interpretation": "Post-run reconstruction with a per-decision causal cutoff; no verdicts changed."}


def run_harness(command, repo, env, log_path):
    """Keep live intake in the existing harness; echo compact progress."""
    folder = None
    last_progress = 0.0
    with log_path.open("w") as log:
        process = subprocess.Popen(command, cwd=repo, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, errors="replace", bufsize=1)
        try:
            for line in process.stdout:
                log.write(line)
                log.flush()
                if line.startswith("Results: "):
                    if folder is not None:
                        raise RuntimeError("The harness announced more than one result folder.")
                    folder = Path(line.strip().removeprefix("Results: ")).resolve()
                    if folder.parent != (repo / "test_open").resolve() or not folder.name.startswith("ran_faults_"):
                        raise RuntimeError("Unexpected harness result path.")
                if line.startswith("LIVE wall=") and time.monotonic() - last_progress >= 5:
                    print("  " + line.strip(), flush=True)
                    last_progress = time.monotonic()
            code = process.wait()
        except BaseException:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    process.wait(timeout=5)
            raise
        finally:
            process.stdout.close()
    return code, folder


def aggregate(batch, manifest):
    valid = [trial for trial in manifest["trials"] if trial["status"] == "PASS"]
    result = {"batch_status": "PASS" if len(valid) == len(manifest["rng_runs"]) else "CHECK_RESULTS",
              "planned_runs": len(manifest["rng_runs"]), "valid_runs": len(valid),
              "rng_runs": [t["rng_run"] for t in valid], "pilot_included_in_totals": False,
              "trials": manifest["trials"], "pooled": {},
              "experimental_unit": "one fresh simulation per distinct ns3 RngRun",
              "interpretation": "Packet totals are descriptive; packets/cases within a run are paired. First-alarm offsets use observed reference ticks, not exact E2 latency."}
    rows = []
    for case in CASES:
        result["pooled"][case] = {}
        for method in METHODS:
            metrics = [t["summary"]["metrics_live_only"][case][method] for t in valid]
            total = {key: sum(m[key] for m in metrics) for key in METRIC_KEYS}
            injected = sum(t["summary"]["channel_stats"][case]["source_forged"] for t in valid)
            dropped = sum(t["summary"]["channel_stats"][case]["dropped_forged"] for t in valid)
            delays = [t["transition"]["first_alarm_delay_on_observed_reference_clock"].get(case, {}).get(method, {}).get("delay_ms") for t in valid]
            measured = [d for d in delays if d is not None]
            row = {"case": case, "method": method, **total, "all_injected_forged": injected,
                   "dropped_forged": dropped,
                   "false_alarm_fraction_of_delivered_benign": total["FP"] / total["live_benign"] if total["live_benign"] else None,
                   "detection_fraction_of_delivered_forged": total["TP"] / total["live_attack"] if total["live_attack"] else None,
                   "runs_with_false_alarms": sum(m["FP"] > 0 for m in metrics),
                   "runs_with_missed_attacks": sum(m["FN"] > 0 for m in metrics),
                   "runs_with_indeterminate": sum(m["indeterminate_benign"] + m["indeterminate_attack"] > 0 for m in metrics),
                   "first_alarm_observed_delay_ms_by_run": delays,
                   "min_observed_delay_ms": min(measured) if measured else None,
                   "max_observed_delay_ms": max(measured) if measured else None}
            result["pooled"][case][method] = row
            rows.append({key: value for key, value in row.items() if key != "first_alarm_observed_delay_ms_by_run"})
    save_json(batch / "batch_summary.json", result)
    with (batch / "batch_metrics.csv").open("w", newline="") as destination:
        writer = csv.DictWriter(destination, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print("\n=== REPEAT TRIAL SUMMARY ===", flush=True)
    print(f"BATCH_STATUS={result['batch_status']} VALID_RUNS={len(valid)}/{result['planned_runs']} RngRun={result['rng_runs']}")
    for row in rows:
        print(f"CASE={row['case']} METHOD={row['method']} BENIGN={row['live_benign']} FP={row['FP']} "
              f"TP={row['TP']}/{row['live_attack']} FN={row['FN']} "
              f"INDETERMINATE={row['indeterminate_benign']}/{row['indeterminate_attack']} "
              f"FORGED_DROPPED={row['dropped_forged']} FP_RUNS={row['runs_with_false_alarms']}/{len(valid)}")
    for case in ("forged", "forged_faults"):
        for method in METHODS:
            values = result["pooled"][case][method]
            print(f"OBSERVED_DELAY CASE={case} METHOD={method} RANGE_MS={values['min_observed_delay_ms']}..{values['max_observed_delay_ms']}")
    print("Lost reports have no security verdict. Packet totals within a run are correlated.")
    print("Results saved in: " + str(batch), flush=True)
    return result["batch_status"]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--scripts-dir", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--rng-runs", type=rng_runs, default=rng_runs("6202,6203,6204,6205,6206"))
    parser.add_argument("--pilot-dir", type=Path)
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()
    repo, scripts = args.repo.expanduser().resolve(), args.scripts_dir.expanduser().resolve()
    dependencies = [scripts / "ran_online_detector.py", scripts / "ran_live_faults.py",
                    scripts / "install_ran_late_attach_v2.py"]
    if not dependencies[-1].is_file():
        dependencies[-1] = scripts / "install_ran_late_attach.py"
    if not (repo / "ns3").is_file() or not all(path.is_file() for path in dependencies):
        parser.error("Run from the repo and keep the three existing scripts beside this file (or use --scripts-dir).")
    source_paths = [repo / "scratch/scenario-online-security.cc", repo / "src/mmwave/helper/mmwave-helper.cc"]
    for path, marker in zip(source_paths, ("BEGIN RAN_SECURITY_LATE_ATTACH_V2", "BEGIN RAN_SECURITY_LATE_NAS_V2")):
        if not path.is_file() or marker not in path.read_text():
            parser.error("Install and pass the V2 genuine-join trial before running repetitions.")
    if "RAN_SECURITY_LATE_NAS_V2" not in dependencies[-1].read_text():
        parser.error("The late-attach controller is an older version; use install_ran_late_attach_v2.py.")
    (repo / "test_open").mkdir(exist_ok=True)
    batch = Path(tempfile.mkdtemp(prefix="ran_repeat_", dir=str(repo / "test_open")))
    frozen = batch / "scripts"
    frozen.mkdir()
    for path, name in zip(dependencies, ("ran_online_detector.py", "ran_live_faults.py", "install_ran_late_attach_v2.py")):
        shutil.copy2(path, frozen / name)
    shutil.copy2(Path(__file__).resolve(), frozen / "ran_repeat_trials.py")
    sys.path.insert(0, str(frozen))
    base = load_module("ran_online_detector", frozen / "ran_online_detector.py")
    late = load_module("ran_repeat_late_controller", frozen / "install_ran_late_attach_v2.py")
    source_hashes = {str(p.relative_to(repo)): sha256(p) for p in source_paths}
    manifest = {"rng_runs": args.rng_runs, "trials": [], "pilot_included_in_totals": False,
                "source_sha256": source_hashes, "script_sha256": {p.name: sha256(p) for p in frozen.iterdir() if p.is_file()},
                "parameters": {"late_attach_ms": 500, "ues": 2, "sim_seconds": 1.7,
                               "delay_ms": 250, "grace_ms": 300, "fault_window_ms": [300, 1400],
                               "forgery_window_ms": [1000, 1400], "drop_times_ms": [400, 600, 1100, 1300]},
                "source_clock": "simulator time aligned to received complete RRC snapshots",
                "generation_metadata_and_labels_are_rule_inputs": False}
    print("Batch results: " + str(batch), flush=True)
    save_json(batch / "manifest.json", manifest)
    try:
        if args.pilot_dir:
            pilot = args.pilot_dir.expanduser().resolve()
            pilot_config = json.loads((pilot / "config.json").read_text())
            if pilot_config["seed"] in args.rng_runs:
                raise RuntimeError("The requested RngRun list repeats the pilot's RngRun.")
            audited = audit_run(pilot, base)
            save_json(batch / "pilot_audit.json", {"folder": str(pilot), **audited})
            print(f"PILOT_AUDIT={audited['audit_status']} DECISION_ROWS={audited['decision_rows']}", flush=True)
            for example in audited["false_alarm_examples_for_count_rule"][:6]:
                print("PILOT_FALSE_ALARM " + json.dumps(example), flush=True)
        if not args.skip_build:
            print("Building the existing V2 scenario once...", flush=True)
            subprocess.run([str(repo / "ns3"), "build", "-j", "2"], cwd=repo, check=True)
        binary = repo / "build/scratch/ns3.42-scenario-online-security-default"
        if binary.is_file():
            manifest["scenario_binary_sha256"] = sha256(binary)
        for index, rng_run in enumerate(args.rng_runs, 1):
            if any(sha256(p) != source_hashes[str(p.relative_to(repo))] for p in source_paths):
                raise RuntimeError("Scenario sources changed during the batch; stopped before the next trial.")
            command = [sys.executable, str(frozen / "ran_live_faults.py"), "--repo", str(repo),
                       "--ues", "2", "--seed", str(rng_run), "--sim-seconds", "1.7",
                       "--grace-ms", "300", "--delay-ms", "250", "--fault-start-ms", "300",
                       "--fault-end-ms", "1400", "--forge-start-ms", "1000", "--forge-end-ms", "1400",
                       "--drop-times-ms", "400,600,1100,1300", "--max-wall-seconds", "180"]
            trial = {"rng_run": rng_run, "status": "RUNNING", "command": command}
            manifest["trials"].append(trial)
            save_json(batch / "manifest.json", manifest)
            print(f"\nTRIAL={index}/{len(args.rng_runs)} RngRun={rng_run}", flush=True)
            code, folder = run_harness(command, repo, dict(os.environ, RAN_SECURITY_LATE_ATTACH_MS="500"),
                                      batch / f"trial_{rng_run}.log")
            trial.update({"return_code": code, "folder": str(folder) if folder else None})
            if code != 0 or folder is None:
                raise RuntimeError(f"RngRun {rng_run} failed; inspect trial_{rng_run}.log and its result folder.")
            control = {**manifest["parameters"], "rng_run": rng_run, "source_sha256": source_hashes,
                       "command": command, "batch_folder": str(batch), "attach_mode": "V2 PHY startup / delayed native NAS Connect"}
            save_json(folder / "experiment_control.json", control)
            with (batch / f"trial_{rng_run}.log").open("a") as log, redirect_stdout(log):
                joined = late.summarize(folder, 500, control)
            if not joined:
                raise RuntimeError(f"RngRun {rng_run}: the genuine UE join was not validated.")
            audit = audit_run(folder, base)
            save_json(folder / "decision_audit.json", audit)
            trial.update({"status": "PASS", "audit": audit,
                          "summary": json.loads((folder / "summary.json").read_text()),
                          "transition": json.loads((folder / "transition_validation.json").read_text())})
            save_json(batch / "manifest.json", manifest)
            print(f"TRIAL_STATUS=PASS JOIN=PASS AUDIT=PASS SOURCE_REPORTS={trial['summary']['counts']['source_reports_runner_running']}", flush=True)
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError, base.DataError, KeyboardInterrupt) as error:
        message = str(error) or "Interrupted; completed and partial results are retained."
        manifest["error"] = f"{type(error).__name__}: {message}"
        if manifest["trials"] and manifest["trials"][-1]["status"] == "RUNNING":
            manifest["trials"][-1].update({"status": "CHECK_RESULTS", "error": manifest["error"]})
        print("STOP: " + manifest["error"], flush=True)
    finally:
        save_json(batch / "manifest.json", manifest)
    return 0 if aggregate(batch, manifest) == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
