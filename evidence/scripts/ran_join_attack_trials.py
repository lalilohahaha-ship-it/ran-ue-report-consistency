#!/usr/bin/env python3
"""Test forged new UE-ID entries across the genuine UE join, using live intake.

Select the passed ran_windows_... checkpoint with --window-batch. Reuse its
verified scripts, native sources, five RngRun values, 2.0 s duration and five
paired channel cases. Only the report-copy forgery window changes from
1000--1400 ms to 300--700 ms. The second real UE starts connection at 500 ms.
Two history windows (300 and 100 ms) use the same 250 ms channel delay.

The earlier warm-up results for C1/C4 are comparison records, not new samples.
Source membership and complete raw RRC snapshots must match the earlier run
with the same RngRun. Count, membership and time-aware rules are unchanged.
An indeterminate attack is reported separately from a detected attack and an
accepted attack. No post-run information changes a live verdict. First-alarm
offsets describe the attack episode on the received reference clock, not every
packet's detection latency or exact E2 latency. PASS measures data quality,
causal auditing and source pairing, independently of detection performance.
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


PROFILES = (
    {"id": "J1", "delay_ms": 250, "grace_ms": 300, "comparison_id": "C1"},
    {"id": "J2", "delay_ms": 250, "grace_ms": 100, "comparison_id": "C4"},
)
SCRIPT_NAMES = ("ran_online_detector.py", "ran_live_faults.py", "install_ran_late_attach_v2.py",
                "ran_repeat_trials.py", "ran_window_sweep.py")
SOURCE_NAMES = ("scratch/scenario-online-security.cc", "src/mmwave/helper/mmwave-helper.cc")


def diagnose(folder, base):
    """Explain ambiguous attack packets using only their recorded history cutoff."""
    config = json.loads((folder / "config.json").read_text())
    grace_us = round(config["grace_ms"] * 1000)
    stream, frames = base.StateStream(grace_us, config["forge_imsi"]), []
    with (folder / "ue_events.csv.states.csv").open() as source:
        for row in csv.DictReader(source):
            frame = stream.accept(row)
            if frame is not None:
                frames.append(frame)
    with (folder / "reference_receipts.csv").open() as source:
        receipts = {int(r["sim_time_us"]): float(r["received_wall_s"]) for r in csv.DictReader(source)}
    with (folder / "decisions.csv").open() as source:
        rows = [r for r in csv.DictReader(source) if r["included_in_live_metrics"] == "1"]
    by_packet = {}
    for row in rows:
        by_packet.setdefault((row["case"], row["report_id"]), {})[row["method"]] = row
    ambiguous, count_accepted = [], []
    for methods in by_packet.values():
        temporal = methods["time_aware"]
        if temporal["synthetic_attack"] != "1":
            continue
        case, clock, cell = temporal["case"], int(temporal["reference_watermark_us"]), int(temporal["cell_id"])
        count, wall = int(temporal["reported_count"]), float(temporal["decision_wall_s"])
        common = {"case": case, "report_id": int(temporal["report_id"]), "cell_id": cell,
                  "source_generation_us": int(temporal["source_generation_us"]),
                  "decision_clock_us": clock, "reported_count": count,
                  "reported_imsis": json.loads(temporal["reported_imsis"]),
                  "verdicts": {name: r["verdict"] for name, r in methods.items()}}
        if methods["ue_count"]["verdict"] == "consistent":
            count_accepted.append(common)
        if temporal["verdict"] != "indeterminate":
            continue
        candidates = []
        for frame in frames:
            if not clock - grace_us <= frame.stamp_us <= clock:
                continue
            contexts = frame.cells[cell]
            if count != len(contexts) or not any(ue[1] == 0 for ue in contexts):
                continue
            if receipts[frame.stamp_us] > wall + 0.000002:
                raise RuntimeError("Diagnostic frame arrived after its decision.")
            candidates.append({"snapshot_us": frame.stamp_us,
                               "known_imsis": sorted({u[1] for u in contexts if u[1] > 0}),
                               "unknown_rntis": [u[0] for u in contexts if u[1] == 0]})
        if temporal["reason"] == "unknown_reference_identity" and not candidates:
            raise RuntimeError("Indeterminate verdict has no count-compatible unknown reference.")
        ambiguous.append({**common, "reason": temporal["reason"], "compatible_unknown_frames": candidates})
    return {"time_aware_indeterminate_attack_packets": ambiguous,
            "ue_count_accepted_attack_packets": count_accepted,
            "unresolved_attack_is_counted_as_detected": False,
            "diagnostics_change_live_verdicts": False,
            "interpretation": "Raw historical unknown identities are inspected only at each decision's causal cutoff."}


def totals(trials, controller, baseline=False):
    pooled = {}
    for case in controller.CASES:
        pooled[case] = {}
        for method in controller.METHODS:
            records = [t["comparison_summary" if baseline else "summary"]["metrics_live_only"][case][method]
                       for t in trials]
            values = {key: sum(record[key] for record in records) for key in controller.METRIC_KEYS}
            values["false_alarm_fraction_of_delivered_benign"] = values["FP"] / values["live_benign"] if values["live_benign"] else None
            values["detection_fraction_of_delivered_forged"] = values["TP"] / values["live_attack"] if values["live_attack"] else None
            pooled[case][method] = values
    return pooled


def summarize(batch, manifest, controller):
    valid = [t for t in manifest["trials"] if t["status"] == "PASS"]
    profiles, rows = {}, []
    for profile in PROFILES:
        selected = [t for t in valid if t["profile_id"] == profile["id"]]
        current, previous = totals(selected, controller), totals(selected, controller, baseline=True)
        profiles[profile["id"]] = {**profile, "valid_runs": len(selected),
                                   "overlap_metrics": current, "warmup_comparison_metrics": previous}
        for label, metrics in (("overlap_300_700_ms", current), ("warmup_1000_1400_ms_existing", previous)):
            for case in controller.CASES:
                for method in controller.METHODS:
                    rows.append({"profile_id": profile["id"], "delay_ms": profile["delay_ms"],
                                 "grace_ms": profile["grace_ms"], "attack_window": label,
                                 "case": case, "method": method, "valid_runs": len(selected), **metrics[case][method]})
    planned = len(PROFILES) * len(manifest["rng_runs"])
    issues = [t["pairing_issue"] for t in valid if t.get("pairing_issue")]
    status = "PASS" if len(valid) == planned and not issues and not manifest.get("error") else "CHECK_RESULTS"
    report = {"join_attack_status": status, "valid_runs": len(valid), "planned_runs": planned,
              "rng_runs": manifest["rng_runs"], "profiles": profiles, "pairing_issues": issues,
              "per_run_results": manifest["trials"], "unresolved_attacks_counted_as_detected": False,
              "interpretation": "Live new UE-ID insertion overlaps the genuine join. Earlier warm-up runs are paired comparison data, not additional independent samples. Unresolved verdicts remain separate; no decisions are revised post-run."}
    controller.save_json(batch / "join_attack_summary.json", report)
    with (batch / "join_attack_metrics.csv").open("w", newline="") as destination:
        writer = csv.DictWriter(destination, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print("\n=== JOIN ATTACK SUMMARY ===", flush=True)
    print(f"JOIN_ATTACK_STATUS={status} VALID_RUNS={len(valid)}/{planned} PAIRED_SOURCE_MATCH={'PASS' if not issues else 'CHECK_RESULTS'}")
    for profile in PROFILES:
        group = profiles[profile["id"]]
        print(f"\nCONFIG={profile['id']} DELAY_MS={profile['delay_ms']} GRACE_MS={profile['grace_ms']} VALID_RUNS={group['valid_runs']}/{len(manifest['rng_runs'])}")
        for case in ("forged", "forged_faults"):
            print("  CASE=" + case)
            for method in controller.METHODS:
                current = group["overlap_metrics"][case][method]
                previous = group["warmup_comparison_metrics"][case][method]
                print(f"    METHOD={method} OVERLAP_TP={current['TP']}/{current['live_attack']} "
                      f"FN={current['FN']} ATTACK_INDETERMINATE={current['indeterminate_attack']} "
                      f"FP={current['FP']}/{current['live_benign']} BENIGN_INDETERMINATE={current['indeterminate_benign']} "
                      f"WARMUP_TP={previous['TP']}/{previous['live_attack']}")
        selected = [t for t in valid if t["profile_id"] == profile["id"]]
        unresolved = sum(len(t["diagnostic"]["time_aware_indeterminate_attack_packets"]) for t in selected)
        accepted = sum(len(t["diagnostic"]["ue_count_accepted_attack_packets"]) for t in selected)
        dropped = sum(t["summary"]["channel_stats"]["forged_faults"]["dropped_forged"] for t in selected)
        print(f"  TIME_AWARE_UNRESOLVED_ATTACK_PACKETS={unresolved} COUNT_ACCEPTED_ATTACK_PACKETS={accepted} MIXED_FORGED_DROPPED={dropped}")
        examples = [e for t in selected for e in t["diagnostic"]["time_aware_indeterminate_attack_packets"]]
        for example in examples[:2]:
            print("  UNKNOWN_REFERENCE_EXAMPLE=" + json.dumps(example))
    for issue in issues:
        print("PAIRING_ISSUE=" + issue)
    print("PASS checks data quality. Indeterminate attacks are unresolved, not detected.")
    print("Reserved new UE-ID insertion only. Episode offsets are not exact E2 latency.")
    print("Results saved in: " + str(batch), flush=True)
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--window-batch", type=Path, required=True)
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()
    repo, checkpoint = args.repo.expanduser().resolve(), args.window_batch.expanduser().resolve()
    previous = json.loads((checkpoint / "window_manifest.json").read_text())
    results = json.loads((checkpoint / "window_summary.json").read_text())
    if results["sweep_status"] != "PASS" or results["pairing_issues"]:
        parser.error("Select a passed, fully paired window sweep.")
    for name in SCRIPT_NAMES:
        path = checkpoint / "scripts" / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != previous["script_sha256"][name]:
            parser.error("A script in the checkpoint is missing or changed: " + name)
    sources = [repo / name for name in SOURCE_NAMES]
    if any(not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != previous["source_sha256"][str(path.relative_to(repo))] for path in sources):
        parser.error("The native sources differ from the passed sweep.")
    if previous["common_parameters"]["sim_seconds"] != 2.0 or previous["common_parameters"]["forgery_window_ms"] != [1000, 1400]:
        parser.error("The comparison checkpoint must use 2.0 s and a 1000--1400 ms forgery window.")
    for profile in PROFILES:
        condition = next(c for c in previous["conditions"] if c["id"] == profile["comparison_id"])
        if any(condition[key] != profile[key] for key in ("delay_ms", "grace_ms")):
            parser.error("Comparison condition has different delay or grace parameters.")
    comparisons = {}
    for trial in previous["trials"]:
        key = (trial["condition_id"], trial["rng_run"])
        if key in comparisons or trial["status"] != "PASS":
            parser.error("The checkpoint has duplicate or failed trials.")
        comparisons[key] = trial
    (repo / "test_open").mkdir(exist_ok=True)
    batch = Path(tempfile.mkdtemp(prefix="ran_join_attacks_", dir=str(repo / "test_open")))
    frozen = batch / "scripts"
    frozen.mkdir()
    for name in SCRIPT_NAMES:
        shutil.copy2(checkpoint / "scripts" / name, frozen / name)
    shutil.copy2(Path(__file__).resolve(), frozen / "ran_join_attack_trials.py")
    for name in SOURCE_NAMES:
        target = batch / "source_snapshot" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(repo / name, target)
    sys.path.insert(0, str(frozen))
    import ran_repeat_trials as controller
    import ran_window_sweep as windows
    base = controller.load_module("ran_online_detector", frozen / "ran_online_detector.py")
    late = controller.load_module("ran_join_late", frozen / "install_ran_late_attach_v2.py")
    runs = controller.rng_runs(",".join(str(run) for run in previous["rng_runs"]))
    common = {**previous["common_parameters"], "forgery_window_ms": [300, 700]}
    manifest = {"window_batch": str(checkpoint), "rng_runs": runs, "profiles": PROFILES, "trials": [],
                "common_parameters": common, "source_sha256": previous["source_sha256"],
                "script_sha256": {p.name: controller.sha256(p) for p in frozen.iterdir() if p.is_file()},
                "generation_metadata_and_labels_are_rule_inputs": False,
                "past_comparison_runs_are_new_independent_samples": False}
    controller.save_json(batch / "join_attack_manifest.json", manifest)
    print(f"Join-attack results: {batch}\nPROFILES={len(PROFILES)} RUNS_PER_PROFILE={len(runs)} TOTAL_NEW_RUNS={len(PROFILES)*len(runs)}", flush=True)
    try:
        if not args.skip_build:
            print("Building the same V2 scenario once...", flush=True)
            subprocess.run([str(repo / "ns3"), "build", "-j", "2"], cwd=repo, check=True)
        binary = repo / "build/scratch/ns3.42-scenario-online-security-default"
        if binary.is_file():
            manifest["scenario_binary_sha256"] = controller.sha256(binary)
        for profile in PROFILES:
            for run in runs:
                if any(controller.sha256(path) != previous["source_sha256"][str(path.relative_to(repo))] for path in sources):
                    raise RuntimeError("Native RAN sources changed during the experiment.")
                if binary.is_file() and controller.sha256(binary) != manifest.get("scenario_binary_sha256"):
                    raise RuntimeError("The scenario executable changed during the experiment.")
                comparison = comparisons[(profile["comparison_id"], run)]
                command = [sys.executable, str(frozen / "ran_live_faults.py"), "--repo", str(repo),
                           "--ues", "2", "--seed", str(run), "--sim-seconds", "2.0",
                           "--delay-ms", "250", "--grace-ms", str(profile["grace_ms"]),
                           "--fault-start-ms", "300", "--fault-end-ms", "1400", "--forge-start-ms", "300",
                           "--forge-end-ms", "700", "--drop-times-ms", "400,600,1100,1300", "--max-wall-seconds", "240"]
                trial = {"profile_id": profile["id"], "rng_run": run, "status": "RUNNING", "command": command,
                         "comparison_folder": comparison["folder"]}
                manifest["trials"].append(trial)
                controller.save_json(batch / "join_attack_manifest.json", manifest)
                print(f"\nTRIAL={len(manifest['trials'])}/{len(PROFILES)*len(runs)} CONFIG={profile['id']} RngRun={run} GRACE_MS={profile['grace_ms']} FORGE_WINDOW_MS=300..700", flush=True)
                log_path = batch / f"{profile['id']}_run_{run}.log"
                code, folder = controller.run_harness(command, repo, dict(os.environ, RAN_SECURITY_LATE_ATTACH_MS="500"), log_path)
                trial.update({"return_code": code, "folder": str(folder) if folder else None})
                if code != 0 or folder is None:
                    raise RuntimeError("Live experiment failed; inspect " + log_path.name)
                control = {**common, **profile, "rng_run": run, "command": command,
                           "source_sha256": previous["source_sha256"], "batch_folder": str(batch),
                           "attach_mode": "V2 PHY startup / native NAS Connect at 500 ms"}
                controller.save_json(folder / "experiment_control.json", control)
                with log_path.open("a") as log, redirect_stdout(log):
                    joined = late.summarize(folder, 500, control)
                if not joined:
                    raise RuntimeError("The genuine UE join did not pass validation.")
                transition = json.loads((folder / "transition_validation.json").read_text())
                transition["interpretation"] = "Native UE join starts at 500 ms; forgeries at 300--700 ms overlap the join. RRC information is post-run validation only; live rules use the received protected snapshots. First-alarm offsets describe an episode, not every attack packet."
                controller.save_json(folder / "transition_validation.json", transition)
                audit = controller.audit_run(folder, base)
                controller.save_json(folder / "decision_audit.json", audit)
                fingerprints = windows.source_fingerprints(folder)
                diagnostic = diagnose(folder, base)
                controller.save_json(folder / "join_attack_diagnostic.json", diagnostic)
                issue = None if fingerprints == comparison["fingerprints"] else f"{profile['id']} RngRun {run}: source states/reports differ from the warm-up comparison."
                trial.update({"status": "PASS", "pairing_issue": issue, "fingerprints": fingerprints, "audit": audit,
                              "diagnostic": diagnostic, "transition": transition,
                              "summary": json.loads((folder / "summary.json").read_text()),
                              "comparison_summary": comparison["summary"]})
                controller.save_json(batch / "join_attack_manifest.json", manifest)
                print(f"TRIAL_STATUS=PASS JOIN=PASS AUDIT=PASS SOURCE_PAIR={'PASS' if issue is None else 'CHECK_RESULTS'} "
                      f"TIME_AWARE_UNRESOLVED_ATTACKS={len(diagnostic['time_aware_indeterminate_attack_packets'])}", flush=True)
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        manifest["error"] = f"{type(error).__name__}: {str(error) or 'Interrupted; partial results retained.'}"
        if manifest["trials"] and manifest["trials"][-1]["status"] == "RUNNING":
            manifest["trials"][-1].update({"status": "CHECK_RESULTS", "error": manifest["error"]})
        print("STOP: " + manifest["error"], flush=True)
    finally:
        controller.save_json(batch / "join_attack_manifest.json", manifest)
    return 0 if summarize(batch, manifest, controller) == "PASS" else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, RuntimeError, StopIteration, argparse.ArgumentTypeError) as error:
        raise SystemExit(f"STOP: {error}") from error
