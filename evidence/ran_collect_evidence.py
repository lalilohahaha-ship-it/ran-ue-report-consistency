#!/usr/bin/env python3
"""Audit and package the existing live RAN experiments without running ns3.

Select ran_join_attacks_... with --join-batch. Follow its recorded window and
repeat checkpoints, audit each distinct run, and export one portable ZIP.
The initial pilot and reused warm-up comparisons are not additional samples.
Metrics remain separate for each condition and simulation duration. Recorded
live verdicts are checked, never replaced by a new classification.

After extracting the ZIP, --verify-bundle PATH checks its file hashes and
repeats the causal audit using the included frozen rules. Python's standard
library is sufficient. No build, installer, source edit, or simulation starts.
"""

import argparse
import csv
import hashlib
import importlib.util
import json
import shutil
import sys
import tempfile
import zipfile
from collections import Counter
from pathlib import Path


STAGES = (
    ("repeat", "manifest.json", "batch_summary.json", "batch_status"),
    ("windows", "window_manifest.json", "window_summary.json", "sweep_status"),
    ("join", "join_attack_manifest.json", "join_attack_summary.json", "join_attack_status"),
)
RUN_FILES = ("config.json", "summary.json", "decisions.csv", "channel_events.jsonl",
             "reference_receipts.csv", "ue_events.csv", "ue_events.csv.states.csv",
             "experiment_control.json", "transition_validation.json", "decision_audit.json")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path):
    return json.loads(path.read_text())


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def read_csv(path):
    with path.open() as source:
        return list(csv.DictReader(source))


def write_csv(path, rows):
    require(bool(rows), "No metric rows to export.")
    with path.open("w", newline="") as destination:
        writer = csv.DictWriter(destination, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def bundle_path(root, relative):
    path = (root / relative).resolve()
    require(path.is_relative_to(root.resolve()), "A bundle path escapes its root.")
    return path


def checkpoint_chain(join_folder):
    join = read_json(join_folder / "join_attack_manifest.json")
    windows_folder = Path(join["window_batch"]).expanduser().resolve()
    windows = read_json(windows_folder / "window_manifest.json")
    repeat_folder = Path(windows["baseline_batch"]).expanduser().resolve()
    folders = {"repeat": repeat_folder, "windows": windows_folder, "join": join_folder}
    checkpoints, records, seen = {}, [], set()
    for stage, manifest_name, summary_name, status_name in STAGES:
        folder = folders[stage]
        manifest, summary = read_json(folder / manifest_name), read_json(folder / summary_name)
        require(summary[status_name] == "PASS" and not manifest.get("error")
                and not summary.get("pairing_issues"), "Checkpoint did not pass: " + str(folder))
        rng_runs = manifest["rng_runs"]
        require(rng_runs and len(set(rng_runs)) == len(rng_runs), "Duplicate or missing RngRun values.")
        require(rng_runs == join["rng_runs"], "Checkpoint RngRun lists differ.")
        require(manifest["source_sha256"] == join["source_sha256"], "Native source checkpoints differ.")
        for name, digest in manifest["script_sha256"].items():
            require(sha256(folder / "scripts" / name) == digest, "Changed checkpoint script: " + name)
            require(join["script_sha256"].get(name) == digest, "Different script versions across stages: " + name)
        groups = [{"id": "R1"}] if stage == "repeat" else manifest["conditions" if stage == "windows" else "profiles"]
        expected = {(g["id"], run) for g in groups for run in rng_runs}
        actual = set()
        for trial in manifest["trials"]:
            group_id = "R1" if stage == "repeat" else trial["condition_id" if stage == "windows" else "profile_id"]
            key = (group_id, trial["rng_run"])
            require(key in expected and key not in actual and trial["status"] == "PASS"
                    and trial["return_code"] == 0 and not trial.get("pairing_issue"), "Incomplete or duplicate trial.")
            actual.add(key)
            run_folder = Path(trial["folder"]).expanduser().resolve()
            require(run_folder not in seen, "A reused run would be counted twice: " + str(run_folder))
            seen.add(run_folder)
            require(read_json(run_folder / "summary.json") == trial["summary"], "Run summary changed after its checkpoint.")
            group = next(g for g in groups if g["id"] == group_id)
            parameters = dict(manifest["parameters"] if stage == "repeat" else manifest["common_parameters"])
            parameters.update({k: group[k] for k in ("delay_ms", "grace_ms") if k in group})
            records.append({"stage": stage, "condition": group_id, "rng_run": trial["rng_run"],
                            "parameters": parameters, "original_folder": str(run_folder),
                            "run_path": f"runs/{group_id}_run_{trial['rng_run']}",
                            "source_sha256": manifest["source_sha256"],
                            "expected_fingerprints": trial.get("fingerprints"),
                            "comparison_id": group.get("comparison_id")})
        require(actual == expected and summary["valid_runs"] == len(expected), "Missing planned runs.")
        checkpoints[stage] = {"folder": str(folder), "manifest": manifest,
                              "manifest_name": manifest_name, "summary_name": summary_name}
    return checkpoints, records


def load_rules(scripts):
    base = load_module("ran_online_detector", scripts / "ran_online_detector.py")
    controller = load_module("ran_evidence_audit", scripts / "ran_repeat_trials.py")
    windows = load_module("ran_evidence_windows", scripts / "ran_window_sweep.py")
    late = load_module("ran_evidence_late", scripts / "install_ran_late_attach_v2.py")
    return base, controller, windows, late


def reference_frames(folder, base, config):
    stream, frames = base.StateStream(round(config["grace_ms"] * 1000), config["forge_imsi"]), {}
    for row in read_csv(folder / "ue_events.csv.states.csv"):
        frame = stream.accept(row)
        if frame is not None:
            frames[frame.stamp_us] = frame
    require(stream.current is None and frames, "Incomplete UE reference.")
    return frames


def packet_examples(folder, record, frames):
    packets, accepted, tolerated = {}, [], []
    for row in read_csv(folder / "decisions.csv"):
        if row["included_in_live_metrics"] == "1":
            packets.setdefault((row["case"], row["report_id"]), {})[row["method"]] = row
    for methods in packets.values():
        count, temporal = methods["ue_count"], methods["time_aware"]
        attack = count["synthetic_attack"] == "1"
        count_miss = attack and count["verdict"] == "consistent"
        delay_tolerated = (not attack and count["verdict"] == "alarm" and temporal["verdict"] == "consistent")
        if not count_miss and not delay_tolerated:
            continue
        cell, clock = int(count["cell_id"]), int(count["reference_watermark_us"])
        latest = frames[clock].cells[cell]
        match = int(temporal["matching_snapshot_us"]) if temporal["matching_snapshot_us"] else None
        example = {"condition": record["condition"], "rng_run": record["rng_run"],
                   "case": count["case"], "report_id": int(count["report_id"]), "cell_id": cell,
                   "generation_us": int(count["source_generation_us"]), "decision_clock_us": clock,
                   "reported_count": int(count["reported_count"]),
                   "reported_imsis": json.loads(count["reported_imsis"]),
                   "latest_reference_count": len(latest), "latest_reference_imsis": sorted(u[1] for u in latest),
                   "latest_reference_raw_contexts": [list(u) for u in latest],
                   "verdicts": {name: row["verdict"] for name, row in methods.items()},
                   "time_aware_matching_snapshot_us": match,
                   "matching_snapshot_imsis": sorted(u[1] for u in frames[match].cells[cell]) if match is not None else None}
        (accepted if count_miss else tolerated).append(example)
    return {"count_accepted_forged_packets": accepted, "benign_mismatches_tolerated_by_history": tolerated}


def audit_record(folder, record, modules, scripts):
    base, controller, windows, late = modules
    config, parameters = read_json(folder / "config.json"), record["parameters"]
    require(config["seed"] == record["rng_run"], "Run has a different RngRun.")
    for key in ("ues", "sim_seconds", "delay_ms", "grace_ms"):
        require(config[key] == parameters[key], "Parameter mismatch: " + key)
    for prefix, parameter in (("forge", "forgery_window_ms"), ("fault", "fault_window_ms")):
        require([config[prefix + "_start_ms"], config[prefix + "_end_ms"]] == parameters[parameter], "Attack/fault window changed.")
    drop_times = sorted({float(value.strip()) for value in config["drop_times_ms"].split(",") if value.strip()})
    require(drop_times == parameters["drop_times_ms"], "Drop schedule changed.")
    require(config["scenario_sha256"] == record["source_sha256"]["scratch/scenario-online-security.cc"]
            and config["harness_sha256"] == sha256(scripts / "ran_live_faults.py"), "Run source/harness hashes differ.")
    audit = controller.audit_run(folder, base)
    fingerprints = windows.source_fingerprints(folder)
    if record["expected_fingerprints"] is not None:
        require(fingerprints == record["expected_fingerprints"], "Saved source pairing data changed.")
    frames = reference_frames(folder, base, config)
    transition = read_json(folder / "transition_validation.json")
    attach_us = round(parameters["late_attach_ms"] * 1000)
    before = {u[1] for f in frames.values() if f.stamp_us < attach_us for cell in f.cells.values() for u in cell if u[1] > 0}
    after = {u[1] for f in frames.values() if f.stamp_us >= attach_us for cell in f.cells.values() for u in cell if u[1] > 0}
    events = [r for r in read_csv(folder / "ue_events.csv") if r["event"] == "CONNECTION_ESTABLISHED" and int(r["imsi"]) in after - before]
    require(transition["transition_status"] == "PASS" and len(before) == 1 and len(after) == 2
            and before < after and events and all(int(e["sim_time_us"]) >= attach_us for e in events)
            and transition["planned_late_attach_us"] == attach_us
            and transition["known_ue_ids_before_attach"] == sorted(before)
            and transition["known_ue_ids_at_or_after_attach"] == sorted(after), "Genuine UE join validation disagrees with the raw reference.")
    offsets = late.observed_clock_delays(folder)
    require(offsets == transition["first_alarm_delay_on_observed_reference_clock"], "Recorded first-alarm offsets changed.")
    return {**record, "audit": audit, "fingerprints": fingerprints,
            "metrics": read_json(folder / "summary.json")["metrics_live_only"],
            "channel_stats": read_json(folder / "summary.json")["channel_stats"],
            "first_alarm_offsets": offsets, "examples": packet_examples(folder, record, frames)}


def check_pairing(records):
    lookup = {(r["condition"], r["rng_run"]): r for r in records}
    for run in {r["rng_run"] for r in records}:
        windows = [r for r in records if r["stage"] == "windows" and r["rng_run"] == run]
        require(all(r["fingerprints"] == windows[0]["fingerprints"] for r in windows), "Source pairing across delay/window conditions failed.")
    for record in records:
        if record["stage"] == "join":
            previous = lookup[(record["comparison_id"], record["rng_run"])]
            require(record["fingerprints"] == previous["fingerprints"], "Join/warm-up source pairing failed.")


def metric_tables(records, controller):
    rows = []
    for record in records:
        p = record["parameters"]
        for case in controller.CASES:
            stats = record["channel_stats"][case]
            for method in controller.METHODS:
                offsets = record["first_alarm_offsets"].get(case, {}).get(method, {})
                rows.append({"stage": record["stage"], "condition": record["condition"], "rng_run": record["rng_run"],
                             "sim_seconds": p["sim_seconds"], "delay_ms": p["delay_ms"], "grace_ms": p["grace_ms"],
                             "forge_start_ms": p["forgery_window_ms"][0], "forge_end_ms": p["forgery_window_ms"][1],
                             "case": case, "method": method, **record["metrics"][case][method],
                             "source_packets": stats["source_packets"], "dropped_packets": stats["dropped_packets"],
                             "injected_forged": stats["source_forged"], "dropped_forged": stats["dropped_forged"],
                             "first_alarm_episode_offset_ms": offsets.get("delay_ms")})
    groups = {}
    for row in rows:
        key = tuple(row[k] for k in ("stage", "condition", "sim_seconds", "delay_ms", "grace_ms", "forge_start_ms", "forge_end_ms", "case", "method"))
        groups.setdefault(key, []).append(row)
    totals = []
    sum_keys = (*controller.METRIC_KEYS, "source_packets", "dropped_packets", "injected_forged", "dropped_forged")
    for group in groups.values():
        first = group[0]
        total = {k: first[k] for k in ("stage", "condition", "sim_seconds", "delay_ms", "grace_ms", "forge_start_ms", "forge_end_ms", "case", "method")}
        total.update({"runs": len(group), **{k: sum(r[k] for r in group) for k in sum_keys}})
        measured = [r["first_alarm_episode_offset_ms"] for r in group if r["first_alarm_episode_offset_ms"] is not None]
        total.update({"FP_fraction_delivered_benign": total["FP"] / total["live_benign"] if total["live_benign"] else None,
                      "TP_fraction_delivered_forged": total["TP"] / total["live_attack"] if total["live_attack"] else None,
                      "runs_with_FP": sum(r["FP"] > 0 for r in group), "runs_with_FN": sum(r["FN"] > 0 for r in group),
                      "min_first_alarm_episode_offset_ms": min(measured) if measured else None,
                      "max_first_alarm_episode_offset_ms": max(measured) if measured else None})
        totals.append(total)
    return rows, totals


def verify_bundle(folder, quiet=False):
    manifest = read_json(folder / "evidence_manifest.json")
    require(manifest["status"] == "PASS", "Evidence export was incomplete.")
    hashes = manifest["file_sha256"]
    actual = {str(p.relative_to(folder)) for p in folder.rglob("*") if p.is_file() and p.name != "evidence_manifest.json"}
    require(actual == set(hashes), "Bundle contains missing or unexpected files.")
    for relative, digest in hashes.items():
        require(sha256(bundle_path(folder, relative)) == digest, "Bundle checksum failed: " + relative)
    scripts = folder / "scripts"
    require(len({r["run_path"] for r in manifest["runs"]}) == len(manifest["runs"]), "Duplicate runs in the bundle index.")
    modules = load_rules(scripts)
    records = [audit_record(bundle_path(folder, r["run_path"]), r, modules, scripts) for r in manifest["runs"]]
    check_pairing(records)
    rows, totals = metric_tables(records, modules[1])
    require(read_json(folder / "condition_metrics.json") == totals, "Exported totals differ from the run audit.")
    as_csv = lambda values: [{k: "" if v is None else str(v) for k, v in row.items()} for row in values]
    require(read_csv(folder / "per_run_metrics.csv") == as_csv(rows)
            and read_csv(folder / "condition_metrics.csv") == as_csv(totals), "CSV metrics differ from the run audit.")
    require(read_json(folder / "packet_examples.json") == {r["run_path"]: r["examples"] for r in records}, "Exported examples differ from the raw decisions.")
    require(len(rows) == manifest["metric_rows"] and len(records) == manifest["unique_simulation_runs"], "Export run counts disagree.")
    if not quiet:
        print(f"BUNDLE_VERIFY=PASS UNIQUE_SIMULATION_RUNS={len(records)} DECISION_ROWS={sum(r['audit']['decision_rows'] for r in records)}")
    return records


def collect(join_folder):
    checkpoints, index = checkpoint_chain(join_folder)
    scripts = join_folder / "scripts"
    modules = load_rules(scripts)
    records = []
    for number, record in enumerate(index, 1):
        records.append(audit_record(Path(record["original_folder"]), record, modules, scripts))
        print(f"AUDIT={number}/{len(index)} CONFIG={record['condition']} RngRun={record['rng_run']} STATUS=PASS", flush=True)
    check_pairing(records)
    output = Path(tempfile.mkdtemp(prefix="ran_evidence_", dir=str(join_folder.parent)))
    print("Evidence: " + str(output), flush=True)
    write_json(output / "evidence_manifest.json", {"status": "INCOMPLETE"})
    shutil.copytree(scripts, output / "scripts", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copy2(Path(__file__).resolve(), output / "ran_collect_evidence.py")
    for name, digest in checkpoints["join"]["manifest"]["source_sha256"].items():
        source = join_folder / "source_snapshot" / name
        require(sha256(source) == digest, "Native source snapshot changed: " + name)
        target = output / "source_snapshot" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    for stage, checkpoint in checkpoints.items():
        target = output / "checkpoints" / stage
        target.mkdir(parents=True)
        for name in (checkpoint["manifest_name"], checkpoint["summary_name"]):
            shutil.copy2(Path(checkpoint["folder"]) / name, target / name)
    for record in index:
        original, target = Path(record["original_folder"]), output / record["run_path"]
        target.mkdir(parents=True)
        for name in RUN_FILES:
            shutil.copy2(original / name, target / name)
        for source in original.glob("cu-cp-cell-*.txt"):
            shutil.copy2(source, target / source.name)
    rows, totals = metric_tables(records, modules[1])
    write_csv(output / "per_run_metrics.csv", rows)
    write_csv(output / "condition_metrics.csv", totals)
    write_json(output / "condition_metrics.json", totals)
    write_json(output / "packet_examples.json", {r["run_path"]: r["examples"] for r in records})
    stage_counts = dict(Counter(r["stage"] for r in records))
    manifest = {"status": "PASS", "unique_simulation_runs": len(records), "stage_counts": stage_counts,
                "metric_rows": len(rows), "runs": index,
                "pilot_and_reused_comparisons_included_as_extra_runs": False,
                "different_conditions_or_durations_pooled": False,
                "live_verdicts_changed": False, "simulation_started": False,
                "file_sha256": {str(p.relative_to(output)): sha256(p) for p in output.rglob("*")
                                if p.is_file() and p.name != "evidence_manifest.json"}}
    write_json(output / "evidence_manifest.json", manifest)
    try:
        verify_bundle(output, quiet=True)
    except Exception:
        manifest["status"] = "CHECK_RESULTS"
        write_json(output / "evidence_manifest.json", manifest)
        raise
    archive = output.with_suffix(".zip")
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as destination:
        for source in sorted(output.rglob("*")):
            if source.is_file() and "__pycache__" not in source.parts and source.suffix != ".pyc":
                destination.write(source, str(Path(output.name) / source.relative_to(output)))
    print(f"\nEVIDENCE_STATUS=PASS UNIQUE_SIMULATION_RUNS={len(records)} STAGES={json.dumps(stage_counts)}")
    for condition in ("J1", "J2"):
        examples = [e for r in records if r["condition"] == condition for e in r["examples"]["count_accepted_forged_packets"]]
        print(f"CONFIG={condition} COUNT_ACCEPTED_FORGED={len(examples)}")
        for example in examples[:2]:
            print("COUNT_MISS_EXAMPLE=" + json.dumps(example))
    print("Verdicts remain live; this step only audits and packages their evidence.")
    print("Packets and channel cases within a run are correlated. Dropped reports have no security verdict.")
    print("ZIP: " + str(archive))
    print("ZIP_SHA256=" + sha256(archive))
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--join-batch", type=Path)
    action.add_argument("--verify-bundle", type=Path)
    args = parser.parse_args()
    # Auditing importable frozen scripts must not write caches into checkpoints.
    sys.dont_write_bytecode = True
    if args.join_batch:
        collect(args.join_batch.expanduser().resolve())
    else:
        verify_bundle(args.verify_bundle.expanduser().resolve())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, RuntimeError, StopIteration) as error:
        raise SystemExit(f"STOP: {error}") from error
