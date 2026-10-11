#!/usr/bin/env python3
"""Prepare a GitHub-ready project from the verified RAN handover directory.

The input is read-only. A new folder holds browsable frozen Python scripts,
two simulator source snapshots, and the complete original evidence bundle.
Verification reuses the recorded causal audit. No simulator or network action
is started. Python 3.10+ and its standard library are sufficient.
"""

import argparse
import hashlib
import importlib.util
import json
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path


PROJECT = "ran-ue-report-consistency"
sys.dont_write_bytecode = True


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
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def safe_path(root, relative):
    name = Path(relative)
    require(not name.is_absolute() and ".." not in name.parts,
            "Invalid project path: " + relative)
    path = root / name
    require(path.resolve().is_relative_to(root.resolve()), "Path escapes the project.")
    return path


def load_collector(folder):
    require(not any(p.is_symlink() for p in folder.rglob("*")),
            "Use a handover directory containing regular files, without symbolic links.")
    manifest = read_json(folder / "evidence_manifest.json")
    script = folder / "ran_collect_evidence.py"
    require(manifest["status"] == "PASS"
            and manifest["file_sha256"].get(script.name) == sha256(script),
            "The evidence collector differs from its passed export.")
    spec = importlib.util.spec_from_file_location("ran_github_evidence", script)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def project_readme(records, totals):
    conditions = list(dict.fromkeys(r["condition"] for r in records))
    seeds = sorted({r["rng_run"] for r in records})
    lookup = {(r["condition"], r["case"], r["method"]): r for r in totals}
    lines = ["# Detecting Forged UE Reports under Missing and Delayed Telemetry", "",
             "A research prototype for live, per-cell UE report consistency checks in ns-O-RAN.", "",
             "**Question:** Can protected UE connection-state history reduce false alarms caused by delayed reports while retaining detection of inserted, never-connected UE IDs?", "",
             "## Implementation", "",
             "| Component | Code |", "|---|---|",
             "| UE count, UE membership, and time-aware consistency rules | [ran_online_detector.py](scripts/ran_online_detector.py) |",
             "| Live intake and five paired channel views | [ran_live_faults.py](scripts/ran_live_faults.py) |",
             "| Repeated trials | [ran_repeat_trials.py](scripts/ran_repeat_trials.py) |",
             "| Delay/history sensitivity experiments | [ran_window_sweep.py](scripts/ran_window_sweep.py) |",
             "| Forgery overlapping a genuine UE join | [ran_join_attack_trials.py](scripts/ran_join_attack_trials.py) |",
             "| Instrumented simulator source snapshots | [simulator/](simulator/) |", "",
             "The count baseline compares against the latest received RRC snapshot. Membership also compares UE IDs. "
             "The time-aware rule requires count and membership to match the same received snapshot within a recent history window. "
             "Generation timestamps and attack labels are used for experiment scheduling and scoring, not by these rules.", "",
             "## Recorded experiments", "",
             f"The evidence contains **{len(records)} distinct simulation runs**, covering {len(conditions)} conditions and "
             f"{len(seeds)} RngRun values ({', '.join(map(str, seeds))}). Conditions reuse those values for pairing. "
             "Each physical run feeds normal, missing-whole-report, delayed, forged, and forged-plus-faults views. "
             "Packets and views within a run are correlated; conditions and simulation durations are kept separate.", "",
             "Selected delayed-only results, shown as false alarms / delivered benign reports:", "",
             "| Condition | Count | Membership | Time-aware |", "|---|---:|---:|---:|"]
    for condition in conditions:
        if condition not in ("C1", "C3", "C4", "C5"):
            continue
        fractions = [f"{lookup[(condition, 'delayed', m)]['FP']}/{lookup[(condition, 'delayed', m)]['live_benign']}"
                     for m in ("ue_count", "ue_membership", "time_aware")]
        lines.append("| " + " | ".join([condition, *fractions]) + " |")
    lines += ["", "Forgery overlapping the genuine UE join, with missing/delayed reports:", "",
              "| Condition | Method | Detected / delivered forged | Accepted forged (FN) | Unresolved forged |",
              "|---|---|---:|---:|---:|"]
    for condition in conditions:
        if not condition.startswith("J"):
            continue
        for method in ("ue_count", "ue_membership", "time_aware"):
            row = lookup[(condition, "forged_faults", method)]
            lines.append(f"| {condition} | {method} | {row['TP']}/{row['live_attack']} | {row['FN']} | {row['indeterminate_attack']} |")
    lines += ["", "Dropped reports receive no security verdict. Unresolved attacks remain in the delivered-attack denominator. "
              "See the [complete condition definitions and interpretation](evidence/README.md), "
              "[condition metrics](evidence/condition_metrics.csv), and [per-run metrics](evidence/per_run_metrics.csv).", "",
              "## Verify the archived results", "",
              "From the project folder, with Python 3.10+:", "",
              "```bash", "python3 scripts/ran_prepare_github.py --verify-repo .", "```", "",
              "Expected: `GITHUB_VERIFY=PASS`. This checks the frozen source copies, file hashes, accounting, and "
              "causality of the original live decisions. PASS describes evidence quality and permits detector errors. "
              "Verification needs no original VM paths, simulator installation, or external Python packages.", "",
              "## Run a fresh simulation", "",
              "A fresh run requires the complete matching ns-O-RAN repository, its dependencies, and a successful build. "
              "This project includes two source snapshots, not the full simulator. "
              "Follow the [fresh live trial instructions](evidence/README.md#fresh-live-trial-in-the-matching-lab-repository); "
              "set `RAN_HANDOVER_DIR` to this project's `evidence` folder. The frozen batch controllers retain their original checkpoint requirements.", "",
              "## Scope", "",
              "Decisions were made while ns3 ran, by tailing local CSV logs. Actual E2 transport, xApp deployment, "
              "mitigation, and physical PRB changes were not evaluated. Forgeries insert reserved UE ID 99999 into "
              "parsed report copies. The protected reference and reports originate in the same simulator/RRC model; "
              "this is an experimental trust assumption. ID reuse, replay, replacement, partial per-UE loss, "
              "and faulty reference telemetry require separate evaluation.", "",
              "A history match is not a direct report-age limit. First-alarm episode offsets use the received "
              "simulation-reference clock and are not exact E2 or processing latency. "
              "Preliminary related-work screening is included in the handover README; general novelty is not established.", "",
              "## Repository contents", "",
              "`scripts/` exposes the frozen experiment code. `simulator/` exposes the two native source snapshots. "
              "`evidence/` retains the complete verified handover bundle, including its original scripts, raw logs, "
              "live decisions, metrics, provenance, and file index. The duplicate code copies are checked against the archive.", "",
              "This folder is prepared for a private GitHub repository. Repository creation and upload are separate steps. "
              "Existing notices in the simulator source snapshots are retained; no new project-wide license is selected here.", ""]
    return "\n".join(lines)


def verify_repo(folder, quiet=False):
    require(not any(p.is_symlink() for p in folder.rglob("*") if ".git" not in p.parts),
            "Project verification does not accept symbolic links.")
    metadata = read_json(folder / "repository_manifest.json")
    require(metadata["status"] == "PASS", "Project preparation did not pass.")
    evidence = folder / "evidence"
    require(sha256(evidence / "evidence_manifest.json") == metadata["evidence_manifest_sha256"],
            "The handover evidence index changed.")
    records = load_collector(evidence).verify_bundle(evidence, quiet=True)
    require(len(records) == metadata["unique_simulation_runs"], "Project run count differs.")
    for destination, original in metadata["derived_files"].items():
        require(sha256(safe_path(folder, destination)) == sha256(safe_path(folder, original)),
                "Frozen source copy differs from the archive: " + destination)
    require(sha256(folder / "scripts" / "ran_prepare_github.py") == metadata["preparer_sha256"],
            "The project preparation script changed.")
    if not quiet:
        print(f"GITHUB_VERIFY=PASS UNIQUE_SIMULATION_RUNS={len(records)}")
    return records


def prepare(handover, output):
    require(output != handover and not output.is_relative_to(handover),
            "Choose an output folder outside the handover directory.")
    require(not output.exists(), "Output already exists; choose a new --output folder.")
    archive = output.with_suffix(".zip")
    require(archive != output, "Choose a directory name without a .zip suffix.")
    require(not archive.exists(), "The output ZIP already exists; choose a new --output folder.")
    records = load_collector(handover).verify_bundle(handover, quiet=True)
    require(bool(records) and (handover / "README.md").is_file()
            and (handover / "handover_metadata.json").is_file(), "Use the completed handover directory.")
    manifest = read_json(handover / "evidence_manifest.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ran_github_stage_", dir=output.parent) as temporary:
        stage = Path(temporary) / output.name
        stage.mkdir()
        evidence = stage / "evidence"
        evidence.mkdir()
        for name in (*manifest["file_sha256"], "evidence_manifest.json"):
            source, destination = safe_path(handover, name), safe_path(evidence, name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        derived = {}
        for relative in manifest["file_sha256"]:
            if relative.startswith("scripts/"):
                destination = relative
            elif relative.startswith("source_snapshot/"):
                destination = "simulator/" + relative.removeprefix("source_snapshot/")
            else:
                continue
            target = safe_path(stage, destination)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(safe_path(handover, relative), target)
            derived[destination] = "evidence/" + relative
        preparer = stage / "scripts" / "ran_prepare_github.py"
        require(not preparer.exists(), "An unexpected preparation script exists in the frozen checkpoint.")
        shutil.copyfile(Path(__file__).resolve(), preparer)
        (stage / "README.md").write_text(project_readme(records, read_json(evidence / "condition_metrics.json")),
                                        encoding="utf-8")
        (stage / ".gitignore").write_text("__pycache__/\n*.py[cod]\n.venv/\nvenv/\n.DS_Store\nThumbs.db\n*.zip\nbuild/\ncmake-cache/\ntest_open/\n.env\n.env.*\n", encoding="utf-8")
        (stage / ".gitattributes").write_text(
            "# Preserve the audited bytes on Windows, Linux, and macOS checkouts.\n* -text\n", encoding="utf-8")
        write_json(stage / "repository_manifest.json", {
            "status": "PASS", "recommended_visibility": "private",
            "unique_simulation_runs": len(records), "derived_files": derived,
            "evidence_manifest_sha256": sha256(evidence / "evidence_manifest.json"),
            "preparer_sha256": sha256(preparer), "simulation_started": False,
            "github_upload_performed": False, "live_verdicts_changed": False})
        verify_repo(stage, quiet=True)
        files = [p for p in stage.rglob("*") if p.is_file()]
        require(all(p.stat().st_size < 100 * 1024 * 1024 for p in files),
                "A file needs large-file handling before a regular GitHub upload.")
        with tempfile.NamedTemporaryFile(prefix="ran_github_zip_", suffix=".zip", dir=output.parent,
                                         delete=False) as temporary_zip:
            temporary_archive = Path(temporary_zip.name)
        try:
            with zipfile.ZipFile(temporary_archive, "w", compression=zipfile.ZIP_DEFLATED) as destination:
                for source in sorted(files):
                    destination.write(source, str(Path(output.name) / source.relative_to(stage)))
            stage.rename(output)
            temporary_archive.rename(archive)
        finally:
            temporary_archive.unlink(missing_ok=True)
    print(f"GITHUB_PREP_STATUS=PASS UNIQUE_SIMULATION_RUNS={len(records)}")
    print("PROJECT: " + str(output))
    print("ZIP: " + str(archive))
    print("ZIP_SHA256=" + sha256(archive))
    print("Prepared local project files. No GitHub upload or simulation was started.")
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--handover-dir", type=Path)
    action.add_argument("--verify-repo", type=Path)
    parser.add_argument("--output", type=Path, default=Path.home() / PROJECT)
    args = parser.parse_args()
    if args.verify_repo:
        verify_repo(args.verify_repo.expanduser().resolve())
    else:
        prepare(args.handover_dir.expanduser().resolve(), args.output.expanduser().resolve())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, RuntimeError, StopIteration) as error:
        raise SystemExit(f"STOP: {error}") from error

