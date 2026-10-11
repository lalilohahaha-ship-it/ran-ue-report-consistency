#!/usr/bin/env python3
"""Make a documented handover ZIP from a passed ran_evidence_... directory.

Run from the original ns-O-RAN repository. The input evidence, native sources,
detector, and recorded live verdicts stay unchanged. A new directory receives
the verified evidence, an English README generated from audited metrics, and
the repository state observed at handover. The completed copy is re-audited
before creating its ZIP. Only Python's standard library is required.
"""

import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path


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


def load_collector(folder):
    manifest = read_json(folder / "evidence_manifest.json")
    source = folder / "ran_collect_evidence.py"
    require(manifest["status"] == "PASS" and manifest["file_sha256"][source.name] == sha256(source),
            "The evidence collector differs from its passed export.")
    spec = importlib.util.spec_from_file_location("ran_handover_evidence", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def repository_state(repo, expected_hashes):
    for name, digest in expected_hashes.items():
        require(sha256(repo / name) == digest, "Repository source differs from the evidence: " + name)
    def git(*arguments):
        try:
            result = subprocess.run(["git", "-C", str(repo), *arguments], text=True,
                                    capture_output=True, timeout=5)
            return result.stdout.strip() if result.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            return None
    return {"recorded_utc": datetime.now(timezone.utc).isoformat(),
            "git_head_at_handover": git("rev-parse", "HEAD"),
            "tracked_file_status_at_handover": git("status", "--porcelain", "--untracked-files=no", "--", "."),
            "source_sha256": expected_hashes,
            "historical_experiment_git_commit_verified": False,
            "interpretation": "Git state is observed at handover. Two native source files match their experiment snapshots; the full repository is not included."}


def readme(records, totals, manifest):
    lookup = {(r["condition"], r["case"], r["method"]): r for r in totals}
    conditions = list(dict.fromkeys(r["condition"] for r in records))
    parameters = {r["condition"]: r["parameters"] for r in records}
    methods = ("ue_count", "ue_membership", "time_aware")
    runs = sorted({r["rng_run"] for r in records})
    lines = ["# Forged UE reports: live ns-O-RAN prototype", "",
             "Research question: Can checking UE report membership against protected RRC connection-state history reduce delay-induced false alarms while retaining detection of inserted, never-connected UE IDs?", "",
             f"This bundle contains {len(records)} distinct simulation runs across {len(conditions)} conditions, using RngRun values {', '.join(map(str, runs))}. "
             "The five channel views within each run share one physical simulation: normal, missing whole reports, delayed reports, forged entries, and forgery combined with missing/delayed reports. "
             "RngRun values are reused across conditions for pairing. Reused comparison runs and the initial pilot are not additional samples.", "",
             "## Start here", "",
             "Extract the ZIP and enter its top-level folder. Verify all recorded decisions and file hashes:", "",
             "```bash", "python3 ran_collect_evidence.py --verify-bundle .", "```", "",
             "Expected: `BUNDLE_VERIFY=PASS`. Verification works without the original VM paths or simulator installation. "
             "PASS means that data, causal auditing, and accounting agree; it permits false positives, false negatives, and unresolved verdicts.", "",
             "| File | Purpose |", "|---|---|",
             "| `condition_metrics.csv` / `.json` | Descriptive totals within each condition |",
             "| `per_run_metrics.csv` | Counts for each RngRun, case, and method |",
             "| `packet_examples.json` | Count-rule misses and benign mismatches explained by historical snapshots |",
             "| `runs/` | Raw reference states/events, source CU-CP logs, channel events, receipt times, and live decisions |",
             "| `scripts/` | Frozen detector, harness, and experiment controllers |",
             "| `source_snapshot/` | Two native source files used by the experiments |",
             "| `checkpoints/` | Original batch records; their absolute paths document provenance |",
             "| `handover_metadata.json` | Input evidence hash and repository state observed at handover |", "",
             "## Conditions", "",
             "Two real UEs are configured. Native connection for the second starts at 500 ms. RRC snapshots are sampled every 10 ms of simulator time. "
             "Delay scheduling follows the latest received complete reference snapshot at report interception.", "",
             "| Condition | Runs | Simulation seconds | Delay ms | History ms | Forgery generation window ms |",
             "|---|---:|---:|---:|---:|---|"]
    for condition in conditions:
        p = parameters[condition]
        n = sum(r["condition"] == condition for r in records)
        lines.append(f"| {condition} | {n} | {p['sim_seconds']:g} | {p['delay_ms']:g} | {p['grace_ms']:g} | {p['forgery_window_ms'][0]}–{p['forgery_window_ms'][1]} |")
    lines += ["", "R1 uses 1.7 s; later conditions use 2.0 s to allow delayed reports to drain. Different durations are kept separate. "
              "Generation timestamps and synthetic attack labels support experiment scheduling/metrics; they are not inputs to the three detector rules.", "",
              "## Results from the audited data", "",
              "Entries below are false alarms / delivered benign reports in the delayed-only case. Count and membership use the latest received snapshot; time-aware requires count and membership to match one snapshot in recent history.", "",
              "| Condition | UE count FP/benign | UE membership FP/benign | Time-aware FP/benign |",
              "|---|---:|---:|---:|"]
    for condition in conditions:
        cells = [f"{lookup[(condition, 'delayed', m)]['FP']}/{lookup[(condition, 'delayed', m)]['live_benign']}" for m in methods]
        lines.append("| " + " | ".join([condition, *cells]) + " |")
    lines += ["", "Attacks overlapping the genuine UE join, in the forged-plus-faults case:", "",
              "| Condition | Method | Detected/delivered forged | Accepted forged (FN) | Unresolved forged |",
              "|---|---|---:|---:|---:|"]
    for condition in conditions:
        if not condition.startswith("J"):
            continue
        for method in methods:
            row = lookup[(condition, "forged_faults", method)]
            lines.append(f"| {condition} | {method} | {row['TP']}/{row['live_attack']} | {row['FN']} | {row['indeterminate_attack']} |")
        row = lookup[(condition, "forged_faults", "time_aware")]
        lines.append("")
        lines.append(f"{condition}: {row['injected_forged']} forged reports were injected; {row['dropped_forged']} were dropped before delivery. Dropped reports receive no security verdict and are excluded from delivered-attack recall.")
        lines.append("")
        if condition != conditions[-1]:
            lines += ["| Condition | Method | Detected/delivered forged | Accepted forged (FN) | Unresolved forged |",
                      "|---|---|---:|---:|---:|"]
    examples = [e for r in records if r["stage"] == "join"
                for e in r["examples"]["count_accepted_forged_packets"]
                if e["case"] == "forged_faults"]
    if examples:
        e = examples[0]
        lines += [f"Count-rule miss example ({e['condition']}, RngRun {e['rng_run']}, cell {e['cell_id']}): "
                  f"report generated at {e['generation_us']/1000:g} ms, decided on reference clock {e['decision_clock_us']/1000:g} ms. "
                  f"Reported IDs were `{e['reported_imsis']}` with count {e['reported_count']}; latest reference IDs were `{e['latest_reference_imsis']}` with count {e['latest_reference_count']}. "
                  f"Verdicts: `{json.dumps(e['verdicts'], sort_keys=True)}`.", ""]
    lines += ["## Interpretation and limits", "",
              "The result supports a scoped comparison of connection-state consistency rules under telemetry faults and real UE joins. "
              "A history window allows a match to a recent state; it is not a direct report-age check. False alarms can remain when the needed old state has left the window.", "",
              "Collection and decisions were live while ns3 was running, by tailing local simulator CSV logs. This is a report-plane prototype; actual E2 transport, an xApp deployment, mitigation, and physical PRB changes were not evaluated. "
              "The attack changes parsed report copies by inserting reserved new UE ID 99999 and incrementing the count. It does not create physical UEs. "
              "ID reuse, replay, replacement, partial per-UE record loss, corrupted reference telemetry, and broader join/leave/handover populations require separate evaluation.", "",
              "The report and reference paths are separate, but both come from the same simulator/RRC model. Reference completeness and integrity are protected assumptions in this experiment, not demonstrated hardware or cryptographic independence. "
              "Checks are per cell against raw RRC context membership, including temporary contexts. A multi-connectivity UE can legitimately appear in both its LTE anchor and a mmWave cell. "
              "Raw temporary unknown identities can produce `indeterminate`; an unresolved attack is neither a true positive nor a false negative. "
              "FP fractions use all delivered benign reports, and TP fractions use all delivered forged reports, including unresolved ones in those denominators.", "",
              "First-alarm offsets are measured from the first intercepted forged report to the first alarm on the received simulation reference clock. "
              "They describe an episode and are not exact E2 latency, wall-clock processing latency, or per-packet detection delay. "
              f"Packets and channel views within a run are correlated. These {len(records)} simulation runs use {len(runs)} distinct RngRun values, paired across conditions. "
              "Use per-run metrics for comparisons and keep conditions separate.", "",
              "## Fresh live trial in the matching lab repository", "",
              "Portable verification above needs only this bundle. A fresh simulation additionally needs the original complete ns-O-RAN tree, its dependencies, matching source snapshots, and a successful build. "
              "The bundle does not contain the full repository or install its dependencies. Run the following from the matching repository, replacing the handover folder path:", "",
              "```bash", 'RAN_HANDOVER_DIR="/absolute/path/to/extracted/handover"',
              "./ns3 build -j 2",
              'RAN_SECURITY_LATE_ATTACH_MS=500 NS_LOG="" python3 "$RAN_HANDOVER_DIR/scripts/ran_live_faults.py" \\\n  --repo "$PWD" --ues 2 --seed 6202 --sim-seconds 2.0 \\\n  --delay-ms 250 --grace-ms 300 \\\n  --fault-start-ms 300 --fault-end-ms 1400 \\\n  --forge-start-ms 300 --forge-end-ms 700 \\\n  --drop-times-ms 400,600,1100,1300 --max-wall-seconds 240',
              "```", "",
              "This is one J1-style live trial, saved into a new result directory. It does not replace the exported evidence. "
              "The batch controllers retain their original checkpoint path requirements; their recorded absolute paths are not portable rerun inputs.", "",
              "## Related work: preliminary positioning", "",
              "Existing work already covers malicious telemetry detection, state consistency, and protected operational evidence. "
              "The contribution proposed here is the scoped comparison around delay, whole-report loss, history-window limits, and a genuine UE join. Priority or general novelty is not established by this screening.", "",
              "- [Rogue Cell / MARRS](https://arxiv.org/html/2505.01816v1): detects manipulated cell telemetry using LSTM autoencoders; sequence-based detection reduces outlier-induced false positives.",
              "- [INVARAN: Invariant-Guided Logical Testing of Open RAN Controllers](https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_yang-tianchang.pdf): finds semantic controller flaws with inferred invariants, including state inconsistencies and falsified reports; discusses delayed/lost acknowledgments.",
              "- [Closing the Visibility Gap](https://arxiv.org/html/2509.03000v1): monitors O-RU configuration/control state using hardware-rooted signed evidence for policy verification.", ""]
    return "\n".join(lines)


def prepare(folder, repo):
    sys.dont_write_bytecode = True
    collector = load_collector(folder)
    records = collector.verify_bundle(folder, quiet=True)
    original = read_json(folder / "evidence_manifest.json")
    require(bool(records), "No verified experiment runs.")
    hashes = records[0]["source_sha256"]
    require(all(r["source_sha256"] == hashes for r in records), "Native source versions differ.")
    state = repository_state(repo, hashes)
    totals = read_json(folder / "condition_metrics.json")
    document = readme(records, totals, original)
    output = Path(tempfile.mkdtemp(prefix="ran_handover_", dir=str(folder.parent)))
    shutil.copytree(folder, output, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (output / "README.md").write_text(document)
    shutil.copy2(Path(__file__).resolve(), output / "ran_prepare_handover.py")
    write_json(output / "handover_metadata.json", {"status": "PASS", "input_evidence_directory": str(folder),
               "input_evidence_manifest_sha256": sha256(folder / "evidence_manifest.json"),
               "unique_simulation_runs": len(records), "repository_observed_at_handover": state,
               "created_new_simulations": False, "recorded_verdicts_changed": False})
    manifest = dict(original)
    manifest["file_sha256"] = {str(p.relative_to(output)): sha256(p) for p in output.rglob("*")
                               if p.is_file() and p.name != "evidence_manifest.json"}
    write_json(output / "evidence_manifest.json", manifest)
    try:
        collector.verify_bundle(output, quiet=True)
    except Exception:
        manifest["status"] = "CHECK_RESULTS"
        write_json(output / "evidence_manifest.json", manifest)
        raise
    archive = output.with_suffix(".zip")
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as destination:
        for source in sorted(output.rglob("*")):
            if source.is_file():
                destination.write(source, str(Path(output.name) / source.relative_to(output)))
    print(f"HANDOVER_STATUS=PASS UNIQUE_SIMULATION_RUNS={len(records)}")
    print("README: " + str(output / "README.md"))
    print("ZIP: " + str(archive))
    print("ZIP_SHA256=" + sha256(archive))
    print("Original evidence and live verdicts preserved. No simulation started.")
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    args = parser.parse_args()
    prepare(args.evidence_dir.expanduser().resolve(), args.repo.expanduser().resolve())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, RuntimeError, StopIteration) as error:
        raise SystemExit(f"STOP: {error}") from error
