#!/usr/bin/env python3
"""Live, log-based detector smoke test for the instrumented ns-O-RAN scenario.

Run from mmwave-LENA-oran after building scenario-online-security with the
V1 state-snapshot logger. No rebuild or changes to simulator source are made.
One fresh simulation feeds two views: the original reports and copies with a
new UE identity added between 300 and 700 simulation ms. This is report-plane
injection at the Python collector, not an E2/xApp or physical-UE attack.

Only complete, already received reference snapshots are used. The strict
rules compare with the latest snapshot. The time-aware rule requires both
count and membership to match ONE snapshot within the grace window; it does
not combine UE identities from different times. Raw per-cell RRC contexts
match this simulator's reporting semantics, including transitional contexts.
The reference is assumed protected from this report-only attacker.

runner_running is the status of the launched ns3 command. Post-exit data and
decisions are saved separately and excluded from live metrics. Reference
watermark minus report-generation time is an alignment offset, NOT measured
attack-detection latency. This short static-UE smoke test cannot demonstrate
a reduction in false positives from delayed or missing telemetry.
"""

import argparse
import csv
import hashlib
import json
import math
import os
import re
import signal
import subprocess
import tempfile
import time
from collections import Counter, deque
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path


METHODS = ("ue_count", "ue_membership", "time_aware")
CASES = ("normal", "forged")
STATE_COLUMNS = {"sim_time_us", "snapshot_id", "row_type", "cell_id",
                 "rnti", "imsi", "rrc_state", "rrc_path"}
KPM_COLUMNS = {"timestamp", "ueImsiComplete", "numActiveUes"}
STATE_PERIOD_US = 10000


class DataError(RuntimeError):
    """A collection/protocol problem, never a forged-UE verdict."""


class CsvTail:
    def __init__(self, path, required):
        self.path, self.required = path, required
        self.offset, self.pending, self.header, self.identity = 0, b"", None, None

    def read(self):
        if not self.path.exists():
            return []
        with self.path.open("rb") as source:
            stat = os.fstat(source.fileno())
            identity = (stat.st_dev, stat.st_ino)
            if self.identity is not None and identity != self.identity:
                raise DataError(f"File replaced: {self.path.name}")
            self.identity = identity
            if stat.st_size < self.offset:
                raise DataError(f"File truncated: {self.path.name}")
            source.seek(self.offset)
            chunk = source.read()
            self.offset += len(chunk)
        lines = (self.pending + chunk).split(b"\n")
        self.pending = lines.pop()
        rows = []
        for raw in lines:
            if not raw.strip():
                continue
            fields = next(csv.reader([raw.decode("utf-8").rstrip("\r")]))
            if self.header is None:
                if len(set(fields)) != len(fields) or not self.required <= set(fields):
                    raise DataError(f"Unexpected CSV header: {self.path.name}")
                self.header = fields
            elif len(fields) != len(self.header):
                raise DataError(f"Unexpected CSV width: {self.path.name}")
            else:
                rows.append(dict(zip(self.header, fields)))
        return rows


@dataclass(frozen=True)
class Snapshot:
    stamp_us: int
    sequence: int
    cells: dict


class StateStream:
    def __init__(self, grace_us, reserved_imsi):
        self.grace_us, self.reserved_imsi = grace_us, reserved_imsi
        self.current, self.latest, self.coverage = None, None, None
        self.history = deque()
        self.frames, self.first_us, self.cell_membership_changes = 0, None, 0

    def accept(self, row):
        stamp, seq = int(row["sim_time_us"]), int(row["snapshot_id"])
        kind, cell = row["row_type"], int(row["cell_id"])
        if kind == "BEGIN":
            if self.current is not None:
                raise DataError("Snapshot BEGIN before the preceding END.")
            if ((self.latest is None and (stamp, seq) != (0, 1))
                    or (self.latest is not None and
                        (stamp != self.latest.stamp_us + STATE_PERIOD_US
                         or seq != self.latest.sequence + 1))):
                raise DataError("Missing, delayed-in-file, or reordered reference frame.")
            self.current = {"stamp": stamp, "sequence": seq, "cells": {}, "paths": {}}
            return None
        cur = self.current
        if cur is None or (stamp, seq) != (cur["stamp"], cur["sequence"]):
            raise DataError("Snapshot framing mismatch.")
        if kind == "CELL":
            if cell <= 0 or cell in cur["cells"] or not row["rrc_path"]:
                raise DataError("Invalid or duplicate cell in reference snapshot.")
            cur["cells"][cell], cur["paths"][cell] = [], row["rrc_path"]
        elif kind == "UE":
            rnti, imsi, state = int(row["rnti"]), int(row["imsi"]), int(row["rrc_state"])
            if (cell not in cur["cells"] or rnti <= 0 or imsi < 0 or state < 0
                    or row["rrc_path"] != cur["paths"][cell]
                    or any(ue[0] == rnti for ue in cur["cells"][cell])):
                raise DataError("Invalid reference UE context.")
            if imsi == self.reserved_imsi:
                raise DataError("Synthetic forged IMSI is a real reference UE; choose another IMSI.")
            cur["cells"][cell].append((rnti, imsi, state))
        elif kind == "END":
            coverage = set(cur["cells"])
            if len(coverage) != 4 or (self.coverage is not None and coverage != self.coverage):
                raise DataError("Reference must cover the same four installed cells.")
            frame = Snapshot(stamp, seq, {c: tuple(ues) for c, ues in cur["cells"].items()})
            if self.latest is not None:
                self.cell_membership_changes += sum(
                    {ue[1] for ue in frame.cells[c]} != {ue[1] for ue in self.latest.cells[c]}
                    for c in coverage)
            self.latest, self.coverage, self.current = frame, coverage, None
            self.history.append(frame)
            while self.history and self.history[0].stamp_us < stamp - self.grace_us:
                self.history.popleft()
            self.frames += 1
            if self.first_us is None:
                self.first_us = stamp
            return frame
        else:
            raise DataError(f"Unknown reference row type: {kind}")
        return None


@dataclass(frozen=True)
class Report:
    cell: int
    generation_us: int
    count: int
    imsis: tuple
    source: str
    first_row_wall_s: float
    received_wall_s: float
    receipt_phase: str


class KpmStream:
    def __init__(self, cell, source):
        self.cell, self.source, self.current, self.last_us = cell, source, None, -1

    def accept(self, row, wall_s, phase):
        stamp = int(row["timestamp"]) * 1000  # This scenario writes simulation milliseconds.
        count, imsi = int(row["numActiveUes"]), int(row["ueImsiComplete"])
        if stamp <= self.last_us or count <= 0 or imsi < 0:
            raise DataError(f"Invalid/repeated KPM group: {self.source}")
        if self.current is None:
            self.current = {"stamp": stamp, "count": count, "imsis": [], "first_wall": wall_s}
        cur = self.current
        if (stamp, count) != (cur["stamp"], cur["count"]):
            raise DataError(f"Incomplete KPM group before the next report: {self.source}")
        cur["imsis"].append(imsi)
        if len(cur["imsis"]) == count:
            report = Report(self.cell, stamp, count, tuple(cur["imsis"]), self.source,
                            cur["first_wall"], wall_s, phase)
            self.current, self.last_us = None, stamp
            return report
        return None


def evaluate(cell, count, imsis, history, grace_us):
    """Rules receive a payload and already available history, never truth labels."""
    if not history or cell not in history[-1].cells:
        return {name: ("indeterminate", "no_reference", None) for name in METHODS}
    latest = history[-1]
    contexts = latest.cells[cell]
    members = set(imsis)
    reference_members = {ue[1] for ue in contexts}
    result = {"ue_count": (
        "consistent" if count == len(contexts) else "alarm", "latest_count", latest.stamp_us)}
    unknown_payload = 0 in members
    result["ue_membership"] = (
        ("indeterminate", "unknown_ue_identity", None) if unknown_payload or 0 in reference_members
        else ("consistent" if members == reference_members else "alarm",
              "latest_membership", latest.stamp_us))
    if unknown_payload:
        result["time_aware"] = ("indeterminate", "unknown_ue_identity", None)
        return result
    uncertain = False
    for frame in reversed(history):
        if not latest.stamp_us - grace_us <= frame.stamp_us <= latest.stamp_us:
            continue
        contexts = frame.cells.get(cell)
        if contexts is None:
            uncertain = True
            continue
        # RAN_TIME_WINDOW_COUNT_GUARD_V1
        # A different context count already rules out this complete snapshot,
        # even if some UE identities have not been resolved yet.
        if count != len(contexts):
            continue
        reference_members = {ue[1] for ue in contexts}
        if 0 in reference_members:
            uncertain = True
        elif count == len(contexts) and members == reference_members:
            result["time_aware"] = ("consistent", "one_matching_snapshot", frame.stamp_us)
            return result
    result["time_aware"] = (("indeterminate", "unknown_reference_identity", None) if uncertain
                            else ("alarm", "no_matching_snapshot_in_window", None))
    return result


class Collector:
    def __init__(self, out, args, process, started, decisions, reports, references):
        self.out, self.args, self.process, self.started = out, args, process, started
        self.decisions, self.reports, self.references = decisions, reports, references
        self.state = StateStream(round(args.grace_ms * 1000), args.forge_imsi)
        self.state_tail = CsvTail(out / "ue_events.csv.states.csv", STATE_COLUMNS)
        self.kpm_tails, self.kpm_streams, self.pending = {}, {}, deque()
        self.counts, self.metrics, self.report_id = Counter(), {}, 0
        self.first_report_wall_s, self.last_reference_wall_s = None, None
        for case in CASES:
            self.metrics[case] = {method: Counter() for method in METHODS}

    def phase(self):
        return "runner_running" if self.process.poll() is None else "after_exit"

    def wall(self):
        return time.monotonic() - self.started

    def read(self):
        # References read after this point cannot be used by this poll's decisions.
        for row in self.state_tail.read():
            frame = self.state.accept(row)
            if frame is not None:
                wall, phase = self.wall(), self.phase()
                self.last_reference_wall_s = wall
                self.counts["reference_frames_" + phase] += 1
                self.references.writerow([frame.sequence, frame.stamp_us, f"{wall:.6f}", phase])
        for path in sorted(self.out.glob("cu-cp-cell-*.txt")):
            match = re.fullmatch(r"cu-cp-cell-(\d+)\.txt", path.name)
            if match is None:
                continue
            if path not in self.kpm_tails:
                cell = int(match.group(1))
                self.kpm_tails[path], self.kpm_streams[path] = CsvTail(path, KPM_COLUMNS), KpmStream(cell, path.name)
            for row in self.kpm_tails[path].read():
                wall, phase = self.wall(), self.phase()
                self.counts["kpm_rows_" + phase] += 1
                report = self.kpm_streams[path].accept(row, wall, phase)
                if report is not None:
                    self.pending.append(report)
                    self.counts["reports_received_" + phase] += 1
                    if self.first_report_wall_s is None:
                        self.first_report_wall_s = wall
        self.decide_ready()

    def decide_ready(self):
        if self.state.latest is None:
            return
        waiting = deque()
        while self.pending:
            report = self.pending.popleft()
            # Generation metadata is unmodified in this identity/count-only attack.
            # Waiting for the protected clock avoids using a lagging reference.
            if report.generation_us > self.state.latest.stamp_us:
                waiting.append(report)
                continue
            if report.cell not in self.state.coverage:
                raise DataError(f"KPM cell {report.cell} has no reference coverage.")
            if self.args.forge_imsi in report.imsis:
                raise DataError("Synthetic forged IMSI already occurs in an original KPM report.")
            self.report_id += 1
            phase, watermark = self.phase(), self.state.latest.stamp_us
            live = report.receipt_phase == "runner_running" and phase == "runner_running"
            self.counts["reports_decided_live" if live else "reports_decided_outside_live"] += 1
            attacked = (round(self.args.forge_start_ms * 1000) <= report.generation_us
                        < round(self.args.forge_end_ms * 1000))
            for case in CASES:
                injected = case == "forged" and attacked
                count = report.count + int(injected)
                imsis = report.imsis + ((self.args.forge_imsi,) if injected else ())
                outcomes = evaluate(report.cell, count, imsis, self.state.history, self.state.grace_us)
                self.reports.write(json.dumps({
                    "report_id": self.report_id, "case": case, "source": report.source,
                    "cell_id": report.cell, "source_generation_us": report.generation_us,
                    "reported_count": count, "reported_imsis": imsis,
                    "first_row_wall_s": report.first_row_wall_s,
                    "received_wall_s": report.received_wall_s,
                    "receipt_phase": report.receipt_phase, "synthetic_attack": injected}) + "\n")
                for method, (verdict, reason, match_us) in outcomes.items():
                    wall = self.wall()
                    metric = self.metrics[case][method]
                    if live:
                        metric["live_total"] += 1
                        metric["live_attack" if injected else "live_benign"] += 1
                        if verdict == "indeterminate":
                            metric["indeterminate_attack" if injected else "indeterminate_benign"] += 1
                        else:
                            key = ("TP" if injected else "FP") if verdict == "alarm" else ("FN" if injected else "TN")
                            metric[key] += 1
                    else:
                        metric["outside_live"] += 1
                    self.decisions.writerow([
                        self.report_id, case, method, report.cell, report.generation_us,
                        report.receipt_phase, phase, int(live), f"{report.received_wall_s:.6f}",
                        f"{wall:.6f}", f"{(wall - report.received_wall_s) * 1000:.3f}",
                        watermark, f"{self.last_reference_wall_s:.6f}", match_us,
                        f"{(watermark - report.generation_us) / 1000:.3f}",
                        count, json.dumps(imsis), int(injected), verdict, reason])
                    if live and method == "time_aware":
                        if injected or metric["live_total"] <= 2:
                            print(f"LIVE {case}: cell={report.cell} sim={report.generation_us / 1000:g}ms "
                                  f"UEs={list(imsis)} verdict={verdict}", flush=True)
        self.pending = waiting

    def issues(self):
        issues = []
        if self.state.current is not None or self.state_tail.pending.strip():
            issues.append("trailing_incomplete_reference")
        if any(tail.pending.strip() for tail in self.kpm_tails.values()):
            issues.append("trailing_incomplete_kpm_line")
        if any(stream.current is not None for stream in self.kpm_streams.values()):
            issues.append("incomplete_kpm_group")
        if self.pending:
            issues.append("reports_waiting_for_reference_clock")
        if not self.state.frames:
            issues.append("no_reference_frames")
        if not self.counts["reports_decided_live"]:
            issues.append("no_live_report_decisions")
        if self.counts["reports_decided_outside_live"]:
            issues.append("reports_decided_outside_live")
        return issues


def stop_process(process):
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def positive_number(text):
    value = float(text)
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError("Must be finite and positive.")
    return value


def arguments():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--sim-seconds", type=positive_number, default=1.0)
    parser.add_argument("--seed", type=int, default=6201)
    parser.add_argument("--ues", type=int, default=1)
    parser.add_argument("--grace-ms", type=positive_number, default=300.0)
    parser.add_argument("--max-wall-seconds", type=positive_number, default=90.0)
    parser.add_argument("--forge-imsi", type=int, default=99999)
    parser.add_argument("--forge-start-ms", type=positive_number, default=300.0)
    parser.add_argument("--forge-end-ms", type=positive_number, default=700.0)
    args = parser.parse_args()
    if args.seed <= 0 or args.ues <= 0 or args.forge_imsi <= 0:
        parser.error("Seed, UE count and forged IMSI must be positive integers.")
    if not args.forge_start_ms < args.forge_end_ms <= args.sim_seconds * 1000:
        parser.error("Attack window must satisfy start < end <= simulation duration.")
    return args


def main():
    args = arguments()
    repo = args.repo.expanduser().resolve()
    source = repo / "scratch/scenario-online-security.cc"
    if not (repo / "ns3").is_file() or not source.is_file():
        raise SystemExit("Run from the ns-O-RAN repository containing the built reference scenario.")
    if "BEGIN RAN_SECURITY_STATE_SNAPSHOTS_V1" not in source.read_text():
        raise SystemExit("Install/build the V1 state-snapshot logger first.")
    (repo / "test_open").mkdir(exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix="ran_detector_", dir=str(repo / "test_open")))
    command = [str(repo / "ns3"), "run",
               f"scenario-online-security --RngRun={args.seed} --ues={args.ues} "
               f"--speedMin=3 --speedMax=10 --simTime={args.sim_seconds:g} "
               "--enableE2FileLogging=1 --SimulatorImplementationType=ns3::RealtimeSimulatorImpl",
               "--no-build", f"--cwd={out}"]
    config = {**vars(args), "repo": str(repo), "command": command,
              "scenario_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
              "detector_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "cases_share_one_simulation": True, "collection": "live_simulator_csv_logs",
              "attack_surface": "parsed_report_copy_at_collector",
              "protected_reference": "per_cell_raw_rrc_context_snapshots",
              "state_period_us": STATE_PERIOD_US,
              "time_rule": "count_and_membership_match_one_received_snapshot_in_grace_window",
              "clock": "latest_received_reference_snapshot_simulation_time",
              "generation_metadata_unmodified": True,
              "live_phase_definition": "ns3_command_running_at_report_completion_and_decision",
              "reference_offset_is_detection_delay": False}
    (out / "config.json").write_text(json.dumps(config, indent=2) + "\n")
    print(f"Results: {out}", flush=True)
    process, collector, stop_reason, error = None, None, "process_exit", None
    started, last_progress = time.monotonic(), 0.0
    try:
        with ExitStack() as stack:
            runlog = stack.enter_context((out / "run.log").open("w"))
            decision_file = stack.enter_context((out / "decisions.csv").open("w", newline=""))
            report_file = stack.enter_context((out / "received_reports.jsonl").open("w"))
            reference_file = stack.enter_context((out / "reference_receipts.csv").open("w", newline=""))
            decisions, references = csv.writer(decision_file), csv.writer(reference_file)
            decisions.writerow([
                "report_id", "case", "method", "cell_id", "source_generation_us",
                "receipt_phase", "decision_phase", "included_in_live_metrics", "received_wall_s",
                "decision_wall_s", "collector_wait_and_processing_ms", "reference_watermark_us",
                "reference_received_wall_s", "matching_snapshot_us", "reference_offset_ms",
                "reported_count", "reported_imsis", "synthetic_attack", "verdict", "reason"])
            references.writerow(["snapshot_id", "sim_time_us", "received_wall_s", "phase"])
            process = subprocess.Popen(command, cwd=repo,
                                       env=dict(os.environ, NS_LOG="", RAN_SECURITY_EVENT_LOG=str(out / "ue_events.csv")),
                                       stdout=runlog, stderr=subprocess.STDOUT, start_new_session=True)
            collector = Collector(out, args, process, started, decisions, report_file, references)
            try:
                while True:
                    collector.read()
                    for file in (decision_file, report_file, reference_file):
                        file.flush()
                    elapsed = time.monotonic() - started
                    if process.poll() is not None:
                        collector.read()  # Complete final drain is explicitly after_exit.
                        break
                    if elapsed >= args.max_wall_seconds:
                        stop_reason = "wall_limit"
                        stop_process(process)
                        collector.read()
                        break
                    if elapsed - last_progress >= 1:
                        print(f"LIVE wall={elapsed:.1f}s snapshots={collector.state.frames} "
                              f"reports={collector.counts['reports_decided_live']}", flush=True)
                        last_progress = elapsed
                    time.sleep(0.01)
            finally:
                stop_process(process)
    except (OSError, ValueError, DataError, UnicodeError, csv.Error) as exc:
        stop_reason, error = "collection_error", f"{type(exc).__name__}: {exc}"
    except KeyboardInterrupt:
        stop_reason, error = "interrupted", "Interrupted by user; partial results retained."
    finally:
        if process is not None:
            stop_process(process)
    issues = collector.issues() if collector is not None else ["collector_not_started"]
    if process is None or process.returncode != 0:
        issues.append("runner_failed")
    if stop_reason != "process_exit":
        issues.append(stop_reason)
    metrics = collector.metrics if collector else {}
    smoke_ok = bool(metrics) and not issues and all(
        metrics["normal"][method]["live_total"] > 0
        and metrics["normal"][method]["TN"] == metrics["normal"][method]["live_total"]
        and metrics["forged"][method]["live_attack"] > 0
        and metrics["forged"][method]["TP"] == metrics["forged"][method]["live_attack"]
        and metrics["forged"][method]["TN"] == metrics["forged"][method]["live_benign"]
        for method in METHODS)
    state = collector.state if collector else None
    summary = {"smoke_status": "PASS" if smoke_ok else "CHECK_RESULTS",
               "stop_reason": stop_reason, "return_code": process.returncode if process else None,
               "wall_seconds": time.monotonic() - started, "error": error, "data_issues": issues,
               "counts": dict(collector.counts) if collector else {},
               "first_report_wall_s": collector.first_report_wall_s if collector else None,
               "reference_frames": state.frames if state else 0,
               "reference_first_us": state.first_us if state else None,
               "reference_last_us": state.latest.stamp_us if state and state.latest else None,
               "reference_cells": sorted(state.coverage) if state and state.coverage else [],
               "reference_cell_membership_changes": state.cell_membership_changes if state else 0,
               "metrics_live_only": metrics,
               "interpretation": "Pipeline smoke only; no missing/delayed-report results or detection-delay claim."}
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print("\n=== ONLINE DETECTOR SMOKE ===")
    print(f"SMOKE_STATUS={summary['smoke_status']} STOP_REASON={stop_reason} RETURN_CODE={summary['return_code']}")
    print(f"COMPLETE_REFERENCE_SNAPSHOTS={summary['reference_frames']} CELL_IDS={summary['reference_cells']}")
    print(f"REPORTS_DECIDED_LIVE={summary['counts'].get('reports_decided_live', 0)}")
    print(f"REPORTS_DECIDED_OUTSIDE_LIVE={summary['counts'].get('reports_decided_outside_live', 0)}")
    for method in METHODS:
        normal, forged = metrics.get("normal", {}).get(method, Counter()), metrics.get("forged", {}).get(method, Counter())
        print(f"{method}: NORMAL_FP={normal['FP']} NORMAL_INDETERMINATE={normal['indeterminate_benign']} "
              f"FORGED_DETECTED={forged['TP']}/{forged['live_attack']} "
              f"FORGED_FN={forged['FN']} FORGED_INDETERMINATE={forged['indeterminate_attack']}")
    print(f"DATA_ISSUES={issues}")
    if error:
        print(f"ERROR={error}")
    print("Smoke test only. Missing/delayed reports and UE state changes are next.")
    print(f"Results saved in: {out}")
    if process is None or process.returncode != 0:
        log = out / "run.log"
        if log.exists():
            with log.open("rb") as f:
                f.seek(max(0, os.fstat(f.fileno()).st_size - 16384))
                print("\n=== RUN LOG: LAST 20 LINES ===\n" + "\n".join(f.read().decode(errors="replace").splitlines()[-20:]))
    return 0 if smoke_ok else (2 if issues else 1)


if __name__ == "__main__":
    raise SystemExit(main())
