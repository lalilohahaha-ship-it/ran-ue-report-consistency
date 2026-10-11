#!/usr/bin/env python3
"""Five paired, live report-channel cases using the verified detector rules.

Keep the fixed ran_online_detector.py in the same directory as this file.
One fresh ns3 simulation feeds normal, missing, delayed, forged, and
forged_faults views. Reports are complete per-cell CU-CP groups before the
collector changes a copy. Whole reports are dropped at specified generation
times. Delayed reports are held until the protected reference watermark
advances by the specified simulation-time delay; no wall-time sleep models
network delay. The reference stream itself is protected and complete.

Only already received complete snapshots enter the detector. Delay scheduling
uses the watermark at collector interception, after clock alignment. The
original generation metadata and synthetic truth labels are harness records,
not inputs to the consistency rules. Dropped attacks have no detector verdict
and remain visible in the ALL-injected-attack denominator.

This is a log-based report-plane experiment, not an E2/xApp deployment. PASS
checks the pipeline and fault delivery, independently of false positives or
missed attacks. A single static-UE run cannot establish the time-aware rule's
benefit. Clock offsets are reported as offsets, not exact detection latency.
"""

import argparse
import csv
import hashlib
import heapq
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter, deque
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

try:
    import ran_online_detector as base
except ImportError as exc:
    raise SystemExit("Place this script beside the existing fixed ran_online_detector.py.") from exc


CASES = ("normal", "missing", "delayed", "forged", "forged_faults")
METHODS = base.METHODS
STAT_KEYS = ("source_packets", "source_forged", "dropped_packets", "dropped_forged",
             "delayed_packets", "delivered_live", "delivered_forged_live", "delivered_outside_live")
METRIC_KEYS = ("live_total", "live_benign", "live_attack", "TP", "FP", "TN", "FN",
               "indeterminate_benign", "indeterminate_attack", "outside_live")


@dataclass(frozen=True)
class Packet:
    report_id: int
    source: base.Report
    case: str
    count: int
    imsis: tuple
    forged: bool
    intercept_us: int
    due_us: int
    nominal_delay_us: int


def in_window(stamp, start_ms, end_ms):
    return round(start_ms * 1000) <= stamp < round(end_ms * 1000)


class Collector:
    def __init__(self, out, args, process, started, decisions, journal, references):
        self.out, self.args, self.process, self.started = out, args, process, started
        self.decisions, self.journal, self.references = decisions, journal, references
        self.state = base.StateStream(round(args.grace_ms * 1000), args.forge_imsi)
        self.state_tail = base.CsvTail(out / "ue_events.csv.states.csv", base.STATE_COLUMNS)
        self.tails, self.streams, self.inputs, self.delivery = {}, {}, deque(), []
        self.counts, self.report_id, self.ticket = Counter(), 0, 0
        self.stats = {case: Counter(dict.fromkeys(STAT_KEYS, 0)) for case in CASES}
        self.metrics = {case: {m: Counter(dict.fromkeys(METRIC_KEYS, 0)) for m in METHODS} for case in CASES}
        self.first_generation_us, self.last_reference_wall_s = None, None
        self.transitions = []

    def phase(self):
        return "runner_running" if self.process.poll() is None else "after_exit"

    def wall(self):
        return time.monotonic() - self.started

    def event(self, event, **details):
        self.journal.write(json.dumps({"event": event, "wall_s": self.wall(),
                                       "phase": self.phase(), **details}) + "\n")

    def read(self):
        for row in self.state_tail.read():
            previous = self.state.latest
            frame = self.state.accept(row)
            if frame is not None:
                self.last_reference_wall_s = self.wall()
                self.counts["reference_frames_" + self.phase()] += 1
                self.references.writerow([frame.sequence, frame.stamp_us,
                                          f"{self.last_reference_wall_s:.6f}", self.phase()])
                if previous is not None:
                    for cell in frame.cells:
                        old, new = previous.cells[cell], frame.cells[cell]
                        old_members, new_members = sorted({u[1] for u in old}), sorted({u[1] for u in new})
                        if old_members != new_members or len(old) != len(new):
                            transition = {"snapshot_us": frame.stamp_us, "cell_id": cell,
                                          "old_count": len(old), "new_count": len(new),
                                          "old_members": old_members, "new_members": new_members}
                            self.transitions.append(transition)
                            self.event("reference_context_change", **transition)
        for path in sorted(self.out.glob("cu-cp-cell-*.txt")):
            match = re.fullmatch(r"cu-cp-cell-(\d+)\.txt", path.name)
            if match is None:
                continue
            if path not in self.tails:
                self.tails[path] = base.CsvTail(path, base.KPM_COLUMNS)
                self.streams[path] = base.KpmStream(int(match.group(1)), path.name)
            for row in self.tails[path].read():
                phase, wall = self.phase(), self.wall()
                self.counts["source_rows_" + phase] += 1
                report = self.streams[path].accept(row, wall, phase)
                if report is not None:
                    self.report_id += 1
                    self.inputs.append((self.report_id, report))
                    self.counts["source_reports_" + phase] += 1
                    if self.first_generation_us is None:
                        self.first_generation_us = report.generation_us
                    self.event("source_report", report_id=self.report_id, cell_id=report.cell,
                               source_generation_us=report.generation_us,
                               original_count=report.count, original_imsis=report.imsis,
                               source_received_wall_s=report.received_wall_s, source_receipt_phase=report.receipt_phase)
        self.enqueue_ready()
        self.deliver_ready()

    def enqueue_ready(self):
        if self.state.latest is None:
            return
        waiting = deque()
        while self.inputs:
            report_id, report = self.inputs.popleft()
            clock = self.state.latest.stamp_us
            if report.generation_us > clock:
                waiting.append((report_id, report))
                continue
            if report.cell not in self.state.coverage:
                raise base.DataError(f"KPM cell {report.cell} has no reference.")
            if self.args.forge_imsi in report.imsis:
                raise base.DataError("Forged test IMSI already occurs in an original report.")
            for case in CASES:
                stats = self.stats[case]
                stats["source_packets"] += 1
                forged = case in ("forged", "forged_faults") and in_window(
                    report.generation_us, self.args.forge_start_ms, self.args.forge_end_ms)
                count = report.count + int(forged)
                imsis = report.imsis + ((self.args.forge_imsi,) if forged else ())
                stats["source_forged"] += int(forged)
                drop = case in ("missing", "forged_faults") and report.generation_us in self.args.drop_us
                if drop:
                    stats["dropped_packets"] += 1
                    stats["dropped_forged"] += int(forged)
                    self.event("dropped", report_id=report_id, case=case, cell_id=report.cell,
                               source_generation_us=report.generation_us, intercept_us=clock,
                               reported_count=count, reported_imsis=imsis, synthetic_attack=forged)
                    continue  # No report arrives, so no security verdict is produced.
                delayed = case in ("delayed", "forged_faults") and in_window(
                    report.generation_us, self.args.fault_start_ms, self.args.fault_end_ms)
                delay_us = round(self.args.delay_ms * 1000) if delayed else 0
                stats["delayed_packets"] += int(delayed)
                packet = Packet(report_id, report, case, count, imsis, forged, clock, clock + delay_us, delay_us)
                self.ticket += 1
                heapq.heappush(self.delivery, (packet.due_us, self.ticket, packet))
                self.event("queued", report_id=report_id, case=case, cell_id=report.cell,
                           source_generation_us=report.generation_us, intercept_us=clock,
                           scheduled_delivery_us=packet.due_us, nominal_delay_us=delay_us,
                           reported_count=count, reported_imsis=imsis, synthetic_attack=forged)
        self.inputs = waiting

    def deliver_ready(self):
        if self.state.latest is None:
            return
        clock = self.state.latest.stamp_us
        while self.delivery and self.delivery[0][0] <= clock:
            _, _, packet = heapq.heappop(self.delivery)
            report = packet.source
            # The rules receive only payload fields and already observed state.
            results = base.evaluate(report.cell, packet.count, packet.imsis,
                                    self.state.history, self.state.grace_us)
            phase = self.phase()
            live = report.receipt_phase == "runner_running" and phase == "runner_running"
            stats = self.stats[packet.case]
            stats["delivered_live" if live else "delivered_outside_live"] += 1
            if live:
                stats["delivered_forged_live"] += int(packet.forged)
            self.event("delivered", report_id=packet.report_id, case=packet.case, cell_id=report.cell,
                       source_generation_us=report.generation_us, delivered_clock_us=clock,
                       intercept_us=packet.intercept_us, scheduled_delivery_us=packet.due_us,
                       actual_channel_hold_us=clock - packet.intercept_us,
                       source_to_decision_offset_us=clock - report.generation_us,
                       included_in_live_metrics=live, synthetic_attack=packet.forged)
            for method, (verdict, reason, match_us) in results.items():
                metric = self.metrics[packet.case][method]
                if live:
                    metric["live_total"] += 1
                    metric["live_attack" if packet.forged else "live_benign"] += 1
                    if verdict == "indeterminate":
                        metric["indeterminate_attack" if packet.forged else "indeterminate_benign"] += 1
                    else:
                        key = ("TP" if packet.forged else "FP") if verdict == "alarm" else ("FN" if packet.forged else "TN")
                        metric[key] += 1
                else:
                    metric["outside_live"] += 1
                self.decisions.writerow([
                    packet.report_id, packet.case, method, report.cell, report.generation_us,
                    report.receipt_phase, phase, int(live), f"{report.received_wall_s:.6f}",
                    f"{self.wall():.6f}", packet.intercept_us, packet.due_us, clock,
                    packet.nominal_delay_us, clock - packet.intercept_us,
                    clock - report.generation_us, match_us, packet.count, json.dumps(packet.imsis),
                    int(packet.forged), verdict, reason])
                if live and method == "time_aware" and (packet.forged or verdict != "consistent"):
                    print(f"LIVE {packet.case}: generated={report.generation_us / 1000:g}ms "
                          f"delivered_clock={clock / 1000:g}ms cell={report.cell} verdict={verdict}", flush=True)

    def issues(self):
        issues = []
        if self.state.current is not None or self.state_tail.pending.strip():
            issues.append("trailing_incomplete_reference")
        if any(t.pending.strip() for t in self.tails.values()):
            issues.append("trailing_incomplete_source_line")
        if any(s.current is not None for s in self.streams.values()):
            issues.append("incomplete_source_report_group")
        if self.inputs:
            issues.append("source_reports_waiting_for_reference")
        if self.delivery:
            issues.append("delayed_packets_not_delivered_before_end")
        if not self.state.frames or not self.counts["source_reports_runner_running"]:
            issues.append("no_live_source_data")
        if self.counts["source_reports_after_exit"]:
            issues.append("source_reports_received_after_exit")
        for case, stats in self.stats.items():
            if stats["delivered_outside_live"]:
                issues.append(case + "_decisions_outside_live")
            if stats["source_packets"] != stats["delivered_live"] + stats["dropped_packets"]:
                issues.append(case + "_incomplete_live_delivery_accounting")
        if not self.stats["missing"]["dropped_packets"]:
            issues.append("requested_drop_not_observed")
        if not self.stats["delayed"]["delayed_packets"]:
            issues.append("requested_delay_not_observed")
        if not self.stats["forged"]["source_forged"]:
            issues.append("requested_forgery_not_observed")
        return issues


def arguments():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--sim-seconds", type=base.positive_number, default=1.0)
    parser.add_argument("--seed", type=int, default=6201)
    parser.add_argument("--ues", type=int, default=1)
    parser.add_argument("--grace-ms", type=base.positive_number, default=300.0)
    parser.add_argument("--delay-ms", type=base.positive_number, default=250.0)
    parser.add_argument("--max-wall-seconds", type=base.positive_number, default=90.0)
    parser.add_argument("--forge-imsi", type=int, default=99999)
    parser.add_argument("--forge-start-ms", type=base.positive_number, default=300.0)
    parser.add_argument("--forge-end-ms", type=base.positive_number, default=700.0)
    parser.add_argument("--fault-start-ms", type=base.positive_number, default=300.0)
    parser.add_argument("--fault-end-ms", type=base.positive_number, default=700.0)
    parser.add_argument("--drop-times-ms", default="400,600")
    args = parser.parse_args()
    if min(args.seed, args.ues, args.forge_imsi) <= 0:
        parser.error("Seed, UE count and forged IMSI must be positive integers.")
    for prefix in ("forge", "fault"):
        if not 0 < getattr(args, prefix + "_start_ms") < getattr(args, prefix + "_end_ms") <= args.sim_seconds * 1000:
            parser.error(prefix + " window must satisfy 0 < start < end <= simulation duration.")
    if args.fault_end_ms + args.delay_ms > args.sim_seconds * 1000:
        parser.error("Allow enough simulation time after the fault window to deliver delayed reports.")
    try:
        args.drop_us = sorted({round(base.positive_number(v.strip()) * 1000)
                               for v in args.drop_times_ms.split(",")})
    except (ValueError, argparse.ArgumentTypeError):
        parser.error("Drop times must be comma-separated positive milliseconds.")
    if not args.drop_us or max(args.drop_us) >= args.sim_seconds * 1000000:
        parser.error("All drop times must be before simulation end.")
    return args


def transition_source(repo, out):
    sections = []
    for name, pattern, after, maximum in (
        ("scratch/scenario-online-security.cc", r"mmwaveHelper->AttachToClosestEnb\s*\(", 4, 1),
        ("src/mmwave/helper/mmwave-helper.h", r"\bAttachToClosestEnb\s*\(", 8, 2),
        ("src/mmwave/helper/mmwave-helper.cc", r"MmWaveHelper::AttachToClosestEnb\s*\(", 24, 2),
    ):
        path = repo / name
        if not path.is_file():
            continue
        lines = path.read_text(errors="replace").splitlines()
        hits = [i for i, line in enumerate(lines) if re.search(pattern, line)]
        selected = set()
        for hit in hits[:maximum]:
            selected.update(range(max(0, hit - 1), min(len(lines), hit + after)))
        sections.append("FILE: " + name + "\n" + "\n".join(f"{i + 1}: {lines[i]}" for i in sorted(selected)))
    text = "\n\n".join(sections) + "\n"
    (out / "transition_source.txt").write_text(text)
    print("\n=== LATE ATTACH SOURCE CHECK ===\n" + text)


def main():
    args = arguments()
    repo = args.repo.expanduser().resolve()
    source = repo / "scratch/scenario-online-security.cc"
    if not (repo / "ns3").is_file() or not source.is_file():
        raise SystemExit("Run from mmwave-LENA-oran with the built reference scenario.")
    if "BEGIN RAN_SECURITY_STATE_SNAPSHOTS_V1" not in source.read_text():
        raise SystemExit("The built V1 state logger is required.")
    if "RAN_TIME_WINDOW_COUNT_GUARD_V1" not in Path(base.__file__).read_text():
        raise SystemExit("First apply fix_ran_time_window.py to the detector in this script's directory.")
    (repo / "test_open").mkdir(exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix="ran_faults_", dir=str(repo / "test_open")))
    command = [str(repo / "ns3"), "run",
               f"scenario-online-security --RngRun={args.seed} --ues={args.ues} "
               f"--speedMin=3 --speedMax=10 --simTime={args.sim_seconds:g} "
               "--enableE2FileLogging=1 --SimulatorImplementationType=ns3::RealtimeSimulatorImpl",
               "--no-build", f"--cwd={out}"]
    config = {**vars(args), "repo": str(repo), "command": command,
              "cases": CASES, "cases_share_one_simulation": True,
              "scenario_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
              "rules_sha256": hashlib.sha256(Path(base.__file__).read_bytes()).hexdigest(),
              "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "collection": "live_simulator_csv_logs", "attack_surface": "parsed_report_copy",
              "protected_reference": "complete_per_cell_raw_rrc_context_snapshots",
              "delay_clock": "latest_received_reference_watermark_at_interception",
              "generation_metadata_unmodified": True, "offsets_are_detection_latency": False,
              "live_phase_definition": "ns3_command_running_at_source_reception_and_decision",
              "dropped_reports_have_security_verdict": False,
              "pipeline_pass_requires_zero_false_positives": False,
              "all_injected_attack_denominator_includes_dropped_attacks": True}
    (out / "config.json").write_text(json.dumps(config, indent=2) + "\n")
    print(f"Results: {out}", flush=True)
    process, collector, stop_reason, error = None, None, "process_exit", None
    started, last_progress = time.monotonic(), 0.0
    try:
        with ExitStack() as stack:
            log = stack.enter_context((out / "run.log").open("w"))
            decision_file = stack.enter_context((out / "decisions.csv").open("w", newline=""))
            journal = stack.enter_context((out / "channel_events.jsonl").open("w"))
            reference_file = stack.enter_context((out / "reference_receipts.csv").open("w", newline=""))
            decisions, references = csv.writer(decision_file), csv.writer(reference_file)
            decisions.writerow([
                "report_id", "case", "method", "cell_id", "source_generation_us", "source_receipt_phase",
                "decision_phase", "included_in_live_metrics", "source_received_wall_s", "decision_wall_s",
                "channel_intercept_us", "scheduled_delivery_us", "reference_watermark_us", "nominal_delay_us",
                "actual_channel_hold_us", "source_to_decision_offset_us", "matching_snapshot_us",
                "reported_count", "reported_imsis", "synthetic_attack", "verdict", "reason"])
            references.writerow(["snapshot_id", "sim_time_us", "received_wall_s", "phase"])
            process = subprocess.Popen(command, cwd=repo,
                                       env=dict(os.environ, NS_LOG="", RAN_SECURITY_EVENT_LOG=str(out / "ue_events.csv")),
                                       stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            collector = Collector(out, args, process, started, decisions, journal, references)
            try:
                while True:
                    collector.read()
                    for file in (decision_file, journal, reference_file):
                        file.flush()
                    elapsed = time.monotonic() - started
                    if process.poll() is not None:
                        collector.read()
                        break
                    if elapsed >= args.max_wall_seconds:
                        stop_reason = "wall_limit"
                        base.stop_process(process)
                        collector.read()
                        break
                    if elapsed - last_progress >= 1:
                        print(f"LIVE wall={elapsed:.1f}s snapshots={collector.state.frames} "
                              f"source_reports={collector.counts['source_reports_runner_running']} "
                              f"queued={len(collector.delivery)}", flush=True)
                        last_progress = elapsed
                    time.sleep(0.01)
            finally:
                base.stop_process(process)
    except (OSError, ValueError, base.DataError, UnicodeError, csv.Error) as exc:
        stop_reason, error = "collection_error", f"{type(exc).__name__}: {exc}"
    except KeyboardInterrupt:
        stop_reason, error = "interrupted", "Interrupted; partial results retained."
    finally:
        if process is not None:
            base.stop_process(process)
    issues = collector.issues() if collector else ["collector_not_started"]
    if process is None or process.returncode != 0:
        issues.append("runner_failed")
    if stop_reason != "process_exit":
        issues.append(stop_reason)
    stats, metrics = (collector.stats, collector.metrics) if collector else ({}, {})
    rates = {}
    for case in stats:
        rates[case] = {}
        for method in METHODS:
            metric = metrics[case][method]
            rates[case][method] = {
                "false_alarm_fraction_of_delivered_benign": metric["FP"] / metric["live_benign"] if metric["live_benign"] else None,
                "detection_fraction_of_delivered_forged": metric["TP"] / metric["live_attack"] if metric["live_attack"] else None,
                "detection_fraction_of_all_injected_forged": metric["TP"] / stats[case]["source_forged"] if stats[case]["source_forged"] else None}
    transitions = [t for t in collector.transitions
                   if collector.first_generation_us is not None and t["snapshot_us"] >= collector.first_generation_us] if collector else []
    count_changes = sum(t["old_count"] != t["new_count"] for t in transitions)
    member_changes = sum(t["old_members"] != t["new_members"] for t in transitions)
    queued = [{"report_id": p.report_id, "case": p.case, "due_us": p.due_us,
               "source_generation_us": p.source.generation_us, "forged": p.forged}
              for _, _, p in collector.delivery] if collector else []
    summary = {"pipeline_status": "PASS" if not issues else "CHECK_RESULTS", "stop_reason": stop_reason,
               "return_code": process.returncode if process else None, "wall_seconds": time.monotonic() - started,
               "error": error, "data_issues": issues, "counts": dict(collector.counts) if collector else {},
               "reference_frames": collector.state.frames if collector else 0,
               "reference_cells": sorted(collector.state.coverage or []) if collector else [],
               "membership_changes_after_first_kpm": member_changes, "count_changes_after_first_kpm": count_changes,
               "context_transitions_after_first_kpm": transitions, "channel_stats": stats,
               "metrics_live_only": metrics, "rates": rates, "queued_at_exit": queued,
               "interpretation": "Single paired live fault-channel run; offsets are not exact detection delay."}
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print("\n=== FIVE-CASE LIVE RESULT ===")
    print(f"PIPELINE_STATUS={summary['pipeline_status']} STOP_REASON={stop_reason} RETURN_CODE={summary['return_code']}")
    print(f"COMPLETE_REFERENCE_SNAPSHOTS={summary['reference_frames']} CELL_IDS={summary['reference_cells']}")
    print(f"SOURCE_REPORTS_LIVE={summary['counts'].get('source_reports_runner_running', 0)}")
    print(f"UE_MEMBERSHIP_CHANGES_AFTER_FIRST_KPM={member_changes} UE_COUNT_CHANGES_AFTER_FIRST_KPM={count_changes}")
    for case in CASES:
        s = stats.get(case, Counter())
        print(f"\nCASE={case} SOURCE={s['source_packets']} DROPPED={s['dropped_packets']} "
              f"DELAYED={s['delayed_packets']} DELIVERED_LIVE={s['delivered_live']} "
              f"FORGED_INJECTED={s['source_forged']} FORGED_DROPPED={s['dropped_forged']}")
        for method in METHODS:
            m = metrics.get(case, {}).get(method, Counter())
            print(f"  {method}: BENIGN={m['live_benign']} FP={m['FP']} "
                  f"BENIGN_INDETERMINATE={m['indeterminate_benign']} FORGED_DETECTED={m['TP']}/{m['live_attack']} "
                  f"FN={m['FN']} FORGED_INDETERMINATE={m['indeterminate_attack']} "
                  f"DETECTED_OF_ALL_INJECTED={m['TP']}/{s['source_forged']}")
    print(f"\nDATA_ISSUES={issues} QUEUED_AT_EXIT={len(queued)}")
    if error:
        print(f"ERROR={error}")
    if not transitions:
        print("No UE count/membership changes after the first KPM: this run cannot establish a temporal-rule benefit.")
    print("Dropped reports produce no security verdict. Offsets are not exact detection latency.")
    print(f"Results saved in: {out}")
    transition_source(repo, out)
    if process is None or process.returncode != 0:
        log_path = out / "run.log"
        if log_path.exists():
            with log_path.open("rb") as f:
                f.seek(max(0, os.fstat(f.fileno()).st_size - 16384))
                print("\n=== RUN LOG: LAST 20 LINES ===\n" + "\n".join(f.read().decode(errors="replace").splitlines()[-20:]))
    return 0 if not issues else 2


if __name__ == "__main__":
    raise SystemExit(main())
