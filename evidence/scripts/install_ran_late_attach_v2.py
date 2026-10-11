#!/usr/bin/env python3
"""Install opt-in delayed UE connection with PHY prepared at simulation startup.

Use beside the fixed ran_online_detector.py and ran_live_faults.py. Only the
instrumented scratch scenario and MC attachment helper are modified; both
original files are backed up. The prior whole-helper delay is migrated.
Without RAN_SECURITY_LATE_ATTACH_MS, its existing attachment behavior remains
the default. With that variable, exactly two MC UE devices are required: UE
index 0 connects immediately and index 1 starts native NAS connection later.
Both devices run the existing lower-layer registration at startup. The helper's
default bearer setup and target selection remain in their original locations.

The default trial lasts 1.7 simulation seconds. UE 2 starts attachment at
500 ms. Report delays are 250 ms; grace is 300 ms. Benign delayed reports can
span the join, while forgeries are inserted at 1000--1400 ms, after a warm-up
interval. An attack overlapping the join is a separate future test.

After the live run, independently saved RRC events and snapshots validate the
transition. First-alarm delay is reported on the observed reference clock
(10 ms ticks), not as exact Simulator::Now(), wall time, or E2 latency.
"""

import argparse
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

try:
    import ran_online_detector as base
except ImportError as exc:
    raise SystemExit("Keep this script beside the fixed ran_online_detector.py.") from exc


ANCHOR = "  mmwaveHelper->AttachToClosestEnb (mcUeDevs, mmWaveEnbDevs, lteEnbDevs);"
LEGACY_CALLBACK = r'''
// BEGIN RAN_SECURITY_LATE_ATTACH_CALLBACK_V1
namespace ran_security_late_attach
{
template <typename HelperPtr>
static void Attach(HelperPtr helper, ns3::NetDeviceContainer ueDevices,
                   ns3::NetDeviceContainer mmWaveDevices,
                   ns3::NetDeviceContainer lteDevices)
{
  std::cerr << "[RAN-LATE-ATTACH] executing_us="
            << ns3::Simulator::Now().GetMicroSeconds()
            << " delayed_ues=" << ueDevices.GetN() << std::endl;
  helper->AttachToClosestEnb(ueDevices, mmWaveDevices, lteDevices);
}
}
// END RAN_SECURITY_LATE_ATTACH_CALLBACK_V1

'''
LEGACY_ATTACH = r'''  // BEGIN RAN_SECURITY_LATE_ATTACH_V1
  const char* ranLateAttachValue = std::getenv("RAN_SECURITY_LATE_ATTACH_MS");
  if (ranLateAttachValue == nullptr || ranLateAttachValue[0] == '\0')
    {
  mmwaveHelper->AttachToClosestEnb (mcUeDevs, mmWaveEnbDevs, lteEnbDevs);
    }
  else
    {
      // RAN_LATE_ATTACH_SIMTIME_SCOPE_FIX_V1
      ns3::DoubleValue ranSimTimeSeconds;
      ns3::GlobalValue::GetValueByName("simTime", ranSimTimeSeconds);
      char* ranLateAttachEnd = nullptr;
      errno = 0;
      const double ranLateAttachMs = std::strtod(ranLateAttachValue, &ranLateAttachEnd);
      if (errno != 0 || ranLateAttachEnd == ranLateAttachValue
          || *ranLateAttachEnd != '\0' || !std::isfinite(ranLateAttachMs)
          || ranLateAttachMs <= 0 || ranLateAttachMs / 1000.0 >= ranSimTimeSeconds.Get()
          || mcUeDevs.GetN() != 2)
        {
          NS_FATAL_ERROR("Late attach requires two UEs and a finite positive delay before simulation end");
        }
      ns3::NetDeviceContainer ranImmediateUes;
      ns3::NetDeviceContainer ranDelayedUes;
      ranImmediateUes.Add(mcUeDevs.Get(0));
      ranDelayedUes.Add(mcUeDevs.Get(1));
      std::cerr << "[RAN-LATE-ATTACH] immediate_ues=1 delayed_ues=1 planned_ms="
                << ranLateAttachMs << std::endl;
      mmwaveHelper->AttachToClosestEnb(ranImmediateUes, mmWaveEnbDevs, lteEnbDevs);
      ns3::Simulator::Schedule(
          ns3::Seconds(ranLateAttachMs / 1000.0),
          &ran_security_late_attach::Attach<decltype(mmwaveHelper)>, mmwaveHelper,
          ranDelayedUes, mmWaveEnbDevs, lteEnbDevs);
    }
  // END RAN_SECURITY_LATE_ATTACH_V1'''


ATTACH = r'''  // BEGIN RAN_SECURITY_LATE_ATTACH_V2
  const char* ranLateAttachValue = std::getenv("RAN_SECURITY_LATE_ATTACH_MS");
  if (ranLateAttachValue != nullptr && ranLateAttachValue[0] != '\0')
    {
      ns3::DoubleValue ranSimTimeSeconds;
      ns3::GlobalValue::GetValueByName("simTime", ranSimTimeSeconds);
      char* ranLateAttachEnd = nullptr;
      errno = 0;
      const double ranLateAttachMs = std::strtod(ranLateAttachValue, &ranLateAttachEnd);
      if (errno != 0 || ranLateAttachEnd == ranLateAttachValue
          || *ranLateAttachEnd != '\0' || !std::isfinite(ranLateAttachMs)
          || ranLateAttachMs <= 0 || ranLateAttachMs / 1000.0 >= ranSimTimeSeconds.Get()
          || mcUeDevs.GetN() != 2)
        {
          NS_FATAL_ERROR("Delayed NAS connection requires two UEs and a positive delay before simulation end");
        }
      const std::string ranLateNodeId = std::to_string(mcUeDevs.Get(1)->GetNode()->GetId());
      if (::setenv("RAN_SECURITY_LATE_ATTACH_NODE_ID", ranLateNodeId.c_str(), 1) != 0)
        {
          NS_FATAL_ERROR("Cannot configure the delayed UE node");
        }
      std::cerr << "[RAN-LATE-ATTACH] phy_init_all_ues=2 delayed_node="
                << ranLateNodeId << " planned_ms=" << ranLateAttachMs << std::endl;
    }
  mmwaveHelper->AttachToClosestEnb (mcUeDevs, mmWaveEnbDevs, lteEnbDevs);
  // END RAN_SECURITY_LATE_ATTACH_V2'''

NAS_CONNECT = '''    lteUeNas->Connect(enbLteDevice->GetCellId(),
                      enbLteDevice->GetDlEarfcn()); // the MmWaveCell will be automatically selected'''
NAS_DELAY = r'''    // BEGIN RAN_SECURITY_LATE_NAS_V2
    const char* ranLateDelay = std::getenv("RAN_SECURITY_LATE_ATTACH_MS");
    const char* ranLateNode = std::getenv("RAN_SECURITY_LATE_ATTACH_NODE_ID");
    if (ranLateDelay != nullptr && ranLateDelay[0] != '\0' && ranLateNode != nullptr
        && std::string(ranLateNode) == std::to_string(ueDevice->GetNode()->GetId()))
    {
        char* ranLateEnd = nullptr;
        errno = 0;
        const double ranLateMs = std::strtod(ranLateDelay, &ranLateEnd);
        if (errno != 0 || ranLateEnd == ranLateDelay || *ranLateEnd != '\0'
            || !std::isfinite(ranLateMs) || ranLateMs <= 0
            || ns3::Simulator::Now().GetMicroSeconds() != 0)
        {
            NS_FATAL_ERROR("Delayed NAS connection must be configured at simulation startup");
        }
        std::cerr << "[RAN-LATE-NAS] scheduled_imsi=" << mcDevice->GetImsi()
                  << " node=" << ranLateNode << " planned_ms=" << ranLateMs
                  << " phy_prepared_us=" << ns3::Simulator::Now().GetMicroSeconds()
                  << std::endl;
        ns3::Simulator::Schedule(
            ns3::Seconds(ranLateMs / 1000.0),
            static_cast<void (ns3::EpcUeNas::*)(uint16_t, uint32_t)>(&ns3::EpcUeNas::Connect),
            lteUeNas, enbLteDevice->GetCellId(), enbLteDevice->GetDlEarfcn());
    }
    else
    {
        lteUeNas->Connect(enbLteDevice->GetCellId(),
                          enbLteDevice->GetDlEarfcn());
    }
    // END RAN_SECURITY_LATE_NAS_V2'''


def add_includes(text, includes):
    for include in includes:
        line = "#include " + include
        if line not in text:
            text = line + "\n" + text
    return text


def prepare_scenario(text):
    if "BEGIN RAN_SECURITY_LATE_ATTACH_V2" in text:
        if text.count(ATTACH) != 1 or "BEGIN RAN_SECURITY_LATE_ATTACH_V1" in text:
            raise RuntimeError("Existing V2 scenario differs; no files changed.")
        return text
    if "BEGIN RAN_SECURITY_STATE_SNAPSHOTS_V1" not in text:
        raise RuntimeError("The existing state-snapshot logger is required.")
    if "InstallMcUeDevice" not in text:
        raise RuntimeError("The MC UE scenario is required.")
    if len(re.findall(r"(?m)^int\s+main\s*\(", text)) != 1 or not re.search(r"Simulator::Stop\s*\(\s*Seconds\s*\(\s*simTime\s*\)", text):
        raise RuntimeError("Expected the existing main and simTime stop condition.")
    if "BEGIN RAN_SECURITY_LATE_ATTACH_V1" in text:
        if text.count(LEGACY_ATTACH) != 1 or text.count(LEGACY_CALLBACK) != 1:
            raise RuntimeError("Existing V1 scenario differs; no files changed.")
        text = text.replace(LEGACY_ATTACH, ATTACH, 1).replace(LEGACY_CALLBACK, "", 1)
    else:
        if text.count(ANCHOR) != 1:
            raise RuntimeError("Expected one MC-UE attachment anchor; no files changed.")
        text = text.replace(ANCHOR, ATTACH, 1)
    return add_includes(text, ("<cerrno>", "<cmath>", "<cstdlib>", "<iostream>", "<string>"))


def prepare_helper(text, nas_header):
    if not re.search(r"void\s+Connect\s*\(\s*uint16_t\s+\w+\s*,\s*uint32_t\s+\w+\s*\)\s*;", nas_header):
        raise RuntimeError("Expected the verified two-argument EpcUeNas::Connect API.")
    method = list(re.finditer(r"(?m)^void\s*\nMmWaveHelper::AttachMcToClosestEnb\s*\(", text))
    if len(method) != 1:
        raise RuntimeError("Expected one MC attachment implementation; no files changed.")
    start = method[0].start()
    end = text.find("\n}", method[0].end())
    if end < 0:
        raise RuntimeError("Cannot identify the MC attachment body; no files changed.")
    end += 2
    body = text[start:end]
    if "BEGIN RAN_SECURITY_LATE_NAS_V2" in text:
        if body.count(NAS_DELAY) != 1 or text.count("BEGIN RAN_SECURITY_LATE_NAS_V2") != 1:
            raise RuntimeError("Existing helper delay differs; no files changed.")
        return text
    if body.count(NAS_CONNECT) != 1 or text.count("RAN_SECURITY_LATE_NAS"):
        raise RuntimeError("Expected the verified MC NAS connection call; no files changed.")
    before, after = body.split(NAS_CONNECT)
    if ("AddUePhy" not in before or "RegisterOtherEnb" not in before
            or "ActivateEpsBearer" not in after or "SetLteTargetEnb" not in after):
        raise RuntimeError("Expected lower-layer setup before NAS and existing bearer/target setup after it.")
    body = body.replace(NAS_CONNECT, NAS_DELAY, 1)
    return add_includes(text[:start] + body + text[end:],
                        ("<cerrno>", "<cmath>", "<cstdlib>", "<iostream>", "<string>", '"ns3/fatal-error.h"'))


def install(repo):
    path = repo / "scratch/scenario-online-security.cc"
    helper = repo / "src/mmwave/helper/mmwave-helper.cc"
    originals = {target: target.read_bytes() for target in (path, helper)}
    header = (repo / "src/mmwave/helper/mmwave-helper.h").read_text()
    signature = r"AttachToClosestEnb\s*\(\s*NetDeviceContainer\s+\w+\s*,\s*NetDeviceContainer\s+\w+\s*,\s*NetDeviceContainer\s+\w+\s*\)"
    if not re.search(signature, header):
        raise RuntimeError("Expected the verified three-container MC attachment API.")
    nas_header = (repo / "src/lte/model/epc-ue-nas.h").read_text()
    replacements = {path: prepare_scenario(originals[path].decode("utf-8")).encode("utf-8"),
                    helper: prepare_helper(originals[helper].decode("utf-8"), nas_header).encode("utf-8")}
    changed = [target for target in originals if replacements[target] != originals[target]]
    if not changed:
        print("V2 PHY preparation and delayed NAS connection already installed.", flush=True)
        return
    backup = repo / "test_open" / f"ran_late_attach_v2_backup_{time.time_ns()}"
    backup.mkdir(parents=True)
    for target in changed:
        with (backup / (target.name + ".original")).open("xb") as destination:
            destination.write(originals[target])
    for target, original in originals.items():
        if target.read_bytes() != original:
            raise RuntimeError("A source changed concurrently; no files written.")
    for target in changed:
        target.write_bytes(replacements[target])
        print(f"Updated: {target}", flush=True)
    print(f"Backup: {backup}", flush=True)


def observed_clock_delays(folder):
    starts = {}
    with (folder / "channel_events.jsonl").open() as source:
        for line in source:
            event = json.loads(line)
            if (event["event"] in ("queued", "dropped") and event.get("synthetic_attack")
                    and event["phase"] == "runner_running"):
                case, clock = event["case"], int(event["intercept_us"])
                starts[case] = min(starts.get(case, clock), clock)
    first = {}
    with (folder / "decisions.csv").open() as source:
        for row in csv.DictReader(source):
            if row["included_in_live_metrics"] == "1" and row["synthetic_attack"] == "1" and row["verdict"] == "alarm":
                key, clock = (row["case"], row["method"]), int(row["reference_watermark_us"])
                first[key] = min(first.get(key, clock), clock)
    result = {}
    for case, start in sorted(starts.items()):
        result[case] = {}
        for method in base.METHODS:
            detected = first.get((case, method))
            result[case][method] = {"episode_start_observed_us": start,
                                    "first_alarm_observed_us": detected,
                                    "delay_ms": (detected - start) / 1000 if detected is not None else None}
    return result


def summarize(folder, attach_ms, control):
    planned_us = round(attach_ms * 1000)
    stream, frames = base.StateStream(300000, 99999), []
    with (folder / "ue_events.csv.states.csv").open() as source:
        for row in csv.DictReader(source):
            frame = stream.accept(row)
            if frame is not None:
                frames.append(frame)
    if stream.current is not None or not frames:
        raise RuntimeError("Missing or incomplete state reference in the transition run.")
    with (folder / "ue_events.csv").open() as source:
        events = list(csv.DictReader(source))
    connections = [event for event in events if event["event"] == "CONNECTION_ESTABLISHED"]
    before = {ue[1] for frame in frames if frame.stamp_us < planned_us
              for contexts in frame.cells.values() for ue in contexts if ue[1] > 0}
    after = {ue[1] for frame in frames if frame.stamp_us >= planned_us
             for contexts in frame.cells.values() for ue in contexts if ue[1] > 0}
    late_ids = after - before
    ue2_connections = [e for e in connections if int(e["imsi"]) in late_ids]
    pipeline = json.loads((folder / "summary.json").read_text())
    transition_ok = (len(before) == 1 and len(after) == 2 and before <= after
                     and len(late_ids) == 1 and bool(ue2_connections)
                     and all(int(e["sim_time_us"]) >= planned_us for e in ue2_connections)
                     and pipeline["count_changes_after_first_kpm"] > 0)
    delays = observed_clock_delays(folder)
    report = {"transition_status": "PASS" if transition_ok else "CHECK_RESULTS",
              "planned_late_attach_us": planned_us, "known_ue_ids_before_attach": sorted(before),
              "known_ue_ids_at_or_after_attach": sorted(after), "ue2_connection_events": ue2_connections,
              "late_ue_imsi_values": sorted(late_ids),
              "reference_clock_tick_us": base.STATE_PERIOD_US,
              "first_alarm_delay_on_observed_reference_clock": delays,
              "delay_is_exact_simulator_or_e2_latency": False,
              "control": control,
              "interpretation": "PHY registered at startup; native NAS Connect delayed for UE index 1. RRC events validate the genuine join; benign delays span it; attacks follow warm-up."}
    (folder / "transition_validation.json").write_text(json.dumps(report, indent=2) + "\n")
    print("\n=== GENUINE UE JOIN CHECK ===", flush=True)
    print(f"TRANSITION_STATUS={report['transition_status']} PLANNED_ATTACH_US={planned_us}")
    print(f"KNOWN_UE_IDS_BEFORE={sorted(before)} KNOWN_UE_IDS_AFTER={sorted(after)}")
    for event in ue2_connections:
        print(f"UE2_IMSI={event['imsi']} CONNECTED_US={event['sim_time_us']} CELL_ID={event['cell_id']} RNTI={event['rnti']}")
    print(f"UE_COUNT_CHANGES_AFTER_FIRST_KPM={pipeline['count_changes_after_first_kpm']}")
    print("=== OBSERVED REFERENCE-CLOCK FIRST-ALARM DELAY ===")
    for case, methods in delays.items():
        for method, values in methods.items():
            print(f"CASE={case} METHOD={method} OBSERVED_DELAY_MS={values['delay_ms']}")
    print("Delay uses the received reference clock in 10 ms ticks; it is not exact simulator or E2 latency.")
    print(f"Results saved in: {folder}", flush=True)
    return transition_ok


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--attach-ms", type=base.positive_number, default=500.0)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-run", action="store_true")
    args = parser.parse_args()
    repo = args.repo.expanduser().resolve()
    harness = Path(__file__).resolve().parent / "ran_live_faults.py"
    if not (repo / "ns3").is_file() or not harness.is_file():
        parser.error("Run from mmwave-LENA-oran; keep ran_live_faults.py beside this installer.")
    if args.attach_ms >= 1700:
        parser.error("Attachment must precede this trial's 1700 ms stop.")
    install(repo)
    if not args.skip_build:
        subprocess.run([str(repo / "ns3"), "build", "-j", "2"], cwd=repo, check=True)
    if args.skip_run:
        return 0
    before = set((repo / "test_open").glob("ran_faults_*"))
    command = [sys.executable, str(harness), "--repo", str(repo), "--ues", "2", "--seed", "6201",
               "--sim-seconds", "1.7", "--grace-ms", "300", "--delay-ms", "250",
               "--fault-start-ms", "300", "--fault-end-ms", "1400",
               "--forge-start-ms", "1000", "--forge-end-ms", "1400",
               "--drop-times-ms", "400,600,1100,1300", "--max-wall-seconds", "180"]
    control = {"late_attach_ms": args.attach_ms, "ues": 2, "sim_seconds": 1.7,
               "fault_window_ms": [300, 1400], "forgery_window_ms": [1000, 1400],
               "drop_times_ms": [400, 600, 1100, 1300], "delay_ms": 250, "grace_ms": 300,
               "attach_mode": "V2: PHY setup for all UEs at startup; native NAS Connect delayed for UE index 1",
               "source_sha256": {str(path.relative_to(repo)): hashlib.sha256(path.read_bytes()).hexdigest()
                                  for path in (repo / "scratch/scenario-online-security.cc", repo / "src/mmwave/helper/mmwave-helper.cc")},
               "command": command, "controller_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    print("\nStarting V2 trial: both PHYs prepared at startup; UE 2 starts NAS connection at 500 ms by default.", flush=True)
    run = subprocess.run(command, cwd=repo,
                         env=dict(os.environ, RAN_SECURITY_LATE_ATTACH_MS=f"{args.attach_ms:g}"))
    created = set((repo / "test_open").glob("ran_faults_*")) - before
    if len(created) != 1:
        raise RuntimeError("Cannot identify one new run; inspect the printed Results path.")
    folder = created.pop()
    (folder / "experiment_control.json").write_text(json.dumps(control, indent=2) + "\n")
    if run.returncode != 0:
        print(f"Live harness returned {run.returncode}; partial results and control saved in {folder}.", flush=True)
        return run.returncode
    return 0 if summarize(folder, args.attach_ms, control) else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"STOP: {error}") from error
