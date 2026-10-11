#include <string>
#include <cmath>
#include <cerrno>
#include "ns3/lte-enb-rrc.h"
#include <vector>
#include <set>
#include "ns3/core-module.h"
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/* *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors: Andrea Lacava <thecave003@gmail.com>
 *          Michele Polese <michele.polese@gmail.com>
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/applications-module.h"
#include "ns3/point-to-point-helper.h"
#include <ns3/lte-ue-net-device.h>
#include "ns3/mmwave-helper.h"
#include "ns3/epc-helper.h"
#include "ns3/mmwave-point-to-point-epc-helper.h"
#include "ns3/lte-helper.h"
#include "ns3/isotropic-antenna-model.h"

using namespace ns3;
using namespace mmwave;

/**
 * Scenario Zero
 * 
 */

NS_LOG_COMPONENT_DEFINE ("ScenarioZero");

void
PrintGnuplottableUeListToFile (std::string filename)
{
  std::ofstream outFile;
  outFile.open (filename.c_str (), std::ios_base::out | std::ios_base::trunc);
  if (!outFile.is_open ())
    {
      NS_LOG_ERROR ("Can't open file " << filename);
      return;
    }
  for (NodeList::Iterator it = NodeList::Begin (); it != NodeList::End (); ++it)
    {
      Ptr<Node> node = *it;
      int nDevs = node->GetNDevices ();
      for (int j = 0; j < nDevs; j++)
        {
          Ptr<LteUeNetDevice> uedev = node->GetDevice (j)->GetObject<LteUeNetDevice> ();
          Ptr<MmWaveUeNetDevice> mmuedev = node->GetDevice (j)->GetObject<MmWaveUeNetDevice> ();
          Ptr<McUeNetDevice> mcuedev = node->GetDevice (j)->GetObject<McUeNetDevice> ();
          if (uedev)
            {
              Vector pos = node->GetObject<MobilityModel> ()->GetPosition ();
              outFile << "set label \"" << uedev->GetImsi () << "\" at " << pos.x << "," << pos.y
                      << " left font \"Helvetica,8\" textcolor rgb \"black\" front point pt 1 ps "
                         "0.3 lc rgb \"black\" offset 0,0"
                      << std::endl;
            }
          else if (mmuedev)
            {
              Vector pos = node->GetObject<MobilityModel> ()->GetPosition ();
              outFile << "set label \"" << mmuedev->GetImsi () << "\" at " << pos.x << "," << pos.y
                      << " left font \"Helvetica,8\" textcolor rgb \"black\" front point pt 1 ps "
                         "0.3 lc rgb \"black\" offset 0,0"
                      << std::endl;
            }
          else if (mcuedev)
            {
              Vector pos = node->GetObject<MobilityModel> ()->GetPosition ();
              outFile << "set label \"" << mcuedev->GetImsi () << "\" at " << pos.x << "," << pos.y
                      << " left font \"Helvetica,8\" textcolor rgb \"black\" front point pt 1 ps "
                         "0.3 lc rgb \"black\" offset 0,0"
                      << std::endl;
            }
        }
    }
}

void
PrintGnuplottableEnbListToFile (std::string filename)
{
  std::ofstream outFile;
  outFile.open (filename.c_str (), std::ios_base::out | std::ios_base::trunc);
  if (!outFile.is_open ())
    {
      NS_LOG_ERROR ("Can't open file " << filename);
      return;
    }
  for (NodeList::Iterator it = NodeList::Begin (); it != NodeList::End (); ++it)
    {
      Ptr<Node> node = *it;
      int nDevs = node->GetNDevices ();
      for (int j = 0; j < nDevs; j++)
        {
          Ptr<LteEnbNetDevice> enbdev = node->GetDevice (j)->GetObject<LteEnbNetDevice> ();
          Ptr<MmWaveEnbNetDevice> mmdev = node->GetDevice (j)->GetObject<MmWaveEnbNetDevice> ();
          if (enbdev)
            {
              Vector pos = node->GetObject<MobilityModel> ()->GetPosition ();
              outFile << "set label \"" << enbdev->GetCellId () << "\" at " << pos.x << "," << pos.y
                      << " left font \"Helvetica,8\" textcolor rgb \"blue\" front  point pt 4 ps "
                         "0.3 lc rgb \"blue\" offset 0,0"
                      << std::endl;
            }
          else if (mmdev)
            {
              Vector pos = node->GetObject<MobilityModel> ()->GetPosition ();
              outFile << "set label \"" << mmdev->GetCellId () << "\" at " << pos.x << "," << pos.y
                      << " left font \"Helvetica,8\" textcolor rgb \"red\" front  point pt 4 ps "
                         "0.3 lc rgb \"red\" offset 0,0"
                      << std::endl;
            }
        }
    }
}

void
PrintPosition (Ptr<Node> node)
{
  Ptr<MobilityModel> model = node->GetObject<MobilityModel> ();
  NS_LOG_UNCOND ("Position +****************************** " << model->GetPosition () << " at time "
                                                             << Simulator::Now ().GetSeconds ());
}

static ns3::GlobalValue g_bufferSize ("bufferSize", "RLC tx buffer size (MB)",
                                      ns3::UintegerValue (10),
                                      ns3::MakeUintegerChecker<uint32_t> ());

static ns3::GlobalValue g_enableTraces ("enableTraces", "If true, generate ns-3 traces",
                                        ns3::BooleanValue (true), ns3::MakeBooleanChecker ());

static ns3::GlobalValue g_e2lteEnabled ("e2lteEnabled", "If true, send LTE E2 reports",
                                        ns3::BooleanValue (true), ns3::MakeBooleanChecker ());

static ns3::GlobalValue g_e2nrEnabled ("e2nrEnabled", "If true, send NR E2 reports",
                                       ns3::BooleanValue (true), ns3::MakeBooleanChecker ());

static ns3::GlobalValue g_e2du ("e2du", "If true, send DU reports", ns3::BooleanValue (true),
                                ns3::MakeBooleanChecker ());

static ns3::GlobalValue g_e2cuUp ("e2cuUp", "If true, send CU-UP reports", ns3::BooleanValue (true),
                                  ns3::MakeBooleanChecker ());

static ns3::GlobalValue g_e2cuCp ("e2cuCp", "If true, send CU-CP reports", ns3::BooleanValue (true),
                                  ns3::MakeBooleanChecker ());

static ns3::GlobalValue g_reducedPmValues ("reducedPmValues", "If true, use a subset of the the pm containers",
                                        ns3::BooleanValue (false), ns3::MakeBooleanChecker ());

static ns3::GlobalValue
    g_hoSinrDifference ("hoSinrDifference",
                        "The value for which an handover between MmWave eNB is triggered",
                        ns3::DoubleValue (3), ns3::MakeDoubleChecker<double> ());

static ns3::GlobalValue
    g_indicationPeriodicity ("indicationPeriodicity",
                             "E2 Indication Periodicity reports (value in seconds)",
                             ns3::DoubleValue (0.1), ns3::MakeDoubleChecker<double> (0.01, 2.0));

static ns3::GlobalValue g_ues("ues",
			     "Number of UEs",
				ns3::UintegerValue(5),
				ns3::MakeUintegerChecker<uint32_t>(1, 255));

static ns3::GlobalValue g_speedMin(
			"speedMin",
			"Minimum UE speed in m/s",
			ns3::DoubleValue(2.0),
			ns3::MakeDoubleChecker<double>(0.0));

static ns3::GlobalValue g_speedMax(
                        "speedMax",
                        "Maximum UE speed in m/s",
                        ns3::DoubleValue(4.0),
                        ns3::MakeDoubleChecker<double>(0.0));


static ns3::GlobalValue g_simTime ("simTime", "Simulation time in seconds", ns3::DoubleValue (1000),
                                   ns3::MakeDoubleChecker<double> (0.1, 1000000.0));

static ns3::GlobalValue g_outageThreshold ("outageThreshold",
                                           "SNR threshold for outage events [dB]", // use -1000.0 with NoAuto
                                           ns3::DoubleValue (-5.0),
                                           ns3::MakeDoubleChecker<double> ());

static ns3::GlobalValue g_numberOfRaPreambles (
    "numberOfRaPreambles",
    "how many random access preambles are available for the contention based RACH process",
    ns3::UintegerValue (40), // Indicated for TS use case, 52 is default
    ns3::MakeUintegerChecker<uint8_t> ());

static ns3::GlobalValue
    g_handoverMode ("handoverMode",
                    "HO euristic to be used,"
                    "can be only \"NoAuto\", \"FixedTtt\", \"DynamicTtt\",   \"Threshold\"",
                    ns3::StringValue ("DynamicTtt"), ns3::MakeStringChecker ());

static ns3::GlobalValue g_e2TermIp ("e2TermIp", "The IP address of the RIC E2 termination",
                                    ns3::StringValue ("127.0.0.1"), ns3::MakeStringChecker ());

static ns3::GlobalValue
    g_enableE2FileLogging ("enableE2FileLogging",
                           "If true, generate offline file logging instead of connecting to RIC",
                           ns3::BooleanValue (false), ns3::MakeBooleanChecker ());

static ns3::GlobalValue g_controlFileName ("controlFileName",
                                           "The path to the control file (can be absolute)",
                                           ns3::StringValue (""),
                                           ns3::MakeStringChecker ());


// BEGIN RAN_SECURITY_REFERENCE_LOGGER_V1
namespace ran_security_reference
{
static std::ofstream eventLog;

static void WriteEvent(const std::string& context, const char* event,
                       uint64_t imsi, uint16_t cellId, uint16_t rnti,
                       uint16_t targetCellId)
{
  eventLog << ns3::Simulator::Now().GetMicroSeconds() << ","
           << event << "," << imsi << "," << cellId << "," << rnti
           << "," << targetCellId << "," << context << std::endl;
  if (!eventLog.good())
    {
      NS_FATAL_ERROR("RAN security reference logger: write failed");
    }
}

static void OnConnection(std::string context, uint64_t imsi,
                          uint16_t cellId, uint16_t rnti)
{
  WriteEvent(context, "CONNECTION_ESTABLISHED", imsi, cellId, rnti, 0);
}

static void OnReconfiguration(std::string context, uint64_t imsi,
                               uint16_t cellId, uint16_t rnti)
{
  WriteEvent(context, "CONNECTION_RECONFIGURATION", imsi, cellId, rnti, 0);
}

static void OnHandoverStart(std::string context, uint64_t imsi,
                            uint16_t cellId, uint16_t rnti,
                            uint16_t targetCellId)
{
  WriteEvent(context, "HANDOVER_START", imsi, cellId, rnti, targetCellId);
}

static void OnHandoverEnd(std::string context, uint64_t imsi,
                          uint16_t cellId, uint16_t rnti)
{
  WriteEvent(context, "HANDOVER_END_OK", imsi, cellId, rnti, 0);
}


// BEGIN RAN_SECURITY_STATE_SNAPSHOTS_V1
static std::ofstream stateLog;
static std::vector<ns3::Ptr<ns3::LteEnbRrc>> stateRrcs;
static std::vector<std::string> statePaths;
static uint64_t stateSequence = 0;

static void StateRow(int64_t now, uint64_t sequence, const char* type,
                     uint16_t cell, uint16_t rnti, uint64_t imsi,
                     int state, const std::string& path)
{
  stateLog << now << "," << sequence << "," << type << "," << cell
           << "," << rnti << "," << imsi << "," << state << "," << path << "\n";
}

static void SnapshotState()
{
  const int64_t now = ns3::Simulator::Now().GetMicroSeconds();
  const uint64_t sequence = ++stateSequence;
  std::set<uint16_t> cells;
  for (const auto& rrc : stateRrcs)
    {
      const uint16_t cell = rrc->GetCellId();
      if (cell == 0 || !cells.insert(cell).second)
        {
          NS_FATAL_ERROR("UE state reference requires unique nonzero primary cell IDs");
        }
    }
  StateRow(now, sequence, "BEGIN", 0, 0, 0, -1, "");
  for (std::size_t i = 0; i < stateRrcs.size(); ++i)
    {
      const uint16_t cell = stateRrcs[i]->GetCellId();
      StateRow(now, sequence, "CELL", cell, 0, 0, -1, statePaths[i]);
      const auto ueMap = stateRrcs[i]->GetUeMap();
      for (const auto& ue : ueMap)
        {
          StateRow(now, sequence, "UE", cell, ue.first, ue.second->GetImsi(),
                   static_cast<int>(ue.second->GetState()), statePaths[i]);
        }
    }
  StateRow(now, sequence, "END", 0, 0, 0, -1, "");
  stateLog.flush();
  if (!stateLog.good())
    {
      NS_FATAL_ERROR("UE state snapshot write failed");
    }
  ns3::Simulator::Schedule(ns3::MilliSeconds(10), &SnapshotState);
}

static void StartStateLogging(const std::string& eventPath, uint32_t expectedRrcObjects)
{
  if (stateRrcs.size() != expectedRrcObjects || stateRrcs.size() != statePaths.size())
    {
      NS_FATAL_ERROR("UE state reference does not cover all installed RRC objects");
    }
  const std::string path = eventPath + ".states.csv";
  std::ifstream existing(path.c_str());
  if (existing.good())
    {
      NS_FATAL_ERROR("UE state log already exists: " << path);
    }
  stateLog.open(path.c_str(), std::ios::out);
  if (!stateLog.is_open())
    {
      NS_FATAL_ERROR("Cannot create UE state log: " << path);
    }
  stateLog << "sim_time_us,snapshot_id,row_type,cell_id,rnti,imsi,rrc_state,rrc_path"
           << std::endl;
  std::cerr << "[RAN-STATE] rrc_objects=" << stateRrcs.size()
            << " period_us=10000 path=" << path << std::endl;
  ns3::Simulator::ScheduleNow(&SnapshotState);
}
// END RAN_SECURITY_STATE_SNAPSHOTS_V1

static void Install(uint32_t expectedRrcObjects)
{
  const char* configuredPath = std::getenv("RAN_SECURITY_EVENT_LOG");
  const std::string path = configuredPath && configuredPath[0]
      ? configuredPath : "ran-security-ue-events.csv";
  std::ifstream existing(path.c_str());
  if (existing.good())
    {
      NS_FATAL_ERROR("Reference log already exists: " << path
          << ". Set RAN_SECURITY_EVENT_LOG to a new path for this run.");
    }
  eventLog.open(path.c_str(), std::ios::out);
  if (!eventLog.is_open())
    {
      NS_FATAL_ERROR("Cannot create reference log: " << path);
    }
  eventLog << "sim_time_us,event,imsi,cell_id,rnti,target_cell_id,rrc_path"
           << std::endl;

  auto matches = ns3::Config::LookupMatches(
      "/NodeList/*/DeviceList/*/LteEnbRrc");
  std::cerr << "[RAN-REFERENCE] RRC objects matched=" << matches.GetN()
            << " expected=" << expectedRrcObjects << std::endl;
  if (matches.GetN() != expectedRrcObjects || matches.GetN() == 0)
    {
      NS_FATAL_ERROR("RRC lookup did not cover all installed eNB devices. "
          "Check the actual Config paths before collecting data.");
    }

  for (uint32_t i = 0; i < matches.GetN(); ++i)
    {
      auto object = matches.Get(i);
      const std::string context = matches.GetMatchedPath(i);
      auto rrc = ns3::DynamicCast<ns3::LteEnbRrc>(object);
      if (!rrc) { NS_FATAL_ERROR("Matched reference object is not LteEnbRrc"); }
      stateRrcs.push_back(rrc);
      statePaths.push_back(context);
      const bool connection = object->TraceConnect(
          "ConnectionEstablished", context, ns3::MakeCallback(&OnConnection));
      const bool reconfiguration = object->TraceConnect(
          "ConnectionReconfiguration", context,
          ns3::MakeCallback(&OnReconfiguration));
      const bool start = object->TraceConnect(
          "HandoverStart", context, ns3::MakeCallback(&OnHandoverStart));
      const bool end = object->TraceConnect(
          "HandoverEndOk", context, ns3::MakeCallback(&OnHandoverEnd));
      if (!(connection && reconfiguration && start && end))
        {
          NS_FATAL_ERROR("RRC trace connection failed: " << context);
        }
      std::cerr << "[RAN-REFERENCE] connected " << context
                << " type=" << object->GetInstanceTypeId().GetName()
                << std::endl;
    }
  StartStateLogging(path, expectedRrcObjects);
  std::cerr << "[RAN-REFERENCE] writing " << path << std::endl;
}
} // namespace ran_security_reference
// END RAN_SECURITY_REFERENCE_LOGGER_V1

int
main (int argc, char *argv[])
{
  // LogComponentEnableAll (LOG_PREFIX_ALL);
   // RAN security: verbose debug logging disabled.
   // RAN security: verbose debug logging disabled.

  // The maximum X coordinate of the scenario


  double maxXAxis = 4000;
  // The maximum Y coordinate of the scenario
  double maxYAxis = 4000;

  // Command line arguments
  // NASLAB_RAN_BASELINE_V1: opt-in automatic NR association.
  bool enableAutomaticNrAssociation = false;
  CommandLine cmd;
  cmd.AddValue ("enableAutomaticNrAssociation",
                "Repeat automatic NR association checks",
                enableAutomaticNrAssociation);
  cmd.Parse (argc, argv);
  Config::SetDefault ("ns3::LteEnbRrc::EnableAutomaticNrAssociation",
                      BooleanValue (enableAutomaticNrAssociation));
  NS_LOG_UNCOND ("NASLAB_RAN_BASELINE_V1 auto_nr="
                 << enableAutomaticNrAssociation
                 << " timestamp_unit=simulation_ms");

  bool harqEnabled = true;

  UintegerValue uintegerValue;
  BooleanValue booleanValue;
  StringValue stringValue;
  DoubleValue doubleValue;

  GlobalValue::GetValueByName ("hoSinrDifference", doubleValue);
  double hoSinrDifference = doubleValue.Get ();
  GlobalValue::GetValueByName ("bufferSize", uintegerValue);
  uint32_t bufferSize = uintegerValue.Get ();
  GlobalValue::GetValueByName ("enableTraces", booleanValue);
  bool enableTraces = booleanValue.Get ();
  GlobalValue::GetValueByName ("outageThreshold", doubleValue);
  double outageThreshold = doubleValue.Get ();
  GlobalValue::GetValueByName ("handoverMode", stringValue);
  std::string handoverMode = stringValue.Get ();
  GlobalValue::GetValueByName ("e2TermIp", stringValue);
  std::string e2TermIp = stringValue.Get ();
  GlobalValue::GetValueByName ("enableE2FileLogging", booleanValue);
  bool enableE2FileLogging = booleanValue.Get ();
  GlobalValue::GetValueByName ("numberOfRaPreambles", uintegerValue);
  uint8_t numberOfRaPreambles = uintegerValue.Get ();

  NS_LOG_UNCOND ("bufferSize " << bufferSize << " OutageThreshold " << outageThreshold
                               << " HandoverMode " << handoverMode << " e2TermIp " << e2TermIp
                               << " enableE2FileLogging " << enableE2FileLogging);

  GlobalValue::GetValueByName ("e2lteEnabled", booleanValue);
  bool e2lteEnabled = booleanValue.Get ();
  GlobalValue::GetValueByName ("e2nrEnabled", booleanValue);
  bool e2nrEnabled = booleanValue.Get ();
  GlobalValue::GetValueByName ("e2du", booleanValue);
  bool e2du = booleanValue.Get ();
  GlobalValue::GetValueByName ("e2cuUp", booleanValue);
  bool e2cuUp = booleanValue.Get ();
  GlobalValue::GetValueByName ("e2cuCp", booleanValue);
  bool e2cuCp = booleanValue.Get ();

  GlobalValue::GetValueByName ("reducedPmValues", booleanValue);
  bool reducedPmValues = booleanValue.Get ();

  GlobalValue::GetValueByName ("indicationPeriodicity", doubleValue);
  double indicationPeriodicity = doubleValue.Get ();
  GlobalValue::GetValueByName ("controlFileName", stringValue);
  std::string controlFilename = stringValue.Get ();

  NS_LOG_UNCOND ("e2lteEnabled " << e2lteEnabled << " e2nrEnabled " << e2nrEnabled << " e2du "
                                 << e2du << " e2cuCp " << e2cuCp << " e2cuUp " << e2cuUp
                                 << " controlFilename " << controlFilename
                                 << " indicationPeriodicity " << indicationPeriodicity);

  Config::SetDefault ("ns3::LteEnbNetDevice::ControlFileName", StringValue (controlFilename));
  Config::SetDefault ("ns3::LteEnbNetDevice::E2Periodicity", DoubleValue (indicationPeriodicity));
  Config::SetDefault ("ns3::MmWaveEnbNetDevice::E2Periodicity",
                      DoubleValue (indicationPeriodicity));

  Config::SetDefault ("ns3::MmWaveHelper::E2ModeLte", BooleanValue (e2lteEnabled));
  Config::SetDefault ("ns3::MmWaveHelper::E2ModeNr", BooleanValue (e2nrEnabled));

  // The DU PM reports should come from both NR gNB as well as LTE eNB,
  // since in the RLC/MAC/PHY entities are present in BOTH NR gNB as well as LTE eNB.
  // DU reports from LTE eNB are not implemented in this release
  Config::SetDefault ("ns3::MmWaveEnbNetDevice::EnableDuReport", BooleanValue (e2du));

  // The CU-UP PM reports should only come from LTE eNB, since in the NS3 “EN-DC
  // simulation (Option 3A)”, the PDCP is only in the LTE eNB and NOT in the NR gNB
  Config::SetDefault ("ns3::MmWaveEnbNetDevice::EnableCuUpReport", BooleanValue (e2cuUp));
  Config::SetDefault ("ns3::LteEnbNetDevice::EnableCuUpReport", BooleanValue (e2cuUp));

  Config::SetDefault ("ns3::MmWaveEnbNetDevice::EnableCuCpReport", BooleanValue (e2cuCp));
  Config::SetDefault ("ns3::LteEnbNetDevice::EnableCuCpReport", BooleanValue (e2cuCp));

  Config::SetDefault ("ns3::MmWaveEnbNetDevice::ReducedPmValues", BooleanValue (reducedPmValues));
  Config::SetDefault ("ns3::LteEnbNetDevice::ReducedPmValues", BooleanValue (reducedPmValues));

  Config::SetDefault ("ns3::LteEnbNetDevice::EnableE2FileLogging",
                      BooleanValue (enableE2FileLogging));
  Config::SetDefault ("ns3::MmWaveEnbNetDevice::EnableE2FileLogging",
                      BooleanValue (enableE2FileLogging));

  Config::SetDefault ("ns3::MmWaveEnbMac::NumberOfRaPreambles",
                      UintegerValue (numberOfRaPreambles));

  Config::SetDefault ("ns3::MmWaveHelper::HarqEnabled", BooleanValue (harqEnabled));
  Config::SetDefault ("ns3::MmWaveHelper::UseIdealRrc", BooleanValue (true));
  Config::SetDefault ("ns3::MmWaveHelper::E2TermIp", StringValue (e2TermIp));

  Config::SetDefault ("ns3::MmWaveFlexTtiMacScheduler::HarqEnabled", BooleanValue (harqEnabled));
  Config::SetDefault ("ns3::MmWavePhyMacCommon::NumHarqProcess", UintegerValue (100));
  //Config::SetDefault ("ns3::MmWaveBearerStatsCalculator::EpochDuration", TimeValue (MilliSeconds (10.0)));

  // set to false to use the 3GPP radiation pattern (proper configuration of the bearing and downtilt angles is needed)
  Config::SetDefault("ns3::PhasedArrayModel::AntennaElement",
                       PointerValue(CreateObject<IsotropicAntennaModel>()));
  Config::SetDefault ("ns3::ThreeGppChannelModel::UpdatePeriod", TimeValue (MilliSeconds (100.0)));
  Config::SetDefault ("ns3::ThreeGppChannelConditionModel::UpdatePeriod",
                      TimeValue (MilliSeconds (100)));

  Config::SetDefault ("ns3::LteRlcAm::ReportBufferStatusTimer", TimeValue (MilliSeconds (10.0)));
  Config::SetDefault ("ns3::LteRlcUmLowLat::ReportBufferStatusTimer",
                      TimeValue (MilliSeconds (10.0)));
  Config::SetDefault ("ns3::LteRlcUm::MaxTxBufferSize", UintegerValue (bufferSize * 1024 * 1024));
  Config::SetDefault ("ns3::LteRlcUmLowLat::MaxTxBufferSize",
                      UintegerValue (bufferSize * 1024 * 1024));
  Config::SetDefault ("ns3::LteRlcAm::MaxTxBufferSize", UintegerValue (bufferSize * 1024 * 1024));

  Config::SetDefault ("ns3::LteEnbRrc::OutageThreshold", DoubleValue (outageThreshold));
  Config::SetDefault ("ns3::LteEnbRrc::SecondaryCellHandoverMode", StringValue (handoverMode));
  Config::SetDefault ("ns3::LteEnbRrc::HoSinrDifference", DoubleValue (hoSinrDifference));

  // Carrier bandwidth in Hz
  double bandwidth = 20e6;
  // Center frequency in Hz
  double centerFrequency = 3.5e9;
  // Distance between the mmWave BSs and the two co-located LTE and mmWave BSs in meters
  double isd = 1000; // (interside distance)
  // Number of antennas in each UE
  int numAntennasMcUe = 1;
  // Number of antennas in each mmWave BS
  int numAntennasMmWave = 1;

  NS_LOG_INFO ("Bandwidth " << bandwidth << " centerFrequency " << double (centerFrequency)
                            << " isd " << isd << " numAntennasMcUe " << numAntennasMcUe
                            << " numAntennasMmWave " << numAntennasMmWave);

  // Set the number of antennas in the devices
  Config::SetDefault ("ns3::McUeNetDevice::AntennaNum", UintegerValue (numAntennasMcUe));
  Config::SetDefault ("ns3::MmWaveNetDevice::AntennaNum", UintegerValue (numAntennasMmWave));
  Config::SetDefault ("ns3::MmWavePhyMacCommon::Bandwidth", DoubleValue (bandwidth));
  Config::SetDefault ("ns3::MmWavePhyMacCommon::CenterFreq", DoubleValue (centerFrequency));

  Ptr<MmWaveHelper> mmwaveHelper = CreateObject<MmWaveHelper> ();
  mmwaveHelper->SetPathlossModelType ("ns3::ThreeGppUmiStreetCanyonPropagationLossModel");
  mmwaveHelper->SetChannelConditionModelType ("ns3::ThreeGppUmiStreetCanyonChannelConditionModel");

  Ptr<MmWavePointToPointEpcHelper> epcHelper = CreateObject<MmWavePointToPointEpcHelper> ();
  mmwaveHelper->SetEpcHelper (epcHelper);

  uint8_t nMmWaveEnbNodes = 3;
  uint8_t nLteEnbNodes = 1;
  UintegerValue ueValue;
  GlobalValue::GetValueByName("ues" , ueValue);
  uint32_t ues = ueValue.Get();
  uint8_t nUeNodes = ues; //* nMmWaveEnbNodes;
  //uint8_t nUeNodes = 1;
  NS_LOG_INFO (" Bandwidth " << bandwidth << " centerFrequency " << double (centerFrequency)
                             << " isd " << isd << " numAntennasMcUe " << numAntennasMcUe
                             << " numAntennasMmWave " << numAntennasMmWave << " nMmWaveEnbNodes "
                             << unsigned (nMmWaveEnbNodes));

  // Get SGW/PGW and create a single RemoteHost
  Ptr<Node> pgw = epcHelper->GetPgwNode ();
  NodeContainer remoteHostContainer;
  remoteHostContainer.Create (1);
  Ptr<Node> remoteHost = remoteHostContainer.Get (0);
  InternetStackHelper internet;
  internet.Install (remoteHostContainer);

  // Create the Internet by connecting remoteHost to pgw. Setup routing too
  PointToPointHelper p2ph;
  p2ph.SetDeviceAttribute ("DataRate", DataRateValue (DataRate ("100Gb/s")));
  p2ph.SetDeviceAttribute ("Mtu", UintegerValue (2500));
  p2ph.SetChannelAttribute ("Delay", TimeValue (Seconds (0.010)));
  NetDeviceContainer internetDevices = p2ph.Install (pgw, remoteHost);
  Ipv4AddressHelper ipv4h;
  ipv4h.SetBase ("1.0.0.0", "255.0.0.0");
  Ipv4InterfaceContainer internetIpIfaces = ipv4h.Assign (internetDevices);
  // interface 0 is localhost, 1 is the p2p device
  Ipv4Address remoteHostAddr = internetIpIfaces.GetAddress (1);
  Ipv4StaticRoutingHelper ipv4RoutingHelper;
  Ptr<Ipv4StaticRouting> remoteHostStaticRouting =
      ipv4RoutingHelper.GetStaticRouting (remoteHost->GetObject<Ipv4> ());
  remoteHostStaticRouting->AddNetworkRouteTo (Ipv4Address ("7.0.0.0"), Ipv4Mask ("255.0.0.0"), 1);

  // create LTE, mmWave eNB nodes and UE node
  NodeContainer ueNodes;
  NodeContainer mmWaveEnbNodes;
  NodeContainer lteEnbNodes;
  NodeContainer allEnbNodes;
  mmWaveEnbNodes.Create (nMmWaveEnbNodes);
  lteEnbNodes.Create (nLteEnbNodes);
  ueNodes.Create (nUeNodes);
  allEnbNodes.Add (lteEnbNodes);
  allEnbNodes.Add (mmWaveEnbNodes);

  // Position
  Vector centerPosition = Vector (maxXAxis / 2, maxYAxis / 2, 3);

  // Install Mobility Model
  Ptr<ListPositionAllocator> enbPositionAlloc = CreateObject<ListPositionAllocator> ();

  // We want a center with one LTE enb and one mmWave co-located in the same place
  enbPositionAlloc->Add (centerPosition);
  enbPositionAlloc->Add (centerPosition);

  double x, y;
  double nConstellation = nMmWaveEnbNodes - 1;

  // This guarantee that each of the rest BSs is placed at the same distance from the two co-located in the center
  for (int8_t i = 0; i < nConstellation; ++i)
    {
      x = isd * cos ((2 * M_PI * i) / (nConstellation));
      y = isd * sin ((2 * M_PI * i) / (nConstellation));
      enbPositionAlloc->Add (Vector (centerPosition.x + x, centerPosition.y + y, 3));
    }

  MobilityHelper enbmobility;
  enbmobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  enbmobility.SetPositionAllocator (enbPositionAlloc);
  enbmobility.Install (allEnbNodes);

  MobilityHelper uemobility;

  Ptr<UniformDiscPositionAllocator> uePositionAlloc = CreateObject<UniformDiscPositionAllocator> ();

  uePositionAlloc->SetX (centerPosition.x);
  uePositionAlloc->SetY (centerPosition.y);
  uePositionAlloc->SetRho (isd);
  DoubleValue speedMinValue;
  DoubleValue speedMaxValue;
  GlobalValue::GetValueByName("speedMin", speedMinValue);
  GlobalValue::GetValueByName("speedMax", speedMaxValue);
  double speedMin = speedMinValue.Get();
  double speedMax = speedMaxValue.Get();
  NS_ABORT_MSG_IF(speedMin > speedMax,
			"speedMin must be less than or equal to speedMax");

  Ptr<UniformRandomVariable> speed = CreateObject<UniformRandomVariable>();
  speed->SetAttribute("Min", DoubleValue(speedMin));
  speed->SetAttribute("Max", DoubleValue(speedMax));




  uemobility.SetMobilityModel ("ns3::RandomWalk2dOutdoorMobilityModel", "Speed",
                               PointerValue (speed), "Bounds",
                               RectangleValue (Rectangle (0, maxXAxis, 0, maxYAxis)));
  uemobility.SetPositionAllocator (uePositionAlloc);
  uemobility.Install (ueNodes);

  // Install mmWave, lte, mc Devices to the nodes
  NetDeviceContainer lteEnbDevs = mmwaveHelper->InstallLteEnbDevice (lteEnbNodes);
  NetDeviceContainer mmWaveEnbDevs = mmwaveHelper->InstallEnbDevice (mmWaveEnbNodes);
  NetDeviceContainer mcUeDevs = mmwaveHelper->InstallMcUeDevice (ueNodes);

  // Install the IP stack on the UEs
  internet.Install (ueNodes);
  Ipv4InterfaceContainer ueIpIface;
  ueIpIface = epcHelper->AssignUeIpv4Address (NetDeviceContainer (mcUeDevs));
  // Assign IP address to UEs, and install applications
  for (uint32_t u = 0; u < ueNodes.GetN (); ++u)
    {
      Ptr<Node> ueNode = ueNodes.Get (u);
      // Set the default gateway for the UE
      Ptr<Ipv4StaticRouting> ueStaticRouting =
          ipv4RoutingHelper.GetStaticRouting (ueNode->GetObject<Ipv4> ());
      ueStaticRouting->SetDefaultRoute (epcHelper->GetUeDefaultGatewayAddress (), 1);
    }

  // Add X2 interfaces
  mmwaveHelper->AddX2Interface (lteEnbNodes, mmWaveEnbNodes);

  // Manual attachment
  // Subscribe before UE attachment to capture initial events.
  ran_security_reference::Install(
      lteEnbDevs.GetN() + mmWaveEnbDevs.GetN());

  // BEGIN RAN_SECURITY_LATE_ATTACH_V2
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
  // END RAN_SECURITY_LATE_ATTACH_V2

  // Install and start applications
  // On the remoteHost there is UDP OnOff Application

  uint16_t portUdp = 60000;
  Address sinkLocalAddressUdp (InetSocketAddress (Ipv4Address::GetAny (), portUdp));
  PacketSinkHelper sinkHelperUdp ("ns3::UdpSocketFactory", sinkLocalAddressUdp);
  AddressValue serverAddressUdp (InetSocketAddress (remoteHostAddr, portUdp));

  ApplicationContainer sinkApp;
  sinkApp.Add (sinkHelperUdp.Install (remoteHost));

  // -------------------------------------------------------
  // Dynamic downlink traffic for KPM traffic prediction
  // -------------------------------------------------------

  ApplicationContainer clientLow;
  ApplicationContainer clientMedium;
  ApplicationContainer clientHigh;
  ApplicationContainer clientBurst;
  ApplicationContainer clientRecovery;

  // Get simulation duration
  GlobalValue::GetValueByName ("simTime", doubleValue);
  double simTime = doubleValue.Get ();

  // Divide simulation into 5 traffic phases
  double t1 = simTime * 0.20;
  double t2 = simTime * 0.40;
  double t3 = simTime * 0.60;
  double t4 = simTime * 0.80;

  for (uint32_t u = 0; u < ueNodes.GetN (); ++u)
    {
      // Downlink sink at each UE
      PacketSinkHelper dlPacketSinkHelper (
          "ns3::UdpSocketFactory",
          InetSocketAddress (Ipv4Address::GetAny (), 1234));

      sinkApp.Add (dlPacketSinkHelper.Install (ueNodes.Get (u)));

      // ---------------- LOW LOAD ----------------
      // 1280 bytes every 2000 us ~= 5.12 Mbps / UE
      UdpClientHelper lowClient (ueIpIface.GetAddress (u), 1234);
      lowClient.SetAttribute (
          "Interval",
          TimeValue (MicroSeconds (2000)));
      lowClient.SetAttribute (
          "MaxPackets",
          UintegerValue (UINT32_MAX));
      lowClient.SetAttribute (
          "PacketSize",
          UintegerValue (1280));

      clientLow.Add (lowClient.Install (remoteHost));

      // ---------------- MEDIUM LOAD ----------------
      // 1280 bytes every 1000 us ~= 10.24 Mbps / UE
      UdpClientHelper mediumClient (ueIpIface.GetAddress (u), 1234);
      mediumClient.SetAttribute (
          "Interval",
          TimeValue (MicroSeconds (1000)));
      mediumClient.SetAttribute (
          "MaxPackets",
          UintegerValue (UINT32_MAX));
      mediumClient.SetAttribute (
          "PacketSize",
          UintegerValue (1280));

      clientMedium.Add (mediumClient.Install (remoteHost));

      // ---------------- HIGH LOAD ----------------
      // 1280 bytes every 500 us ~= 20.48 Mbps / UE
      UdpClientHelper highClient (ueIpIface.GetAddress (u), 1234);
      highClient.SetAttribute (
          "Interval",
          TimeValue (MicroSeconds (500)));
      highClient.SetAttribute (
          "MaxPackets",
          UintegerValue (UINT32_MAX));
      highClient.SetAttribute (
          "PacketSize",
          UintegerValue (1280));

      clientHigh.Add (highClient.Install (remoteHost));

      // ---------------- BURST LOAD ----------------
      // 1280 bytes every 250 us ~= 40.96 Mbps / UE
      UdpClientHelper burstClient (ueIpIface.GetAddress (u), 1234);
      burstClient.SetAttribute (
          "Interval",
          TimeValue (MicroSeconds (250)));
      burstClient.SetAttribute (
          "MaxPackets",
          UintegerValue (UINT32_MAX));
      burstClient.SetAttribute (
          "PacketSize",
          UintegerValue (1280));

      clientBurst.Add (burstClient.Install (remoteHost));

      // ---------------- RECOVERY ----------------
      UdpClientHelper recoveryClient (ueIpIface.GetAddress (u), 1234);
      recoveryClient.SetAttribute (
          "Interval",
          TimeValue (MicroSeconds (1000)));
      recoveryClient.SetAttribute (
          "MaxPackets",
          UintegerValue (UINT32_MAX));
      recoveryClient.SetAttribute (
          "PacketSize",
          UintegerValue (1280));

      clientRecovery.Add (recoveryClient.Install (remoteHost));
    }

  // Start sinks
  sinkApp.Start (Seconds (0.0));

  // Traffic phases
  clientLow.Start (Seconds (0.1));
  clientLow.Stop (Seconds (t1));

  clientMedium.Start (Seconds (t1));
  clientMedium.Stop (Seconds (t2));

  clientHigh.Start (Seconds (t2));
  clientHigh.Stop (Seconds (t3));

  clientBurst.Start (Seconds (t3));
  clientBurst.Stop (Seconds (t4));

  clientRecovery.Start (Seconds (t4));
  clientRecovery.Stop (Seconds (simTime - 0.1));

  std::cout << "\n=== Dynamic Traffic Profile ===" << std::endl;
  std::cout << "LOW      : 0.1 - " << t1 << " s" << std::endl;
  std::cout << "MEDIUM   : " << t1 << " - " << t2 << " s" << std::endl;
  std::cout << "HIGH     : " << t2 << " - " << t3 << " s" << std::endl;
  std::cout << "BURST    : " << t3 << " - " << t4 << " s" << std::endl;
  std::cout << "RECOVERY : " << t4 << " - " << simTime << " s" << std::endl;
  // int numPrints = 5;
  // for (int i = 0; i < numPrints; i++)
  //   {
  //     for (uint32_t j = 0; j < ueNodes.GetN (); j++)
  //       {
  //         Simulator::Schedule (Seconds (i * simTime / numPrints), &PrintPosition, ueNodes.Get (j));
  //       }
  //   }

  if (enableTraces)
    {
      mmwaveHelper->EnableTraces ();
    }

  // trick to enable PHY traces for the LTE stack
  Ptr<LteHelper> lteHelper = CreateObject<LteHelper> ();
  lteHelper->Initialize ();
  lteHelper->EnablePhyTraces ();
  lteHelper->EnableMacTraces ();

  // Since nodes are randomly allocated during each run we always need to print their positions
  PrintGnuplottableUeListToFile ("ues.txt");
  PrintGnuplottableEnbListToFile ("enbs.txt");

  bool run = true;
  if (run)
    {
      NS_LOG_UNCOND ("Simulation time is " << simTime << " seconds ");
      Simulator::Stop (Seconds (simTime));
      NS_LOG_INFO ("Run Simulation.");
      Simulator::Run ();
    }

  NS_LOG_INFO (lteHelper);
  Simulator::Destroy ();
  NS_LOG_INFO ("Done.");
  return 0;
}
