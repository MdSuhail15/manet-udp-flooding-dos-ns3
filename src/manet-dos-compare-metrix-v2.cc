/*
 * Copyright (c) 2011 University of Kansas
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Justin Rohrer <rohrej@ittc.ku.edu>
 *
 * James P.G. Sterbenz <jpgs@ittc.ku.edu>, director
 * ResiliNets Research Group  https://resilinets.org/
 * Information and Telecommunication Technology Center (ITTC)
 * and Department of Electrical Engineering and Computer Science
 * The University of Kansas Lawrence, KS USA.
 *
 * Work supported in part by NSF FIND (Future Internet Design) Program
 * under grant CNS-0626918 (Postmodern Internet Architecture),
 * NSF grant CNS-1050226 (Multilayer Network Resilience Analysis and Experimentation on GENI),
 * US Department of Defense (DoD), and ITTC at The University of Kansas.
 */

/*
 * This example program allows one to run ns-3 DSDV, DSR, AODV, or OLSR under
 * a typical random waypoint mobility model.
 *
 * By default, the simulation runs for 200 simulated seconds, of which
 * the first 100 are used for start-up time.  The number of nodes is 50.
 * Nodes move according to RandomWaypointMobilityModel with a speed of
 * 20 m/s and no pause time within a 300x1500 m region.  The WiFi is
 * in ad hoc mode with a 11 Mb/s rate (802.11b) and a Friis loss model.
 * The transmit power is set to 7.5 dBm.
 *
 * It is possible to change the mobility and density of the network by
 * directly modifying the speed and the number of nodes.  It is also
 * possible to change the characteristics of the network by changing
 * the transmit power (as power increases, the impact of mobility
 * decreases and the effective density increases).
 *
 * By default, AODV is used, but specifying a string of 'OLSR', 'DSDV', or
 * 'DSR' to the protocol command-line argument will change the protocol.
 *
 * By default, there are 10 source/sink data pairs sending UDP data
 * at an application rate of 2.048 Kb/s each.    This is typically done
 * at a rate of 4 64-byte packets per second.  Application data is
 * started at a random time between 100 and 101 seconds and continues
 * to the end of the simulation.
 *
 * The program outputs a few items:
 * - packet receptions are notified to stdout such as:
 *   <timestamp> <node-id> received one packet from <src-address>
 * - each second, the data reception statistics are tabulated and output
 *   to a comma-separated value (csv) file
 * - mobility traces of the nodes are printed to 'manet-routing-compare.mob';
 *   this trace can be disabled using a command-line argument
 * - some tracing and flow monitor configuration that used to work is
 *   left commented inline in the program
 *
 * This version adds an optional UDP flooding DoS scenario.
 * It does not modify AODV/DSDV source files. Malicious node(s) simply
 * generate high-rate UDP traffic, creating contention and reducing the
 * performance of legitimate MANET flows. It also writes a FlowMonitor
 * summary CSV for PDR, throughput, average delay, and lost packets.
 */

#include "ns3/aodv-module.h"
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/dsdv-module.h"
#include "ns3/dsr-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/olsr-module.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/netanim-module.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

using namespace ns3;
using namespace dsr;

NS_LOG_COMPONENT_DEFINE("manet-dos-compare");

/**
 * Routing experiment class.
 *
 * It handles the creation and run of an experiment.
 */
class RoutingExperiment
{
  public:
    RoutingExperiment();
    /**
     * Run the experiment.
     */
    void Run();

    /**
     * Handles the command-line parameters.
     * @param argc The argument count.
     * @param argv The argument vector.
     */
    void CommandSetup(int argc, char** argv);

  private:
    /**
     * Setup the receiving socket in a Sink Node.
     * @param addr The address of the node.
     * @param node The node pointer.
     * @return the socket.
     */
    Ptr<Socket> SetupPacketReceive(Ipv4Address addr, Ptr<Node> node);
    /**
     * Receive a packet.
     * @param socket The receiving socket.
     */
    void ReceivePacket(Ptr<Socket> socket);
    /**
     * Compute the throughput.
     */
    void CheckThroughput();

    uint32_t port{9};            //!< Receiving port number.
    uint32_t bytesTotal{0};      //!< Total received bytes.
    uint32_t packetsReceived{0}; //!< Total received packets.

    std::string m_CSVfileName{"manet-routing.output.csv"}; //!< CSV filename (per-second).
    std::string m_summaryFile{"manet-summary.csv"};        //!< Summary CSV (one row per run).
    uint32_t m_seed{1};                                    //!< RNG run number (for seed averaging).
    int m_nSinks{10};                                      //!< Number of sink nodes.
    std::string m_protocolName{"AODV"};                    //!< Protocol name.
    double m_txp{7.5};                                     //!< Tx power.
    bool m_traceMobility{true};                            //!< Enable mobility tracing.
    bool m_flowMonitor{false};                             //!< Enable FlowMonitor XML output.
    bool m_enableAnim{false};                              //!< Write NetAnim XML animation

    // Experiment controls used for the A-D experiment matrix.
    int m_nodeSpeed{20};                                   //!< Maximum RandomWaypoint speed in m/s.
    int m_nodePause{0};                                    //!< RandomWaypoint pause time in seconds.

    // UDP flooding DoS attack parameters.
    // This models an availability attack without modifying AODV/DSDV source files.
    bool m_enableDos{false};                               //!< Enable UDP flooding attack.
    uint32_t m_numAttackers{1};                            //!< Number of malicious flooding nodes for Set E.
    std::string m_attackerNodes{""};                       //!< Optional comma-separated attacker IDs. If empty, use highest node IDs.
    uint32_t m_attackTargetNode{0};                        //!< Node targeted by flood traffic.
    uint32_t m_attackPort{9999};                           //!< Attack destination port. Different from legitimate port.
    std::string m_dosRate{"1Mbps"};                        //!< Flooding data rate per attacker.
    uint32_t m_dosPacketSize{512};                         //!< Flooding packet size in bytes.
    double m_dosStart{50.0};                               //!< Attack start time.
    double m_dosStop{200.0};                               //!< Attack stop time.
};

RoutingExperiment::RoutingExperiment()
{
}

static std::string
Trim(const std::string& value)
{
    size_t first = 0;
    while (first < value.size() && std::isspace(static_cast<unsigned char>(value[first])))
    {
        ++first;
    }

    size_t last = value.size();
    while (last > first && std::isspace(static_cast<unsigned char>(value[last - 1])))
    {
        --last;
    }

    return value.substr(first, last - first);
}

static std::vector<uint32_t>
ParseNodeList(const std::string& csv)
{
    std::vector<uint32_t> nodes;
    std::stringstream ss(csv);
    std::string token;

    while (std::getline(ss, token, ','))
    {
        token = Trim(token);
        if (token.empty())
        {
            continue;
        }
        nodes.push_back(static_cast<uint32_t>(std::stoul(token)));
    }

    return nodes;
}

static std::string
JoinNodeList(const std::vector<uint32_t>& nodes, const std::string& sep = "|")
{
    std::ostringstream oss;
    for (size_t i = 0; i < nodes.size(); ++i)
    {
        if (i > 0)
        {
            oss << sep;
        }
        oss << nodes[i];
    }
    return oss.str();
}

static inline std::string
PrintReceivedPacket(Ptr<Socket> socket, Ptr<Packet> packet, Address senderAddress)
{
    std::ostringstream oss;

    oss << Simulator::Now().GetSeconds() << " " << socket->GetNode()->GetId();

    if (InetSocketAddress::IsMatchingType(senderAddress))
    {
        InetSocketAddress addr = InetSocketAddress::ConvertFrom(senderAddress);
        oss << " received one packet from " << addr.GetIpv4();
    }
    else
    {
        oss << " received one packet!";
    }
    return oss.str();
}

void
RoutingExperiment::ReceivePacket(Ptr<Socket> socket)
{
    Ptr<Packet> packet;
    Address senderAddress;
    while ((packet = socket->RecvFrom(senderAddress)))
    {
        bytesTotal += packet->GetSize();
        packetsReceived += 1;
        NS_LOG_UNCOND(PrintReceivedPacket(socket, packet, senderAddress));
    }
}

void
RoutingExperiment::CheckThroughput()
{
    double kbs = (bytesTotal * 8.0) / 1000;
    bytesTotal = 0;

    std::ofstream out(m_CSVfileName, std::ios::app);

    out << (Simulator::Now()).GetSeconds() << "," << kbs << "," << packetsReceived << ","
        << m_nSinks << "," << m_protocolName << "," << m_txp << ","
        << (m_enableDos ? "true" : "false") << "," << m_numAttackers << ",\"" << m_attackerNodes << "\","
        << m_attackTargetNode << "," << m_dosRate << ","
        << m_nodeSpeed << "," << m_nodePause << std::endl;

    out.close();
    packetsReceived = 0;
    Simulator::Schedule(Seconds(1), &RoutingExperiment::CheckThroughput, this);
}

Ptr<Socket>
RoutingExperiment::SetupPacketReceive(Ipv4Address addr, Ptr<Node> node)
{
    TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
    Ptr<Socket> sink = Socket::CreateSocket(node, tid);
    InetSocketAddress local = InetSocketAddress(addr, port);
    sink->Bind(local);
    sink->SetRecvCallback(MakeCallback(&RoutingExperiment::ReceivePacket, this));

    return sink;
}

void
RoutingExperiment::CommandSetup(int argc, char** argv)
{
    CommandLine cmd(__FILE__);
    cmd.AddValue("CSVfileName", "The name of the CSV output file name", m_CSVfileName);
    cmd.AddValue("summaryFile", "One-row-per-run summary CSV with PDR/throughput/delay/lost", m_summaryFile);
    cmd.AddValue("seed", "RNG run number for repeatable seed averaging", m_seed);
    cmd.AddValue("traceMobility", "Enable mobility tracing", m_traceMobility);
    cmd.AddValue("protocol", "Routing protocol (OLSR, AODV, DSDV, DSR)", m_protocolName);
    cmd.AddValue("flowMonitor", "Enable FlowMonitor XML output", m_flowMonitor);
    cmd.AddValue("nodeSpeed", "Maximum RandomWaypoint speed in m/s", m_nodeSpeed);
    cmd.AddValue("nodePause", "RandomWaypoint pause time in seconds", m_nodePause);

    // DoS flooding options. Examples:
    // --enableDos=true --numAttackers=1 --dosRate=1Mbps
    // --enableDos=true --numAttackers=3 --dosRate=1Mbps
    // --enableDos=true --numAttackers=5 --dosRate=1Mbps
    // Optional override: --attackerNodes=49,48,47
    cmd.AddValue("enableDos", "Enable UDP flooding DoS attack", m_enableDos);
    cmd.AddValue("numAttackers", "Number of malicious flooding nodes used when attackerNodes is empty", m_numAttackers);
    cmd.AddValue("attackerNodes", "Optional comma-separated attacker node IDs. If empty, highest node IDs are used", m_attackerNodes);
    cmd.AddValue("attackTargetNode", "Node ID targeted by the flooding node", m_attackTargetNode);
    cmd.AddValue("attackPort", "UDP destination port used by the flooding attack", m_attackPort);
    cmd.AddValue("dosRate", "UDP flooding data rate, e.g., 500kbps, 1Mbps, 2Mbps", m_dosRate);
    cmd.AddValue("dosPacketSize", "UDP flooding packet size in bytes", m_dosPacketSize);
    cmd.AddValue("dosStart", "Time when the flooding attack starts", m_dosStart);
    cmd.AddValue("dosStop", "Time when the flooding attack stops", m_dosStop);

    cmd.AddValue("enableAnim", "Write NetAnim XML animation file", m_enableAnim);

    cmd.Parse(argc, argv);

    std::vector<std::string> allowedProtocols{"OLSR", "AODV", "DSDV", "DSR"};

    if (std::find(std::begin(allowedProtocols), std::end(allowedProtocols), m_protocolName) ==
        std::end(allowedProtocols))
    {
        NS_FATAL_ERROR("No such protocol:" << m_protocolName);
    }
}

int
main(int argc, char* argv[])
{
    RoutingExperiment experiment;
    experiment.CommandSetup(argc, argv);
    experiment.Run();

    return 0;
}

void
RoutingExperiment::Run()
{
    Packet::EnablePrinting();

    // Seed the RNG so repeated runs with different --seed values differ,
    // which is what makes multi-seed averaging statistically meaningful.
    RngSeedManager::SetSeed(1);
    RngSeedManager::SetRun(m_seed);

    // blank out the last output file and write the column headers
    std::ofstream out(m_CSVfileName);
    out << "SimulationSecond,"
        << "ReceiveRate,"
        << "PacketsReceived,"
        << "NumberOfSinks,"
        << "RoutingProtocol,"
        << "TransmissionPower,"
        << "DosEnabled,"
        << "NumAttackers,"
        << "AttackerNodes,"
        << "AttackTargetNode,"
        << "DosRate,"
        << "NodeSpeed,"
        << "NodePause" << std::endl;
    out.close();

    int nWifis = 50;
    std::vector<uint32_t> attackerNodes = ParseNodeList(m_attackerNodes);

    if (m_enableDos)
    {
        if (m_numAttackers == 0 && attackerNodes.empty())
        {
            NS_FATAL_ERROR("enableDos=true requires numAttackers > 0 or a non-empty --attackerNodes list");
        }
        if (m_attackTargetNode >= static_cast<uint32_t>(nWifis))
        {
            NS_FATAL_ERROR("attackTargetNode must be a valid node ID between 0 and " << (nWifis - 1));
        }

        // If no explicit attacker list is provided, choose the highest node IDs.
        // This keeps attackers away from the original sink/source nodes in the default example:
        // sinks 0-9 and legitimate sources 10-19. For Set E, use --numAttackers=1, 3, or 5.
        if (attackerNodes.empty())
        {
            for (uint32_t id = static_cast<uint32_t>(nWifis); id > 0 && attackerNodes.size() < m_numAttackers; --id)
            {
                uint32_t candidate = id - 1;
                if (candidate != m_attackTargetNode)
                {
                    attackerNodes.push_back(candidate);
                }
            }
        }

        if (attackerNodes.empty())
        {
            NS_FATAL_ERROR("No valid attacker nodes selected");
        }

        for (size_t i = 0; i < attackerNodes.size(); ++i)
        {
            uint32_t attacker = attackerNodes[i];
            if (attacker >= static_cast<uint32_t>(nWifis))
            {
                NS_FATAL_ERROR("All attacker node IDs must be between 0 and " << (nWifis - 1));
            }
            if (attacker == m_attackTargetNode)
            {
                NS_FATAL_ERROR("An attacker node cannot also be the attack target node");
            }
            for (size_t j = i + 1; j < attackerNodes.size(); ++j)
            {
                if (attackerNodes[j] == attacker)
                {
                    NS_FATAL_ERROR("Duplicate attacker node ID found: " << attacker);
                }
            }
        }

        // Keep m_numAttackers aligned with the actual list used in this run.
        m_numAttackers = static_cast<uint32_t>(attackerNodes.size());
        m_attackerNodes = JoinNodeList(attackerNodes);
    }

    double TotalTime = 200.0;
    std::string rate("2048bps");
    std::string phyMode("DsssRate11Mbps");
    std::string tr_name("manet-dos-compare");
    int nodeSpeed = m_nodeSpeed; // in m/s
    int nodePause = m_nodePause; // in s

    Config::SetDefault("ns3::OnOffApplication::PacketSize", StringValue("64"));
    Config::SetDefault("ns3::OnOffApplication::DataRate", StringValue(rate));

    // Set Non-unicastMode rate to unicast mode
    Config::SetDefault("ns3::WifiRemoteStationManager::NonUnicastMode", StringValue(phyMode));

    NodeContainer adhocNodes;
    adhocNodes.Create(nWifis);

    // setting up wifi phy and channel using helpers
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211b);

    YansWifiPhyHelper wifiPhy;
    YansWifiChannelHelper wifiChannel;
    wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss("ns3::FriisPropagationLossModel");
    wifiPhy.SetChannel(wifiChannel.Create());

    // Add a mac and disable rate control
    WifiMacHelper wifiMac;
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode",
                                 StringValue(phyMode),
                                 "ControlMode",
                                 StringValue(phyMode));

    wifiPhy.Set("TxPowerStart", DoubleValue(m_txp));
    wifiPhy.Set("TxPowerEnd", DoubleValue(m_txp));

    wifiMac.SetType("ns3::AdhocWifiMac");
    NetDeviceContainer adhocDevices = wifi.Install(wifiPhy, wifiMac, adhocNodes);

    MobilityHelper mobilityAdhoc;
    int64_t streamIndex = 0; // used to get consistent mobility across scenarios

    ObjectFactory pos;
    pos.SetTypeId("ns3::RandomRectanglePositionAllocator");
    pos.Set("X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=300.0]"));
    pos.Set("Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1500.0]"));

    Ptr<PositionAllocator> taPositionAlloc = pos.Create()->GetObject<PositionAllocator>();
    streamIndex += taPositionAlloc->AssignStreams(streamIndex);

    std::stringstream ssSpeed;
    ssSpeed << "ns3::UniformRandomVariable[Min=0.0|Max=" << nodeSpeed << "]";
    std::stringstream ssPause;
    ssPause << "ns3::ConstantRandomVariable[Constant=" << nodePause << "]";
    mobilityAdhoc.SetMobilityModel("ns3::RandomWaypointMobilityModel",
                                   "Speed",
                                   StringValue(ssSpeed.str()),
                                   "Pause",
                                   StringValue(ssPause.str()),
                                   "PositionAllocator",
                                   PointerValue(taPositionAlloc));
    mobilityAdhoc.SetPositionAllocator(taPositionAlloc);
    mobilityAdhoc.Install(adhocNodes);
    streamIndex += mobilityAdhoc.AssignStreams(adhocNodes, streamIndex);

    AodvHelper aodv;
    OlsrHelper olsr;
    DsdvHelper dsdv;
    DsrHelper dsr;
    DsrMainHelper dsrMain;
    Ipv4ListRoutingHelper list;
    InternetStackHelper internet;

    if (m_protocolName == "OLSR")
    {
        list.Add(olsr, 100);
        internet.SetRoutingHelper(list);
        internet.Install(adhocNodes);
    }
    else if (m_protocolName == "AODV")
    {
        list.Add(aodv, 100);
        internet.SetRoutingHelper(list);
        internet.Install(adhocNodes);
    }
    else if (m_protocolName == "DSDV")
    {
        list.Add(dsdv, 100);
        internet.SetRoutingHelper(list);
        internet.Install(adhocNodes);
    }
    else if (m_protocolName == "DSR")
    {
        internet.Install(adhocNodes);
        dsrMain.Install(dsr, adhocNodes);
        if (m_flowMonitor)
        {
            NS_FATAL_ERROR("Error: FlowMonitor does not work with DSR. Terminating.");
        }
    }
    else
    {
        NS_FATAL_ERROR("No such protocol:" << m_protocolName);
    }

    NS_LOG_INFO("assigning ip address");

    Ipv4AddressHelper addressAdhoc;
    addressAdhoc.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer adhocInterfaces;
    adhocInterfaces = addressAdhoc.Assign(adhocDevices);

    OnOffHelper onoff1("ns3::UdpSocketFactory", Address());
    onoff1.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1.0]"));
    onoff1.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0.0]"));

    for (int i = 0; i < m_nSinks; i++)
    {
        Ptr<Socket> sink = SetupPacketReceive(adhocInterfaces.GetAddress(i), adhocNodes.Get(i));

        AddressValue remoteAddress(InetSocketAddress(adhocInterfaces.GetAddress(i), port));
        onoff1.SetAttribute("Remote", remoteAddress);

        Ptr<UniformRandomVariable> var = CreateObject<UniformRandomVariable>();
        ApplicationContainer temp = onoff1.Install(adhocNodes.Get(i + m_nSinks));
        temp.Start(Seconds(var->GetValue(100.0, 101.0)));
        temp.Stop(Seconds(TotalTime));
    }

    // Optional UDP flooding DoS attack.
    // The attacker uses a different UDP port from the legitimate traffic.
    // Therefore, the existing ReceivePacket() callback and per-second CSV count only legitimate
    // source/sink traffic on port 9, while the attack still consumes wireless bandwidth.
    if (m_enableDos)
    {
        OnOffHelper dosFlood("ns3::UdpSocketFactory",
                             InetSocketAddress(adhocInterfaces.GetAddress(m_attackTargetNode),
                                               m_attackPort));
        dosFlood.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1.0]"));
        dosFlood.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0.0]"));
        dosFlood.SetAttribute("DataRate", DataRateValue(DataRate(m_dosRate)));
        dosFlood.SetAttribute("PacketSize", UintegerValue(m_dosPacketSize));

        ApplicationContainer attackApps;
        for (uint32_t attacker : attackerNodes)
        {
            attackApps.Add(dosFlood.Install(adhocNodes.Get(attacker)));
        }
        attackApps.Start(Seconds(m_dosStart));
        attackApps.Stop(Seconds(m_dosStop));

        NS_LOG_UNCOND("UDP flooding DoS enabled: attacker nodes "
                      << JoinNodeList(attackerNodes) << " -> target node " << m_attackTargetNode
                      << ", rate per attacker=" << m_dosRate
                      << ", packetSize=" << m_dosPacketSize
                      << ", port=" << m_attackPort << ", start=" << m_dosStart
                      << ", stop=" << m_dosStop);
    }

    std::stringstream ss;
    ss << nWifis;
    std::string nodes = ss.str();

    std::stringstream ss2;
    ss2 << nodeSpeed;
    std::string sNodeSpeed = ss2.str();

    std::stringstream ss3;
    ss3 << nodePause;
    std::string sNodePause = ss3.str();

    std::stringstream ss4;
    ss4 << rate;
    std::string sRate = ss4.str();

    // NS_LOG_INFO("Configure Tracing.");
    // tr_name = tr_name + "_" + m_protocolName +"_" + nodes + "nodes_" + sNodeSpeed + "speed_" +
    // sNodePause + "pause_" + sRate + "rate";

    // AsciiTraceHelper ascii;
    // Ptr<OutputStreamWrapper> osw = ascii.CreateFileStream(tr_name + ".tr");
    // wifiPhy.EnableAsciiAll(osw);
    AsciiTraceHelper ascii;
    if (m_traceMobility)
    {
        MobilityHelper::EnableAsciiAll(ascii.CreateFileStream(tr_name + ".mob"));
    }

    FlowMonitorHelper flowmonHelper;
    Ptr<FlowMonitor> flowmon;
    // Always install FlowMonitor so we can compute PDR/throughput/delay/lost,
    // except for DSR which is incompatible with it.
    bool useFlowmon = (m_protocolName != "DSR");
    if (useFlowmon)
    {
        flowmon = flowmonHelper.InstallAll();
    }

    NS_LOG_INFO("Run Simulation.");

    CheckThroughput();

    // >>> INSERT THE ANIMATION BLOCK HERE <
    AnimationInterface* anim = nullptr;
    if (m_enableAnim)
    {
        anim = new AnimationInterface("manet-anim.xml");
        anim->SetMaxPktsPerTraceFile(5000000);
        anim->EnablePacketMetadata(false); // shows source/dest info when you click a packet in NetAnim

        for (uint32_t i = 0; i < adhocNodes.GetN(); ++i)
        {
            if (i < 10)      anim->UpdateNodeDescription(i, "SINK");
            else if (i < 20) anim->UpdateNodeDescription(i, "SRC");
        }

    // Make the target node stand out — bigger, red, clearly labelled
        anim->UpdateNodeDescription(m_attackTargetNode, "TARGET");
        anim->UpdateNodeColor(m_attackTargetNode, 0, 255, 0);      // Green
        anim->UpdateNodeSize(m_attackTargetNode, 6, 6);            // bigger than default (~2-3)

    // Highlight attacker nodes distinctly, if DoS is active
        if (m_enableDos)
        {
            for (uint32_t attacker : attackerNodes)
            {
                anim->UpdateNodeDescription(attacker, "ATTACKER");
                anim->UpdateNodeColor(attacker, 255, 140, 0);      // orange
                anim->UpdateNodeSize(attacker, 5, 5);
            }
        }
    }
    // >>> END ANIMATION BLOCK <

    Simulator::Stop(Seconds(TotalTime));
    Simulator::Run();

    if (m_flowMonitor && useFlowmon)
    {
        flowmon->SerializeToXmlFile(tr_name + "-" + m_protocolName + (m_enableDos ? "-dos" : "-normal") + ".flowmon", false, false);
    }

    // ----------------------------------------------------------------
    // Compute the four report metrics from FlowMonitor, counting ONLY
    // legitimate traffic (destination port 9). The DoS flood uses port
    // 9999 and is deliberately excluded so metrics reflect the victims'
    // experience, not the attacker's junk traffic.
    //   PDR       = rxPackets / txPackets (%)
    //   Throughput= rxBytes*8 / active duration (kbps)
    //   Avg delay = delaySum / rxPackets (ms)
    //   Lost      = lostPackets (and txPackets - rxPackets as a check)
    // ----------------------------------------------------------------
    if (useFlowmon)
    {
        flowmon->CheckForLostPackets();
        Ptr<Ipv4FlowClassifier> classifier =
            DynamicCast<Ipv4FlowClassifier>(flowmonHelper.GetClassifier());
        FlowMonitor::FlowStatsContainer stats = flowmon->GetFlowStats();

        uint64_t txPackets = 0, rxPackets = 0, flowmonLostPackets = 0;
        uint64_t rxBytes = 0;
        double delaySumSeconds = 0.0;
        double firstTx = std::numeric_limits<double>::max();
        double lastRx = 0.0;

        for (auto it = stats.begin(); it != stats.end(); ++it)
        {
            Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(it->first);
            // Only legitimate UDP flows (destination port == 'port', i.e. 9).
            // Attack traffic uses m_attackPort and is deliberately excluded.
            if (t.protocol != 17 || t.destinationPort != port)
            {
                continue;
            }
            txPackets += it->second.txPackets;
            rxPackets += it->second.rxPackets;
            flowmonLostPackets += it->second.lostPackets;
            rxBytes += it->second.rxBytes;
            delaySumSeconds += it->second.delaySum.GetSeconds();

            if (it->second.txPackets > 0)
            {
                firstTx = std::min(firstTx, it->second.timeFirstTxPacket.GetSeconds());
            }
            if (it->second.rxPackets > 0)
            {
                lastRx = std::max(lastRx, it->second.timeLastRxPacket.GetSeconds());
            }
        }

        // Use FlowMonitor packet times for throughput duration, with a safe fallback.
        double activeDuration = (lastRx > firstTx) ? (lastRx - firstTx) : (TotalTime - 100.0);
        if (activeDuration <= 0.0)
        {
            activeDuration = TotalTime;
        }

        double pdr = (txPackets > 0)
                         ? (static_cast<double>(rxPackets) / txPackets) * 100.0
                         : 0.0;
        double throughputKbps = (rxBytes * 8.0) / (activeDuration * 1000.0);
        double avgDelayMs = (rxPackets > 0)
                                ? (delaySumSeconds / rxPackets) * 1000.0
                                : 0.0;
        uint64_t lostByDiff = (txPackets >= rxPackets) ? (txPackets - rxPackets) : 0;

        // Append one summary row; write header if file is new/empty.
        std::ifstream testf(m_summaryFile);
        bool needHeader = (!testf.good() || testf.peek() == std::ifstream::traits_type::eof());
        testf.close();

        std::ofstream sout(m_summaryFile, std::ios::app);
        if (needHeader)
        {
            sout << "Protocol,DosEnabled,Seed,NodeSpeed,NodePause,NumAttackers,AttackerNodes,"
                 << "AttackTargetNode,DosRate,TxPackets,RxPackets,PDR_percent,"
                 << "Throughput_kbps,AvgDelay_ms,LostPacketsByDiff,FlowmonLostPackets,ActiveDuration_s\n";
        }
        sout << m_protocolName << ","
             << (m_enableDos ? "true" : "false") << ","
             << m_seed << ","
             << nodeSpeed << ","
             << nodePause << ","
             << (m_enableDos ? attackerNodes.size() : 0) << ","
             << (m_enableDos ? JoinNodeList(attackerNodes) : "") << ","
             << m_attackTargetNode << ","
             << m_dosRate << ","
             << txPackets << ","
             << rxPackets << ","
             << pdr << ","
             << throughputKbps << ","
             << avgDelayMs << ","
             << lostByDiff << ","
             << flowmonLostPackets << ","
             << activeDuration << "\n";
        sout.close();

        NS_LOG_UNCOND("[" << m_protocolName << (m_enableDos ? " DoS" : " normal")
                          << " seed=" << m_seed
                          << " speed=" << nodeSpeed
                          << " attackers=" << (m_enableDos ? JoinNodeList(attackerNodes) : "none")
                          << "] PDR=" << pdr << "%"
                          << " Thpt=" << throughputKbps << "kbps"
                          << " Delay=" << avgDelayMs << "ms"
                          << " LostByDiff=" << lostByDiff
                          << " FlowmonLost=" << flowmonLostPackets);
    }

    Simulator::Destroy();
}
