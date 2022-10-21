using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Threading.Tasks;
using PacketDotNet;
using PacketDotNet.Utils;
using SharpPcap;

namespace Sniffer.Sniffer
{
    internal class sniffer
    {
        bool isRead = false;

        IPAddress ipNetwork = new IPAddress(0);
        IPAddress ipMask = new IPAddress(0);
        IPAddress Wildcard = new IPAddress(0);
        IPAddress ipBroadcost = new IPAddress(0);

        Thread? threadCapture;

        List<ShortSRCIPtoDSTIPInfo> allIPSrcToDstaddress = new List<ShortSRCIPtoDSTIPInfo>();

        public static CaptureDeviceList getAllCaptureDevce()
        {
            return CaptureDeviceList.Instance;
        }

        public sniffer(ICaptureDevice Capturedevice, string ipSNetwork, string ipMask)
        {
            this.ipMask = IPAddress.Parse(ipMask);
            this.ipNetwork = IPAddress.Parse(ipSNetwork);

            Wildcard = IPAddress.Parse("255.255.255.255");

            long Wildcardlong = Wildcard.Address;

            Wildcardlong -= this.ipMask.Address;

            Wildcard = new IPAddress(Wildcardlong);

            this.ipBroadcost = new IPAddress(ipNetwork.Address + Wildcardlong);

            ICaptureDevice captureDevice = Capturedevice;
            captureDevice.OnPacketArrival += new PacketArrivalEventHandler(Program_OnPacketArrival);
            captureDevice.Open(DeviceModes.Promiscuous, 1000);
            threadCapture = new Thread(captureDevice.Capture);
            threadCapture.Start();
        }

        void Program_OnPacketArrival(object sender, PacketCapture e)
        {
            IPAddress? dstip;
            IPAddress? srcip;

            var testsssss = IPAddress.Parse("192.168.1.1");
            try
            {
                if (isRead) { return; }
                var tt = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);

                var ipV4Packet = tt.Extract<IPv4Packet>();
                if (ipV4Packet == null) { return; }

                TcpPacket tcpPacket = tt.Extract<TcpPacket>();

                UdpPacket udpPacket = tt.Extract<UdpPacket>();

                if (tcpPacket == null && udpPacket == null) { return; }

                var destinationPort = udpPacket != null ? udpPacket.DestinationPort : tcpPacket.DestinationPort;

                dstip = ipV4Packet.DestinationAddress;

                srcip = ipV4Packet.SourceAddress;

                if (destinationPort == 37008)
                {
                    var testTSZP = ParserTzsp.Parse(udpPacket.PayloadData);

                    var protocol = testTSZP.header.encapsulated_protocol;

                    if (protocol == (short)ParserTzsp.HeaderEncapsulatedProtocol.Ethernet)
                    {
                        ByteArraySegment testss = new ByteArraySegment(testTSZP.encapsulated_packet);

                        Packet packet = Packet.ParsePacket(e.GetPacket().LinkLayerType, testTSZP.encapsulated_packet);

                        ipV4Packet = packet.Extract<IPv4Packet>();
                        if (ipV4Packet == null) { return; }

                        tcpPacket = packet.Extract<TcpPacket>();

                        udpPacket = packet.Extract<UdpPacket>();

                        if (tcpPacket == null && udpPacket == null) { return; }
                        dstip = ipV4Packet.DestinationAddress;
                        srcip = ipV4Packet.SourceAddress;

                        if (srcip.Address == testsssss.Address)
                        {
                            
                        }
                    }
                }
                var port = udpPacket != null ? udpPacket.DestinationPort : tcpPacket.DestinationPort;

                var ttset = tt.Extract<PacketDotNet.EthernetPacket>();
                
                var mac = new byte[0];
                if (ttset != null)
                {
                    ttset.SourceHardwareAddress.GetAddressBytes(); 
                }

                var isLocalSrc = isLocalAddress(srcip);

                var isLocalDsc = isLocalAddress(dstip);

                if (isLocalSrc && isLocalDsc || !isLocalSrc)
                {
                    return;
                }

                updateStatistic(srcip, dstip, port, mac);
            }
            catch (Exception ee)
            {
                //Console.WriteLine($"---{ee.Message}---");
            }
        }
        bool isLocalAddress(IPAddress iPAddress)
        {
            var ipBytes = iPAddress.GetAddressBytes();
            var localIpBytes = ipNetwork.GetAddressBytes();

            if (ipBytes[0] == localIpBytes[0] && ipBytes[1] == localIpBytes[1] /*&& ipBytes[2] == localIpBytes[2]*/)
            {
                return true;
            }

            return false;
        }

        void updateStatistic(IPAddress srcAdress, IPAddress dscAdress, ushort port, byte[] mac)
        {
            foreach (var ips in allIPSrcToDstaddress)
            {
                if (ips.srcIP.Address == srcAdress.Address)
                {
                    foreach (var dsct in ips.ipList)
                    {
                        if (dsct.iPAddress.Address == dscAdress.Address)
                        {
                            if (!dsct.iPorts.Contains(port))
                            {
                                dsct.iPorts.Add(port);
                            }

                            dsct.count++;
                            return;
                        }
                    }
                    // если нету ни одного dsc адреса

                    ips.ipList.Add(createDscList(dscAdress, port));

                    return;
                }
            }

            // если нету ни одного src адреса

            var src = createSRCList(srcAdress, mac);

            src.ipList.Add(createDscList(dscAdress, port));

            allIPSrcToDstaddress.Add(src);

        }

        ShortTCPIPPacket createDscList(IPAddress distIP, ushort port)
        {
            ShortTCPIPPacket infodscip = new ShortTCPIPPacket();

            infodscip.count++;

            infodscip.iPorts.Add(port);

            infodscip.iPAddress = distIP;

            return infodscip;
        }

        ShortSRCIPtoDSTIPInfo createSRCList(IPAddress srcAddress, byte[] mac)
        {
            ShortSRCIPtoDSTIPInfo info = new ShortSRCIPtoDSTIPInfo();

            info.physicalAddress = new System.Net.NetworkInformation.PhysicalAddress(mac);

            info.srcIP = srcAddress;

            return info;
        }

        public string getStatistic()
        {
            isRead = true;
            string outString = "";

            sort();

            var tmpallIPSrcToDstaddress = allIPSrcToDstaddress;

            foreach (var ips in tmpallIPSrcToDstaddress)
            {
                outString += $"{ips.srcIP} mac: {ips.physicalAddress.ToString()} ->";
                int count = 0;
                foreach (var dsct in ips.ipList)
                {
                    outString += $"\n  {dsct.iPAddress} Counts: {dsct.count} nsLookup: {NSLookup.getHostname(dsct.iPAddress.ToString())} Ports: ";

                    foreach (var port in dsct.iPorts)
                    {
                        outString += $"{port}; ";
                    }

                    count++;
                    if (count >= 20)
                    {
                        break;
                    }
                }

                outString += "\n\n";
            }

            isRead = false;

            return outString;
        }
        void sort()
        {
            foreach (var tmp in allIPSrcToDstaddress)
            {
                tmp.ipList.Sort(new ShortTCPIPPacketComparer());
            }
        }

    }

}
