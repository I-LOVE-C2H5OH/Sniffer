using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;

namespace Sniffer.Sniffer
{
    internal class ShortSRCIPtoDSTIPInfo
    {
        public List<ShortTCPIPPacket> ipList = new List<ShortTCPIPPacket>();

        public PhysicalAddress physicalAddress = new PhysicalAddress(new byte[0]);

        public IPAddress srcIP = new IPAddress(0);
    }
}
