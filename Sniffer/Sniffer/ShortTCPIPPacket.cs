using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Sniffer.Sniffer
{
    internal class ShortTCPIPPacket
    {
        public IPAddress iPAddress = new IPAddress(0);

        // Список всех юзанных портов на данном IP
        public List<ushort> iPorts = new List<ushort>();

        // к-во обращений на данный ip
        public int count = 0;
    }

    class ShortTCPIPPacketComparer : IComparer<ShortTCPIPPacket>
    {
        CaseInsensitiveComparer comparer = new CaseInsensitiveComparer();
        public int Compare(ShortTCPIPPacket? p1, ShortTCPIPPacket? p2)
        {
            int result = comparer.Compare(p2.count, p1.count);
            return result;
        }

    }
}
