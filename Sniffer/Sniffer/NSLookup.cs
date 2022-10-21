using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Sniffer.Sniffer
{
    internal class NSLookup
    {
        public static string getHostname(string ip)
        {
            try
            {
                //The IP or Host Entry to lookup
                IPHostEntry ipEntry;
                //The IP Address Array. Holds an array of resolved Host Names.
                IPAddress[] ipAddr;
                //Value of alpha characters
                char[] alpha = "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ-".ToCharArray();
                //If alpha characters exist we know we are doing a forward lookup
                if (ip.IndexOfAny(alpha) != -1)
                {
                    ipEntry = Dns.GetHostByName(ip);
                    ipAddr = ipEntry.AddressList;
                    Console.WriteLine("\nHost Name : " + ip);
                    int i = 0;
                    int len = ipAddr.Length;
                    for (i = 0; i < len; i++)
                    {
                        Console.WriteLine("Address {0} : {1} ", i, ipAddr[i].ToString());
                    }
                    return "";
                }
                //If no alpha characters exist we do a reverse lookup
                else
                {
                    ipEntry = Dns.Resolve(ip);
                    return ipEntry.HostName;
                }
            }
            catch (System.Net.Sockets.SocketException se)
            {
                // The system had problems resolving the address passed
                return se.Message.ToString();
            }
            catch (System.FormatException fe)
            {
                // Non unicode chars were probably passed
                return fe.Message.ToString();
            }


            return "";
        }

    }
}
