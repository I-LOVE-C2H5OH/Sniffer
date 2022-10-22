

using Sniffer.Sniffer;
using System.Text.RegularExpressions;

namespace Sniffer
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var allCaptureDevce = sniffer.getAllCaptureDevce();

            Console.WriteLine("select a captureDevice");

            for (int i = 0; i < allCaptureDevce.Count; i ++)
            {
                var device = allCaptureDevce[i];
                Console.WriteLine($"{i} - {device.Description}");
            }

            int variable = int.Parse(Console.ReadLine());

            Console.Write("Enter a Network ip Addres\n");

            var network = Console.ReadLine();

            Console.Write("Enter a mask this network\n");

            var mask = Console.ReadLine();

            Console.Write("Enter a TSZPPort or 0\n");

            ushort tszpport = ushort.Parse(Console.ReadLine());

            var sniffers = new sniffer(allCaptureDevce[variable], network, mask, tszpport);

            while (true)
            {
                Console.Write("Enter a stat to show statistic\n");

                var read = Console.ReadLine();

                if (read != null && read == "show")
                {
                    Console.WriteLine(sniffers.getStatistic());
                }
            }

            //Console.WriteLine("Hello, World!");
        }
    }
}