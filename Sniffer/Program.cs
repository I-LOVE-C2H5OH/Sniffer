

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

            Console.Write("Enter a Network ip Addres");

            var network = Console.ReadLine();

            Console.Write("Enter a mask this network");

            var mask = Console.ReadLine();

            var sniffers = new sniffer(allCaptureDevce[variable], network, mask);

            while (true)
            {
                Console.Write("Enter a stat to show statistic");

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