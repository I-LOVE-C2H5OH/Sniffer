using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Sniffer.Sniffer
{
    public class ParserTzsp
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct TzspPacket
        {
            public ProtocolHeader header;
            public Dictionary<string, byte[]> fields;
            public byte[] encapsulated_packet;
            public byte[] packet;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct ProtocolHeader
        {
            public byte version;
            public byte type;
            public ushort encapsulated_protocol;
        };

        [SuppressMessage("ReSharper", "UnusedMember.Global")]
        public enum HeaderType
        {
            ReceivedTagList = 0x0000,
            PacketForTransmit = 0x0001,
            Reserved = 0x0002,
            Configuration = 0x0003,
            Keepalive = 0x0004,
            PortOpener = 0x0005
        };

        [SuppressMessage("ReSharper", "UnusedMember.Global")]
        public enum HeaderEncapsulatedProtocol : ushort
        {
            Ethernet = 0x01,
            Ieee802Dot11 = 0x12,
            PrismHeader = 0x77,
            WlanAvs = 0x7F
        };

        [SuppressMessage("ReSharper", "UnusedMember.Global")]
        private enum TaggedFields : byte
        {
            TagPadding = 0x00,
            TagEnd = 0x01,
            TagRawRssi = 0x0A, //signed byte or signed short
            TagSnr = 0x0B, //signed byte or signed short
            TagDataRate = 0x0C, //unsigned byte
            TagTimestamp = 0x0D, //four byte unsigned int
            TagContentionFree = 0x0F, //unsigned byte
            TagDecrypted = 0x10, //unsigned byte
            TagFcsError = 0x11, //unsigned byte
            TagRxChannel = 0x12, //unsigned byte
            TagPacketCount = 0x28, //four byte unsigned int
            TagRxFrameLength = 0x29, //two byte unsigned short
            TagWlanRadioHdrSerial = 0x3C  //variable length field
        };

        public static TzspPacket Parse(byte[] packet)
        {
            var result = new TzspPacket();
            var fields = new Dictionary<string, byte[]>();
            result.fields = fields;

            if (packet.Length < Marshal.SizeOf(typeof(ProtocolHeader)) + sizeof(byte)) // + TAG_END
            {
                throw new Exception(null);
            }

            result.header.version = packet[0];
            result.header.type = packet[1];
            result.header.encapsulated_protocol = BitConverter.ToUInt16(new[] { packet[3], packet[2] }, 0);

            if (result.header.version != 1 || result.header.type > (int)HeaderType.PortOpener)
            {
                throw new Exception(null);
            }

            var index = Marshal.SizeOf(typeof(ProtocolHeader));
            ParseFields(packet, ref index, ref result.fields);

            if (packet.Length < index + 1)
            {
                throw new Exception(null);
            }

            result.encapsulated_packet = new byte[packet.Length - index];
            Array.Copy(packet, Convert.ToInt32(index), result.encapsulated_packet, 0, Convert.ToInt32(packet.Length - index));

            result.packet = packet;

            return result;
        }

        private static void ParseFields(byte[] packet, ref int index, ref Dictionary<string, byte[]> fields)
        {
            if (packet.Length - index < sizeof(byte)) // + TAG_END
            {
                throw new Exception(null);
            }

            while (packet.Length - index > 0)
            {
                if (packet[index + 0] != 0x00 && packet[index + 0] != 0x01 && packet.Length - index < 3 &&
                    packet.Length - index < packet[index + 1] + 3)
                {
                    throw new Exception(null);
                }

                if (packet[index + 0] == (byte)TaggedFields.TagPadding || packet[index + 0] == (byte)TaggedFields.TagEnd)
                {
                    fields.Add(GetTaggedFields(packet[index + 0]), null);
                    if (packet[index + 0] == (byte)TaggedFields.TagEnd) { index++; break; }
                    index++;
                }
                else
                {
                    var value = new byte[packet[index + 1]];
                    Array.Copy(packet, Convert.ToInt32(index + 2), value, 0, Convert.ToInt32(packet[index + 1]));
                    fields.Add(GetTaggedFields(packet[index + 0]), value);
                    index += packet[index + 1] + 2;
                }
            }
        }

        private static string GetHeaderType(byte type)
        {
            return Enum.GetName(typeof(HeaderType), type);
        }

        public static string GetProtocol(ushort encapsulatedProtocol)
        {
            return Enum.GetName(typeof(HeaderEncapsulatedProtocol), encapsulatedProtocol);
        }

        private static string GetTaggedFields(byte taggedField)
        {
            return Enum.GetName(typeof(TaggedFields), taggedField);
        }

        [SuppressMessage("ReSharper", "UnusedMember.Global")]
        public string ToString(TzspPacket tzsp)
        {
            string result = "Protocol TZSP parser\n";
            result += $"Reseived packet length {tzsp.packet.Length} bytes; {BitConverter.ToString(tzsp.packet)}\n";
            result += $"\tVersion: {tzsp.header.version};\n";
            result += $"\tType: {GetHeaderType(tzsp.header.type)};\n";
            result += $"\tEncapsulated protocol: {GetProtocol(tzsp.header.encapsulated_protocol)};\n";
            foreach (var item in tzsp.fields)
            {
                if (item.Key == "TagPadding" || item.Key == "TagEnd")
                {
                    result += $"\tField: {item.Key};\n";
                }
                else
                {
                    var val = typeof(ParserTzsp)
                        .GetMethod($"Get{item.Key}", BindingFlags.Public | BindingFlags.Static)
                        .Invoke(null, new object[] { item.Value });
                    result += $"\tField: {item.Key}: {val};\n";
                }
            }
            result += $"\tEncapsulated_packet: {BitConverter.ToString(tzsp.encapsulated_packet)};\n";
            result += "\n";
            return result;
        }

        [SuppressMessage("ReSharper", "UnusedMember.Global")]
        public static short GetTagRawRssi(byte[] s)
        { //signed byte or signed short
            if (s.Length == 1)
            {
                var val = new[] { (sbyte)s[0] };
                return val[0];
            }

            var networkByte = BitConverter.ToInt16(s, 0);
            return IPAddress.NetworkToHostOrder(networkByte);
        }

        [SuppressMessage("ReSharper", "UnusedMember.Global")]
        public static short GetTagSnr(byte[] s)
        { //signed byte or signed short
            if (s.Length == 1)
            {
                var val = new[] { (sbyte)s[0] };
                return val[0];
            }

            var networkByte = BitConverter.ToInt16(s, 0);
            return IPAddress.NetworkToHostOrder(networkByte);
        }

        [SuppressMessage("ReSharper", "UnusedMember.Global")]
        public static byte GetTagDataRate(byte[] s)
        { //unsigned byte
            return s[0];
        }

        // todo: check
        [SuppressMessage("ReSharper", "UnusedMember.Global")]
        public static ulong GetTagTimestamp(byte[] s)   // not checked
        { //four byte unsigned int
            var networkByte = BitConverter.ToUInt32(s, 0);
            return (ulong)IPAddress.NetworkToHostOrder(networkByte);
        }

        [SuppressMessage("ReSharper", "UnusedMember.Global")]
        public static byte GetTagContentionFree(byte[] s)
        { //unsigned byte
            return s[0];
        }

        [SuppressMessage("ReSharper", "UnusedMember.Global")]
        public static byte GetTagDecrypted(byte[] s)
        { //unsigned byte
            return s[0];
        }

        [SuppressMessage("ReSharper", "UnusedMember.Global")]
        public static byte GetTagFcsError(byte[] s)
        { //unsigned byte
            return s[0];
        }

        [SuppressMessage("ReSharper", "UnusedMember.Global")]
        public static byte GetTagRxChannel(byte[] s)
        { //unsigned byte
            return s[0];
        }

        // todo: check
        [SuppressMessage("ReSharper", "UnusedMember.Global")]
        public static ulong GetTagPacketCount(byte[] s) // not checked
        { //four byte unsigned int
            var networkByte = BitConverter.ToUInt32(s, 0);
            return (ulong)IPAddress.NetworkToHostOrder(networkByte);
        }

        [SuppressMessage("ReSharper", "UnusedMember.Global")]
        public static ushort GetTagRxFrameLength(byte[] s)
        { //two byte unsigned short
            var networkByte = BitConverter.ToInt16(s, 0);
            return (ushort)IPAddress.NetworkToHostOrder(networkByte);
        }

        // todo: check
        [SuppressMessage("ReSharper", "UnusedMember.Global")]
        public static string GetTagWlanRadioHdrSerial(byte[] s) // not checked
        { //variable length field
            return s.ToString();
        }
    }
}
