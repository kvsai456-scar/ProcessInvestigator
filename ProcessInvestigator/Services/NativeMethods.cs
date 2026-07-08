using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using ProcessInvestigator.Models;

namespace ProcessInvestigator.Services
{
    /// <summary>
    /// Thin wrapper over GetExtendedTcpTable / GetExtendedUdpTable (iphlpapi.dll)
    /// so we can answer "what is this PID connected to right now" - the same
    /// data netstat -ano shows, but queried in-process instead of shelling out.
    /// </summary>
    internal static class NativeMethods
    {
        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen,
            bool sort, int ipVersion, TCP_TABLE_CLASS tblClass, uint reserved = 0);

        private enum TCP_TABLE_CLASS { TCP_TABLE_OWNER_PID_ALL = 5 }

        private const int AF_INET = 2;

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public uint localPort; // stored big-endian, first 2 bytes matter
            public uint remoteAddr;
            public uint remotePort;
            public uint owningPid;
        }

        private static readonly string[] TcpStates =
        {
            "", "CLOSED", "LISTENING", "SYN_SENT", "SYN_RCVD", "ESTABLISHED",
            "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK",
            "TIME_WAIT", "DELETE_TCB"
        };

        /// <summary>Returns every active IPv4 TCP connection/listener with its owning PID.</summary>
        public static List<(int Pid, NetworkConnectionInfo Conn)> GetAllTcpConnections()
        {
            var results = new List<(int, NetworkConnectionInfo)>();
            int bufSize = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref bufSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);
            IntPtr buffer = Marshal.AllocHGlobal(bufSize);
            try
            {
                uint ret = GetExtendedTcpTable(buffer, ref bufSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);
                if (ret != 0) return results;

                int rowCount = Marshal.ReadInt32(buffer);
                IntPtr rowPtr = IntPtr.Add(buffer, 4);
                int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

                for (int i = 0; i < rowCount; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    var conn = new NetworkConnectionInfo
                    {
                        Protocol = "TCP",
                        LocalAddress = new IPAddress(row.localAddr).ToString(),
                        LocalPort = PortFromNetworkOrder(row.localPort),
                        RemoteAddress = new IPAddress(row.remoteAddr).ToString(),
                        RemotePort = PortFromNetworkOrder(row.remotePort),
                        State = row.state < TcpStates.Length ? TcpStates[row.state] : row.state.ToString()
                    };
                    results.Add(((int)row.owningPid, conn));
                    rowPtr = IntPtr.Add(rowPtr, rowSize);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
            return results;
        }

        private static int PortFromNetworkOrder(uint port)
        {
            // Only the low 16 bits carry the port, stored big-endian.
            ushort p = (ushort)port;
            return IPAddress.NetworkToHostOrder((short)p) & 0xFFFF;
        }
    }
}
