using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using ProcessInvestigator.Models;

namespace ProcessInvestigator.Services
{
    /// <summary>
    /// v1.4 "Security token information" goal. Reads the primary access token of a process:
    /// the account it's running as, its integrity level (the thing that distinguishes a
    /// medium-integrity browser tab from a high-integrity admin tool), whether it's an
    /// elevated UAC token, its session ID, and its full privilege set with enabled/disabled
    /// state - the same fields Process Explorer's Security tab shows.
    /// </summary>
    public static class TokenInspector
    {
        public static TokenInfo GetTokenInfo(int pid)
        {
            var info = new TokenInfo();

            IntPtr hProcess = NativeMethodsToken.OpenProcess(
                NativeMethodsToken.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (hProcess == IntPtr.Zero)
            {
                info.Error = "Access denied opening process (protected process or insufficient privilege).";
                return info;
            }

            IntPtr hToken = IntPtr.Zero;
            try
            {
                if (!NativeMethodsToken.OpenProcessToken(hProcess, NativeMethodsToken.TOKEN_QUERY, out hToken))
                {
                    info.Error = "Access denied opening process token.";
                    return info;
                }

                ReadUser(hToken, info);
                ReadIntegrityLevel(hToken, info);
                ReadElevation(hToken, info);
                ReadSessionId(hToken, info);
                ReadPrivileges(hToken, info);
            }
            catch (Exception ex)
            {
                info.Error = $"Token query failed: {ex.Message}";
            }
            finally
            {
                if (hToken != IntPtr.Zero) NativeMethodsToken.CloseHandle(hToken);
                NativeMethodsToken.CloseHandle(hProcess);
            }

            return info;
        }

        private static void ReadUser(IntPtr hToken, TokenInfo info)
        {
            if (!TryGetTokenInfo(hToken, NativeMethodsToken.TokenUser, out IntPtr buffer, out _))
                return;
            try
            {
                // TOKEN_USER = { SID_AND_ATTRIBUTES User = { PSID Sid; DWORD Attributes } }
                IntPtr sid = Marshal.ReadIntPtr(buffer);
                if (sid == IntPtr.Zero) return;

                try
                {
                    var sidObj = new SecurityIdentifier(sid);
                    info.UserSid = sidObj.Value;
                    try { info.UserAccount = sidObj.Translate(typeof(NTAccount)).ToString(); }
                    catch { /* well-known SID with no mapped account, or lookup unavailable offline */ }
                }
                catch { /* malformed SID - leave fields null */ }
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private static void ReadIntegrityLevel(IntPtr hToken, TokenInfo info)
        {
            if (!TryGetTokenInfo(hToken, NativeMethodsToken.TokenIntegrityLevel, out IntPtr buffer, out _))
                return;
            try
            {
                IntPtr sid = Marshal.ReadIntPtr(buffer);
                if (sid == IntPtr.Zero) return;

                // Integrity level is encoded as the last sub-authority (RID) of a
                // S-1-16-<level> SID (the "Mandatory Label" authority).
                byte subAuthorityCount = Marshal.ReadByte(sid, 1);
                if (subAuthorityCount == 0) return;
                int lastIndex = subAuthorityCount - 1;
                int rid = Marshal.ReadInt32(sid, 8 + lastIndex * 4);

                info.IntegrityLevel = rid switch
                {
                    < 0x1000 => "Untrusted",
                    < 0x2000 => "Low",
                    < 0x3000 => "Medium",
                    < 0x4000 => "High",
                    < 0x5000 => "System",
                    _ => "Protected"
                };
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private static void ReadElevation(IntPtr hToken, TokenInfo info)
        {
            if (TryGetTokenInfo(hToken, NativeMethodsToken.TokenElevation, out IntPtr elevBuf, out _))
            {
                try { info.IsElevated = Marshal.ReadInt32(elevBuf) != 0; }
                finally { Marshal.FreeHGlobal(elevBuf); }
            }

            if (TryGetTokenInfo(hToken, NativeMethodsToken.TokenElevationType, out IntPtr typeBuf, out _))
            {
                try
                {
                    info.ElevationType = Marshal.ReadInt32(typeBuf) switch
                    {
                        1 => "Default", // TokenElevationTypeDefault - UAC disabled, or the only token available
                        2 => "Full",    // TokenElevationTypeFull - elevated admin token
                        3 => "Limited", // TokenElevationTypeLimited - filtered standard-user token
                        _ => "Unknown"
                    };
                }
                finally { Marshal.FreeHGlobal(typeBuf); }
            }
        }

        private static void ReadSessionId(IntPtr hToken, TokenInfo info)
        {
            if (!TryGetTokenInfo(hToken, NativeMethodsToken.TokenSessionId, out IntPtr buffer, out _))
                return;
            try { info.SessionId = Marshal.ReadInt32(buffer); }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private static void ReadPrivileges(IntPtr hToken, TokenInfo info)
        {
            if (!TryGetTokenInfo(hToken, NativeMethodsToken.TokenPrivileges, out IntPtr buffer, out _))
                return;
            try
            {
                int count = Marshal.ReadInt32(buffer);
                IntPtr entryPtr = IntPtr.Add(buffer, 4);
                int entrySize = Marshal.SizeOf<NativeMethodsToken.LUID_AND_ATTRIBUTES>();

                for (int i = 0; i < count; i++)
                {
                    var entry = Marshal.PtrToStructure<NativeMethodsToken.LUID_AND_ATTRIBUTES>(entryPtr);
                    entryPtr = IntPtr.Add(entryPtr, entrySize);

                    var sb = new StringBuilder(256);
                    int nameLen = sb.Capacity;
                    var luid = entry.Luid;
                    if (!NativeMethodsToken.LookupPrivilegeName(null, ref luid, sb, ref nameLen))
                        continue;

                    info.Privileges.Add(new TokenPrivilegeInfo
                    {
                        Name = sb.ToString(),
                        Enabled = (entry.Attributes & NativeMethodsToken.SE_PRIVILEGE_ENABLED) != 0,
                        EnabledByDefault = (entry.Attributes & NativeMethodsToken.SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0
                    });
                }
                info.Privileges = info.Privileges.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToList();
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        /// <summary>Calls GetTokenInformation with a growing buffer until it fits; on success the
        /// caller owns `buffer` and must Marshal.FreeHGlobal it.</summary>
        private static bool TryGetTokenInfo(IntPtr hToken, int infoClass, out IntPtr buffer, out int size)
        {
            size = 0;
            NativeMethodsToken.GetTokenInformation(hToken, infoClass, IntPtr.Zero, 0, out size);
            if (size <= 0)
            {
                buffer = IntPtr.Zero;
                return false;
            }

            buffer = Marshal.AllocHGlobal(size);
            if (NativeMethodsToken.GetTokenInformation(hToken, infoClass, buffer, size, out size))
                return true;

            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
            return false;
        }
    }

    /// <summary>P/Invoke declarations specific to token inspection - see HandleEnumerator's
    /// class remarks for why each feature keeps its own native surface separate.</summary>
    internal static class NativeMethodsToken
    {
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        public const uint TOKEN_QUERY = 0x0008;

        public const int TokenUser = 1;
        public const int TokenPrivileges = 3;
        public const int TokenSessionId = 12;
        public const int TokenElevationType = 18;
        public const int TokenElevation = 20;
        public const int TokenIntegrityLevel = 25;

        public const uint SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
        public const uint SE_PRIVILEGE_ENABLED = 0x00000002;

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetTokenInformation(
            IntPtr tokenHandle, int tokenInformationClass,
            IntPtr tokenInformation, int tokenInformationLength, out int returnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeName(
            string? systemName, ref LUID luid, StringBuilder buffer, ref int bufferLength);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);
    }
}
