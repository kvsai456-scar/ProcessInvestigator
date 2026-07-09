namespace ProcessInvestigator.Models
{
    public class ParentChainEntry
    {
        public int Pid { get; set; }
        public string Name { get; set; } = "";
        public string? ExecutablePath { get; set; }
        public bool StillRunning { get; set; }
    }

    public class ModuleInfo
    {
        public string ModuleName { get; set; } = "";
        public string? FileName { get; set; }
        public long ModuleMemorySize { get; set; }

        /// <summary>Module base address in the target process, formatted as hex (e.g. "0x7FFA12340000"). v1.4.</summary>
        public string? BaseAddress { get; set; }
        /// <summary>Company/Description/FileVersion from the module's Win32 version resource, via VersionInfoCache. v1.4.</summary>
        public string? Company { get; set; }
        public string? Description { get; set; }
        public string? FileVersion { get; set; }
    }

    /// <summary>One OS handle open in the investigated process. v1.4 "Handle viewer" goal.</summary>
    public class HandleInfo
    {
        public int Handle { get; set; }
        public string TypeName { get; set; } = "";
        /// <summary>Best-effort object name; null when the OS wouldn't resolve one in time
        /// (see HandleEnumerator - name queries are skipped/time-boxed for hang-prone types).</summary>
        public string? Name { get; set; }
    }

    /// <summary>One entitlement in a process token's privilege array. v1.4 "Security token information" goal.</summary>
    public class TokenPrivilegeInfo
    {
        public string Name { get; set; } = "";
        public bool Enabled { get; set; }
        public bool EnabledByDefault { get; set; }
    }

    /// <summary>Security token summary for the investigated process. v1.4 "Security token information" goal.</summary>
    public class TokenInfo
    {
        public string? UserSid { get; set; }
        /// <summary>DOMAIN\User, resolved via LookupAccountSid where possible.</summary>
        public string? UserAccount { get; set; }
        /// <summary>Untrusted / Low / Medium / High / System / Protected / Unknown.</summary>
        public string IntegrityLevel { get; set; } = "Unknown";
        public bool IsElevated { get; set; }
        /// <summary>Default / Full / Limited - from TokenElevationType.</summary>
        public string ElevationType { get; set; } = "Unknown";
        public int SessionId { get; set; } = -1;
        public List<TokenPrivilegeInfo> Privileges { get; set; } = new();
        /// <summary>Set when the token couldn't be opened/queried at all (e.g. protected process, access denied).</summary>
        public string? Error { get; set; }
    }

    public class ServiceInfo
    {
        public string Name { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string State { get; set; } = "";
        public string StartMode { get; set; } = "";
        public string? PathName { get; set; }
        public string? ServiceDll { get; set; }
        public string StartName { get; set; } = "";
    }

    public class NetworkConnectionInfo
    {
        public string Protocol { get; set; } = "";
        public string LocalAddress { get; set; } = "";
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; } = "";
        public int RemotePort { get; set; }
        public string State { get; set; } = "";
    }

    public class SignatureInfo
    {
        public bool IsSigned { get; set; }
        public string? Subject { get; set; }
        public string? Issuer { get; set; }
        public bool ValidChain { get; set; }
        public string? Error { get; set; }
    }

    /// <summary>
    /// Everything gathered about one process when the user clicks "Investigate".
    /// This is the object the report export renders to text.
    /// </summary>
    public class InvestigationReport
    {
        public int Pid { get; set; }
        public string Name { get; set; } = "";
        public string? ExecutablePath { get; set; }
        public string? CommandLine { get; set; }
        public string? User { get; set; }
        public DateTime? StartTime { get; set; }
        public DateTime GeneratedAt { get; set; } = DateTime.Now;

        public long? FileSizeBytes { get; set; }
        public string? Sha256Hash { get; set; }
        public string? Md5Hash { get; set; }

        public List<ParentChainEntry> ParentChain { get; set; } = new();
        /// <summary>Processes currently reporting this PID as their ParentProcessId - the "downward" half of the process tree.</summary>
        public List<ParentChainEntry> Children { get; set; } = new();
        public List<ModuleInfo> LoadedModules { get; set; } = new();
        public List<ServiceInfo> AssociatedServices { get; set; } = new();
        public List<NetworkConnectionInfo> NetworkConnections { get; set; } = new();
        public SignatureInfo? Signature { get; set; }

        /// <summary>v1.4: security token summary (user, integrity level, elevation, privileges).</summary>
        public TokenInfo? Token { get; set; }
        /// <summary>v1.4: open OS handles in this process.</summary>
        public List<HandleInfo> Handles { get; set; } = new();
        /// <summary>True if HandleEnumerator stopped early because the process had more open
        /// handles than MaxHandlesPerProcess - see HandleEnumerator for the cap and why.</summary>
        public bool HandlesTruncated { get; set; }

        public List<string> Notes { get; set; } = new();
    }
}
