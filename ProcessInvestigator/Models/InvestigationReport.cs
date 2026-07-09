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
        public List<string> Notes { get; set; } = new();
    }
}
