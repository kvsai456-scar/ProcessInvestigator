using System.Diagnostics;
using System.IO;
using System.Management;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;
using ProcessInvestigator.Models;

namespace ProcessInvestigator.Services
{
    /// <summary>WMI-derived extra info for one process, refreshed each tick.</summary>
    public class WmiProcInfo
    {
        public int ParentPid;
        public string? CommandLine;
        public string? ExecutablePath;
    }

    public class ProcessInvestigatorService
    {
        /// <summary>
        /// One cheap WMI query per refresh tick for ParentProcessId/CommandLine/ExecutablePath
        /// (Process.GetProcesses() alone can't give us these). Owner (user name) is deliberately
        /// NOT fetched here - GetOwner() is a per-process remote-style call and is too slow to run
        /// for every row on every tick; it's fetched lazily in the Investigate dialog instead.
        /// </summary>
        public Dictionary<int, WmiProcInfo> GetWmiSnapshot()
        {
            var map = new Dictionary<int, WmiProcInfo>();
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, ParentProcessId, CommandLine, ExecutablePath FROM Win32_Process");
            foreach (ManagementObject mo in searcher.Get())
            {
                int pid = Convert.ToInt32(mo["ProcessId"]);
                map[pid] = new WmiProcInfo
                {
                    ParentPid = mo["ParentProcessId"] != null ? Convert.ToInt32(mo["ParentProcessId"]) : 0,
                    CommandLine = mo["CommandLine"] as string,
                    ExecutablePath = mo["ExecutablePath"] as string
                };
            }
            return map;
        }

        public string? GetOwner(int pid)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT * FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (ManagementObject mo in searcher.Get())
                {
                    var outParams = mo.InvokeMethod("GetOwner", null, null);
                    var domain = outParams?["Domain"] as string;
                    var user = outParams?["User"] as string;
                    if (user != null) return string.IsNullOrEmpty(domain) ? user : $"{domain}\\{user}";
                }
            }
            catch { /* SYSTEM/protected processes may deny this even elevated */ }
            return null;
        }

        /// <summary>Walks ParentProcessId upward until it hits PID 0/4, an unknown PID, or a cycle.</summary>
        public List<ParentChainEntry> GetParentChain(int pid, Dictionary<int, WmiProcInfo> snapshot)
        {
            var chain = new List<ParentChainEntry>();
            var visited = new HashSet<int>();
            int current = pid;

            while (current > 0 && visited.Add(current))
            {
                string name = "";
                string? path = null;
                bool running = false;
                try
                {
                    using var p = Process.GetProcessById(current);
                    name = p.ProcessName;
                    running = true;
                    try { path = p.MainModule?.FileName; } catch { /* access denied */ }
                }
                catch
                {
                    name = "(exited)";
                }

                chain.Add(new ParentChainEntry { Pid = current, Name = name, ExecutablePath = path, StillRunning = running });

                if (!snapshot.TryGetValue(current, out var info) || info.ParentPid == current) break;
                current = info.ParentPid;
            }
            return chain;
        }

        /// <summary>
        /// v1.4 "Module viewer" goal: the v1.3 Loaded-DLLs list enriched with base address
        /// (useful for spotting manually-mapped/reflectively-loaded modules that don't line up
        /// with where the loader would normally place them) and Company/Description/FileVersion
        /// from each module's own version resource (not just the main executable's), via the
        /// same VersionInfoCache the process grid's Company/Description columns use.
        /// </summary>
        public List<ModuleInfo> GetLoadedModules(int pid)
        {
            var modules = new List<ModuleInfo>();
            try
            {
                using var p = Process.GetProcessById(pid);
                foreach (ProcessModule m in p.Modules)
                {
                    string? fileName = null;
                    IntPtr baseAddr = IntPtr.Zero;
                    try { fileName = m.FileName; } catch { }
                    try { baseAddr = m.BaseAddress; } catch { }

                    var version = VersionInfoCache.Get(fileName);

                    modules.Add(new ModuleInfo
                    {
                        ModuleName = m.ModuleName,
                        FileName = fileName,
                        ModuleMemorySize = SafeMemorySize(m),
                        BaseAddress = baseAddr != IntPtr.Zero ? $"0x{baseAddr.ToInt64():X}" : null,
                        Company = version.Company,
                        Description = version.Description,
                        FileVersion = GetFileVersion(fileName)
                    });
                }
            }
            catch
            {
                // Access denied (protected process) or process exited mid-inspection.
            }
            return modules.OrderBy(m => m.ModuleName, StringComparer.OrdinalIgnoreCase).ToList();
        }

        private static long SafeMemorySize(ProcessModule m)
        {
            try { return m.ModuleMemorySize; } catch { return 0; }
        }

        private static string? GetFileVersion(string? path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
            try { return FileVersionInfo.GetVersionInfo(path).FileVersion; }
            catch { return null; }
        }

        /// <summary>
        /// Finds Windows services hosted inside this PID (relevant for svchost.exe processes,
        /// which can host multiple services) and resolves each service's ServiceDll - the same
        /// registry lookup used manually in the XMRig investigation (sc qc / reg query workflow).
        /// </summary>
        public List<ServiceInfo> GetAssociatedServices(int pid)
        {
            var services = new List<ServiceInfo>();
            using var searcher = new ManagementObjectSearcher(
                $"SELECT * FROM Win32_Service WHERE ProcessId = {pid}");
            foreach (ManagementObject mo in searcher.Get())
            {
                string name = mo["Name"] as string ?? "";
                var info = new ServiceInfo
                {
                    Name = name,
                    DisplayName = mo["DisplayName"] as string ?? "",
                    State = mo["State"] as string ?? "",
                    StartMode = mo["StartMode"] as string ?? "",
                    PathName = mo["PathName"] as string,
                    StartName = mo["StartName"] as string ?? ""
                };
                info.ServiceDll = ResolveServiceDll(name);
                services.Add(info);
            }
            return services;
        }

        /// <summary>
        /// ServiceDll usually lives under ...\Services\<name>\Parameters, but some
        /// malware (and a few legitimate services) write it directly under the
        /// service key, so both locations are checked - matching the manual
        /// "reg query ... /s" step from the incident report.
        /// </summary>
        private string? ResolveServiceDll(string serviceName)
        {
            try
            {
                using var paramKey = Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Services\{serviceName}\Parameters");
                if (paramKey?.GetValue("ServiceDll") is string dll1) return dll1;

                using var rootKey = Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Services\{serviceName}");
                if (rootKey?.GetValue("ServiceDll") is string dll2) return dll2;
            }
            catch { /* insufficient privilege or key absent */ }
            return null;
        }

        public List<NetworkConnectionInfo> GetNetworkConnections(int pid)
        {
            return NativeMethods.GetAllTcpConnections()
                .Where(x => x.Pid == pid)
                .Select(x => x.Conn)
                .ToList();
        }

        /// <summary>The other half of the tree from GetParentChain: processes currently
        /// pointing at this PID as their parent. Snapshot-based, so a child that has
        /// already exited by the time this runs simply won't appear - same limitation
        /// GetParentChain already has for exited ancestors.</summary>
        public List<ParentChainEntry> GetDirectChildren(int pid, Dictionary<int, WmiProcInfo> snapshot)
        {
            var children = new List<ParentChainEntry>();
            foreach (var kvp in snapshot)
            {
                if (kvp.Value.ParentPid != pid || kvp.Key == pid)
                    continue;

                string name = "";
                string? path = kvp.Value.ExecutablePath;
                bool running = false;
                try
                {
                    using var p = Process.GetProcessById(kvp.Key);
                    name = p.ProcessName;
                    running = true;
                }
                catch
                {
                    name = "(exited)";
                }

                children.Add(new ParentChainEntry { Pid = kvp.Key, Name = name, ExecutablePath = path, StillRunning = running });
            }
            return children.OrderBy(c => c.Pid).ToList();
        }

        /// <summary>
        /// SHA-256 and MD5 of the executable on disk - the two hashes most triage
        /// workflows / VirusTotal lookups expect. Reads the whole file once and feeds
        /// both algorithms from the same stream rather than opening it twice.
        /// Large files (multi-GB) are skipped rather than hashed in full, since that
        /// would block the Investigate dialog for a long time for little benefit.
        /// </summary>
        private const long MaxHashableFileBytes = 500L * 1024 * 1024; // 500 MB

        public (string? Sha256, string? Md5) ComputeFileHashes(string? filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return (null, null);

            try
            {
                var length = new FileInfo(filePath).Length;
                if (length > MaxHashableFileBytes)
                    return (null, null);

                using var stream = File.OpenRead(filePath);
                using var sha256 = System.Security.Cryptography.SHA256.Create();
                using var md5 = System.Security.Cryptography.MD5.Create();

                var buffer = new byte[81920];
                int read;
                while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    sha256.TransformBlock(buffer, 0, read, null, 0);
                    md5.TransformBlock(buffer, 0, read, null, 0);
                }
                sha256.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                md5.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

                return (
                    Convert.ToHexString(sha256.Hash!).ToLowerInvariant(),
                    Convert.ToHexString(md5.Hash!).ToLowerInvariant());
            }
            catch
            {
                // File locked, deleted since the process launched, or access denied.
                return (null, null);
            }
        }

        public long? GetFileSize(string? filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return null;
            try { return new FileInfo(filePath).Length; }
            catch { return null; }
        }

        /// <summary>Authenticode signature check - flags unsigned binaries running from odd locations.</summary>
        public SignatureInfo GetSignatureInfo(string? filePath)
        {
            var result = new SignatureInfo();
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            {
                result.Error = "File not accessible";
                return result;
            }
            try
            {
                using var cert = X509Certificate.CreateFromSignedFile(filePath!);
                using var cert2 = new X509Certificate2(cert);
                using var chain = new X509Chain();
                result.IsSigned = true;
                result.Subject = cert2.Subject;
                result.Issuer = cert2.Issuer;
                result.ValidChain = chain.Build(cert2);
            }
            catch
            {
                result.IsSigned = false;
            }
            return result;
        }

        /// <summary>Assembles the full report shown in the Investigate window and used for export.</summary>
        public InvestigationReport BuildReport(int pid, Dictionary<int, WmiProcInfo> snapshot)
        {
            var report = new InvestigationReport { Pid = pid };
            try
            {
                using var p = Process.GetProcessById(pid);
                report.Name = p.ProcessName;
                report.StartTime = SafeStartTime(p);
                try { report.ExecutablePath = p.MainModule?.FileName; } catch { }
            }
            catch
            {
                report.Notes.Add("Process exited before it could be fully inspected.");
            }

            if (snapshot.TryGetValue(pid, out var wmi))
            {
                report.CommandLine = wmi.CommandLine;
                report.ExecutablePath ??= wmi.ExecutablePath;
            }

            report.User = GetOwner(pid);
            report.ParentChain = GetParentChain(pid, snapshot);
            report.Children = GetDirectChildren(pid, snapshot);
            report.LoadedModules = GetLoadedModules(pid);
            report.AssociatedServices = GetAssociatedServices(pid);
            report.NetworkConnections = GetNetworkConnections(pid);
            report.Signature = GetSignatureInfo(report.ExecutablePath);
            report.FileSizeBytes = GetFileSize(report.ExecutablePath);
            (report.Sha256Hash, report.Md5Hash) = ComputeFileHashes(report.ExecutablePath);

            report.Token = TokenInspector.GetTokenInfo(pid);
            report.Handles = HandleEnumerator.GetHandles(pid, out bool truncated);
            report.HandlesTruncated = truncated;

            // Heuristic flags worth surfacing up front, mirroring what stood out
            // in the manual XMRig investigation (SYSTEM process outside expected
            // paths, unsigned binary, listed under a generic host process, etc.)
            if (report.ExecutablePath != null &&
                report.ExecutablePath.Contains(@"\System32\", StringComparison.OrdinalIgnoreCase) &&
                report.Signature?.IsSigned == false)
            {
                report.Notes.Add("Unsigned executable running from System32 - worth extra scrutiny.");
            }
            if (report.AssociatedServices.Any(s => s.ServiceDll == null && s.PathName?.Contains("svchost", StringComparison.OrdinalIgnoreCase) == true))
            {
                report.Notes.Add("Service hosted by svchost.exe with no resolvable ServiceDll.");
            }
            if (report.FileSizeBytes > MaxHashableFileBytes)
            {
                report.Notes.Add($"Executable is larger than {MaxHashableFileBytes / (1024 * 1024)} MB - hashes were skipped.");
            }
            if (report.Token?.Privileges.Any(p => p.Name == "SeDebugPrivilege" && p.Enabled) == true)
            {
                report.Notes.Add("SeDebugPrivilege is enabled - this process can open/inspect other processes regardless of owner, including credential-holding ones like lsass.exe.");
            }
            if (report.HandlesTruncated)
            {
                report.Notes.Add($"More than {HandleEnumerator.MaxHandlesPerProcess} open handles - handle list was truncated.");
            }

            return report;
        }

        private static DateTime? SafeStartTime(Process p)
        {
            try { return p.StartTime; } catch { return null; }
        }
    }
}
