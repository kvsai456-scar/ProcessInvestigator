using System.Management;

namespace ProcessInvestigator.Services
{
    /// <summary>
    /// svchost.exe (and a handful of other Windows host processes) can run several
    /// unrelated services inside one PID, which is why Task Manager shows
    /// "Host Process for Windows Services" instead of anything meaningful. This
    /// resolves the actual DisplayNames of services running inside a given PID so
    /// the grid can show e.g. "svchost.exe (DCOM Server Process Launcher, Plug and Play)"
    /// instead of a bare, generic "svchost.exe".
    ///
    /// Deliberately separate from ProcessInvestigatorService.GetAssociatedServices,
    /// which also resolves each service's ServiceDll via the registry - useful for
    /// the on-demand Investigate report, but too much work to repeat on a live tick.
    /// This only fetches Name/DisplayName, and only for processes worth asking about.
    /// </summary>
    public class ServiceHostResolver
    {
        /// <summary>Process names that can plausibly host more than one Windows service.</summary>
        private static readonly HashSet<string> HostProcessNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "svchost.exe",
            "svchost",
        };

        private static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(30);

        private readonly Dictionary<int, (string? Summary, DateTime CheckedAt)> _cache = new();

        public static bool IsHostProcess(string? name) => name != null && HostProcessNames.Contains(name);

        /// <summary>
        /// Returns a comma-joined "ServiceA, ServiceB" summary for the given PID, or null if
        /// it's not a host process, has no resolvable services, or the WMI query fails.
        /// Result is cached for RefreshInterval since a given svchost group's service list
        /// rarely changes mid-session.
        /// </summary>
        public string? Resolve(int pid, string? processName)
        {
            if (!IsHostProcess(processName))
                return null;

            if (_cache.TryGetValue(pid, out var cached) && DateTime.Now - cached.CheckedAt < RefreshInterval)
                return cached.Summary;

            string? summary = null;
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT DisplayName FROM Win32_Service WHERE ProcessId = {pid}");

                var names = new List<string>();
                foreach (ManagementObject mo in searcher.Get())
                {
                    if (mo["DisplayName"] is string dn && !string.IsNullOrWhiteSpace(dn))
                        names.Add(dn);
                }

                if (names.Count > 0)
                    summary = string.Join(", ", names.OrderBy(n => n, StringComparer.OrdinalIgnoreCase));
            }
            catch
            {
                // WMI unavailable or access denied - leave summary null, try again next interval.
            }

            _cache[pid] = (summary, DateTime.Now);
            return summary;
        }

        public void Remove(int pid) => _cache.Remove(pid);

        public void Clear() => _cache.Clear();
    }
}
