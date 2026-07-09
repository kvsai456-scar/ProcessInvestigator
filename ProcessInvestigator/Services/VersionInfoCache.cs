using System.Collections.Concurrent;
using System.Diagnostics;

namespace ProcessInvestigator.Services
{
    public readonly record struct VersionInfo(string? Company, string? Description);

    /// <summary>
    /// Reads Company/FileDescription out of a binary's Win32 version resource for the
    /// Company and Description grid columns. Like IconCache, this is a per-path cache
    /// for the app's lifetime - FileVersionInfo.GetVersionInfo does a small amount of
    /// disk I/O, so it's only worth paying once per unique executable path rather than
    /// on every refresh tick.
    /// </summary>
    public static class VersionInfoCache
    {
        private static readonly ConcurrentDictionary<string, VersionInfo> _cache = new();

        public static VersionInfo Get(string? path)
        {
            if (string.IsNullOrEmpty(path)) return default;

            return _cache.GetOrAdd(path, p =>
            {
                try
                {
                    var info = FileVersionInfo.GetVersionInfo(p);
                    return new VersionInfo(
                        Clean(info.CompanyName),
                        Clean(info.FileDescription));
                }
                catch
                {
                    // Missing file, no version resource, or access denied.
                    return default;
                }
            });
        }

        private static string? Clean(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
    }
}
