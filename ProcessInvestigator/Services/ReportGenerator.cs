using System.Text;
using ProcessInvestigator.Models;

namespace ProcessInvestigator.Services
{
    public static class ReportGenerator
    {
        public static string ToText(InvestigationReport r)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Process Investigation Report");
            sb.AppendLine($"Generated: {r.GeneratedAt:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine(new string('=', 60));

            sb.AppendLine();
            sb.AppendLine("1. Process Overview");
            sb.AppendLine($"   PID:            {r.Pid}");
            sb.AppendLine($"   Name:           {r.Name}");
            sb.AppendLine($"   Path:           {r.ExecutablePath ?? "(unavailable)"}");
            sb.AppendLine($"   File size:      {(r.FileSizeBytes.HasValue ? $"{r.FileSizeBytes:N0} bytes" : "(unavailable)")}");
            sb.AppendLine($"   SHA-256:        {r.Sha256Hash ?? "(unavailable)"}");
            sb.AppendLine($"   MD5:            {r.Md5Hash ?? "(unavailable)"}");
            sb.AppendLine($"   Command line:   {r.CommandLine ?? "(unavailable)"}");
            sb.AppendLine($"   User:           {r.User ?? "(unavailable)"}");
            sb.AppendLine($"   Start time:     {(r.StartTime.HasValue ? r.StartTime.Value.ToString("yyyy-MM-dd HH:mm:ss") : "(unavailable)")}");

            if (r.Signature != null)
            {
                sb.AppendLine();
                sb.AppendLine("2. Digital Signature");
                sb.AppendLine($"   Signed:         {r.Signature.IsSigned}");
                if (r.Signature.IsSigned)
                {
                    sb.AppendLine($"   Subject:        {r.Signature.Subject}");
                    sb.AppendLine($"   Issuer:         {r.Signature.Issuer}");
                    sb.AppendLine($"   Chain valid:    {r.Signature.ValidChain}");
                }
            }

            sb.AppendLine();
            sb.AppendLine("3. Process Tree");
            sb.AppendLine("   Ancestors: " + string.Join("  ->  ",
                r.ParentChain.Select(c => $"{c.Name}({c.Pid})" + (c.StillRunning ? "" : " [exited]"))));
            if (r.Children.Count == 0)
            {
                sb.AppendLine("   Children:  (none)");
            }
            else
            {
                sb.AppendLine("   Children:");
                foreach (var c in r.Children)
                    sb.AppendLine($"     - {c.Name}({c.Pid})" + (c.StillRunning ? "" : " [exited]"));
            }

            sb.AppendLine();
            sb.AppendLine("4. Associated Services");
            if (r.AssociatedServices.Count == 0)
            {
                sb.AppendLine("   None (this process does not host a Windows service).");
            }
            foreach (var s in r.AssociatedServices)
            {
                sb.AppendLine($"   - {s.Name} ({s.DisplayName})");
                sb.AppendLine($"       State: {s.State}   StartMode: {s.StartMode}   RunAs: {s.StartName}");
                sb.AppendLine($"       PathName:   {s.PathName}");
                sb.AppendLine($"       ServiceDll: {s.ServiceDll ?? "(none found)"}");
            }

            sb.AppendLine();
            sb.AppendLine($"5. Loaded Modules / DLLs ({r.LoadedModules.Count} total)");
            foreach (var m in r.LoadedModules)
            {
                sb.AppendLine($"   - {m.ModuleName,-30} {m.FileName}");
            }

            sb.AppendLine();
            sb.AppendLine($"6. Network Connections ({r.NetworkConnections.Count} active)");
            if (r.NetworkConnections.Count == 0)
            {
                sb.AppendLine("   None observed at time of scan.");
            }
            foreach (var n in r.NetworkConnections)
            {
                sb.AppendLine($"   - {n.Protocol} {n.LocalAddress}:{n.LocalPort} -> {n.RemoteAddress}:{n.RemotePort} [{n.State}]");
            }

            if (r.Notes.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("7. Notes / Flags");
                foreach (var note in r.Notes)
                    sb.AppendLine($"   * {note}");
            }

            return sb.ToString();
        }
    }
}
