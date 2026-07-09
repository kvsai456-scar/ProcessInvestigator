using System.IO;
using System.Windows;
using Microsoft.Win32;
using ProcessInvestigator.Models;
using ProcessInvestigator.Services;

namespace ProcessInvestigator
{
    public partial class InvestigateWindow : Window
    {
        private readonly InvestigationReport _report;

        /// <summary>Lightweight node for the Process Tree tab - bound via a HierarchicalDataTemplate in XAML.</summary>
        public class TreeNode
        {
            public string Text { get; set; } = "";
            public bool IsCurrent { get; set; }
            public bool StillRunning { get; set; } = true;
            public System.Collections.ObjectModel.ObservableCollection<TreeNode> Children { get; } = new();
        }

        public InvestigateWindow(InvestigationReport report)
        {
            InitializeComponent();
            _report = report;
            Populate();
        }

        private void Populate()
        {
            TitleText.Text = $"{_report.Name} (PID {_report.Pid})";
            SubtitleText.Text = _report.ExecutablePath ?? "Path unavailable";
            NotesList.ItemsSource = _report.Notes;

            OverviewText.Text =
                $"PID:            {_report.Pid}\n" +
                $"Name:           {_report.Name}\n" +
                $"Path:           {_report.ExecutablePath ?? "(unavailable)"}\n" +
                $"File size:      {FormatFileSize(_report.FileSizeBytes)}\n" +
                $"Command line:   {_report.CommandLine ?? "(unavailable)"}\n" +
                $"User:           {_report.User ?? "(unavailable)"}\n" +
                $"Start time:     {(_report.StartTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "(unavailable)")}\n" +
                $"Signed:         {(_report.Signature?.IsSigned == true ? $"Yes ({_report.Signature.Subject})" : "No / unverifiable")}\n" +
                $"SHA-256:        {_report.Sha256Hash ?? "(unavailable)"}\n" +
                $"MD5:            {_report.Md5Hash ?? "(unavailable)"}";

            ProcessTreeView.ItemsSource = new[] { BuildProcessTree(_report) };

            ModulesGrid.ItemsSource = _report.LoadedModules;
            ServicesGrid.ItemsSource = _report.AssociatedServices;
            NetworkGrid.ItemsSource = _report.NetworkConnections;

            HandlesGrid.ItemsSource = _report.Handles;
            HandlesNoteText.Text = _report.HandlesTruncated
                ? $"Showing first {_report.Handles.Count} handles (list truncated - this process has more open than that)."
                : $"{_report.Handles.Count} open handles.";

            PopulateToken();
        }

        private void PopulateToken()
        {
            var t = _report.Token;
            if (t == null)
            {
                TokenText.Text = "(not available)";
                return;
            }
            if (t.Error != null)
            {
                TokenText.Text = t.Error;
                PrivilegesGrid.ItemsSource = null;
                return;
            }

            TokenText.Text =
                $"User:             {t.UserAccount ?? "(unresolved)"}\n" +
                $"SID:              {t.UserSid ?? "(unavailable)"}\n" +
                $"Integrity level:  {t.IntegrityLevel}\n" +
                $"Elevated:         {t.IsElevated} (type: {t.ElevationType})\n" +
                $"Session ID:       {t.SessionId}";

            PrivilegesGrid.ItemsSource = t.Privileges;
        }

        private static string FormatFileSize(long? bytes)
        {
            if (bytes == null) return "(unavailable)";
            double mb = bytes.Value / 1024.0 / 1024.0;
            return mb >= 1 ? $"{mb:N2} MB ({bytes:N0} bytes)" : $"{bytes:N0} bytes";
        }

        /// <summary>
        /// Builds a single-root tree: topmost ancestor down through ParentChain to the
        /// investigated process (bolded), with its direct Children attached as leaves
        /// underneath - the "parent/child process tree" v1.3 goal.
        /// </summary>
        private static TreeNode BuildProcessTree(InvestigationReport r)
        {
            // ParentChain is ordered [self, parent, grandparent, ... root] - reverse to build root-down.
            TreeNode? previous = null;
            TreeNode? root = null;

            for (int i = r.ParentChain.Count - 1; i >= 0; i--)
            {
                var entry = r.ParentChain[i];
                var node = new TreeNode
                {
                    Text = FormatEntry(entry),
                    IsCurrent = i == 0,
                    StillRunning = entry.StillRunning
                };

                if (previous == null) root = node;
                else previous.Children.Add(node);

                previous = node;
            }

            // No parent chain at all (e.g. PID 0/4 or the process exited before we could
            // walk it) - fall back to a single root node for the investigated process itself.
            if (root == null)
            {
                root = new TreeNode { Text = $"{r.Name} (PID {r.Pid})", IsCurrent = true };
                previous = root;
            }

            foreach (var child in r.Children)
            {
                previous!.Children.Add(new TreeNode
                {
                    Text = FormatEntry(child),
                    StillRunning = child.StillRunning
                });
            }

            return root;
        }

        private static string FormatEntry(ParentChainEntry c) =>
            $"{c.Name} (PID {c.Pid})" + (c.StillRunning ? "" : "  [exited]");

        private void ExportButton_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new SaveFileDialog
            {
                FileName = $"investigation_{_report.Name}_{_report.Pid}.txt",
                Filter = "Text report (*.txt)|*.txt"
            };
            if (dlg.ShowDialog() == true)
            {
                File.WriteAllText(dlg.FileName, ReportGenerator.ToText(_report));
                MessageBox.Show("Report saved.", "Process Investigator");
            }
        }
    }
}
