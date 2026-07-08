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
                $"Command line:   {_report.CommandLine ?? "(unavailable)"}\n" +
                $"User:           {_report.User ?? "(unavailable)"}\n" +
                $"Start time:     {(_report.StartTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "(unavailable)")}\n" +
                $"Signed:         {(_report.Signature?.IsSigned == true ? $"Yes ({_report.Signature.Subject})" : "No / unverifiable")}";

            ParentChainList.ItemsSource = _report.ParentChain
                .Select(c => $"{c.Name} (PID {c.Pid}){(c.StillRunning ? "" : "  [exited]")}  ->  {c.ExecutablePath}");

            ModulesGrid.ItemsSource = _report.LoadedModules;
            ServicesGrid.ItemsSource = _report.AssociatedServices;
            NetworkGrid.ItemsSource = _report.NetworkConnections;
        }

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
