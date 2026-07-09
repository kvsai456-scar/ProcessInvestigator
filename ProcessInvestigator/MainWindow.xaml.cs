using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Threading;
using ProcessInvestigator.Models;
using ProcessInvestigator.Services;

namespace ProcessInvestigator
{
    public partial class MainWindow : Window
    {
        private readonly ObservableCollection<ProcessRow> _rows = new();
        private readonly ProcessCache _cache = new();
        private readonly ICollectionView _view;

        // Two-speed refresh, the same split Task Manager itself uses:
        //   - a cheap 1s tick that only re-samples numbers (CPU/mem/threads/handles)
        //     for rows that already exist, with no process enumeration and no WMI;
        //   - a heavier 4s tick that reconciles the row list against reality (safety
        //     net for any missed watcher event) and refreshes WMI-derived fields
        //     (parent PID, command line, path) plus hosted-service names.
        // Process add/remove itself doesn't wait on either timer - ProcessWatcherService
        // reports that instantly via WMI trace events.
        private readonly DispatcherTimer _fastTimer = new() { Interval = TimeSpan.FromSeconds(1) };
        private readonly DispatcherTimer _slowTimer = new() { Interval = TimeSpan.FromSeconds(4) };
        private readonly ProcessInvestigatorService _service = new();
        private readonly ProcessWatcherService _watcher = new();
        private readonly PerformanceUpdater _performanceUpdater = new();
        private readonly ServiceHostResolver _serviceHostResolver = new();

        public MainWindow()
        {
            InitializeComponent();
            ProcessGrid.ItemsSource = _rows;
            _view = System.Windows.Data.CollectionViewSource.GetDefaultView(_rows);

            // Instant add/remove the moment Windows reports a process starting
            // or exiting, instead of waiting up to a tick for the next poll.
            _watcher.ProcessStarted += (_, e) => Dispatcher.Invoke(() => AddRowIfMissing(e.Pid, e.Name, e.ParentPid));
            _watcher.ProcessStopped += (_, e) => Dispatcher.Invoke(() => RemoveRow(e.Pid));
            _watcher.WatchError += (_, msg) => Dispatcher.Invoke(() =>
                StatusText.Text = $"Live process events unavailable ({msg}) - falling back to polling only");
            _watcher.Start();

            _fastTimer.Tick += (_, _) => RefreshLiveStats();
            _slowTimer.Tick += (_, _) => ReconcileProcessList();
            _fastTimer.Start();
            _slowTimer.Start();

            // First paint shouldn't wait for either timer to fire.
            ReconcileProcessList();
            RefreshLiveStats();
        }

    private void AddRowIfMissing(int pid, string name, int parentPid)
    {
        if (_cache.Contains(pid))
            return;

        var row = new ProcessRow
        {
            Pid = pid,
            Name = name,
            ParentPid = parentPid
        };

        try
        {
            using var p = Process.GetProcessById(pid);

            try
            {
                row.ExecutablePath = p.MainModule?.FileName;
            }
            catch { }
        }
        catch
        {
            return;
        }

        EnrichRow(row);

        _cache.Add(row);

        _rows.Add(row);

        StatusText.Text =
            $"{_rows.Count} processes | live | +{name} (PID {pid})";
    }

    private void RemoveRow(int pid)
    {
        var row = _cache.Get(pid);

        if (row == null)
            return;

        _cache.Remove(pid);
        _performanceUpdater.Remove(pid);
        _serviceHostResolver.Remove(pid);
        _rows.Remove(row);
        StatusText.Text =
            $"{_rows.Count} processes | live | -{row.Name} (PID {pid})";
    }

        /// <summary>
        /// Fast tick (every 1s): re-samples CPU%/memory/threads/handles for rows that
        /// already exist. Pure Process.GetProcessById per known PID, no WMI, no full
        /// process enumeration - this is what keeps the UI feeling smooth instead of
        /// re-doing a full scan every second like the old engine did.
        /// </summary>
        private void RefreshLiveStats()
        {
            _performanceUpdater.Update(_cache);
            StatusText.Text = $"{_rows.Count} processes  |  live  |  updated {DateTime.Now:HH:mm:ss}";
        }

        /// <summary>
        /// Slow tick (every 4s): the heavier pass. Process add/remove is normally handled
        /// instantly by the WMI event watcher, so this exists as a safety net in case an
        /// event was ever missed, plus it's where the WMI-derived fields (parent PID,
        /// command line, path) and hosted-service names actually get refreshed, since
        /// those don't change fast enough to justify asking every second.
        /// </summary>
        private void ReconcileProcessList()
        {
            var wmi = _service.GetWmiSnapshot();
            _performanceUpdater.UpdateThreadsAndHandles(_cache);

            var seenPids = new HashSet<int>();
            var processes = Process.GetProcesses();

            foreach (var p in processes)
            {
                seenPids.Add(p.Id);

                wmi.TryGetValue(p.Id, out var wmiInfo);
                var existing = _cache.Get(p.Id);

                if (existing == null)
                {
                    existing = new ProcessRow
                    {
                        Pid = p.Id,
                        Name = p.ProcessName
                    };

                    _cache.Add(existing);
                    _rows.Add(existing);
                }

                existing.ParentPid = wmiInfo?.ParentPid ?? existing.ParentPid;
                existing.CommandLine = wmiInfo?.CommandLine ?? existing.CommandLine;
                existing.ExecutablePath = wmiInfo?.ExecutablePath ?? existing.ExecutablePath;

                EnrichRow(existing);
            }

            // Safety net for the same reason - normally RemoveRow already handled this.
            for (int i = _rows.Count - 1; i >= 0; i--)
            {
                var row = _rows[i];

                if (!seenPids.Contains(row.Pid))
                {
                    _cache.Remove(row.Pid);
                    _performanceUpdater.Remove(row.Pid);
                    _serviceHostResolver.Remove(row.Pid);
                    _rows.RemoveAt(i);
                }
            }

            foreach (var p in processes) p.Dispose();
        }

        /// <summary>
        /// Fills in the fields that are cheap to cache but not worth recomputing every
        /// tick: icon, Company/Description (from FileVersionInfo, keyed by path so a
        /// second svchost.exe row is free), and hosted-service names for svchost-style
        /// processes. Safe to call repeatedly - each piece only does real work once
        /// per unique path/PID until its own cache says otherwise.
        /// </summary>
        private void EnrichRow(ProcessRow row)
        {
            if (row.ExecutablePath != null)
            {
                if (row.IconSource == null)
                    row.IconSource = IconCache.GetIcon(row.ExecutablePath);

                if (row.Company == null && row.Description == null)
                {
                    var info = VersionInfoCache.Get(row.ExecutablePath);
                    row.Company = info.Company;
                    row.Description = info.Description;
                }
            }

            row.HostedServices = _serviceHostResolver.Resolve(row.Pid, row.Name);
        }

        private void FilterBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            FilterHint.Visibility = string.IsNullOrEmpty(FilterBox.Text)
                ? Visibility.Visible : Visibility.Collapsed;

            string text = FilterBox.Text.Trim();
            _view.Filter = string.IsNullOrEmpty(text)
                ? null
                : o => MatchesFilter((ProcessRow)o, text);
        }

        /// <summary>Search by name, PID, path or company - v1.2 goal, was name/PID only.</summary>
        private static bool MatchesFilter(ProcessRow row, string text)
        {
            return row.Name.Contains(text, StringComparison.OrdinalIgnoreCase)
                || row.Pid.ToString().Contains(text)
                || (row.HostedServices?.Contains(text, StringComparison.OrdinalIgnoreCase) ?? false)
                || (row.ExecutablePath?.Contains(text, StringComparison.OrdinalIgnoreCase) ?? false)
                || (row.Company?.Contains(text, StringComparison.OrdinalIgnoreCase) ?? false);
        }

        private ProcessRow? SelectedRow => ProcessGrid.SelectedItem as ProcessRow;

        private void Investigate_Click(object sender, RoutedEventArgs e)
        {
            var row = SelectedRow;
            if (row == null) return;

            var wmi = _service.GetWmiSnapshot();
            var report = _service.BuildReport(row.Pid, wmi);
            var win = new InvestigateWindow(report) { Owner = this };
            win.Show();
        }

        private void OpenFileLocation_Click(object sender, RoutedEventArgs e)
        {
            var row = SelectedRow;
            if (row?.ExecutablePath == null || !File.Exists(row.ExecutablePath))
            {
                MessageBox.Show("File path is unavailable or inaccessible.", "Process Investigator");
                return;
            }
            Process.Start("explorer.exe", $"/select,\"{row.ExecutablePath}\"");
        }

        private void CopyPath_Click(object sender, RoutedEventArgs e)
        {
            var row = SelectedRow;
            if (row?.ExecutablePath != null) Clipboard.SetText(row.ExecutablePath);
        }

        private void EndProcess_Click(object sender, RoutedEventArgs e)
        {
            var row = SelectedRow;
            if (row == null) return;

            var confirm = MessageBox.Show(
                $"End process {row.Name} (PID {row.Pid})? This cannot be undone.",
                "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (confirm != MessageBoxResult.Yes) return;

            try
            {
                using var p = Process.GetProcessById(row.Pid);
                p.Kill();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Could not end process: {ex.Message}", "Process Investigator",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            _fastTimer.Stop();
            _slowTimer.Stop();
            _watcher.Dispose();
            base.OnClosed(e);
        }
    }
}
