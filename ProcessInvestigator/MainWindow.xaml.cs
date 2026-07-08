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
        private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
        private readonly ProcessInvestigatorService _service = new();
        private readonly ProcessWatcherService _watcher = new();
        private readonly PerformanceUpdater _performanceUpdater = new();

        public MainWindow()
        {
            InitializeComponent();
            ProcessGrid.ItemsSource = _rows;
            _view = System.Windows.Data.CollectionViewSource.GetDefaultView(_rows);

            // Instant add/remove the moment Windows reports a process starting
            // or exiting, instead of waiting up to 1s for the next poll tick.
            _watcher.ProcessStarted += (_, e) => Dispatcher.Invoke(() => AddRowIfMissing(e.Pid, e.Name, e.ParentPid));
            _watcher.ProcessStopped += (_, e) => Dispatcher.Invoke(() => RemoveRow(e.Pid));
            _watcher.WatchError += (_, msg) => Dispatcher.Invoke(() =>
                StatusText.Text = $"Live process events unavailable ({msg}) - falling back to polling only");
            _watcher.Start();

            // CPU%/memory still need periodic sampling - there's no push API for
            // that - but this now only has to keep numbers fresh, not detect
            // new/exited processes, so it can run lighter than before.
            _timer.Tick += (_, _) => RefreshStats();
            _timer.Start();
            RefreshStats();
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

        if (!string.IsNullOrEmpty(row.ExecutablePath))
            row.IconSource = IconCache.GetIcon(row.ExecutablePath);

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
        _rows.Remove(row);
        StatusText.Text =
            $"{_rows.Count} processes | live | -{row.Name} (PID {pid})";
    }

        /// <summary>
        /// Updates CPU%/memory/path for rows that already exist. Process add/remove
        /// is handled instantly by the event watcher above; this is a safety-net
        /// full reconcile too, in case an event was ever missed.
        /// </summary>
        private void RefreshStats()
        {
            var wmi = _service.GetWmiSnapshot();
            _performanceUpdater.Update(_cache);

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

                if (existing.IconSource == null && existing.ExecutablePath != null)
                {
                    existing.IconSource = IconCache.GetIcon(existing.ExecutablePath);
                }
            }

            // Safety net for the same reason - normally RemoveRow already handled this.
            for (int i = _rows.Count - 1; i >= 0; i--)
{
            var row = _rows[i];

            if (!seenPids.Contains(row.Pid))
            {
                _cache.Remove(row.Pid);

                _performanceUpdater.Remove(row.Pid);

                _rows.RemoveAt(i);
            }
}

           foreach (var p in processes) p.Dispose();
            StatusText.Text = $"{_rows.Count} processes  |  live  |  updated {DateTime.Now:HH:mm:ss}";
        }

        private void FilterBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            FilterHint.Visibility = string.IsNullOrEmpty(FilterBox.Text)
                ? Visibility.Visible : Visibility.Collapsed;

            string text = FilterBox.Text.Trim();
            _view.Filter = string.IsNullOrEmpty(text)
                ? null
                : o => ((ProcessRow)o).Name.Contains(text, StringComparison.OrdinalIgnoreCase)
                       || ((ProcessRow)o).Pid.ToString().Contains(text);
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
            _timer.Stop();
            _watcher.Dispose();
            base.OnClosed(e);
        }
    }
}
