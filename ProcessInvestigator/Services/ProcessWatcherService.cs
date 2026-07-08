using System.Management;

namespace ProcessInvestigator.Services
{
    public class ProcessStartedEventArgs : EventArgs
    {
        public int Pid { get; init; }
        public string Name { get; init; } = "";
        public int ParentPid { get; init; }
    }

    public class ProcessStoppedEventArgs : EventArgs
    {
        public int Pid { get; init; }
    }

    /// <summary>
    /// Task Manager and Process Explorer both still poll for CPU/memory numbers
    /// (there's no push API for that), but process creation/exit itself doesn't
    /// have to wait for the next poll tick - Windows exposes it as an ETW trace
    /// via WMI (Win32_ProcessStartTrace / Win32_ProcessStopTrace), which fires
    /// within milliseconds of the actual event. This gives the process list
    /// itself a "live" feel while CPU/memory still refresh on a timer.
    /// Requires admin privileges to subscribe - fine, since the app runs elevated.
    /// </summary>
    public class ProcessWatcherService : IDisposable
    {
        private ManagementEventWatcher? _startWatcher;
        private ManagementEventWatcher? _stopWatcher;

        public event EventHandler<ProcessStartedEventArgs>? ProcessStarted;
        public event EventHandler<ProcessStoppedEventArgs>? ProcessStopped;
        public event EventHandler<string>? WatchError;

        public void Start()
        {
            try
            {
                _startWatcher = new ManagementEventWatcher(
                    new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
                _startWatcher.EventArrived += (_, e) =>
                {
                    ProcessStarted?.Invoke(this, new ProcessStartedEventArgs
                    {
                        Pid = System.Convert.ToInt32(e.NewEvent.Properties["ProcessID"].Value),
                        Name = e.NewEvent.Properties["ProcessName"]?.Value as string ?? "",
                        ParentPid = System.Convert.ToInt32(e.NewEvent.Properties["ParentProcessID"].Value)
                    });
                };
                _startWatcher.Start();

                _stopWatcher = new ManagementEventWatcher(
                    new WqlEventQuery("SELECT * FROM Win32_ProcessStopTrace"));
                _stopWatcher.EventArrived += (_, e) =>
                {
                    ProcessStopped?.Invoke(this, new ProcessStoppedEventArgs
                    {
                        Pid = System.Convert.ToInt32(e.NewEvent.Properties["ProcessID"].Value)
                    });
                };
                _stopWatcher.Start();
            }
            catch (Exception ex)
            {
                // Falls back gracefully - MainWindow keeps its poll-based refresh
                // as the only source of truth if event watching can't start
                // (e.g. WMI service unavailable, insufficient privileges).
                WatchError?.Invoke(this, ex.Message);
            }
        }

        public void Dispose()
        {
            try { _startWatcher?.Stop(); _startWatcher?.Dispose(); } catch { }
            try { _stopWatcher?.Stop(); _stopWatcher?.Dispose(); } catch { }
        }
    }
}
