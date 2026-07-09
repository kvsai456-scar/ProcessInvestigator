using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Media;

namespace ProcessInvestigator.Models
{
    /// <summary>
    /// One row in the live, auto-refreshing process grid.
    /// Cheap to build every refresh tick - anything expensive
    /// (DLLs, services, network, signatures) is fetched only
    /// on-demand when the user clicks "Investigate".
    /// </summary>
    public class ProcessRow : INotifyPropertyChanged
    {
        public int Pid { get; set; }
        public int ParentPid { get; set; }
        public string Name { get; set; } = "";
        public string? ExecutablePath { get; set; }
        public string? CommandLine { get; set; }
        public string? User { get; set; }
        public DateTime? StartTime { get; set; }

        private ImageSource? _iconSource;
        public ImageSource? IconSource
        {
            get => _iconSource;
            set { _iconSource = value; OnPropertyChanged(); }
        }

        private double _cpuPercent;
        public double CpuPercent
        {
            get => _cpuPercent;
            set { _cpuPercent = value; OnPropertyChanged(); }
        }

        private long _memoryBytes;
        public long MemoryBytes
        {
            get => _memoryBytes;
            set { _memoryBytes = value; OnPropertyChanged(); }
        }

        public string MemoryDisplay => $"{MemoryBytes / 1024.0 / 1024.0:N1} MB";

        private int _threadCount;
        public int ThreadCount
        {
            get => _threadCount;
            set { _threadCount = value; OnPropertyChanged(); }
        }

        private int _handleCount;
        public int HandleCount
        {
            get => _handleCount;
            set { _handleCount = value; OnPropertyChanged(); }
        }

        private string? _company;
        /// <summary>From the exe's FileVersionInfo. Resolved lazily/once per path - see VersionInfoCache.</summary>
        public string? Company
        {
            get => _company;
            set { _company = value; OnPropertyChanged(); }
        }

        private string? _description;
        /// <summary>From the exe's FileVersionInfo (FileDescription). Resolved lazily/once per path.</summary>
        public string? Description
        {
            get => _description;
            set { _description = value; OnPropertyChanged(); }
        }

        private string? _hostedServices;
        /// <summary>
        /// For host processes like svchost.exe/dllhost.exe that can run multiple Windows
        /// services inside one PID, this holds the friendly "(ServiceA, ServiceB)" summary
        /// resolved via ServiceHostResolver. Null for ordinary single-purpose processes.
        /// </summary>
        public string? HostedServices
        {
            get => _hostedServices;
            set { _hostedServices = value; OnPropertyChanged(); OnPropertyChanged(nameof(DisplayName)); }
        }

        /// <summary>
        /// What the Name column actually shows: "svchost.exe (DcomLaunch, PlugPlay)" for
        /// service-hosting processes, otherwise just the plain process name.
        /// </summary>
        public string DisplayName => string.IsNullOrEmpty(HostedServices)
            ? Name
            : $"{Name} ({HostedServices})";

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
