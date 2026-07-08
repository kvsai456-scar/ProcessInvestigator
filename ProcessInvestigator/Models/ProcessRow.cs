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

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
