using System;
using System.Collections.Generic;
using System.Diagnostics;
using ProcessInvestigator.Models;

namespace ProcessInvestigator.Services
{
    /// <summary>
    /// Updates live performance statistics for processes that are
    /// already present in the ProcessCache.
    ///
    /// Responsibility:
    ///   - CPU %
    ///   - Working Set (RAM)
    ///   - Thread Count
    ///   - Handle Count
    ///
    /// It NEVER creates or removes ProcessRow objects.
    /// </summary>
    public class PerformanceUpdater
    {
        private readonly Dictionary<int, TimeSpan> _lastCpuTime = new();
        private DateTime _lastSample = DateTime.Now;

        public void Update(ProcessCache cache)
        {
            var now = DateTime.Now;
            var elapsed = (now - _lastSample).TotalSeconds;
            if (elapsed <= 0)
                elapsed = 1;

            foreach (var row in cache.Values)
            {
                try
                {
                    using var process = Process.GetProcessById(row.Pid);

                    // CPU
                    var cpuTime = process.TotalProcessorTime;

                    if (_lastCpuTime.TryGetValue(row.Pid, out var previous))
                    {
                        var delta = (cpuTime - previous).TotalSeconds;

                        var cpu =
                            (delta / elapsed / Environment.ProcessorCount) * 100.0;

                        if (cpu < 0)
                            cpu = 0;

                        row.CpuPercent = Math.Round(cpu, 1);
                    }

                    _lastCpuTime[row.Pid] = cpuTime;

                    // Memory
                    row.MemoryBytes = process.WorkingSet64;

                    // Threads
                   
                }
                catch
                {
                    // Process exited or access denied.
                }
            }

            _lastSample = now;
        }

        public void Remove(int pid)
        {
            _lastCpuTime.Remove(pid);
        }

        public void Clear()
        {
            _lastCpuTime.Clear();
            _lastSample = DateTime.Now;
        }
    }
}
