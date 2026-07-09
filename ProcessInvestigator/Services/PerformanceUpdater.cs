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
    /// Split into two passes on purpose:
    ///   - Update(): CPU% and Working Set - both are cheap field reads off an
    ///     already-open Process handle, safe to run every second.
    ///   - UpdateThreadsAndHandles(): Threads/Handles - process.Threads forces
    ///     a full toolhelp snapshot of the *entire system's* thread table on
    ///     every access, which is genuinely expensive. Running that for every
    ///     cached process on a 1s tick was blocking the UI thread badly enough
    ///     to make scrolling laggy, so it's called from the slower reconcile
    ///     tick instead, where the cost is amortized over a longer interval.
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
                }
                catch
                {
                    // Process exited or access denied.
                }
            }

            _lastSample = now;
        }

        /// <summary>
        /// Threads/Handles - deliberately NOT part of the 1s Update() pass, see class
        /// remarks. Call this from the slower tick instead.
        /// </summary>
        public void UpdateThreadsAndHandles(ProcessCache cache)
        {
            foreach (var row in cache.Values)
            {
                try
                {
                    using var process = Process.GetProcessById(row.Pid);
                    row.ThreadCount = process.Threads.Count;
                    row.HandleCount = process.HandleCount;
                }
                catch
                {
                    // Process exited or access denied.
                }
            }
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
