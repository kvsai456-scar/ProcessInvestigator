using ProcessInvestigator.Models;
using System.Collections.Generic;

namespace ProcessInvestigator.Services
{
    public class ProcessCache
    {
        private readonly Dictionary<int, ProcessRow> _cache = new();

        public IReadOnlyDictionary<int, ProcessRow> Items => _cache;

        public bool Contains(int pid)
        {
            return _cache.ContainsKey(pid);
        }

        public ProcessRow? Get(int pid)
        {
            _cache.TryGetValue(pid, out var row);
            return row;
        }

        public void Add(ProcessRow row)
        {
            _cache[row.Pid] = row;
        }

        public bool Remove(int pid)
        {
            return _cache.Remove(pid);
        }

        public IEnumerable<ProcessRow> Values
        {
            get { return _cache.Values; }
        }
    }
}