using System.Runtime.InteropServices;
using System.Threading;
using ProcessInvestigator.Models;

namespace ProcessInvestigator.Services
{
    /// <summary>
    /// v1.4 "Handle viewer" goal. Enumerates the OS handles (files, keys, mutexes, events,
    /// sections, etc.) currently open inside a target process - the same data Process
    /// Explorer's / Sysinternals Handle.exe's lower pane shows.
    ///
    /// There is no documented, supported Win32 API for "list handles owned by PID X".
    /// The only way to get this (short of ETW handle tracing) is the same technique every
    /// handle-viewer tool uses:
    ///   1. NtQuerySystemInformation(SystemHandleInformation) - an undocumented ntdll export,
    ///      stable since NT4 - which returns EVERY handle open system-wide.
    ///   2. Filter that list down to the target PID.
    ///   3. DuplicateHandle() each raw handle value into our own process so we can query it.
    ///   4. NtQueryObject() the duplicate to get its type name and (optionally) its object name.
    ///
    /// Step 4's name query is the well-known hazard here: querying the name of certain handle
    /// types (named pipes and mailslots in particular, via the "File" type) can block forever
    /// if the other end of the pipe never responds, because the query is serviced by the same
    /// driver that owns the pipe. Every public tool that does this (Process Explorer, Process
    /// Hacker/System Informer, and older Sysinternals Handle.exe) works around it by running
    /// the name query on its own throwaway thread with a short timeout and abandoning that
    /// thread if it doesn't return in time. We do the same below.
    /// </summary>
    public static class HandleEnumerator
    {
        // Hard cap so a process with tens of thousands of handles (some SYSTEM services do)
        // doesn't turn "Investigate" into a multi-second stall. The grid shows a "truncated"
        // note when this is hit.
        public const int MaxHandlesPerProcess = 500;

        // Name queries get this long to return before we give up on that one handle and move on.
        private static readonly TimeSpan NameQueryTimeout = TimeSpan.FromMilliseconds(150);

        public static List<HandleInfo> GetHandles(int pid, out bool truncated)
        {
            truncated = false;
            var results = new List<HandleInfo>();

            List<SYSTEM_HANDLE_TABLE_ENTRY_INFO> allHandles;
            try
            {
                allHandles = QuerySystemHandles();
            }
            catch
            {
                // NtQuerySystemInformation missing/blocked (e.g. locked-down environment) -
                // degrade to an empty list rather than crashing the Investigate dialog.
                return results;
            }

            IntPtr sourceProcess = NativeMethodsHandles.OpenProcess(
                NativeMethodsHandles.PROCESS_DUP_HANDLE | NativeMethodsHandles.PROCESS_QUERY_LIMITED_INFORMATION,
                false, pid);
            if (sourceProcess == IntPtr.Zero)
            {
                // Access denied (protected process) or PID no longer exists - same
                // "degrade gracefully" behaviour as the rest of the investigation service.
                return results;
            }

            try
            {
                IntPtr currentProcess = NativeMethodsHandles.GetCurrentProcess();

                foreach (var entry in allHandles)
                {
                    if (entry.UniqueProcessId != pid)
                        continue;

                    if (results.Count >= MaxHandlesPerProcess)
                    {
                        truncated = true;
                        break;
                    }

                    if (!NativeMethodsHandles.DuplicateHandle(
                            sourceProcess, (IntPtr)entry.HandleValue,
                            currentProcess, out IntPtr dup,
                            0, false, NativeMethodsHandles.DUPLICATE_SAME_ACCESS))
                    {
                        continue; // handle closed/invalid between the snapshot and now
                    }

                    try
                    {
                        string typeName = QueryTypeName(dup) ?? "Unknown";

                        // Skip name resolution for the type most prone to hanging (pipes/mailslots
                        // surface as "File"); everything else still goes through the timeout guard.
                        string? name = typeName.Equals("File", StringComparison.OrdinalIgnoreCase)
                            ? null
                            : QueryNameWithTimeout(dup);

                        results.Add(new HandleInfo
                        {
                            Handle = entry.HandleValue,
                            TypeName = typeName,
                            Name = string.IsNullOrWhiteSpace(name) ? null : name
                        });
                    }
                    finally
                    {
                        NativeMethodsHandles.CloseHandle(dup);
                    }
                }
            }
            finally
            {
                NativeMethodsHandles.CloseHandle(sourceProcess);
            }

            return results.OrderBy(h => h.Handle).ToList();
        }

        private static List<SYSTEM_HANDLE_TABLE_ENTRY_INFO> QuerySystemHandles()
        {
            int bufferSize = 1 << 20; // start at 1MB; system-wide handle tables can be large
            IntPtr buffer = IntPtr.Zero;
            try
            {
                while (true)
                {
                    buffer = Marshal.AllocHGlobal(bufferSize);
                    int status = NativeMethodsHandles.NtQuerySystemInformation(
                        NativeMethodsHandles.SystemHandleInformation, buffer, bufferSize, out int returnLength);

                    if (status == NativeMethodsHandles.STATUS_INFO_LENGTH_MISMATCH)
                    {
                        Marshal.FreeHGlobal(buffer);
                        buffer = IntPtr.Zero;
                        bufferSize = returnLength > 0 ? returnLength + 0x10000 : bufferSize * 2;
                        if (bufferSize > 256 * 1024 * 1024) // sanity ceiling - 256MB is absurd for this
                            return new List<SYSTEM_HANDLE_TABLE_ENTRY_INFO>();
                        continue;
                    }
                    if (status != 0) // NTSTATUS != STATUS_SUCCESS
                        return new List<SYSTEM_HANDLE_TABLE_ENTRY_INFO>();

                    return ParseHandleTable(buffer);
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            }
        }

        private static List<SYSTEM_HANDLE_TABLE_ENTRY_INFO> ParseHandleTable(IntPtr buffer)
        {
            var list = new List<SYSTEM_HANDLE_TABLE_ENTRY_INFO>();
            long count = Marshal.ReadInt32(buffer); // SYSTEM_HANDLE_INFORMATION.HandleCount (native long, low 32 bits used)
            int entrySize = Marshal.SizeOf<SYSTEM_HANDLE_TABLE_ENTRY_INFO>();
            IntPtr entryPtr = IntPtr.Add(buffer, IntPtr.Size); // header is pointer-aligned

            for (long i = 0; i < count; i++)
            {
                list.Add(Marshal.PtrToStructure<SYSTEM_HANDLE_TABLE_ENTRY_INFO>(entryPtr));
                entryPtr = IntPtr.Add(entryPtr, entrySize);
            }
            return list;
        }

        private static string? QueryTypeName(IntPtr handle)
        {
            const int bufSize = 0x1000;
            IntPtr buffer = Marshal.AllocHGlobal(bufSize);
            try
            {
                int status = NativeMethodsHandles.NtQueryObject(
                    handle, NativeMethodsHandles.ObjectTypeInformation, buffer, bufSize, out _);
                if (status != 0) return null;

                // OBJECT_TYPE_INFORMATION starts with a UNICODE_STRING (Length, MaxLength, Buffer ptr).
                short length = Marshal.ReadInt16(buffer);
                IntPtr strPtr = Marshal.ReadIntPtr(buffer, IntPtr.Size == 8 ? 8 : 4);
                if (strPtr == IntPtr.Zero || length <= 0) return null;
                return Marshal.PtrToStringUni(strPtr, length / 2);
            }
            catch { return null; }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        /// <summary>Runs NtQueryObject(ObjectNameInformation) on a dedicated background thread and
        /// abandons it if it doesn't return within NameQueryTimeout - see class remarks for why.</summary>
        private static string? QueryNameWithTimeout(IntPtr handle)
        {
            string? result = null;
            var done = new ManualResetEventSlim(false);

            var worker = new Thread(() =>
            {
                try { result = QueryNameBlocking(handle); }
                catch { /* best-effort */ }
                finally { done.Set(); }
            })
            { IsBackground = true }; // background so a hung thread can't keep the process alive
            worker.Start();

            return done.Wait(NameQueryTimeout) ? result : null; // timed out - leave the thread to die on its own
        }

        private static string? QueryNameBlocking(IntPtr handle)
        {
            const int bufSize = 0x1000;
            IntPtr buffer = Marshal.AllocHGlobal(bufSize);
            try
            {
                int status = NativeMethodsHandles.NtQueryObject(
                    handle, NativeMethodsHandles.ObjectNameInformation, buffer, bufSize, out _);
                if (status != 0) return null;

                short length = Marshal.ReadInt16(buffer);
                IntPtr strPtr = Marshal.ReadIntPtr(buffer, IntPtr.Size == 8 ? 8 : 4);
                if (strPtr == IntPtr.Zero || length <= 0) return null;
                return Marshal.PtrToStringUni(strPtr, length / 2);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
    }

    /// <summary>
    /// Matches SystemHandleInformation (class 16), the classic/legacy handle-table layout.
    /// HandleValue is 16 bits here - in the extremely rare case a process has more than 65535
    /// live handles at once, values wrap and could collide; the fix would be switching to
    /// SystemExtendedHandleInformation (class 64), which uses a full pointer-sized handle
    /// field, at the cost of a larger/less universally-documented struct. Not worth the extra
    /// complexity for a triage tool - flagged here for anyone hitting that edge case later.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
    {
        public ushort UniqueProcessId;
        public ushort CreatorBackTraceIndex;
        public byte ObjectTypeIndex;
        public byte HandleAttributes;
        public ushort HandleValue;
        public IntPtr Object;
        public uint GrantedAccess;
    }

    /// <summary>P/Invoke declarations specific to handle enumeration, kept separate from
    /// NativeMethods (network) and TokenInspector's declarations so each feature's native
    /// surface is easy to find and audit on its own.</summary>
    internal static class NativeMethodsHandles
    {
        public const int SystemHandleInformation = 16;
        public const int ObjectTypeInformation = 2;
        public const int ObjectNameInformation = 1;
        public const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);

        public const uint PROCESS_DUP_HANDLE = 0x0040;
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        public const uint DUPLICATE_SAME_ACCESS = 0x00000002;

        [DllImport("ntdll.dll")]
        public static extern int NtQuerySystemInformation(
            int systemInformationClass, IntPtr systemInformation, int systemInformationLength, out int returnLength);

        [DllImport("ntdll.dll")]
        public static extern int NtQueryObject(
            IntPtr handle, int objectInformationClass, IntPtr objectInformation, int objectInformationLength, out int returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DuplicateHandle(
            IntPtr hSourceProcessHandle, IntPtr hSourceHandle,
            IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,
            uint dwDesiredAccess, bool bInheritHandle, uint dwOptions);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);
    }
}
