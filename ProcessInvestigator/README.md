# Process Investigator

A lightweight Process Explorer-style tool: live process list + a right-click
"Investigate" action that pulls together everything you'd otherwise chase
down manually (parent chain, loaded DLLs, hosted services + ServiceDll,
live network connections, Authenticode signature).

## Requirements
- Windows 10/11
- .NET 8 SDK: https://dotnet.microsoft.com/download/dotnet/8.0

## Build & Run

**Option A — Visual Studio (easiest, no terminal at all)**
1. Install Visual Studio 2022 Community (free) with the ".NET desktop
   development" workload.
2. Double-click `ProcessInvestigator.csproj` to open it.
3. Press F5 (or the green ▶ Run button). A UAC prompt appears, then the
   app window opens — same experience as launching Process Explorer.

**Option B — build one standalone .exe you can pin/double-click forever**
Run this once, in PowerShell, from the project folder:
```powershell
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```
This produces one file:
```
bin\Release\net8.0-windows\win-x64\publish\ProcessInvestigator.exe
```
Copy that `.exe` anywhere (Desktop, `C:\Tools`, wherever) and double-click
it from then on — no dotnet, no terminal, no PowerShell involved. It behaves
exactly like Process Explorer.exe: a UAC prompt (it needs admin rights),
then the window opens directly.

The PowerShell step above is only a one-time "compile it" step — the same
role Visual Studio's Build button plays. It's not something you run every
time you use the app, same as you wouldn't recompile Process Explorer each
time you open it.

The app requests admin elevation on launch (via `app.manifest`) — this is
required to see SYSTEM-owned processes, read other services' `ServiceDll`
registry values, and enumerate modules in processes you don't own. Windows
will show a UAC prompt.

## Using it
1. The main window lists all running processes, auto-refreshing every 2s
   (CPU %, memory, parent PID, path). Use the filter box to narrow by
   name or PID.
2. Right-click any process → **Investigate...** to open the detail window:
   - **Overview** — path, command line, owner, start time, signature status
   - **Parent Chain** — walks up ParentProcessId to show the full launch chain
   - **Loaded DLLs** — every module loaded in the process
   - **Services** — any Windows service hosted in this process (relevant for
     `svchost.exe`), with its resolved `ServiceDll` path
   - **Network** — live TCP connections owned by this PID
3. Click **Export Report...** to save a text report of everything gathered.
4. Right-click also offers **Open File Location**, **Copy Path**, and
   **End Process**.

## Known limitations (things to extend if you need them)
- TCP (IPv4) connections only — no UDP or IPv6 yet; both use the same
  `GetExtended*Table` pattern in `Services/NativeMethods.cs` if you want to add them.
- No historical logging — this is a live snapshot tool, not a recorder.
  For persistence-over-time (e.g. catching a process that reappears after
  weeks, like the XMRig case), you'd want a background service that polls
  and diffs snapshots, writing changes to a local log/db.
- No file hashing (MD5/SHA256) of the executable or DLLs yet — straightforward
  to add in `ProcessInvestigatorService` using `System.Security.Cryptography`
  if you want VirusTotal-style IOC lookups.
- Protected processes (some SYSTEM/antimalware processes) will still deny
  module enumeration even when elevated — this is a Windows protection, not
  a bug; the tool degrades gracefully and shows what it can.
