using System.Security.Principal;
using System.Windows;
using System.Windows.Threading;

namespace ProcessInvestigator
{
    public partial class App : Application
    {
        public App()
        {
            // Without these, an unhandled exception on startup just kills the
            // process instantly with no dialog and no console output when
            // launched by double-click - which is exactly the symptom that
            // made this so hard to diagnose. Now any crash shows the real
            // exception message instead of vanishing silently.
            DispatcherUnhandledException += (_, args) =>
            {
                MessageBox.Show(
                    $"Unhandled exception:\n\n{args.Exception}",
                    "Process Investigator - Crash",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                args.Handled = true;
            };

            AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            {
                MessageBox.Show(
                    $"Fatal unhandled exception:\n\n{args.ExceptionObject}",
                    "Process Investigator - Fatal Crash",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            };
        }

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Warn (rather than crash) if somehow not elevated - most data
            // sources will silently return partial/empty results instead of
            // throwing, which is confusing without this check.
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
            {
                MessageBox.Show(
                    "Process Investigator is not running as Administrator.\n\n" +
                    "Some data (SYSTEM-owned processes, service DLLs, other users' " +
                    "process modules) will be unavailable until you restart it elevated.",
                    "Limited privileges",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
        }
    }
}
