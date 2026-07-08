using System.Collections.Concurrent;
using System.Drawing;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace ProcessInvestigator.Services
{
    /// <summary>
    /// Task Manager shows a per-app icon next to each process; this does the same
    /// by pulling the icon embedded in each .exe via Shell32/GDI+. Extraction is
    /// mildly expensive, so results are cached per path for the app's lifetime.
    /// </summary>
    public static class IconCache
    {
        private static readonly ConcurrentDictionary<string, ImageSource?> _cache = new();
        private static readonly ImageSource? _fallback = LoadFallback();

        public static ImageSource? GetIcon(string? path)
        {
            if (string.IsNullOrEmpty(path)) return _fallback;

            return _cache.GetOrAdd(path, p =>
            {
                try
                {
                    using var icon = Icon.ExtractAssociatedIcon(p);
                    if (icon == null) return _fallback;

                    var src = Imaging.CreateBitmapSourceFromHIcon(
                        icon.Handle, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
                    src.Freeze(); // required to use across threads / bind safely
                    return src;
                }
                catch
                {
                    return _fallback;
                }
            });
        }

        private static ImageSource? LoadFallback()
        {
            try
            {
                // Generic "gear" glyph as a stand-in when a path is unavailable
                // or protected (SYSTEM processes we can't open a handle to).
                using var icon = SystemIcons.Application;
                var src = Imaging.CreateBitmapSourceFromHIcon(
                    icon.Handle, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
                src.Freeze();
                return src;
            }
            catch
            {
                return null;
            }
        }
    }
}
