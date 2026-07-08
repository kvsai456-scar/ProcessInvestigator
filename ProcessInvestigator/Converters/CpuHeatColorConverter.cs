using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace ProcessInvestigator.Converters
{
    public class CpuHeatColorConverter : IValueConverter
    {
        private static readonly SolidColorBrush Low = new(Color.FromRgb(0x4C, 0xAF, 0x50));   // green
        private static readonly SolidColorBrush Mid = new(Color.FromRgb(0xFF, 0xB3, 0x00));   // amber
        private static readonly SolidColorBrush High = new(Color.FromRgb(0xE5, 0x39, 0x35));  // red

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            double cpu = value is double d ? d : 0;
            if (cpu >= 50) return High;
            if (cpu >= 15) return Mid;
            return Low;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }

    /// <summary>Maps a 0-100 percentage to a pixel width for the mini CPU bar. Parameter = max width.</summary>
    public class PercentToWidthConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            double percent = value is double d ? Math.Clamp(d, 0, 100) : 0;
            double maxWidth = parameter != null ? System.Convert.ToDouble(parameter, culture) : 70.0;
            return percent / 100.0 * maxWidth;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }
}
