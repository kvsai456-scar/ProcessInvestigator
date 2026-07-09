using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace ProcessInvestigator.Converters
{
    /// <summary>Bolds the tree node representing the process the user actually investigated.</summary>
    public class BoolToWeightConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
            => value is true ? System.Windows.FontWeights.Bold : System.Windows.FontWeights.Normal;

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotImplementedException();
    }

    /// <summary>Grays out tree nodes for processes that have already exited by the time the snapshot was taken.</summary>
    public class RunningToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
            => value is true ? Brushes.Black : Brushes.Gray;

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotImplementedException();
    }
}
