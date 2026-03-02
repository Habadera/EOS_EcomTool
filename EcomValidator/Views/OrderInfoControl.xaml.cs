using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using EcomValidator.Models;
using EcomValidator.Services;

namespace EcomValidator.Views
{
    public partial class OrderInfoControl : UserControl
    {
        private readonly ObservableCollection<OrderInfoResponse> _orderHeaderRows = new();
        private string _lastOrderJson = "";
        private const string OrderBaseUrl_Prod = "https://api.epicgames.dev";

        // Callbacks to talk to MainWindow
        public Func<string?>? GetToken { get; set; }
        public Action<string>? LogMsg { get; set; }

        public OrderInfoControl()
        {
            InitializeComponent();
            OrderHeaderGrid.ItemsSource = _orderHeaderRows;
        }

        public void ClearData()
        {
            _orderHeaderRows.Clear();
            OrderIdBox.Text = "";
            _lastOrderJson = "";
        }

        private string GetSelectedOrderBaseUrl()
        {
            var selected = (OrderEnvCombo?.SelectedItem as ComboBoxItem)?.Content?.ToString();
            return selected switch
            {
                "Prod" => OrderBaseUrl_Prod,
                "Custom" => (OrderCustomBaseUrlBox.Text ?? "").Trim().TrimEnd('/'),
                _ => OrderBaseUrl_Prod
            };
        }

        private void OrderEnvCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var isCustom = (OrderEnvCombo.SelectedItem as ComboBoxItem)?.Content?.ToString() == "Custom";
            if (OrderCustomBaseUrlBox != null) OrderCustomBaseUrlBox.Visibility = isCustom ? Visibility.Visible : Visibility.Collapsed;
        }

        private void RowExpander_Click(object sender, RoutedEventArgs e)
        {
            if (sender is ToggleButton toggle && DataGridRow.GetRowContainingElement(toggle) is DataGridRow row)
                row.DetailsVisibility = row.DetailsVisibility == Visibility.Visible ? Visibility.Collapsed : Visibility.Visible;
        }

        private async void OrderFetchBtn_Click(object sender, RoutedEventArgs e)
        {
            _orderHeaderRows.Clear();
            var rawInput = OrderIdBox.Text ?? "";
            var ids = rawInput.Split(new[] { '\r', '\n', ',', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries)
                              .Select(x => x.Trim()).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct().ToList();

            if (ids.Count == 0) { LogMsg?.Invoke("Enter Order ID(s)."); return; }
            if (ids.Count > 100) ids = ids.Take(100).ToList();

            var token = GetToken?.Invoke();
            if (string.IsNullOrWhiteSpace(token)) { LogMsg?.Invoke("Get Token first."); return; }

            try
            {
                LogMsg?.Invoke($"Fetching {ids.Count} order(s)...");
                var result = await EpicApiService.FetchOrderInfoAsync(GetSelectedOrderBaseUrl(), ids, token);

                if (result.Data.Count == 0) LogMsg?.Invoke("No orders returned.");
                foreach (var o in result.Data) _orderHeaderRows.Add(o);

                _lastOrderJson = result.RawJson;

                LogMsg?.Invoke($"Fetched {result.Data.Count} orders.");
            }
            catch (Exception ex) { LogMsg?.Invoke("Fetch Error: " + ex.Message); }
        }

        private void CopyOrderJsonBtn_Click(object sender, RoutedEventArgs e) => Clipboard.SetText(_lastOrderJson);
    }
}