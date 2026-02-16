#nullable enable
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives; // Required for ToggleButton
using System.Windows.Media; // Required for Brush
using System.Windows.Interop;
using Microsoft.Win32;

using EcomValidator.Services;

namespace EcomValidator
{
    public partial class MainWindow : Window
    {
        // ===== VERSION CONTROL =====
        private const string ToolVersion = "1.1";

        private readonly EosInitialize _eos;

        private readonly ObservableCollection<object> _webRows = new();
        private readonly ObservableCollection<object> _summaryRows = new();

        private readonly ObservableCollection<OrderInfoResponse> _orderHeaderRows = new();

        private string _lastOrderJson = "";
        private string _lastWebJson = "";
        private string? _serverAccessToken;
        private bool _isInitialized = false;

        // ===== Order Info environment =====
        private const string OrderBaseUrl_Prod = "https://api.epicgames.dev";

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

        // ===== App settings =====
        private sealed class AppSettings
        {
            public string? ProductId { get; set; }
            public string? SandboxId { get; set; }
            public string? DeploymentId { get; set; }
            public string? ClientId { get; set; }
            public string? ClientSecret { get; set; }
            public bool Remember { get; set; }
        }

        private static string SettingsDir =>
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "EcomValidator");
        private static string SettingsPath => Path.Combine(SettingsDir, "settings.secure");
        private static readonly byte[] _entropy = Encoding.UTF8.GetBytes("EcomValidator-v1-entropy");

        // Offer resolvers
        private readonly Dictionary<string, string> _offerNameMap = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> _offerNameMapFromApi = new(StringComparer.OrdinalIgnoreCase);

        // ===== DWM title-bar =====
        private const int DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1 = 19;
        private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
        private const int DWMWA_CAPTION_COLOR = 35;
        private const int DWMWA_TEXT_COLOR = 36;

        [DllImport("dwmapi.dll")]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

        public MainWindow()
        {
            InitializeComponent();

            OrderEnvCombo.SelectedIndex = 0; // Default to PROD

            WebEntitlementsGrid.ItemsSource = _webRows;
            SummaryGrid.ItemsSource = _summaryRows;
            OrderHeaderGrid.ItemsSource = _orderHeaderRows;

            // Load Env
            ProductIdBox.Text = Environment.GetEnvironmentVariable("EOS_PRODUCT_ID") ?? "";
            SandboxIdBox.Text = Environment.GetEnvironmentVariable("EOS_SANDBOX_ID") ?? "";
            DeploymentIdBox.Text = Environment.GetEnvironmentVariable("EOS_DEPLOYMENT_ID") ?? "";
            ClientIdBox.Text = Environment.GetEnvironmentVariable("EOS_CLIENT_ID") ?? "";

            RememberCredsChk.IsChecked = false;
            LoadSettingsEncrypted();

            _eos = new EosInitialize(msg => Log(msg));

            this.SourceInitialized += (_, __) => ApplyDarkTitleBar();
            this.Closed += (s, e) =>
            {
                try { _eos.Dispose(); } catch { }
                if (RememberCredsChk.IsChecked == true) SaveSettingsEncryptedFromUI();
            };
        }

        private void ApplyDarkTitleBar()
        {
            var hwnd = new WindowInteropHelper(this).Handle;
            if (hwnd == IntPtr.Zero) return;
            int enable = 1;
            DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref enable, sizeof(int));
            DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1, ref enable, sizeof(int));
            int caption = unchecked((int)0x00252526);
            int text = unchecked((int)0x00F1F1F1);
            DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, ref caption, sizeof(int));
            DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, ref text, sizeof(int));
        }

        // ================= Helpers =================
        private void Log(string msg)
        {
            Dispatcher.Invoke(() =>
            {
                LogText.AppendText($"[{DateTime.Now:T}] {msg}\n");
                LogText.ScrollToEnd();
            });
        }
        private void ClearLog_Click(object sender, RoutedEventArgs e) => LogText.Text = "";

        private void Menu_Exit_Click(object sender, RoutedEventArgs e) => Close();

        // UPDATED: Now uses the ToolVersion variable
        private void Menu_About_Click(object sender, RoutedEventArgs e) =>
            MessageBox.Show($"Ecom Validator\nVersion {ToolVersion}\n\n© 2026 Epic Games", "About", MessageBoxButton.OK, MessageBoxImage.Information);

        // ================= Settings (Encrypted) =================
        private static string EncryptToBase64(string plainText)
        {
            var data = Encoding.UTF8.GetBytes(plainText);
            var protectedBytes = ProtectedData.Protect(data, _entropy, DataProtectionScope.CurrentUser);
            return Convert.ToBase64String(protectedBytes);
        }
        private static string DecryptFromBase64(string base64)
        {
            try
            {
                var protectedBytes = Convert.FromBase64String(base64);
                var data = ProtectedData.Unprotect(protectedBytes, _entropy, DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(data);
            }
            catch { return ""; }
        }

        private void LoadSettingsEncrypted()
        {
            try
            {
                if (!File.Exists(SettingsPath)) return;
                var b64 = File.ReadAllText(SettingsPath);
                var json = DecryptFromBase64(b64);
                if (string.IsNullOrWhiteSpace(json)) return;
                var s = JsonSerializer.Deserialize<AppSettings>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (s?.Remember == true)
                {
                    ProductIdBox.Text = s.ProductId; SandboxIdBox.Text = s.SandboxId;
                    DeploymentIdBox.Text = s.DeploymentId; ClientIdBox.Text = s.ClientId;
                    ClientSecretBox.Password = s.ClientSecret; RememberCredsChk.IsChecked = true;
                    Log("Credentials loaded.");
                }
            }
            catch { Log("Failed to load settings."); }
        }

        private void SaveSettingsEncryptedFromUI()
        {
            try
            {
                if (RememberCredsChk.IsChecked != true)
                {
                    if (File.Exists(SettingsPath)) File.Delete(SettingsPath);
                    return;
                }
                Directory.CreateDirectory(SettingsDir);
                var s = new AppSettings
                {
                    ProductId = ProductIdBox.Text,
                    SandboxId = SandboxIdBox.Text,
                    DeploymentId = DeploymentIdBox.Text,
                    ClientId = ClientIdBox.Text,
                    ClientSecret = ClientSecretBox.Password,
                    Remember = true
                };
                var json = JsonSerializer.Serialize(s);
                File.WriteAllText(SettingsPath, EncryptToBase64(json));
                Log("Credentials saved.");
            }
            catch (Exception ex) { Log("Save error: " + ex.Message); }
        }

        private void SaveCredsBtn_Click(object sender, RoutedEventArgs e) => SaveSettingsEncryptedFromUI();
        private void ClearCredentialsBtn_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show("Clear all credentials?", "Confirm", MessageBoxButton.YesNo) != MessageBoxResult.Yes) return;
            if (File.Exists(SettingsPath)) File.Delete(SettingsPath);
            ProductIdBox.Text = ""; SandboxIdBox.Text = ""; DeploymentIdBox.Text = ""; ClientIdBox.Text = ""; ClientSecretBox.Password = "";
            RememberCredsChk.IsChecked = false; _isInitialized = false; _serverAccessToken = null;
            GetServerTokenBtn.IsEnabled = false; _webRows.Clear(); _summaryRows.Clear(); _orderHeaderRows.Clear();
            Log("Credentials cleared.");
        }

        // ================= EOS Logic =================
        private void InitBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _eos.InitializePlatform(ProductIdBox.Text, SandboxIdBox.Text, DeploymentIdBox.Text, ClientIdBox.Text, ClientSecretBox.Password,
                    false, 0, Path.Combine(Environment.CurrentDirectory, "Cache"), "12345678901234567890123456789012");

                _isInitialized = true;
                GetServerTokenBtn.IsEnabled = true;

                // Turn Button GREEN
                InitBtn.Background = (Brush)FindResource("Brush.Success");

                if (RememberCredsChk.IsChecked == true) SaveSettingsEncryptedFromUI();
                Log("EOS Initialized.");
            }
            catch (Exception ex) { Log("Init Failed: " + ex.Message); }
        }

        private async void GetServerTokenBtn_Click(object sender, RoutedEventArgs e)
        {
            if (!_isInitialized) { Log("Init first."); return; }
            try
            {
                _serverAccessToken = await _eos.GetServerAccessTokenAsync(ClientIdBox.Text, ClientSecretBox.Password, DeploymentIdBox.Text);
                Log("Token acquired.");

                // Turn Button GREEN
                GetServerTokenBtn.Background = (Brush)FindResource("Brush.Success");

                if (RememberCredsChk.IsChecked == true) SaveSettingsEncryptedFromUI();
            }
            catch (Exception ex) { Log("Token Failed: " + ex.Message); }
        }

        // ================= Order Fetch =================
        private void OrderEnvCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var isCustom = (OrderEnvCombo.SelectedItem as ComboBoxItem)?.Content?.ToString() == "Custom";
            if (OrderCustomBaseUrlBox != null) OrderCustomBaseUrlBox.Visibility = isCustom ? Visibility.Visible : Visibility.Collapsed;
        }

        // NEW: Manually toggle Row Details visibility to fix the "Mouse Hold" issue.
        private void RowExpander_Click(object sender, RoutedEventArgs e)
        {
            if (sender is ToggleButton toggle &&
                DataGridRow.GetRowContainingElement(toggle) is DataGridRow row)
            {
                // Toggle visibility
                row.DetailsVisibility = row.DetailsVisibility == Visibility.Visible
                    ? Visibility.Collapsed
                    : Visibility.Visible;
            }
        }

        private async void OrderFetchBtn_Click(object sender, RoutedEventArgs e)
        {
            _orderHeaderRows.Clear();
            var rawInput = OrderIdBox.Text ?? "";
            var ids = rawInput.Split(new[] { '\r', '\n', ',', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries)
                              .Select(x => x.Trim()).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct().ToList();

            if (ids.Count == 0) { Log("Enter Order ID(s)."); return; }
            if (ids.Count > 100) ids = ids.Take(100).ToList();
            if (string.IsNullOrWhiteSpace(_serverAccessToken)) { Log("Get Token first."); return; }

            try
            {
                Log($"Fetching {ids.Count} order(s)...");
                var orders = await FetchOrderInfoAsync(GetSelectedOrderBaseUrl(), ids, _serverAccessToken);
                if (orders.Count == 0) Log("No orders returned.");

                foreach (var o in orders) _orderHeaderRows.Add(o);

                _lastOrderJson = JsonSerializer.Serialize(orders, new JsonSerializerOptions { WriteIndented = true });
                Log($"Fetched {orders.Count} orders.");
            }
            catch (Exception ex) { Log("Fetch Error: " + ex.Message); }
        }

        private void CopyOrderJsonBtn_Click(object sender, RoutedEventArgs e) => Clipboard.SetText(_lastOrderJson);

        private async Task<List<OrderInfoResponse>> FetchOrderInfoAsync(string baseUrl, List<string> ids, string token)
        {
            using var http = new HttpClient();
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var query = string.Join("&", ids.Select(id => $"id={Uri.EscapeDataString(id)}"));
            var url = $"{baseUrl.TrimEnd('/')}/epic/ecom/v3/orders?{query}";
            Log($"GET {url}");

            var resp = await http.GetAsync(url);
            var body = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode) throw new Exception($"{resp.StatusCode} {body}");

            var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            List<OrderInfoResponse>? list = null;

            if (root.ValueKind == JsonValueKind.Array)
                list = JsonSerializer.Deserialize<List<OrderInfoResponse>>(body, opts);
            else if (root.ValueKind == JsonValueKind.Object)
            {
                if (root.TryGetProperty("data", out var d) && d.ValueKind == JsonValueKind.Array)
                    list = JsonSerializer.Deserialize<List<OrderInfoResponse>>(d.GetRawText(), opts);
                else
                {
                    try
                    {
                        var dict = JsonSerializer.Deserialize<Dictionary<string, OrderInfoResponse>>(body, opts);
                        if (dict?.Any() == true) list = dict.Values.Where(x => !string.IsNullOrEmpty(x.OrderId)).ToList();
                    }
                    catch { }

                    if (list == null)
                    {
                        var single = JsonSerializer.Deserialize<OrderInfoResponse>(body, opts);
                        if (single?.OrderId != null) list = new List<OrderInfoResponse> { single };
                    }
                }
            }
            return list ?? new List<OrderInfoResponse>();
        }

        // ================= Placeholders =================
        private void WebGetEntitlementsBtn_Click(object sender, RoutedEventArgs e) { } // Placeholder
        private void CopyWebJsonBtn_Click(object sender, RoutedEventArgs e) { } // Placeholder
        private void SummaryFetchBtn_Click(object sender, RoutedEventArgs e) { } // Placeholder
        private void CopySummaryJsonBtn_Click(object sender, RoutedEventArgs e) { } // Placeholder
        private void LoadOfferMapBtn_Click(object sender, RoutedEventArgs e) { } // Placeholder


        // ================= Models =================
        public sealed class OrderInfoResponse
        {
            public string? OrderId { get; set; }
            public string? InvoiceId { get; set; }
            public string? ParentOrderId { get; set; }
            public string? OrderType { get; set; }
            public string? OrderStatus { get; set; }
            public string? Currency { get; set; }
            public string? Symbol { get; set; }
            public int? TotalPrice { get; set; }
            public int? TotalDiscounted { get; set; }
            public int? TotalTax { get; set; }
            public DateTime? CreationDate { get; set; }
            public DateTime? LastModifiedDate { get; set; }
            public DateTime? CompletedAt { get; set; }
            public List<OrderLineOffer>? LineOffers { get; set; }
        }

        public sealed class OrderLineOffer
        {
            public string? OfferId { get; set; }
            public string? Title { get; set; }
            public int? Quantity { get; set; }
            public int? TotalPrice { get; set; }
            public int? UnitPrice { get; set; }
            public int? DiscountedPrice { get; set; }
            public string? Namespace { get; set; }
            public string? NamespaceDisplayName { get; set; }
            public string? SellerId { get; set; }
            public string? SellerName { get; set; }
        }
    }
}