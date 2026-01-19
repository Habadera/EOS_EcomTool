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
using System.Windows.Interop;
using Microsoft.Win32;

using EcomValidator.Services; // EosInitialize

namespace EcomValidator
{
    public partial class MainWindow : Window
    {
        private readonly EosInitialize _eos;

        private readonly ObservableCollection<object> _webRows = new();
        private readonly ObservableCollection<object> _summaryRows = new();

        private readonly ObservableCollection<object> _orderHeaderRows = new();
        private readonly ObservableCollection<object> _orderLineOfferRows = new();

        private string _lastOrderJson = "";

        private string _lastWebJson = "";
        private string? _serverAccessToken;
        private bool _isInitialized = false;

        // ===== Order Info environment =====
        private const string OrderBaseUrl_GameDev = "https://ecommerceintegration-public-service-gamedev.ol.epicgames.net";
        private const string OrderBaseUrl_Prod = "https://ecommerceintegration-public-service-ecomprod02.ol.epicgames.com";

        private string GetSelectedOrderBaseUrl()
        {
            var selected = (OrderEnvCombo?.SelectedItem as ComboBoxItem)?.Content?.ToString();

            return selected switch
            {
                "Prod" => OrderBaseUrl_Prod,
                "Custom" => (OrderCustomBaseUrlBox.Text ?? "").Trim().TrimEnd('/'),
                _ => OrderBaseUrl_GameDev
            };
        }

        // ===== App settings (encrypted at rest) =====
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

        // Offer name resolvers
        private readonly Dictionary<string, string> _offerNameMap = new(StringComparer.OrdinalIgnoreCase);        // CSV/manual
        private readonly Dictionary<string, string> _offerNameMapFromApi = new(StringComparer.OrdinalIgnoreCase); // Web API

        // ===== DWM title-bar (dark) =====
        private const int DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1 = 19;
        private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
        private const int DWMWA_CAPTION_COLOR = 35;
        private const int DWMWA_TEXT_COLOR = 36;

        [DllImport("dwmapi.dll")]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

        public MainWindow()
        {
            InitializeComponent();

            // Order Info defaults
            OrderEnvCombo.SelectedIndex = 0; // GameDEV

            // Explicit initial disabled state (also set in XAML)
            GetServerTokenBtn.IsEnabled = false;
            CopyBearerTokenBtn.IsEnabled = false;

            // Bind grids
            WebEntitlementsGrid.ItemsSource = _webRows;
            SummaryGrid.ItemsSource = _summaryRows;

            // Bind Order Info grids
            OrderHeaderGrid.ItemsSource = _orderHeaderRows;
            OrderLineOffersGrid.ItemsSource = _orderLineOfferRows;

            // Load env defaults if present
            ProductIdBox.Text = Environment.GetEnvironmentVariable("EOS_PRODUCT_ID") ?? "";
            SandboxIdBox.Text = Environment.GetEnvironmentVariable("EOS_SANDBOX_ID") ?? "";
            DeploymentIdBox.Text = Environment.GetEnvironmentVariable("EOS_DEPLOYMENT_ID") ?? "";
            ClientIdBox.Text = Environment.GetEnvironmentVariable("EOS_CLIENT_ID") ?? "";

            // Checkbox unchecked by default; only load if saved file opted-in
            RememberCredsChk.IsChecked = false;
            LoadSettingsEncrypted();

            // ✅ FIX: pass a logger delegate
            _eos = new EosInitialize(msg => Log(msg));

            // Apply dark title bar once HWND exists
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
            _ = DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref enable, sizeof(int));
            _ = DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1, ref enable, sizeof(int));

            int caption = unchecked((int)0x00222222);
            int text = unchecked((int)0x00F3F3F3);
            _ = DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, ref caption, sizeof(int));
            _ = DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, ref text, sizeof(int));
        }

        // === Menu Handlers ===
        private void Menu_Exit_Click(object sender, RoutedEventArgs e)
        {
            Log("Application exiting by user request.");
            Close(); // triggers your existing Closed event (which disposes EOS etc.)
        }

        private void Menu_About_Click(object sender, RoutedEventArgs e)
        {
            string version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "1.0.0";
            string message = $"Ecom Validator\nVersion {version}\n\n" +
                             "Developed for internal Epic Games SDK testing.\n" +
                             "© 2025 YourName or Company\n\n" +
                             "This tool retrieves and validates entitlements using EOS Web APIs.";

            MessageBox.Show(message, "About Ecom Validator", MessageBoxButton.OK, MessageBoxImage.Information);
        }


        // ================= Helpers =================
        private void Log(string msg) => LogText.Text += $"[{DateTime.Now:T}] {msg}\n";
        private void ClearLog_Click(object sender, RoutedEventArgs e) => LogText.Text = "";

        // ================= Settings (encrypted) =================
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
                if (s == null) return;

                if (s.Remember)
                {
                    ProductIdBox.Text = s.ProductId ?? "";
                    SandboxIdBox.Text = s.SandboxId ?? "";
                    DeploymentIdBox.Text = s.DeploymentId ?? "";
                    ClientIdBox.Text = s.ClientId ?? "";
                    ClientSecretBox.Password = s.ClientSecret ?? "";
                    RememberCredsChk.IsChecked = true;
                    Log("Loaded saved credentials (encrypted).");
                }
                else
                {
                    RememberCredsChk.IsChecked = false;
                    Log("Saved credentials present but 'Remember' is off; not loading.");
                }
            }
            catch (Exception ex) { Log("Settings load error: " + ex.Message); }
        }

        private void SaveSettingsEncryptedFromUI()
        {
            try
            {
                if (RememberCredsChk.IsChecked != true)
                {
                    if (File.Exists(SettingsPath)) File.Delete(SettingsPath);
                    Log("Not remembering credentials; secure storage removed.");
                    return;
                }

                Directory.CreateDirectory(SettingsDir);
                var s = new AppSettings
                {
                    ProductId = ProductIdBox.Text?.Trim(),
                    SandboxId = SandboxIdBox.Text?.Trim(),
                    DeploymentId = DeploymentIdBox.Text?.Trim(),
                    ClientId = ClientIdBox.Text?.Trim(),
                    ClientSecret = ClientSecretBox.Password?.Trim(),
                    Remember = true
                };
                var json = JsonSerializer.Serialize(s, new JsonSerializerOptions { WriteIndented = false });
                var b64 = EncryptToBase64(json);
                File.WriteAllText(SettingsPath, b64);
                Log("Credentials saved (encrypted).");
            }
            catch (Exception ex) { Log("Settings save error: " + ex.Message); }
        }

        private void SaveCredsBtn_Click(object sender, RoutedEventArgs e)
        {
            if (RememberCredsChk.IsChecked == true) SaveSettingsEncryptedFromUI();
            else
            {
                if (File.Exists(SettingsPath)) { try { File.Delete(SettingsPath); } catch { } }
                Log("Tick 'Remember credentials' to enable saving.");
            }
        }

        private void ClearCredentialsBtn_Click(object sender, RoutedEventArgs e)
        {
            var confirm = MessageBox.Show(
                "This will clear all credential fields and delete the encrypted settings file on this PC.\n\nProceed?",
                "Clear credentials",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (confirm != MessageBoxResult.Yes) return;

            try
            {
                if (File.Exists(SettingsPath))
                {
                    File.Delete(SettingsPath);
                }

                ProductIdBox.Text = "";
                SandboxIdBox.Text = "";
                DeploymentIdBox.Text = "";
                ClientIdBox.Text = "";
                ClientSecretBox.Password = "";

                RememberCredsChk.IsChecked = false;

                _isInitialized = false;
                _serverAccessToken = null;
                GetServerTokenBtn.IsEnabled = false;
                CopyBearerTokenBtn.IsEnabled = false;

                _webRows.Clear();
                _summaryRows.Clear();

                _orderHeaderRows.Clear();
                _orderLineOfferRows.Clear();
                _lastOrderJson = "";


                TryDeleteSdkCache();

                Log("🧹 Credentials cleared and secure storage wiped.");
            }
            catch (Exception ex)
            {
                Log("Clear credentials error: " + ex.Message);
            }
        }

        private static string SdkCacheDir => Path.Combine(Environment.CurrentDirectory, "Cache");
        private void TryDeleteSdkCache()
        {
            try { if (Directory.Exists(SdkCacheDir)) Directory.Delete(SdkCacheDir, true); }
            catch (Exception ex) { Log("Cache clear error: " + ex.Message); }
        }

        // ===== EOS init / token flow =====

        private void InitBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _eos.InitializePlatform(
                    productId: ProductIdBox.Text,
                    sandboxId: SandboxIdBox.Text,
                    deploymentId: DeploymentIdBox.Text,
                    clientId: ClientIdBox.Text,
                    clientSecret: ClientSecretBox.Password,
                    isServer: false,
                    flags: 0,
                    cacheDirectory: SdkCacheDir,
                    encryptionKey32: "12345678901234567890123456789012"
                );

                _isInitialized = true;
                GetServerTokenBtn.IsEnabled = true;

                if (RememberCredsChk.IsChecked == true) SaveSettingsEncryptedFromUI();
                Log("✅ EOS SDK initialized.");
            }
            catch (Exception ex)
            {
                _isInitialized = false;
                GetServerTokenBtn.IsEnabled = false;
                Log("💥 Exception during EOS init: " + ex.Message);
            }
        }

        private async void GetServerTokenBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!_isInitialized)
                {
                    Log("Initialize EOS first.");
                    return;
                }

                var clientId = ClientIdBox.Text?.Trim();
                var clientSecret = ClientSecretBox.Password?.Trim();
                var deploymentId = DeploymentIdBox.Text?.Trim();

                if (string.IsNullOrWhiteSpace(clientId) ||
                    string.IsNullOrWhiteSpace(clientSecret) ||
                    string.IsNullOrWhiteSpace(deploymentId))
                {
                    Log("Client ID, Client Secret, and Deployment ID are required for server token.");
                    return;
                }

                var token = await _eos.GetServerAccessTokenAsync(clientId!, clientSecret!, deploymentId!);

                _serverAccessToken = token;
                CopyBearerTokenBtn.IsEnabled = true;
                Log("✅ Server access token acquired (client credentials).");

                if (RememberCredsChk.IsChecked == true) SaveSettingsEncryptedFromUI();
            }
            catch (Exception ex) { Log("💥 Token error: " + ex.Message); }
        }

        private void CopyBearerTokenBtn_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrWhiteSpace(_serverAccessToken))
            {
                Clipboard.SetText(_serverAccessToken);
                Log("Bearer token copied to clipboard.");
            }
            else
            {
                Log("No bearer token yet. Use 'Get Access Token' first.");
            }
        }

        // ===== Partner view =====
        private async void WebGetEntitlementsBtn_Click(object sender, RoutedEventArgs e)
        {
            _webRows.Clear();

            var id = WebIdentityIdBox.Text?.Trim();
            var token = _serverAccessToken?.Trim();
            var sandbox = SandboxIdBox.Text?.Trim();

            if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(token)) { Log("Provide identityId and click 'Get Access Token' first."); return; }
            if (string.IsNullOrWhiteSpace(sandbox)) { Log("Sandbox ID is required for the entitlements API."); return; }

            try
            {
                var docs = await FetchEntitlementsAsync(id!, token!, sandbox!);

                foreach (var row in docs)
                {
                    _webRows.Add(new
                    {
                        row.Id,
                        row.EntitlementName,
                        row.Namespace,
                        row.CatalogItemId,
                        row.EntitlementType,
                        row.GrantDate,
                        row.Consumable,
                        row.Status,
                        row.UseCount,
                        row.EntitlementSource
                    });
                }

                _lastWebJson = JsonSerializer.Serialize(docs);
                Log($"✅ Web API entitlements: {docs.Count} entries.");
            }
            catch (Exception ex) { Log("💥 Web API error: " + ex.Message); }
        }

        private void CopyWebJsonBtn_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrWhiteSpace(_lastWebJson)) { Clipboard.SetText(_lastWebJson); Log("Web API JSON copied to clipboard."); }
            else Log("No JSON data to copy yet.");
        }

        // ===== Summary tab =====

        private async void SummaryFetchBtn_Click(object sender, RoutedEventArgs e)
        {
            _summaryRows.Clear();
            _offerNameMapFromApi.Clear();

            var id = SumIdentityIdBox.Text?.Trim();
            var token = _serverAccessToken?.Trim();
            var sandbox = SandboxIdBox.Text?.Trim();
            var from = FromDatePicker.SelectedDate?.Date;
            var to = ToDatePicker.SelectedDate?.Date;
            var inclUnred = ShowUnredeemedChk.IsChecked == true;
            var inclRed = ShowRedeemedChk.IsChecked == true;
            var search = (SearchBox.Text ?? "").Trim();
            var autoResolve = AutoResolveNamesChk.IsChecked == true;

            if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(token)) { Log("Provide identityId and click 'Get Access Token' first."); return; }
            if (string.IsNullOrWhiteSpace(sandbox)) { Log("Sandbox ID is required for the entitlements API."); return; }

            try
            {
                var ents = await FetchEntitlementsAsync(id!, token!, sandbox!);

                if (autoResolve)
                {
                    try
                    {
                        await BuildOfferNameMapFromWebApiAsync(id!, token!, sandbox!);
                        Log($"Offer names resolved via Web API: mapped {_offerNameMapFromApi.Count} catalog items.");
                    }
                    catch (Exception ex)
                    {
                        Log($"⚠️ Offer name resolution (Web API) failed, using CSV mapping only. Details: {ex.Message}");
                    }
                }

                var filtered = ents.Select(d =>
                {
                    var isRedeemed = (d.Consumable == true && (d.UseCount ?? 0) > 0);
                    var offerName = ResolveOfferName(d.CatalogItemId);

                    return new SummaryRow
                    {
                        GrantDate = d.GrantDate,
                        EntitlementId = d.Id ?? "",
                        CatalogItemId = d.CatalogItemId ?? "",
                        OfferName = offerName,
                        Status = d.Status ?? "",
                        Consumable = d.Consumable ?? false,
                        UseCount = d.UseCount ?? 0,
                        IsRedeemed = isRedeemed,
                        RedeemedAt = null
                    };
                });

                if (from.HasValue) filtered = filtered.Where(r => r.GrantDate.HasValue && r.GrantDate.Value.Date >= from.Value);
                if (to.HasValue) filtered = filtered.Where(r => r.GrantDate.HasValue && r.GrantDate.Value.Date <= to.Value);

                if (!(inclRed && inclUnred))
                {
                    if (inclRed) filtered = filtered.Where(r => r.IsRedeemed);
                    else if (inclUnred) filtered = filtered.Where(r => !r.IsRedeemed);
                    else filtered = Enumerable.Empty<SummaryRow>();
                }

                if (!string.IsNullOrWhiteSpace(search))
                {
                    filtered = filtered.Where(r =>
                        (r.CatalogItemId?.IndexOf(search, StringComparison.OrdinalIgnoreCase) ?? -1) >= 0 ||
                        (r.OfferName?.IndexOf(search, StringComparison.OrdinalIgnoreCase) ?? -1) >= 0);
                }

                var list = filtered.OrderByDescending(r => r.GrantDate ?? DateTime.MinValue).ToList();
                foreach (var r in list) _summaryRows.Add(r);

                Log($"✅ Summary rows: {list.Count} (filters applied).");
            }
            catch (Exception ex) { Log("💥 Summary fetch error: " + ex.Message); }
        }

        private void CopySummaryJsonBtn_Click(object sender, RoutedEventArgs e)
        {
            var json = JsonSerializer.Serialize(_summaryRows, new JsonSerializerOptions { WriteIndented = true });
            Clipboard.SetText(json);
            Log("Summary JSON copied to clipboard.");
        }

        // ===== Order Info tab =====

        private async void OrderFetchBtn_Click(object sender, RoutedEventArgs e)
        {
            _orderHeaderRows.Clear();
            _orderLineOfferRows.Clear();

            var identityId = OrderIdentityIdBox.Text?.Trim();
            var orderId = OrderIdBox.Text?.Trim();
            var token = _serverAccessToken?.Trim();

            if (string.IsNullOrWhiteSpace(identityId) || string.IsNullOrWhiteSpace(orderId))
            {
                Log("Provide Identity ID and Order ID.");
                return;
            }

            if (string.IsNullOrWhiteSpace(token))
            {
                Log("Get an access token first (Credentials tab -> Get Access Token).");
                return;
            }

            try
            {
                var baseUrl = GetSelectedOrderBaseUrl();
                if (string.IsNullOrWhiteSpace(baseUrl) || !Uri.TryCreate(baseUrl, UriKind.Absolute, out _))
                {
                    Log("Invalid base URL. Pick GameDEV/Prod or enter a valid Custom Base URL.");
                    return;
                }

                var order = await FetchOrderInfoAsync(baseUrl, identityId!, orderId!, token!);

                _orderHeaderRows.Add(new
                {
                    order.OrderId,
                    order.InvoiceId,
                    order.ParentOrderId,
                    order.OrderType,
                    order.OrderStatus,
                    order.Currency,
                    order.Symbol,
                    order.TotalPrice,
                    order.TotalDiscounted,
                    order.TotalTax,
                    order.CreationDate,
                    order.LastModifiedDate,
                    order.CompletedAt
                });

                if (order.LineOffers != null)
                {
                    foreach (var line in order.LineOffers)
                    {
                        _orderLineOfferRows.Add(new
                        {
                            line.OfferId,
                            line.Title,
                            line.Quantity,
                            line.TotalPrice,
                            line.UnitPrice,
                            line.DiscountedPrice,
                            line.Namespace,
                            line.NamespaceDisplayName,
                            line.SellerId,
                            line.SellerName
                        });
                    }
                }

                _lastOrderJson = JsonSerializer.Serialize(order, new JsonSerializerOptions { WriteIndented = true });
                Log($"✅ Order fetched. Line offers: {order.LineOffers?.Count ?? 0}");
            }
            catch (Exception ex)
            {
                Log("💥 Order fetch error: " + ex.Message);
            }
        }

        private void CopyOrderJsonBtn_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrWhiteSpace(_lastOrderJson))
            {
                Clipboard.SetText(_lastOrderJson);
                Log("Order JSON copied to clipboard.");
            }
            else
            {
                Log("No Order JSON to copy yet.");
            }
        }

        private async Task<OrderInfoResponse> FetchOrderInfoAsync(string baseUrl, string identityId, string orderId, string bearerToken)

        {
            using var http = new HttpClient();
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);

            // GameDEV public service host (as per spec)
            var url = $"{baseUrl.TrimEnd('/')}/ecommerceintegration/api/eos/v3/identities/{identityId}/orders/{orderId}";

            var resp = await http.GetAsync(url);
            var body = await resp.Content.ReadAsStringAsync();

            if (!resp.IsSuccessStatusCode)
                throw new InvalidOperationException($"Order Info API failed: {resp.StatusCode} {body}");

            var order = JsonSerializer.Deserialize<OrderInfoResponse>(body, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            if (order == null)
                throw new InvalidOperationException("Order Info API returned empty response.");

            return order;
        }

        private sealed class OrderInfoResponse
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

        private sealed class OrderLineOffer
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


        // ===== Offer map CSV loader =====
        private void LoadOfferMapBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dlg = new OpenFileDialog
                {
                    Title = "Select Offer Name Mapping CSV (CatalogItemId,OfferName)",
                    Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
                    Multiselect = false
                };
                if (dlg.ShowDialog() == true)
                {
                    var lines = File.ReadAllLines(dlg.FileName);
                    int count = 0;

                    _offerNameMap.Clear();
                    foreach (var line in lines)
                    {
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        var parts = line.Split(',');
                        if (parts.Length < 2) continue;

                        var id = parts[0].Trim();
                        var name = string.Join(",", parts.Skip(1)).Trim(); // keep commas in name
                        if (!string.IsNullOrWhiteSpace(id))
                        {
                            _offerNameMap[id] = name;
                            count++;
                        }
                    }
                    Log($"Loaded offer name mapping: {count} entries.");
                }
            }
            catch (Exception ex) { Log("Offer map load error: " + ex.Message); }
        }

        // ===== Offer name resolver =====
        private string ResolveOfferName(string? catalogItemId)
        {
            if (string.IsNullOrWhiteSpace(catalogItemId)) return "";
            if (_offerNameMapFromApi.TryGetValue(catalogItemId, out var apiName)) return apiName;
            if (_offerNameMap.TryGetValue(catalogItemId, out var csvName)) return csvName;
            return "";
        }

        // ===== HTTP helpers & models =====
        private async Task<List<WebEntitlement>> FetchEntitlementsAsync(string identityId, string bearerToken, string sandboxId)
        {
            using var http = new HttpClient();
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);

            var url = $"https://api.epicgames.dev/epic/ecom/v4/identities/{identityId}/entitlements?sandboxId={sandboxId}";
            var resp = await http.GetAsync(url);
            var body = await resp.Content.ReadAsStringAsync();

            if (!resp.IsSuccessStatusCode)
                throw new InvalidOperationException($"Web API failed: {resp.StatusCode} {body}");

            var docs = JsonSerializer.Deserialize<List<WebEntitlement>>(body, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            }) ?? new List<WebEntitlement>();

            return docs;
        }

        private async Task BuildOfferNameMapFromWebApiAsync(string identityId, string bearerToken, string sandboxId)
        {
            using var http = new HttpClient();
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);

            var url = $"https://api.epicgames.dev/epic/ecom/v3/identities/{identityId}/namespaces/{sandboxId}/offers";
            var resp = await http.GetAsync(url);
            var body = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode)
                throw new InvalidOperationException($"Offers API failed: {resp.StatusCode} {body}");

            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            void MapFromOffersArray(JsonElement arr)
            {
                foreach (var offerEl in arr.EnumerateArray())
                {
                    string title = "";
                    if (offerEl.TryGetProperty("title", out var t1) && t1.ValueKind == JsonValueKind.String) title = t1.GetString() ?? "";
                    else if (offerEl.TryGetProperty("name", out var t2) && t2.ValueKind == JsonValueKind.String) title = t2.GetString() ?? "";
                    if (string.IsNullOrWhiteSpace(title)) continue;

                    if (!offerEl.TryGetProperty("items", out var itemsEl) || itemsEl.ValueKind != JsonValueKind.Array) continue;

                    foreach (var itemEl in itemsEl.EnumerateArray())
                    {
                        string? catId = null;
                        if (itemEl.ValueKind == JsonValueKind.Object)
                        {
                            if (itemEl.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.String)
                                catId = idEl.GetString();
                            else if (itemEl.TryGetProperty("catalogItemId", out var cidEl) && cidEl.ValueKind == JsonValueKind.String)
                                catId = cidEl.GetString();
                        }
                        else if (itemEl.ValueKind == JsonValueKind.String)
                        {
                            catId = itemEl.GetString();
                        }

                        if (!string.IsNullOrWhiteSpace(catId))
                            _offerNameMapFromApi[catId!] = title;
                    }
                }
            }

            if (root.ValueKind == JsonValueKind.Array)
            {
                MapFromOffersArray(root);
                return;
            }

            if (root.ValueKind == JsonValueKind.Object)
            {
                string[] candidates = { "elements", "data", "offers", "items", "records", "results" };
                foreach (var key in candidates)
                {
                    if (root.TryGetProperty(key, out var arrEl) && arrEl.ValueKind == JsonValueKind.Array)
                    {
                        MapFromOffersArray(arrEl);
                        return;
                    }
                }

                if (root.TryGetProperty("title", out _) || root.TryGetProperty("name", out _))
                {
                    MapFromOffersArray(JsonDocument.Parse($"[{body}]").RootElement);
                    return;
                }
            }

            throw new InvalidOperationException("Unrecognized Offers API response shape.");
        }

        private void OrderEnvCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var selected = (OrderEnvCombo.SelectedItem as ComboBoxItem)?.Content?.ToString();
            var isCustom = string.Equals(selected, "Custom", StringComparison.OrdinalIgnoreCase);

            OrderCustomBaseUrlBox.Visibility = isCustom ? Visibility.Visible : Visibility.Collapsed;
            OrderUseDefaultCustomBtn.Visibility = isCustom ? Visibility.Visible : Visibility.Collapsed;

            if (!isCustom)
                OrderCustomBaseUrlBox.Text = "";
        }

        private void OrderUseDefaultCustomBtn_Click(object sender, RoutedEventArgs e)
        {
            OrderCustomBaseUrlBox.Text = OrderBaseUrl_GameDev;
        }


        private sealed class WebEntitlement
        {
            public string? Id { get; set; }
            public string? EntitlementName { get; set; }
            public string? Namespace { get; set; }
            public string? CatalogItemId { get; set; }
            public string? EntitlementType { get; set; }
            public DateTime? GrantDate { get; set; }
            public bool? Consumable { get; set; }
            public string? Status { get; set; }
            public int? UseCount { get; set; }
            public string? EntitlementSource { get; set; }
        }

        private sealed class SummaryRow
        {
            public DateTime? GrantDate { get; set; }
            public string EntitlementId { get; set; } = "";
            public string CatalogItemId { get; set; } = "";
            public string OfferName { get; set; } = "";
            public string Status { get; set; } = "";
            public bool Consumable { get; set; }
            public int UseCount { get; set; }
            public bool IsRedeemed { get; set; }
            public DateTime? RedeemedAt { get; set; }
        }
    }
}
