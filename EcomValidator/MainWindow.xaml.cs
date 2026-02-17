#nullable enable
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
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
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Interop;
using Microsoft.Win32;

using EcomValidator.Services;

namespace EcomValidator
{
    public partial class MainWindow : Window
    {
        private const string ToolVersion = "2.1";

        private readonly EosInitialize _eos;

        private readonly ObservableCollection<OrderInfoResponse> _orderHeaderRows = new();
        private readonly ObservableCollection<UserEntitlementRow> _userRows = new();

        private readonly ObservableCollection<CredentialProfile> _profiles = new();

        private string _lastOrderJson = "";
        private string _lastUserJson = "";
        private string? _serverAccessToken;
        private bool _isInitialized = false;

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

        // ===== Data Models =====
        public class CredentialProfile : INotifyPropertyChanged
        {
            private string _name = "Default Profile";
            public Guid Id { get; set; } = Guid.NewGuid();

            public string Name
            {
                get => _name;
                set { _name = value; OnPropertyChanged(nameof(Name)); }
            }

            public string? ProductId { get; set; }
            public string? SandboxId { get; set; }
            public string? DeploymentId { get; set; }
            public string? ClientId { get; set; }
            public string? ClientSecret { get; set; }

            public event PropertyChangedEventHandler? PropertyChanged;
            protected void OnPropertyChanged(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }

        private sealed class AppSettings
        {
            public string? ProductId { get; set; }
            public string? SandboxId { get; set; }
            public string? DeploymentId { get; set; }
            public string? ClientId { get; set; }
            public string? ClientSecret { get; set; }
            public bool Remember { get; set; }

            public List<CredentialProfile> Profiles { get; set; } = new();
            public Guid? SelectedProfileId { get; set; }
        }

        private static string SettingsPath => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "settings.secure");
        private const string EncryptionKey = "EcomValidator_Portable_Key_2026!";

        private readonly Dictionary<string, string> _offerNameMap = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> _offerNameMapFromApi = new(StringComparer.OrdinalIgnoreCase);

        [DllImport("dwmapi.dll")]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

        public MainWindow()
        {
            InitializeComponent();

            OrderEnvCombo.SelectedIndex = 0;

            UserInfoGrid.ItemsSource = _userRows;
            OrderHeaderGrid.ItemsSource = _orderHeaderRows;

            ProfileCombo.ItemsSource = _profiles;

            _eos = new EosInitialize(msg => Log(msg));

            LogText.TextChanged += (s, e) => LogText.ScrollToEnd();

            LoadSettingsEncrypted();

            this.SourceInitialized += (_, __) => ApplyDarkTitleBar();
            this.Closed += (s, e) =>
            {
                SaveSettingsEncryptedFromUI(false);
            };
        }

        private void ApplyDarkTitleBar()
        {
            var hwnd = new WindowInteropHelper(this).Handle;
            if (hwnd == IntPtr.Zero) return;
            int enable = 1;
            DwmSetWindowAttribute(hwnd, 20, ref enable, sizeof(int));
            int caption = unchecked((int)0x00252526);
            int text = unchecked((int)0x00F1F1F1);
            DwmSetWindowAttribute(hwnd, 35, ref caption, sizeof(int));
            DwmSetWindowAttribute(hwnd, 36, ref text, sizeof(int));
        }

        // ================= Helpers =================
        private void Log(string msg)
        {
            Dispatcher.Invoke(() =>
            {
                LogText.AppendText($"[{DateTime.Now:T}] {msg}\n");
            });
        }
        private void ClearLog_Click(object sender, RoutedEventArgs e) => LogText.Text = "";
        private void Menu_Exit_Click(object sender, RoutedEventArgs e) => Close();
        private void Menu_About_Click(object sender, RoutedEventArgs e) =>
            MessageBox.Show($"Ecom Validator\nVersion {ToolVersion}\n\n© 2026 Epic Games", "About", MessageBoxButton.OK, MessageBoxImage.Information);

        // ================= Profile Logic =================

        private void RefreshProfileList()
        {
            CollectionViewSource.GetDefaultView(_profiles)?.Refresh();
        }

        private void CreateNewProfile(string? specificName = null)
        {
            var nameToUse = specificName;

            if (string.IsNullOrWhiteSpace(nameToUse))
            {
                nameToUse = $"Profile {_profiles.Count + 1}";
            }

            var newProfile = new CredentialProfile
            {
                Name = nameToUse!,
                ProductId = "",
                SandboxId = "",
                DeploymentId = "",
                ClientId = "",
                ClientSecret = ""
            };

            _profiles.Add(newProfile);
            ProfileCombo.SelectedItem = newProfile;

            RefreshProfileList();
            Log($"Created new profile: {newProfile.Name}");
        }

        private void BtnNewProfile_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new SimpleInputDialog("New Profile", "Enter profile name:", $"Profile {_profiles.Count + 1}");
            dialog.Owner = this;

            if (dialog.ShowDialog() == true && !string.IsNullOrWhiteSpace(dialog.ResultText))
            {
                ResetEosSession();
                CreateNewProfile(dialog.ResultText.Trim());
                SaveSettingsEncryptedFromUI(true);
            }
        }

        private void BtnRenameProfile_Click(object sender, RoutedEventArgs e)
        {
            if (ProfileCombo.SelectedItem is CredentialProfile profile)
            {
                var dialog = new SimpleInputDialog("Rename Profile", "Enter new name:", profile.Name);
                dialog.Owner = this;

                if (dialog.ShowDialog() == true && !string.IsNullOrWhiteSpace(dialog.ResultText))
                {
                    profile.Name = dialog.ResultText.Trim();
                    RefreshProfileList();
                    SaveSettingsEncryptedFromUI(false);
                    Log($"Profile renamed to: {profile.Name}");
                }
            }
        }

        private void SaveCurrentProfile()
        {
            if (ProfileCombo.SelectedItem is CredentialProfile profile)
            {
                profile.ProductId = ProductIdBox.Text.Trim();
                profile.SandboxId = SandboxIdBox.Text.Trim();
                profile.DeploymentId = DeploymentIdBox.Text.Trim();
                profile.ClientId = ClientIdBox.Text.Trim();
                profile.ClientSecret = ClientSecretBox.Password.Trim();

                SaveSettingsEncryptedFromUI(true);
                Log($"Profile '{profile.Name}' updated and saved.");
            }
            else Log("No profile selected to save.");
        }

        private void BtnSaveProfile_Click(object sender, RoutedEventArgs e)
        {
            SaveCurrentProfile();
        }

        private void BtnDeleteProfile_Click(object sender, RoutedEventArgs e)
        {
            if (ProfileCombo.SelectedItem is CredentialProfile profile)
            {
                if (MessageBox.Show($"Delete profile '{profile.Name}'?", "Confirm", MessageBoxButton.YesNo) == MessageBoxResult.Yes)
                {
                    _profiles.Remove(profile);
                    if (_profiles.Count > 0)
                        ProfileCombo.SelectedIndex = 0;
                    else
                        ClearInputs();

                    SaveSettingsEncryptedFromUI(true);
                    Log("Profile deleted.");
                }
            }
        }

        private void ProfileCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ProfileCombo.SelectedItem is CredentialProfile profile)
            {
                ProductIdBox.Text = profile.ProductId ?? "";
                SandboxIdBox.Text = profile.SandboxId ?? "";
                DeploymentIdBox.Text = profile.DeploymentId ?? "";
                ClientIdBox.Text = profile.ClientId ?? "";
                ClientSecretBox.Password = profile.ClientSecret ?? "";

                ResetEosSession();

                // === FIX: Clear Data Grids & Inputs on Profile Switch ===
                _orderHeaderRows.Clear();
                _userRows.Clear();

                OrderIdBox.Text = "";       // Clear Order IDs
                UserIdentityIdBox.Text = ""; // Clear Identity ID

                _lastOrderJson = "";
                _lastUserJson = "";

                Log($"Switched to profile: {profile.Name}");
            }
        }

        private void ResetEosSession()
        {
            _isInitialized = false;
            _serverAccessToken = null;
            InitBtn.IsEnabled = true;
            GetServerTokenBtn.IsEnabled = false;
            InitBtn.ClearValue(Button.BackgroundProperty);
            GetServerTokenBtn.ClearValue(Button.BackgroundProperty);
        }

        private void ClearInputs()
        {
            ProductIdBox.Text = ""; SandboxIdBox.Text = ""; DeploymentIdBox.Text = "";
            ClientIdBox.Text = ""; ClientSecretBox.Password = "";
            ResetEosSession();
        }

        // ================= Settings (AES Encryption) =================
        private static string EncryptString(string plainText)
        {
            if (string.IsNullOrEmpty(plainText)) return "";
            try
            {
                using var aes = Aes.Create();
                var salt = Encoding.UTF8.GetBytes("EcomSalt_2026");
                using var keyDerivation = new Rfc2898DeriveBytes(EncryptionKey, salt, 1000, HashAlgorithmName.SHA256);
                aes.Key = keyDerivation.GetBytes(32);
                aes.IV = keyDerivation.GetBytes(16);

                using var ms = new MemoryStream();
                using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                using (var sw = new StreamWriter(cs))
                {
                    sw.Write(plainText);
                }
                return Convert.ToBase64String(ms.ToArray());
            }
            catch { return ""; }
        }

        private static string DecryptString(string cipherText)
        {
            if (string.IsNullOrEmpty(cipherText)) return "";
            try
            {
                var buffer = Convert.FromBase64String(cipherText);
                using var aes = Aes.Create();
                var salt = Encoding.UTF8.GetBytes("EcomSalt_2026");
                using var keyDerivation = new Rfc2898DeriveBytes(EncryptionKey, salt, 1000, HashAlgorithmName.SHA256);
                aes.Key = keyDerivation.GetBytes(32);
                aes.IV = keyDerivation.GetBytes(16);

                using var ms = new MemoryStream(buffer);
                using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                using (var sr = new StreamReader(cs))
                {
                    return sr.ReadToEnd();
                }
            }
            catch { return ""; }
        }

        private void LoadSettingsEncrypted()
        {
            try
            {
                if (!File.Exists(SettingsPath))
                {
                    CreateNewProfile("Default Profile");
                    return;
                }

                var b64 = File.ReadAllText(SettingsPath);
                var json = DecryptString(b64);
                if (string.IsNullOrWhiteSpace(json)) return;

                var s = JsonSerializer.Deserialize<AppSettings>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (s == null) return;

                if (s.Profiles == null || s.Profiles.Count == 0)
                {
                    var legacyProfile = new CredentialProfile
                    {
                        Name = "Default Profile",
                        ProductId = s.ProductId,
                        SandboxId = s.SandboxId,
                        DeploymentId = s.DeploymentId,
                        ClientId = s.ClientId,
                        ClientSecret = s.ClientSecret
                    };
                    s.Profiles = new List<CredentialProfile> { legacyProfile };
                    s.SelectedProfileId = legacyProfile.Id;
                }

                _profiles.Clear();
                foreach (var p in s.Profiles) _profiles.Add(p);

                if (s.SelectedProfileId.HasValue)
                {
                    var active = _profiles.FirstOrDefault(p => p.Id == s.SelectedProfileId.Value);
                    if (active != null) ProfileCombo.SelectedItem = active;
                    else if (_profiles.Count > 0) ProfileCombo.SelectedIndex = 0;
                }
                else if (_profiles.Count > 0)
                {
                    ProfileCombo.SelectedIndex = 0;
                }

                Log("Profiles loaded.");
            }
            catch (Exception ex)
            {
                Log("Failed to load settings. Starting fresh. Error: " + ex.Message);
                CreateNewProfile("Default Profile");
            }
        }

        private void SaveSettingsEncryptedFromUI(bool showLog)
        {
            try
            {
                var s = new AppSettings
                {
                    Profiles = _profiles.ToList(),
                    SelectedProfileId = (ProfileCombo.SelectedItem as CredentialProfile)?.Id
                };
                var json = JsonSerializer.Serialize(s);
                File.WriteAllText(SettingsPath, EncryptString(json));
                if (showLog) Log("Settings saved to disk.");
            }
            catch (Exception ex) { Log("Save error: " + ex.Message); }
        }

        private void ClearCredentialsBtn_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show("Delete secure settings file and all profiles?", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
            if (File.Exists(SettingsPath)) File.Delete(SettingsPath);
            _profiles.Clear();
            ClearInputs();
            CreateNewProfile("Default Profile");
            Log("All secure credentials cleared.");
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
                InitBtn.Background = (Brush)FindResource("Brush.Success");

                if (ProfileCombo.SelectedItem != null) SaveCurrentProfile();
                Log("EOS Initialized.");
            }
            catch (Exception ex)
            {
                if (ex.Message.Contains("AlreadyConfigured") || ex.Message.Contains("EOS_AlreadyConfigured"))
                {
                    _isInitialized = true;
                    GetServerTokenBtn.IsEnabled = true;
                    InitBtn.Background = (Brush)FindResource("Brush.Success");
                    Log("Platform already active. Ready to get token for new credentials.");

                    if (ProfileCombo.SelectedItem != null) SaveCurrentProfile();
                }
                else
                {
                    Log("Init Failed: " + ex.Message);
                }
            }
        }

        private async void GetServerTokenBtn_Click(object sender, RoutedEventArgs e)
        {
            if (!_isInitialized) { Log("Init first."); return; }
            try
            {
                _serverAccessToken = await _eos.GetServerAccessTokenAsync(ClientIdBox.Text, ClientSecretBox.Password, DeploymentIdBox.Text);
                Log("Token acquired.");
                GetServerTokenBtn.Background = (Brush)FindResource("Brush.Success");
            }
            catch (Exception ex) { Log("Token Failed: " + ex.Message); }
        }

        // ================= Order Fetch =================
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

        // ================= USER INFO TAB LOGIC =================
        private async void UserFetchBtn_Click(object sender, RoutedEventArgs e)
        {
            _userRows.Clear();
            _offerNameMapFromApi.Clear();

            if (string.IsNullOrWhiteSpace(_serverAccessToken)) { Log("Get Access Token first."); return; }
            if (string.IsNullOrWhiteSpace(UserIdentityIdBox.Text)) { Log("Enter Identity ID."); return; }

            try
            {
                var identityId = UserIdentityIdBox.Text.Trim();
                var sandboxId = SandboxIdBox.Text.Trim();

                // 1. Fetch raw entitlements
                var rawEntitlements = await FetchEntitlementsAsync(identityId, _serverAccessToken!, sandboxId);

                // 2. Try to resolve offer names from API (best effort)
                try { await BuildOfferNameMapFromWebApiAsync(identityId, _serverAccessToken!, sandboxId); }
                catch (Exception ex) { Log($"⚠️ Name resolution warning: {ex.Message}"); }

                // 3. Map to unified view model
                var unifiedList = rawEntitlements.Select(d =>
                {
                    var isRedeemed = (d.Consumable == true && (d.UseCount ?? 0) > 0);
                    return new UserEntitlementRow
                    {
                        EntitlementId = d.Id ?? "",
                        CatalogItemId = d.CatalogItemId ?? "",
                        OfferName = ResolveOfferName(d.CatalogItemId),
                        Status = d.Status ?? "",
                        IsRedeemed = isRedeemed ? "Yes" : "No",
                        GrantDate = d.GrantDate
                    };
                });

                foreach (var r in unifiedList.OrderByDescending(x => x.GrantDate)) _userRows.Add(r);

                _lastUserJson = JsonSerializer.Serialize(rawEntitlements, new JsonSerializerOptions { WriteIndented = true });
                Log($"✅ Fetched {rawEntitlements.Count} user entitlements.");
            }
            catch (Exception ex) { Log("💥 Error: " + ex.Message); }
        }

        private void CopyUserJsonBtn_Click(object sender, RoutedEventArgs e) => Clipboard.SetText(_lastUserJson);

        private void LoadOfferMapBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dlg = new OpenFileDialog { Filter = "CSV (*.csv)|*.csv" };
                if (dlg.ShowDialog() == true)
                {
                    var lines = File.ReadAllLines(dlg.FileName);
                    foreach (var line in lines)
                    {
                        var parts = line.Split(',');
                        if (parts.Length >= 2) _offerNameMap[parts[0].Trim()] = parts[1].Trim();
                    }
                    Log("Offer map loaded.");
                }
            }
            catch (Exception ex) { Log("Error loading map: " + ex.Message); }
        }

        // ================= Shared API Helpers =================

        private string ResolveOfferName(string? catalogItemId)
        {
            if (string.IsNullOrWhiteSpace(catalogItemId)) return "";
            if (_offerNameMapFromApi.TryGetValue(catalogItemId, out var n1)) return n1;
            if (_offerNameMap.TryGetValue(catalogItemId, out var n2)) return n2;
            return "";
        }

        private async Task<List<WebEntitlement>> FetchEntitlementsAsync(string identityId, string bearerToken, string sandboxId)
        {
            using var http = new HttpClient();
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
            var url = $"https://api.epicgames.dev/epic/ecom/v4/identities/{identityId}/entitlements?sandboxId={sandboxId}";
            var resp = await http.GetAsync(url);
            var body = await resp.Content.ReadAsStringAsync();

            if (!resp.IsSuccessStatusCode)
                throw new InvalidOperationException($"Web API failed: {resp.StatusCode} {body}");

            return JsonSerializer.Deserialize<List<WebEntitlement>>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new List<WebEntitlement>();
        }

        private async Task BuildOfferNameMapFromWebApiAsync(string identityId, string bearerToken, string sandboxId)
        {
            using var http = new HttpClient();
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);

            var url = $"https://api.epicgames.dev/epic/ecom/v3/identities/{identityId}/namespaces/{sandboxId}/offers";
            var resp = await http.GetAsync(url);
            var body = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode) return;

            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            void MapFromOffersArray(JsonElement arr)
            {
                foreach (var offerEl in arr.EnumerateArray())
                {
                    string title = "";
                    if (offerEl.TryGetProperty("title", out var t1)) title = t1.GetString() ?? "";
                    else if (offerEl.TryGetProperty("name", out var t2)) title = t2.GetString() ?? "";
                    if (string.IsNullOrWhiteSpace(title)) continue;

                    if (offerEl.TryGetProperty("items", out var itemsEl) && itemsEl.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var itemEl in itemsEl.EnumerateArray())
                        {
                            string? catId = null;
                            if (itemEl.ValueKind == JsonValueKind.Object)
                            {
                                if (itemEl.TryGetProperty("id", out var idEl)) catId = idEl.GetString();
                                else if (itemEl.TryGetProperty("catalogItemId", out var cidEl)) catId = cidEl.GetString();
                            }
                            else if (itemEl.ValueKind == JsonValueKind.String) catId = itemEl.GetString();

                            if (!string.IsNullOrWhiteSpace(catId)) _offerNameMapFromApi[catId!] = title;
                        }
                    }
                }
            }

            if (root.ValueKind == JsonValueKind.Array) MapFromOffersArray(root);
            else if (root.ValueKind == JsonValueKind.Object)
            {
                if (root.TryGetProperty("elements", out var el) && el.ValueKind == JsonValueKind.Array) MapFromOffersArray(el);
                else if (root.TryGetProperty("data", out var d) && d.ValueKind == JsonValueKind.Array) MapFromOffersArray(d);
            }
        }

        // ================= Internal Simple Input Dialog =================
        public class SimpleInputDialog : Window
        {
            private TextBox _textBox;
            public string ResultText { get; private set; } = "";

            public SimpleInputDialog(string title, string prompt, string defaultText = "")
            {
                Title = title;
                Width = 400; Height = 180;
                WindowStartupLocation = WindowStartupLocation.CenterOwner;
                ResizeMode = ResizeMode.NoResize;
                Background = new SolidColorBrush(Color.FromRgb(37, 37, 38));
                Foreground = new SolidColorBrush(Color.FromRgb(241, 241, 241));

                var stack = new StackPanel { Margin = new Thickness(15) };
                stack.Children.Add(new TextBlock { Text = prompt, Foreground = Foreground, Margin = new Thickness(0, 0, 0, 10) });

                _textBox = new TextBox { Text = defaultText, Padding = new Thickness(5), Background = new SolidColorBrush(Color.FromRgb(51, 51, 55)), Foreground = Foreground, BorderBrush = new SolidColorBrush(Color.FromRgb(62, 62, 66)) };
                stack.Children.Add(_textBox);

                var btnStack = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 15, 0, 0) };

                var btnOk = new Button { Content = "OK", Width = 80, Margin = new Thickness(0, 0, 10, 0), IsDefault = true, Padding = new Thickness(5), Background = new SolidColorBrush(Color.FromRgb(62, 62, 66)), Foreground = Foreground };
                btnOk.Click += (s, e) => { ResultText = _textBox.Text; DialogResult = true; Close(); };

                var btnCancel = new Button { Content = "Cancel", Width = 80, IsCancel = true, Padding = new Thickness(5), Background = new SolidColorBrush(Color.FromRgb(62, 62, 66)), Foreground = Foreground };

                btnStack.Children.Add(btnOk);
                btnStack.Children.Add(btnCancel);
                stack.Children.Add(btnStack);

                Content = stack;
            }
        }

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

        // New Unified Model
        public sealed class UserEntitlementRow
        {
            public string? OfferName { get; set; }
            public string? Status { get; set; }
            public string? IsRedeemed { get; set; }
            public DateTime? GrantDate { get; set; }
            public string? EntitlementId { get; set; }
            public string? CatalogItemId { get; set; }
        }

        public sealed class WebEntitlement
        {
            public string? Id { get; set; }
            public string? CatalogItemId { get; set; }
            public DateTime? GrantDate { get; set; }
            public bool? Consumable { get; set; }
            public string? Status { get; set; }
            public int? UseCount { get; set; }
        }
    }
}