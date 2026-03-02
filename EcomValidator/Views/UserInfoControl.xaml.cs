using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using EcomValidator.Models;
using EcomValidator.Services;

namespace EcomValidator.Views
{
    public partial class UserInfoControl : UserControl
    {
        private readonly ObservableCollection<UserEntitlementRow> _userRows = new();
        private readonly Dictionary<string, string> _offerNameMap = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> _offerNameMapFromApi = new(StringComparer.OrdinalIgnoreCase);
        private string _lastUserJson = "";

        // Callbacks to talk to MainWindow
        public Func<string?>? GetToken { get; set; }
        public Func<string?>? GetSandboxId { get; set; }
        public Action<string>? LogMsg { get; set; }

        public UserInfoControl()
        {
            InitializeComponent();
            UserInfoGrid.ItemsSource = _userRows;
        }

        public void ClearData()
        {
            _userRows.Clear();
            UserIdentityIdBox.Text = "";
            _lastUserJson = "";
        }

        private async void UserFetchBtn_Click(object sender, RoutedEventArgs e)
        {
            _userRows.Clear();
            _offerNameMapFromApi.Clear();

            var token = GetToken?.Invoke();
            var sandboxId = GetSandboxId?.Invoke() ?? "";

            if (string.IsNullOrWhiteSpace(token)) { LogMsg?.Invoke("Get Access Token first."); return; }
            if (string.IsNullOrWhiteSpace(UserIdentityIdBox.Text)) { LogMsg?.Invoke("Enter Identity ID."); return; }

            try
            {
                var identityId = UserIdentityIdBox.Text.Trim();

                var result = await EpicApiService.FetchEntitlementsAsync(identityId, token, sandboxId);
                var rawEntitlements = result.Data;
                _lastUserJson = result.RawJson;

                try
                {
                    var apiMap = await EpicApiService.BuildOfferNameMapAsync(identityId, token, sandboxId);
                    foreach (var kvp in apiMap) _offerNameMapFromApi[kvp.Key] = kvp.Value;
                }
                catch (Exception ex) { LogMsg?.Invoke($"⚠️ Name resolution warning: {ex.Message}"); }

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

                LogMsg?.Invoke($"✅ Fetched {rawEntitlements.Count} user entitlements.");
            }
            catch (Exception ex) { LogMsg?.Invoke("💥 Error: " + ex.Message); }
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
                    LogMsg?.Invoke("Offer map loaded.");
                }
            }
            catch (Exception ex) { LogMsg?.Invoke("Error loading map: " + ex.Message); }
        }

        private string ResolveOfferName(string? catalogItemId)
        {
            if (string.IsNullOrWhiteSpace(catalogItemId)) return "";
            if (_offerNameMapFromApi.TryGetValue(catalogItemId, out var n1)) return n1;
            if (_offerNameMap.TryGetValue(catalogItemId, out var n2)) return n2;
            return "";
        }
    }
}