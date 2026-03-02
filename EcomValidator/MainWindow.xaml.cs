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
using EcomValidator.Models; // <-- Added to reference your new Models folder

namespace EcomValidator
{
    public partial class MainWindow : Window
    {
        private const string ToolVersion = "1.2";

        private readonly EosInitialize _eos;

        private readonly ObservableCollection<CredentialProfile> _profiles = new();

        private string? _serverAccessToken;
        private bool _isInitialized = false;

        [DllImport("dwmapi.dll")]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

        public MainWindow()
        {
            InitializeComponent();

            OrderInfoTab.GetToken = () => _serverAccessToken;
            OrderInfoTab.LogMsg = Log;

            UserInfoTab.GetToken = () => _serverAccessToken;
            UserInfoTab.GetSandboxId = () => SandboxIdBox.Text.Trim();
            UserInfoTab.LogMsg = Log;

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

                OrderInfoTab.ClearData();
                UserInfoTab.ClearData();

                Log($"Switched to profile: {profile.Name}");
            }
        }

        private void ResetEosSession()
        {
            _isInitialized = false;
            _serverAccessToken = null;
            InitBtn.IsEnabled = true;
            InitBtn.ClearValue(Button.BackgroundProperty);
            InitBtn.Content = "Init & Connect";
        }

        private void ClearInputs()
        {
            ProductIdBox.Text = ""; SandboxIdBox.Text = ""; DeploymentIdBox.Text = "";
            ClientIdBox.Text = ""; ClientSecretBox.Password = "";
            ResetEosSession();
        }

        private void LoadSettingsEncrypted()
        {
            try
            {
                var s = SettingsManager.LoadSettings();
                if (s == null)
                {
                    CreateNewProfile("Default Profile");
                    return;
                }

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

                SettingsManager.SaveSettings(s);

                if (showLog) Log("Settings saved to disk.");
            }
            catch (Exception ex) { Log("Save error: " + ex.Message); }
        }

        private void ClearCredentialsBtn_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show("Delete secure settings file and all profiles?", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

            SettingsManager.DeleteSettings();

            _profiles.Clear();
            ClearInputs();
            CreateNewProfile("Default Profile");
            Log("All secure credentials cleared.");
        }

        // ================= EOS Logic =================
        private async void InitBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                InitBtn.IsEnabled = false;
                InitBtn.Content = "Connecting...";

                // Step 1: Initialize EOS
                try
                {
                    _eos.InitializePlatform(ProductIdBox.Text, SandboxIdBox.Text, DeploymentIdBox.Text, ClientIdBox.Text, ClientSecretBox.Password,
                        false, 0, Path.Combine(Environment.CurrentDirectory, "Cache"), "12345678901234567890123456789012");

                    _isInitialized = true;
                    Log("EOS Initialized.");
                }
                catch (Exception ex)
                {
                    if (ex.Message.Contains("AlreadyConfigured") || ex.Message.Contains("EOS_AlreadyConfigured"))
                    {
                        _isInitialized = true;
                        Log("Platform already active. Proceeding with new credentials.");
                    }
                    else
                    {
                        throw new Exception($"Init Failed: {ex.Message}");
                    }
                }

                // Save profile if valid so they don't lose their credentials
                if (ProfileCombo.SelectedItem != null) SaveCurrentProfile();

                // Step 2: Get Token
                Log("Requesting Server Token...");
                _serverAccessToken = await _eos.GetServerAccessTokenAsync(ClientIdBox.Text, ClientSecretBox.Password, DeploymentIdBox.Text);

                Log("Token acquired successfully.");
                InitBtn.Background = (Brush)FindResource("Brush.Success");
                InitBtn.Content = "Connected";
                InitBtn.IsEnabled = true;
            }
            catch (Exception ex)
            {
                Log("Connection Failed: " + ex.Message);
                InitBtn.IsEnabled = true;
                InitBtn.Content = "Init & Connect";
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
    }
}