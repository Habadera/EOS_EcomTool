#nullable enable
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Threading;
using Epic.OnlineServices;
using Epic.OnlineServices.Platform;

namespace EcomValidator.Services
{
    /// <summary>
    /// Encapsulates EOS SDK lifecycle (Initialize/Create/Tick/Dispose)
    /// and the OAuth client-credentials token call.
    /// </summary>
    public sealed class EosInitialize : IDisposable
    {
        private PlatformInterface? _platform;
        private DispatcherTimer? _pump;
        private readonly Action<string> _log; // simple logger callback into UI

        public bool IsInitialized => _platform != null;

        public EosInitialize(Action<string> log)
        {
            _log = log ?? (_ => { });
        }

        /// <summary>
        /// Initializes EOS SDK and creates a PlatformInterface with the provided IDs/creds.
        /// Safe to call multiple times; repeated calls no-op if already initialized.
        /// </summary>
        public void InitializePlatform(
            string productId,
            string sandboxId,
            string deploymentId,
            string clientId,
            string clientSecret,
            bool isServer = false,
            PlatformFlags flags = PlatformFlags.None,
            string? cacheDirectory = null,
            string? encryptionKey32 = null)
        {
            if (_platform != null) { _log("EOS already initialized; skipping."); return; }

            _log("Initializing EOS Platform...");

            var initializeOptions = new InitializeOptions
            {
                ProductName = "EcomValidator",
                ProductVersion = "1.0"
            };

            var initResult = PlatformInterface.Initialize(ref initializeOptions);
            _log($"Initialize() result: {initResult}");
            if (initResult != Result.Success)
            {
                throw new InvalidOperationException("EOS SDK failed to initialize.");
            }

            var options = new Epic.OnlineServices.Platform.Options
            {
                ProductId = productId,
                SandboxId = sandboxId,
                DeploymentId = deploymentId,
                ClientCredentials = new ClientCredentials
                {
                    ClientId = clientId,
                    ClientSecret = clientSecret
                },
                IsServer = isServer,
                Flags = flags,
                CacheDirectory = cacheDirectory ?? System.IO.Path.Combine(Environment.CurrentDirectory, "Cache"),
                EncryptionKey = encryptionKey32 ?? "12345678901234567890123456789012"
            };

            _platform = PlatformInterface.Create(ref options)
                        ?? throw new InvalidOperationException("PlatformInterface.Create() returned null. Check IDs, credentials, and native DLLs.");

            // Pump EOS tick ~30 FPS
            _pump ??= new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(33) };
            _pump.Tick += (_, __) =>
            {
                try { _platform?.Tick(); } catch { /* ignore */ }
            };
            _pump.Start();

            _log("EOS Platform fully initialized and ticking.");
        }

        /// <summary>
        /// Client-credentials grant for server access token.
        /// </summary>
        public async Task<string> GetServerAccessTokenAsync(string clientId, string clientSecret, string deploymentId)
        {
            if (string.IsNullOrWhiteSpace(clientId) ||
                string.IsNullOrWhiteSpace(clientSecret) ||
                string.IsNullOrWhiteSpace(deploymentId))
            {
                throw new ArgumentException("Client ID, Client Secret, and Deployment ID are required.");
            }

            using var http = new HttpClient();
            var basicAuth = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{clientId}:{clientSecret}"));
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", basicAuth);

            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["deployment_id"] = deploymentId
            };

            var resp = await http.PostAsync("https://api.epicgames.dev/epic/oauth/v1/token", new FormUrlEncodedContent(form));
            var body = await resp.Content.ReadAsStringAsync();

            if (!resp.IsSuccessStatusCode)
            {
                throw new InvalidOperationException($"OAuth token request failed: {resp.StatusCode} {body}");
            }

            using var doc = JsonDocument.Parse(body);
            var token = doc.RootElement.TryGetProperty("access_token", out var el) ? el.GetString() : null;
            if (string.IsNullOrWhiteSpace(token))
                throw new InvalidOperationException("Token response missing access_token.");

            _log("Server access token acquired (client credentials).");
            return token!;
        }

        public void Dispose()
        {
            try { _pump?.Stop(); } catch { }
            _pump = null;

            try
            {
                _platform?.Release();
                _platform = null;
                PlatformInterface.Shutdown();
            }
            catch { /* ignore */ }
        }
    }
}
