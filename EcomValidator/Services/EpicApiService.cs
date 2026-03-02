using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading.Tasks;
using EcomValidator.Models;

namespace EcomValidator.Services
{
    public static class EpicApiService
    {
        // Best practice: Reusing a single HttpClient instance
        private static readonly HttpClient _http = new HttpClient();

        public static async Task<(List<OrderInfoResponse> Data, string RawJson)> FetchOrderInfoAsync(string baseUrl, List<string> ids, string token)
        {
            using var requestMessage = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl.TrimEnd('/')}/epic/ecom/v3/orders?{string.Join("&", ids.Select(id => $"id={Uri.EscapeDataString(id)}"))}");
            requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var resp = await _http.SendAsync(requestMessage);
            var body = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode) throw new Exception($"{resp.StatusCode} {body}");

            var prettyRawJson = JsonSerializer.Serialize(JsonDocument.Parse(body), new JsonSerializerOptions { WriteIndented = true });
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
            return (list ?? new List<OrderInfoResponse>(), prettyRawJson);
        }

        public static async Task<(List<WebEntitlement> Data, string RawJson)> FetchEntitlementsAsync(string identityId, string bearerToken, string sandboxId)
        {
            using var requestMessage = new HttpRequestMessage(HttpMethod.Get, $"https://api.epicgames.dev/epic/ecom/v4/identities/{identityId}/entitlements?sandboxId={sandboxId}");
            requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);

            var resp = await _http.SendAsync(requestMessage);
            var body = await resp.Content.ReadAsStringAsync();

            if (!resp.IsSuccessStatusCode)
                throw new InvalidOperationException($"Web API failed: {resp.StatusCode} {body}");

            var prettyRawJson = JsonSerializer.Serialize(JsonDocument.Parse(body), new JsonSerializerOptions { WriteIndented = true });
            var list = JsonSerializer.Deserialize<List<WebEntitlement>>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new List<WebEntitlement>();

            return (list, prettyRawJson);
        }

        public static async Task<Dictionary<string, string>> BuildOfferNameMapAsync(string identityId, string bearerToken, string sandboxId)
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            using var requestMessage = new HttpRequestMessage(HttpMethod.Get, $"https://api.epicgames.dev/epic/ecom/v3/identities/{identityId}/namespaces/{sandboxId}/offers");
            requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);

            var resp = await _http.SendAsync(requestMessage);
            var body = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode) return map;

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

                            if (!string.IsNullOrWhiteSpace(catId)) map[catId!] = title;
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

            return map;
        }
    }
}