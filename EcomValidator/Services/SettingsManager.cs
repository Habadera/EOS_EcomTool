using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EcomValidator.Models;

namespace EcomValidator.Services
{
    public static class SettingsManager
    {
        private static string SettingsPath => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "settings.secure");
        private const string EncryptionKey = "EcomValidator_Portable_Key_2026!";
        private const string Salt = "EcomSalt_2026";

        public static AppSettings? LoadSettings()
        {
            if (!File.Exists(SettingsPath)) return null;

            try
            {
                var b64 = File.ReadAllText(SettingsPath);
                var json = DecryptString(b64);
                if (string.IsNullOrWhiteSpace(json)) return null;

                return JsonSerializer.Deserialize<AppSettings>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }
            catch
            {
                return null;
            }
        }

        public static void SaveSettings(AppSettings settings)
        {
            var json = JsonSerializer.Serialize(settings);
            File.WriteAllText(SettingsPath, EncryptString(json));
        }

        public static void DeleteSettings()
        {
            if (File.Exists(SettingsPath))
            {
                File.Delete(SettingsPath);
            }
        }

        private static string EncryptString(string plainText)
        {
            if (string.IsNullOrEmpty(plainText)) return "";
            try
            {
                using var aes = Aes.Create();
                var saltBytes = Encoding.UTF8.GetBytes(Salt);
                using var keyDerivation = new Rfc2898DeriveBytes(EncryptionKey, saltBytes, 1000, HashAlgorithmName.SHA256);
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
                var saltBytes = Encoding.UTF8.GetBytes(Salt);
                using var keyDerivation = new Rfc2898DeriveBytes(EncryptionKey, saltBytes, 1000, HashAlgorithmName.SHA256);
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
    }
}