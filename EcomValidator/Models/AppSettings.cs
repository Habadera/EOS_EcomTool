using System;
using System.Collections.Generic;

namespace EcomValidator.Models
{
    public sealed class AppSettings
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
}