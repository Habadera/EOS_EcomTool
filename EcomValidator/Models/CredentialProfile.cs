using System;
using System.ComponentModel;

namespace EcomValidator.Models
{
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
}