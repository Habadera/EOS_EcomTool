using System;

namespace EcomValidator.Models
{
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