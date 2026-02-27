using System;

namespace EcomValidator.Models
{
    public sealed class UserEntitlementRow
    {
        public string? OfferName { get; set; }
        public string? Status { get; set; }
        public string? IsRedeemed { get; set; }
        public DateTime? GrantDate { get; set; }
        public string? EntitlementId { get; set; }
        public string? CatalogItemId { get; set; }
    }
}