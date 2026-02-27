using System;

namespace EcomValidator.Models
{
    public sealed class OfferItem
    {
        public string? ItemId { get; set; }
        public string? EntitlementId { get; set; }
        public string? EntitlementStatus { get; set; }
        public bool? EntitlementRedeemed { get; set; }
        public DateTime? EntitlementRedeemedAt { get; set; }
    }
}