using System.Collections.Generic;
using static EcomValidator.MainWindow;

namespace EcomValidator.Models
{
    public sealed class OrderLineOffer
    {
        public string? OfferId { get; set; }
        public string? Title { get; set; }
        public int? Quantity { get; set; }
        public int? TotalPrice { get; set; }
        public int? UnitPrice { get; set; }
        public int? DiscountedPrice { get; set; }
        public string? Namespace { get; set; }
        public string? NamespaceDisplayName { get; set; }
        public string? SellerId { get; set; }
        public string? SellerName { get; set; }
        public List<OfferItem>? OfferItems { get; set; }
    }
}