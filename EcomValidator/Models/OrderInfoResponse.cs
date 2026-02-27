using System;
using System.Collections.Generic;
using static EcomValidator.MainWindow;

namespace EcomValidator.Models
{
    public sealed class OrderInfoResponse
    {
        public string? OrderId { get; set; }
        public string? InvoiceId { get; set; }
        public string? ParentOrderId { get; set; }
        public string? OrderType { get; set; }
        public string? OrderStatus { get; set; }
        public string? Currency { get; set; }
        public string? Symbol { get; set; }
        public int? TotalPrice { get; set; }
        public int? TotalDiscounted { get; set; }
        public int? TotalTax { get; set; }
        public DateTime? CreationDate { get; set; }
        public DateTime? LastModifiedDate { get; set; }
        public DateTime? CompletedAt { get; set; }
        public List<OrderLineOffer>? LineOffers { get; set; }
    }
}