// The source of tests/fixture.dll, which crates/clr's tests read.
using System;
using System.Collections.Generic;

namespace Acme.Billing
{
    public interface IPricer { decimal Price(string sku); }

    public class Pricer : IPricer
    {
        static readonly Dictionary<string, decimal> Table = new Dictionary<string, decimal>();

        public decimal Price(string sku) => Table.TryGetValue(sku, out var p) ? p : Fallback(sku);

        private static decimal Fallback(string sku)
        {
            switch (sku.Length) { case 1: return 1m; case 2: return 2m; default: return 0m; }
        }

        public class Cache
        {
            public Func<string, decimal> Make(IPricer pricer) => s => pricer.Price(s) * 2;
        }
    }

    public static class Loader
    {
        public static Type Find() => Type.GetType("Acme.Billing.Pricer") ?? typeof(Pricer);
        public static List<T> One<T>(T item) => new List<T> { item };
    }
}
