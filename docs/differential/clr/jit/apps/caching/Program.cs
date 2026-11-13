using System.Runtime.Caching;
static class Program
{
    static void Main()
    {
        var c = new MemoryCache("probe");
        c.Add("a", 1, new CacheItemPolicy { SlidingExpiration = TimeSpan.FromMinutes(1), RemovedCallback = a => Console.WriteLine(a.RemovedReason) });
        c.Set("b", 2, DateTimeOffset.UtcNow.AddMinutes(1));
        Console.WriteLine($"{c.Get("a")} {c.Contains("b")} {c.GetCount()}");
        c.Remove("a"); c.Trim(50); c.Dispose();
        Console.WriteLine(MemoryCache.Default.AddOrGetExisting("x", 3, ObjectCache.InfiniteAbsoluteExpiration));
    }
}
