using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
public interface IClock { DateTime Now { get; } }
public class Clock : IClock { public DateTime Now => DateTime.UnixEpoch; }
public class Settings { public int Retries { get; set; } }
public class Worker : IDisposable
{
    readonly IClock clock; readonly ILogger<Worker> log; readonly IOptions<Settings> opts;
    public Worker(IClock c, ILogger<Worker> l, IOptions<Settings> o) { clock = c; log = l; opts = o; }
    public void Run() => log.LogInformation("at {Now} retries {R}", clock.Now, opts.Value.Retries);
    public void Dispose() { }
}
class ConsoleishProvider : ILoggerProvider
{
    public ILogger CreateLogger(string c) => new L();
    public void Dispose() { }
    class L : ILogger
    {
        public IDisposable BeginScope<T>(T s) => null;
        public bool IsEnabled(LogLevel l) => true;
        public void Log<T>(LogLevel l, EventId id, T s, Exception e, Func<T, Exception, string> f) => Console.WriteLine(f(s, e));
    }
}
static class Program
{
    static void Main()
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(new ConsoleishProvider()).SetMinimumLevel(LogLevel.Debug));
        services.AddSingleton<IClock, Clock>();
        services.Configure<Settings>(s => s.Retries = 3);
        services.AddScoped<Worker>();
        services.AddTransient(typeof(List<>));
        using var sp = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
        using (var scope = sp.CreateScope()) { scope.ServiceProvider.GetRequiredService<Worker>().Run(); }
        var many = sp.GetServices<IClock>().Count();
        var keyed = new ServiceCollection().AddKeyedSingleton<IClock, Clock>("k").BuildServiceProvider().GetRequiredKeyedService<IClock>("k");
        Console.WriteLine($"{many} {keyed.Now:yyyy} {sp.GetService<List<int>>()?.Count}");
    }
}
