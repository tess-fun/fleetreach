using Serilog;
using Serilog.Events;
using Serilog.Formatting.Json;
static class Program
{
    static void Main()
    {
        var dir = Path.Combine(Path.GetTempPath(), "frlog" + Environment.ProcessId);
        Log.Logger = new LoggerConfiguration().MinimumLevel.Debug().Enrich.FromLogContext()
            .Enrich.WithProperty("App", "probe")
            .WriteTo.Console(outputTemplate: "[{Level:u3}] {Message:lj} {Properties}{NewLine}{Exception}")
            .WriteTo.File(new JsonFormatter(), Path.Combine(dir, "log.json"), rollingInterval: RollingInterval.Day)
            .WriteTo.File(Path.Combine(dir, "log.txt"), fileSizeLimitBytes: 10000, rollOnFileSizeLimit: true)
            .CreateLogger();
        using (Serilog.Context.LogContext.PushProperty("Req", 42))
        {
            Log.Information("Hello {Name} {@Pos} {Count:000}", "world", new { X = 1, Y = 2 }, 5);
            Log.Debug("list {List}", new[] { 1, 2, 3 });
            try { throw new InvalidOperationException("boom"); } catch (Exception e) { Log.Error(e, "failed {What}", "x"); }
        }
        var ctx = Log.ForContext("SourceContext", "Probe");
        ctx.Warning("warn {D:yyyy}", DateTime.UnixEpoch);
        Log.CloseAndFlush();
        Directory.Delete(dir, true);
    }
}
