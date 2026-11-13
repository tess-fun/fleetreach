using Serilog;
static class Program
{
    static void Main()
    {
        var dir = Path.Combine(Path.GetTempPath(), "frcfg" + Environment.ProcessId);
        var json = "{\"Serilog\":{\"Using\":[\"Serilog.Sinks.File\",\"Serilog.Sinks.Console\"],\"MinimumLevel\":{\"Default\":\"Debug\",\"Override\":{\"Microsoft\":\"Warning\"}},"
          + "\"WriteTo\":[{\"Name\":\"Console\",\"Args\":{\"formatter\":\"Serilog.Formatting.Compact.CompactJsonFormatter, Serilog.Formatting.Compact\"}},{\"Name\":\"File\",\"Args\":{\"path\":\"" + dir.Replace("\\", "/") + "/x.log\",\"rollingInterval\":\"Day\"}}],"
          + "\"Enrich\":[\"FromLogContext\",{\"Name\":\"WithProperty\",\"Args\":{\"name\":\"App\",\"value\":\"cfg\"}}],\"Filter\":[]}}";
        var config = new ConfigurationBuilder().AddJsonStream(new MemoryStream(System.Text.Encoding.UTF8.GetBytes(json))).Build();
        using var log = new LoggerConfiguration().ReadFrom.Configuration(config).CreateLogger();
        log.Information("hello {Who}", "cfg");
        log.Dispose();
        Directory.Delete(dir, true);
    }
}
