using Serilog;
public record Item(int Id, string Name);
public class ItemService { public Item Get(int id) => new(id, "n" + id); }
public class Program
{
    public static async Task Main(string[] args)
    {
        Log.Logger = new LoggerConfiguration().WriteTo.Console().CreateBootstrapLogger();
        var b = WebApplication.CreateBuilder(args);
        b.Host.UseSerilog((ctx, lc) => lc.ReadFrom.Configuration(ctx.Configuration).WriteTo.Console().Enrich.FromLogContext());
        b.Services.AddSingleton<ItemService>();
        b.WebHost.UseUrls("http://127.0.0.1:0");
        var app = b.Build();
        app.UseSerilogRequestLogging();
        app.MapGet("/items/{id:int}", (int id, ItemService s) => Results.Ok(s.Get(id)));
        app.MapPost("/items", (Item i) => Results.Created($"/items/{i.Id}", i));
        await app.StartAsync();
        var url = app.Urls.First();
        using var http = new HttpClient();
        Console.WriteLine(await http.GetStringAsync(url + "/items/3"));
        var resp = await http.PostAsync(url + "/items", new StringContent("{\"id\":1,\"name\":\"x\"}", System.Text.Encoding.UTF8, "application/json"));
        Console.WriteLine(resp.StatusCode);
        Console.WriteLine((await http.GetAsync(url + "/missing")).StatusCode);
        await app.StopAsync();
        Log.CloseAndFlush();
    }
}
