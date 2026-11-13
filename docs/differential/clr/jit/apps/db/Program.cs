using Npgsql;
using Microsoft.Data.SqlClient;
static class Program
{
    static async Task Main()
    {
        var b = new NpgsqlConnectionStringBuilder("Host=127.0.0.1;Port=1;Username=u;Password=p;Database=d;Timeout=1");
        await using var ds = NpgsqlDataSource.Create(b.ConnectionString);
        try { await using var c = await ds.OpenConnectionAsync(); } catch (Exception e) { Console.WriteLine("pg " + e.GetType().Name); }
        var sb = new SqlConnectionStringBuilder { DataSource = "tcp:127.0.0.1,1", InitialCatalog = "d", UserID = "u", Password = "p", ConnectTimeout = 1, Encrypt = false };
        try { using var s = new SqlConnection(sb.ConnectionString); s.Open(); } catch (Exception e) { Console.WriteLine("sql " + e.GetType().Name); }
        try
        {
            var cred = new Azure.Identity.ClientSecretCredential("00000000-0000-0000-0000-000000000000", "c", "s", new Azure.Identity.ClientSecretCredentialOptions { AuthorityHost = new Uri("http://127.0.0.1:1/"), Retry = { MaxRetries = 0 } });
            await cred.GetTokenAsync(new Azure.Core.TokenRequestContext(new[] { "https://x/.default" }));
        }
        catch (Exception e) { Console.WriteLine("az " + e.GetType().Name); }
    }
}
