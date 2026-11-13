using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;

public enum Kind { Small, Large }
public class Money { public decimal Amount { get; set; } public string Currency { get; set; } }
public class Order
{
    public int Id { get; set; }
    [JsonConverter(typeof(StringEnumConverter))] public Kind Kind { get; set; }
    public List<Money> Lines { get; set; } = new();
    public Dictionary<string, Money> ByName { get; set; } = new();
    public DateTimeOffset When { get; set; }
    public Guid Ref { get; set; }
}
static class Program
{
    static void Main()
    {
        var o = new Order { Id = 7, Kind = Kind.Large, When = DateTimeOffset.UnixEpoch, Ref = Guid.Empty };
        o.Lines.Add(new Money { Amount = 1.5m, Currency = "EUR" });
        o.ByName["a"] = new Money { Amount = 2, Currency = "USD" };
        var settings = new JsonSerializerSettings { ContractResolver = new CamelCasePropertyNamesContractResolver(), Formatting = Formatting.Indented };
        var text = JsonConvert.SerializeObject(o, settings);
        var back = JsonConvert.DeserializeObject<Order>(text, settings);
        var j = JObject.Parse(text);
        var amounts = j.SelectTokens("$.lines[*].amount").Select(t => (decimal)t).Sum();
        var typed = JsonConvert.DeserializeObject("{\"$type\":\"Money, json\",\"Amount\":3}", new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.Auto });
        using var sw = new StringWriter();
        using (var w = new JsonTextWriter(sw)) { w.WriteStartArray(); w.WriteValue(1); w.WriteEndArray(); }
        var arr = JArray.Parse(sw.ToString());
        Console.WriteLine($"{back.Lines.Count} {amounts} {arr.Count} {j["kind"]} {typed}");
        var x = System.Xml.Linq.XDocument.Parse("<r><a>1</a></r>");
        Console.WriteLine(JsonConvert.SerializeXNode(x));
    }
}
