using Humanizer;
static class Program
{
    static void Main()
    {
        Console.WriteLine("PascalCaseInputString".Humanize());
        Console.WriteLine(DateTime.UtcNow.AddHours(-30).Humanize());
        Console.WriteLine(TimeSpan.FromMinutes(95).Humanize(2));
        Console.WriteLine(1234.ToWords() + " " + 21.ToOrdinalWords() + " " + "man".Pluralize() + " " + 3.ToRoman());
        Console.WriteLine("some title".Transform(To.TitleCase) + " " + 1536L.Bytes().Humanize() + " " + "a_b_c".Pascalize());
        Console.WriteLine(DayOfWeek.Monday.Humanize() + " " + "Monday".DehumanizeTo<DayOfWeek>());
    }
}
