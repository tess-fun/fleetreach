using NuGet.Versioning;
static class Program
{
    static void Main()
    {
        var a = NuGetVersion.Parse("1.2.3-beta.1+meta"); var b = SemanticVersion.Parse("1.2.3");
        var r = VersionRange.Parse("[1.0.0, 2.0.0)"); var f = FloatRange.Parse("1.*");
        Console.WriteLine($"{a < new NuGetVersion(b.Major, b.Minor, b.Patch)} {r.Satisfies(a)} {r.FindBestMatch(new[] { a, NuGetVersion.Parse("1.9") })} {f.Satisfies(a)}");
        Console.WriteLine(VersionComparer.VersionRelease.Compare(a, NuGetVersion.Parse("1.2.3-beta.1")) + " " + r.ToNormalizedString() + " " + a.ToFullString());
    }
}
