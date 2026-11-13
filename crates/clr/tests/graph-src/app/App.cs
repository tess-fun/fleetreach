// The service side of the graph fixture: each call exercises one rule of crates/clr's graph.
using Lib;

namespace App
{
    static class Program
    {
        static void Main()
        {
            Shapes.Total(new Circle());
            Shapes.Total(Shapes.Create<Widget>());
            Shapes.Measure(default(Point));
            System.Console.WriteLine(new Shown());
            using (new Resource()) { }
            Tagged.Run();
            Loader.Load();
        }
    }
}
