// The library side of tests/graphapp.dll + graphlib.dll, which crates/clr's graph tests read.
// Every `Mark` class is a method the graph should reach (or, for Unreached, should not).
using System;

namespace Lib
{
    public static class Unreached { public static void Mark() { } }
    public static class ViaOutside { public static void Mark() { } }
    public static class ViaGeneric { public static void Mark() { } }
    public static class ViaExplicit { public static void Mark() { } }
    public static class ViaStruct { public static void Mark() { } }
    public static class ViaAttribute { public static void Mark() { } }
    public static class ViaString { public static void Mark() { } }
    public static class ViaCircle { public static void Mark() { } }

    public interface IShape { double Area(); }
    public class Circle : IShape { public double Area() { ViaCircle.Mark(); return 3; } }
    /// Never made, so its Area is not a target of IShape.Area.
    public class Square : IShape { public double Area() { Unreached.Mark(); return 4; } }
    public class Widget : IShape { public double Area() { ViaGeneric.Mark(); return 5; } }
    public struct Point : IShape { public double Area() { ViaStruct.Mark(); return 0; } }

    public static class Shapes
    {
        public static double Measure<T>(T s) where T : IShape => s.Area();
        public static double Total(IShape s) => s.Area();
        public static T Create<T>() where T : new() => new T();
    }

    /// The runtime calls ToString through object's slot.
    public class Shown { public override string ToString() { ViaOutside.Mark(); return "s"; } }

    public sealed class Resource : IDisposable { void IDisposable.Dispose() => ViaExplicit.Mark(); }

    [AttributeUsage(AttributeTargets.Class)]
    public sealed class UsesAttribute : Attribute { public UsesAttribute(Type t) { } }
    public class Named { public Named() { ViaAttribute.Mark(); } }
    [Uses(typeof(Named))]
    public class Tagged { public static void Run() { } }

    public class ByString { public ByString() { ViaString.Mark(); } }
    public static class Loader
    {
        public static object Load() => Activator.CreateInstance(Type.GetType("Lib.ByString"));
    }
}
