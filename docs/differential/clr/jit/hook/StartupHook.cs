// Records every method the runtime compiles or binds from ReadyToRun code, written to
// $JIT_OUT at exit as "Assembly<TAB>Type::Method" lines (the assembly file's stem).
using System;
using System.Collections.Concurrent;
using System.Diagnostics.Tracing;
using System.IO;
using System.Linq;
using System.Threading;

internal class StartupHook
{
    static Listener listener;
    public static void Initialize()
    {
        listener = new Listener();
        AppDomain.CurrentDomain.ProcessExit += (_, _) => Flush();
    }
    static void Flush()
    {
        Thread.Sleep(1500);
        var path = Environment.GetEnvironmentVariable("JIT_OUT");
        if (path == null) return;
        File.WriteAllLines(path, listener.Seen.Keys.OrderBy(k => k, StringComparer.Ordinal));
    }
}

internal sealed class Listener : EventListener
{
    public readonly ConcurrentDictionary<string, byte> Seen = new();
    readonly ConcurrentDictionary<ulong, string> modules = new();
    protected override void OnEventSourceCreated(EventSource source)
    {
        if (source.Name == "Microsoft-Windows-DotNETRuntime")
            EnableEvents(source, EventLevel.Verbose, (EventKeywords)(0x10 | 0x8 | 0x2000000000));
    }
    protected override void OnEventWritten(EventWrittenEventArgs e)
    {
        if (e.PayloadNames == null) return;
        int path = e.PayloadNames.IndexOf("ModuleILPath");
        int mid = e.PayloadNames.IndexOf("ModuleID");
        if (path >= 0 && mid >= 0) { modules[Convert.ToUInt64(e.Payload[mid])] = Path.GetFileNameWithoutExtension(e.Payload[path] as string ?? ""); return; }
        int ns = e.PayloadNames.IndexOf("MethodNamespace");
        int name = e.PayloadNames.IndexOf("MethodName");
        if (ns < 0 || name < 0) return;
        var t = e.Payload[ns] as string;
        var m = e.Payload[name] as string;
        if (t == null || m == null) return;
        int b = t.IndexOf('[');
        if (b >= 0) t = t.Substring(0, b);
        string asm = "?";
        if (mid >= 0) modules.TryGetValue(Convert.ToUInt64(e.Payload[mid]), out asm);
        Seen.TryAdd((asm ?? "?") + "\t" + t + "::" + m, 0);
    }
}
