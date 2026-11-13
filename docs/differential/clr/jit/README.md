# JIT oracle for the .NET call graph

`run.sh` builds each app in `apps/` offline from the local NuGet package cache, runs it with
`hook/` as a `DOTNET_STARTUP_HOOKS` assembly (an `EventListener` on the runtime's JIT and
loader events, with `DOTNET_ReadyToRun=0` so precompiled code is compiled too), and compares
what ran with `cargo run -p fleetreach-clr --example clrreach`: every method that ran in one of
the app's output assemblies must be in the graph. A `MISS` line is a hole in the graph.

A line whose assembly is `?` ran in a module the runtime loaded before the hook was listening
(`System.Private.CoreLib`). Matched by name only, these are false alarms where a package
embeds its own copy of a CoreLib-internal helper (`System.IO.PathInternal`,
`System.Text.ValueStringBuilder`, inside `Microsoft.Data.SqlClient` and
`System.Configuration.ConfigurationManager`).

`run.sh` passes the local runtime's shared frameworks (`dotnet --list-runtimes`) as
`--framework` folders: their interfaces narrow which new-slot methods count as the runtime's
way in, as the image scan does with the frameworks an image ships.

Result (2026-11-13, .NET SDK 10.0.301): 11 apps, 6,758 methods ran in their output
assemblies, 0 missed apart from the 10 `?` lines above. With the frameworks' interfaces the
graphs shrink (the ImageSharp app 8,510 to 8,439 reached methods, Newtonsoft 3,344 to 3,245)
and still miss nothing. Each rule in `crates/clr/src/graph.rs`
came from a miss here: private `Main`, explicit interface implementations of outside
interfaces, slots inherited from a base class, overrides of an in-graph override of an outside
slot (`JValue.ToString`), value types made by `initobj` (ImageSharp's resamplers), platform
builds under `runtimes/<rid>/lib/` (SqlClient), and Serilog's configuration reader calling sink
and enricher extension methods by name.
