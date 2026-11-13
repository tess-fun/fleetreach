#!/bin/zsh
# The JIT oracle for crates/clr's call graph: build each app offline from the local NuGet
# cache, run it with a startup hook that records every method the runtime compiles or binds,
# then check that every method that ran in the app's own output folder is in the graph.
#   run.sh [app...]     (default: every folder under apps/)
set -u
cd "${0:a:h}"
root=$(git rev-parse --show-toplevel)
( cd hook && dotnet build -c Release -o out > /dev/null ) || { echo "hook build failed"; exit 1; }
( cd $root && cargo build -q --release -p fleetreach-clr --example clrreach ) || exit 1
hook=$PWD/hook/out/JitHook.dll
apps=($@); (( $#apps )) || apps=(apps/*(/:t))
for app in $apps; do
  dir=apps/$app
  ( cd $dir && dotnet build -c Release -o out --source ~/.nuget/packages -p:NuGetAudit=false > build.log 2>&1 ) \
    || { echo "$app: build failed (see $dir/build.log)"; continue; }
  JIT_OUT=$PWD/$dir/ran.txt DOTNET_STARTUP_HOOKS=$hook DOTNET_ReadyToRun=0 \
    dotnet $dir/out/$app.dll > $dir/run.log 2>&1
  $root/target/release/examples/clrreach $app.dll $dir/out $dir/ran.txt > $dir/cmp.txt 2>/dev/null
  printf "%-11s %s | %s\n" $app "$(head -1 $dir/cmp.txt | cut -d';' -f1)" "$(sed -n 2p $dir/cmp.txt)"
done
