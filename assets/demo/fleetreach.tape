# The README's terminal recording. Re-record with scripts/record-demo.sh (needs VHS and a
# release build); it runs from website/demo, offline, on the demo fleet.
Output ../../assets/demo/fleetreach.gif

Set Shell "bash"
Set FontSize 13
Set Width 1600
Set Height 330
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms
Set WindowBar Colorful

Hide
Type "source ../../assets/demo/setup.sh" Enter
Sleep 2s
Show

# 1. Nine repos in six languages: one ranked queue of bumps (stderr holds the coverage notes).
Type "fleetreach scan -f remediation --enrich 2>/dev/null | head -n 9" Sleep 400ms Enter
Sleep 5s
Type "clear" Enter

# 2. The image that ships the code: app and OS packages in one queue.
Type "fleetreach scan -c ecosystems/images.toml -f remediation --enrich | head -n 11" Sleep 400ms Enter
Sleep 5s
Type "clear" Enter

# 3. Check a fix before anyone applies it.
Type "fleetreach whatif --report report.json --bump axios@1.12.0 | head -n 6" Sleep 400ms Enter
Sleep 4s
Type "clear" Enter

# 4. Where is it, how did it get there, and who owns the repo?
Type "fleetreach scan --why log4j-core" Sleep 400ms Enter
Sleep 4s

Hide
Type `rm -f report.json; rm -rf "$FR_HOME"` Enter
