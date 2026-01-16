# VHS Tape: log-analyzer-mcp demo
# https://github.com/charmbracelet/vhs
#
# Generate the demo GIF by running:
#   cd demo && vhs demo.tape

Output demo.gif

# Terminal settings
Set Shell "bash"
Set FontSize 13
Set Width 800
Set Height 500
Set Theme "Catppuccin Mocha"
Set Framerate 30
Set PlaybackSpeed 1.0
Set TypingSpeed 50ms
Set Padding 20
Set LoopOffset 0%

# Window decoration
Set WindowBar Colorful
Set WindowBarSize 40

# Start recording
Sleep 500ms

# Run the demo command
Type "uv run codesdevs-log-analyzer demo"
Enter

# Wait for demo to complete (demo takes ~18 seconds with sleep timers)
Sleep 22s

# Pause at end for readability
Sleep 2s
