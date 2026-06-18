# vhs tape — regenerates docs/demo/isolation.gif deterministically.
# Install vhs (https://github.com/charmbracelet/vhs), then:  vhs docs/demo/isolation.tape
# Output is written to docs/demo/isolation.gif.

Output docs/demo/isolation.gif

Set FontSize 18
Set Width 1100
Set Height 760
Set Padding 22
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

Type "bash scripts/demo.sh"
Sleep 400ms
Enter
Sleep 4s
