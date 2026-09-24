# VHS tape for the MAVS demo GIF.
#   Regenerate:  vhs demo/mavs.tape   (outputs demo/mavs.gif)
# Scans a copy of the public Magisk APK (git-ignored, not committed).
Output demo/mavs.gif

Set Shell "zsh"
Set FontSize 13
Set Width 1180
Set Height 880
Set Theme "Dracula"
Set Padding 18
Set TypingSpeed 45ms
Set PlaybackSpeed 1.0

Hide
Type "clear" Enter
Show

Sleep 700ms
Type "./mavs.sh -F -f magisk.apk -v -e | head -n 47"
Sleep 800ms
Enter
Sleep 4s
