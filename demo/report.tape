# VHS tape that captures a full-report still (demo/mavs-report.png).
#   Regenerate:
#     vhs demo/report.tape && rm -f /tmp/mavs-report-throwaway.gif
#     magick demo/mavs-report.png -crop 1320x1430+0+0 +repage -colors 128 demo/mavs-report.png
# The README links the demo GIF to this image so viewers can read the whole
# report at their own pace. Scans a git-ignored copy of the public Magisk APK.
Output "/tmp/mavs-report-throwaway.gif"

Set Shell "zsh"
Set FontSize 13
Set Width 1320
Set Height 2560
Set Theme "Dracula"
Set Padding 18

Type "clear" Enter
Sleep 300ms
Type "./mavs.sh -F -f magisk.apk -c" Enter
Sleep 3s
Screenshot demo/mavs-report.png
Sleep 500ms
