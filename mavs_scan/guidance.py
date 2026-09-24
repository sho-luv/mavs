"""Manual verification and exploitation guidance carried from mavs.sh.

These strings are the tool's differentiator: instead of only flagging an issue,
each finding can tell a tester how to confirm it and how to demonstrate impact
with copy-paste commands. Text here is preserved from the original Bash tool so
no operator guidance is lost in the port. ``{package}`` and ``{app}`` are filled
in per target.
"""

from __future__ import annotations

CERT_VALIDATION_EXPLOIT = (
    "Install any valid certificate on the device and attempt to capture "
    "application traffic. This can be done with a self-signed certificate generated "
    "by Burp Suite or Bettercap.\n"
    "Install Cert iOS: https://t.ly/WgJ9\n"
    "Install Cert Android: https://t.ly/MpIl\n"
    "Install Cert Windows Mobile: https://t.ly/In0K"
)

LOGGING_EXPLOIT = (
    "Logging can be examined with logcat. This traffic can be captured and examined "
    "while being captured. Examples:\n"
    "adb logcat -v time | grep '{package}'\n"
    'adb logcat -v time | grep -E "credit|passw|ssn|social"\n'
    "adb logcat -v time > '{app}.log'"
)

SNAPSHOT_EXPLOIT = (
    "Note: root access required to access snapshots.\n"
    "Open the application to a screen with sensitive info, then switch to another app "
    "or the homescreen. A snapshot will have been created. Verify the image is not "
    "blank by accessing it:\n"
    "adb shell \"su -c 'cp -r /data/system/recent_images /sdcard/'\"\n"
    "adb pull /sdcard/recent_images\n"
    "adb shell \"su -c 'rm -r /sdcard/recent_images'\"\n"
    "  or\n"
    "adb shell \"su -c 'cp -r /data/system_ce/0/snapshots /sdcard/'\"\n"
    "adb pull /sdcard/snapshots\n"
    "adb shell \"su -c 'rm -r /sdcard/snapshots'\"\n"
    "Newer versions of Android:\n"
    "adb shell \"su -c 'cp -rf /data/system_ce/0/snapshots /data/local/tmp/ && "
    "chmod -R 777 /data/local/tmp/snapshots'\"\n"
    "adb pull /data/local/tmp/snapshots\n"
    "adb shell \"su -c 'rm -r /data/local/tmp/snapshots'\""
)

BACKUP_EXPLOIT = (
    "If backups are allowed it is possible to make a backup without rooting the "
    "device. Any user can make a backup and view files. adb creates the backup, then "
    "printf extracts it:\n"
    "adb backup {package}\n"
    "Then extract backup.ab (printf writes the gzip header, tail strips the 24-byte AB header):\n"
    '( printf "\\x1f\\x8b\\x08\\x00\\x00\\x00\\x00\\x00" ; tail -c +25 backup.ab ) | tar xfvz -'
)

CLEARTEXT_EXPLOIT = (
    "If cleartext is allowed, exercise the app while capturing its traffic and confirm "
    "plaintext HTTP on the wire. Capture on-device with tcpdump (root), pull the pcap, "
    "and inspect it:\n"
    "adb shell \"su -c 'tcpdump -i any -s0 -w /data/local/tmp/{app}.pcap'\"  # Ctrl-C when done\n"
    "adb shell \"su -c 'chmod 666 /data/local/tmp/{app}.pcap'\"\n"
    "adb pull /data/local/tmp/{app}.pcap\n"
    "adb shell \"su -c 'rm /data/local/tmp/{app}.pcap'\"\n"
    "Then confirm cleartext requests, e.g.:\n"
    "tcpdump -r {app}.pcap -A 'tcp port 80' | grep -Ei 'GET |POST |Host:|Authorization:'\n"
    "  or open {app}.pcap in Wireshark and apply the display filter: http\n"
    "No root? Route the device through an intercepting proxy and watch for http:// flows:\n"
    "mitmproxy --mode regular --listen-port 8080   # set device Wi-Fi proxy to <host>:8080\n"
    "  then look for requests with scheme http:// (not https://) to app endpoints."
)

DEBUG_EXPLOIT = (
    "If debugging is enabled, it is possible to log in as the application and access "
    "the application's directory/files. Root is not needed:\n"
    "adb shell run-as {package}\n"
    "  -or-\n"
    "adb shell run-as {package} tar c ./ > debug.tar && tar -xvf debug.tar --one-top-level\n"
    "  -or-\n"
    "adb shell exec-out run-as {package} tar c databases/ > databases.tar"
)

PEM_EXPLOIT = (
    "Hard coding encryption keys allows an attacker to decrypt data. Access the "
    "identified PEM files to recover embedded key material."
)

FLUTTER_EXPLOIT = (
    "Flutter apps ignore the system/user proxy and certificate store, so standard "
    "interception fails. Proxy the traffic instead:\n"
    "https://blog.nviso.eu/2019/08/13/intercepting-traffic-from-android-flutter-applications/\n"
    "Make a system cert from a Burp cert:\n"
    "Burp Suite -> Proxy -> Options -> Import / export CA certificate -> save as 'cacert.der'\n"
    "openssl x509 -inform DER -in cacert.der -out cacert.pem\n"
    "openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1 | "
    "xargs -t -I name mv cacert.pem name.0\n"
    "adb push <cert>.0 /sdcard/ ; adb shell ; su ; mount -o rw,remount /\n"
    "mv /sdcard/<cert>.0 /system/etc/security/cacerts/\n"
    "chmod 644 /system/etc/security/cacerts/<cert>.0\n"
    "chown root:root /system/etc/security/cacerts/<cert>.0"
)

DATA_STORAGE_EXPLOIT = (
    "Enter fake but identifiable information into the application wherever possible "
    "(usernames, emails, phone, bank info). Then pull the app's private data and "
    "search it:\n"
    "adb shell \"su -c 'cp -rf /data/data/{package} /data/local/tmp/ && "
    "chmod -R 777 /data/local/tmp/{package}'\" && adb pull /data/local/tmp/{package} && "
    "adb shell \"su -c 'rm -r /data/local/tmp/{package}'\"\n"
    "Places to find sensitive data:\n"
    "  - Shared Preferences: ./{package}/shared_prefs/\n"
    "  - SQLite Databases: ./{package}/databases/\n"
    "  - Internal Storage / External Storage"
)

INSTALL_HINT = (
    "Install the app on a device and test it:\n"
    "adb install {apk}\n"
    "adb push {apk} /data/local/tmp/ && "
    'adb shell -t su -c "pm install -t -r -g /data/local/tmp/{apk}"'
)


def fill(text: str | None, *, package: str, app: str, apk: str = "") -> str | None:
    """Substitute target-specific placeholders into a guidance string."""
    if text is None:
        return None
    return text.replace("{package}", package).replace("{app}", app).replace("{apk}", apk)
