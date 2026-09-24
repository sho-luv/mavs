"""Android permission risk map used by the permission analyzer.

Each entry maps a permission to a severity and a short reason. The list favors
permissions that carry privacy or attack-surface risk; unlisted permissions are
reported at informational severity.
"""

from __future__ import annotations

from mavs_scan.model import Severity

PERMISSION_RISK: dict[str, tuple[Severity, str]] = {
    "android.permission.READ_SMS": (Severity.HIGH, "Read SMS messages, including OTP codes."),
    "android.permission.SEND_SMS": (Severity.HIGH, "Send SMS, can incur cost or exfiltrate data."),
    "android.permission.RECEIVE_SMS": (Severity.HIGH, "Intercept incoming SMS, including OTPs."),
    "android.permission.READ_CALL_LOG": (Severity.HIGH, "Read the user's call history."),
    "android.permission.WRITE_CALL_LOG": (Severity.HIGH, "Modify the user's call history."),
    "android.permission.PROCESS_OUTGOING_CALLS": (Severity.HIGH, "Observe outgoing calls."),
    "android.permission.READ_CONTACTS": (Severity.MEDIUM, "Read the user's contacts."),
    "android.permission.WRITE_CONTACTS": (Severity.MEDIUM, "Modify the user's contacts."),
    "android.permission.ACCESS_FINE_LOCATION": (Severity.MEDIUM, "Precise GPS location."),
    "android.permission.ACCESS_COARSE_LOCATION": (Severity.MEDIUM, "Approximate location."),
    "android.permission.ACCESS_BACKGROUND_LOCATION": (
        Severity.HIGH,
        "Location while backgrounded.",
    ),
    "android.permission.RECORD_AUDIO": (Severity.HIGH, "Record audio from the microphone."),
    "android.permission.CAMERA": (Severity.MEDIUM, "Capture photos and video."),
    "android.permission.READ_EXTERNAL_STORAGE": (Severity.MEDIUM, "Read shared external storage."),
    "android.permission.WRITE_EXTERNAL_STORAGE": (
        Severity.MEDIUM,
        "Write shared external storage; world-accessible data risk.",
    ),
    "android.permission.MANAGE_EXTERNAL_STORAGE": (
        Severity.HIGH,
        "Broad all-files access to shared storage.",
    ),
    "android.permission.READ_PHONE_STATE": (Severity.MEDIUM, "Read device and phone identifiers."),
    "android.permission.READ_PHONE_NUMBERS": (Severity.MEDIUM, "Read the device phone numbers."),
    "android.permission.GET_ACCOUNTS": (Severity.MEDIUM, "Enumerate on-device accounts."),
    "android.permission.SYSTEM_ALERT_WINDOW": (
        Severity.HIGH,
        "Draw over other apps; enables overlay/tapjacking attacks.",
    ),
    "android.permission.REQUEST_INSTALL_PACKAGES": (
        Severity.HIGH,
        "Prompt to install APKs; dropper capability.",
    ),
    "android.permission.INSTALL_PACKAGES": (Severity.CRITICAL, "Silently install packages."),
    "android.permission.DELETE_PACKAGES": (Severity.HIGH, "Uninstall packages."),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": (
        Severity.HIGH,
        "Accessibility service; can observe and act on all UI.",
    ),
    "android.permission.BIND_DEVICE_ADMIN": (Severity.HIGH, "Device administration control."),
    "android.permission.WRITE_SETTINGS": (Severity.MEDIUM, "Modify system settings."),
    "android.permission.QUERY_ALL_PACKAGES": (Severity.MEDIUM, "Enumerate all installed packages."),
    "android.permission.DUMP": (Severity.HIGH, "Dump internal system state."),
    "android.permission.READ_LOGS": (Severity.HIGH, "Read system logs of other apps."),
    "android.permission.RECEIVE_BOOT_COMPLETED": (Severity.LOW, "Auto-start on boot."),
    "android.permission.FOREGROUND_SERVICE": (Severity.LOW, "Run a foreground service."),
    "android.permission.USE_FINGERPRINT": (Severity.LOW, "Legacy fingerprint auth API."),
    "android.permission.BODY_SENSORS": (Severity.MEDIUM, "Read body sensor data."),
    "android.permission.ACCESS_MEDIA_LOCATION": (Severity.MEDIUM, "Location tags inside media."),
}
