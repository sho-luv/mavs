"""Pattern rules run over the DEX string pool by the code analyzer.

A rule matches when any of its literal patterns appears in a DEX string, type
descriptor, class name or method name. Matches are code smells or attack
surface, not proof of exploitability; severity reflects typical risk. Patterns
are chosen to appear as literal tokens in DEX rather than needing decompilation.
"""

from __future__ import annotations

from dataclasses import dataclass

from mavs_scan.model import Severity


@dataclass(frozen=True, slots=True)
class CodeRule:
    """A literal-pattern code rule with reporting metadata."""

    rule_id: str
    title: str
    severity: Severity
    patterns: tuple[str, ...]
    description: str
    cwe: str | None = None
    masvs: str | None = None
    reference: str | None = None


RULES: tuple[CodeRule, ...] = (
    CodeRule(
        "MAVS-CODE-HOSTNAME",
        "Hostname verification disabled",
        Severity.HIGH,
        (
            "ALLOW_ALL_HOSTNAME_VERIFIER",
            "AllowAllHostnameVerifier",
            "NullHostnameVerifier",
            "AlwaysAcceptingHostnameVerifier",
        ),
        "Code references a hostname verifier that accepts any hostname, defeating "
        "TLS server identity checks and enabling man-in-the-middle interception.",
        cwe="CWE-295",
        masvs="MASVS-NETWORK-1",
    ),
    CodeRule(
        "MAVS-CODE-PROTSPACE",
        "Authenticates against any protection space",
        Severity.MEDIUM,
        ("canAuthenticateAgainstProtectionSpace",),
        "Code references canAuthenticateAgainstProtectionSpace, historically used to "
        "accept arbitrary server trust and bypass certificate validation.",
        cwe="CWE-295",
        masvs="MASVS-NETWORK-1",
    ),
    CodeRule(
        "MAVS-CODE-TRUSTALL",
        "Custom TrustManager may trust all certificates",
        Severity.HIGH,
        ("javax/net/ssl/X509TrustManager", "TrustAllX509TrustManager", "checkServerTrusted"),
        "A custom X509TrustManager is present. If checkServerTrusted is empty it trusts "
        "every certificate. Confirm the implementation validates the chain.",
        cwe="CWE-295",
        masvs="MASVS-NETWORK-1",
    ),
    CodeRule(
        "MAVS-CODE-WEBVIEW-JS",
        "WebView JavaScript enabled",
        Severity.LOW,
        ("setJavaScriptEnabled",),
        "WebView JavaScript execution is enabled. Combined with untrusted content or "
        "a JavaScript bridge this can lead to code execution in the app context.",
        cwe="CWE-749",
        masvs="MASVS-PLATFORM-2",
    ),
    CodeRule(
        "MAVS-CODE-WEBVIEW-BRIDGE",
        "WebView JavaScript-to-native bridge",
        Severity.MEDIUM,
        ("addJavascriptInterface",),
        "addJavascriptInterface exposes native objects to JavaScript. On untrusted "
        "content this is a common remote-code-execution vector.",
        cwe="CWE-749",
        masvs="MASVS-PLATFORM-2",
    ),
    CodeRule(
        "MAVS-CODE-WEBVIEW-FILE",
        "WebView broad file access",
        Severity.MEDIUM,
        ("setAllowUniversalAccessFromFileURLs", "setAllowFileAccessFromFileURLs"),
        "WebView allows file URLs to read arbitrary local files or cross-origin "
        "content, enabling local file theft from a compromised page.",
        cwe="CWE-200",
        masvs="MASVS-PLATFORM-2",
    ),
    CodeRule(
        "MAVS-CODE-WEBVIEW-DEBUG",
        "WebView contents debugging enabled",
        Severity.LOW,
        ("setWebContentsDebuggingEnabled",),
        "WebView remote debugging is enabled and, in a debuggable build, lets a local "
        "attacker inspect and drive web content.",
        cwe="CWE-489",
        masvs="MASVS-RESILIENCE-4",
    ),
    CodeRule(
        "MAVS-CODE-SSLERROR",
        "WebView SSL errors may be ignored",
        Severity.HIGH,
        ("onReceivedSslError",),
        "WebView overrides onReceivedSslError. If it calls proceed() it ignores TLS "
        "errors and allows interception. Confirm it cancels on error.",
        cwe="CWE-295",
        masvs="MASVS-NETWORK-1",
    ),
    CodeRule(
        "MAVS-CODE-CRYPTO-ECB",
        "Weak block cipher mode (ECB)",
        Severity.MEDIUM,
        ("AES/ECB", "DES/ECB", "/ECB/PKCS5", "/ECB/NoPadding"),
        "ECB mode leaks plaintext structure because identical blocks encrypt "
        "identically. Use an authenticated mode such as AES/GCM.",
        cwe="CWE-327",
        masvs="MASVS-CRYPTO-1",
    ),
    CodeRule(
        "MAVS-CODE-CRYPTO-WEAK",
        "Weak or broken cryptographic primitive",
        Severity.MEDIUM,
        ("DES/", "DESede", "/RC4", "ARC4", "Blowfish", "RC2"),
        "A weak or deprecated cipher is referenced. Prefer AES-GCM for encryption.",
        cwe="CWE-327",
        masvs="MASVS-CRYPTO-1",
    ),
    CodeRule(
        "MAVS-CODE-HASH-WEAK",
        "Weak hash function (MD5/SHA-1)",
        Severity.LOW,
        ("MD5", "SHA-1", "SHA1"),
        "MD5 and SHA-1 are collision-prone and unsuitable for integrity or signature "
        "use. Prefer SHA-256 or stronger.",
        cwe="CWE-327",
        masvs="MASVS-CRYPTO-1",
    ),
    CodeRule(
        "MAVS-CODE-RANDOM",
        "Insecure pseudo-random generator",
        Severity.LOW,
        ("Ljava/util/Random;", "Ljava/lang/Math;->random"),
        "java.util.Random is predictable. Use java.security.SecureRandom for tokens, keys or IVs.",
        cwe="CWE-330",
        masvs="MASVS-CRYPTO-1",
    ),
    CodeRule(
        "MAVS-CODE-WORLD-PERMS",
        "World-readable or world-writable storage mode",
        Severity.HIGH,
        ("MODE_WORLD_READABLE", "MODE_WORLD_WRITEABLE", "MODE_WORLD_WRITABLE"),
        "Files or preferences are created world-accessible, exposing data to every app "
        "on the device.",
        cwe="CWE-276",
        masvs="MASVS-STORAGE-2",
    ),
    CodeRule(
        "MAVS-CODE-EXTSTORAGE",
        "Sensitive data may be written to external storage",
        Severity.LOW,
        ("getExternalStorageDirectory", "getExternalFilesDir", "getExternalCacheDir"),
        "External storage is world-readable on older Android and shared. Confirm no "
        "secrets or PII are written there.",
        cwe="CWE-922",
        masvs="MASVS-STORAGE-1",
    ),
    CodeRule(
        "MAVS-CODE-LOG",
        "Application logging present",
        Severity.LOW,
        ("Landroid/util/Log;", "Lorg/slf4j/Logger;", "Ljava/util/logging/Logger;"),
        "Logging APIs are referenced. Logs can leak sensitive data and are readable "
        "with logcat on debuggable or older devices.",
        cwe="CWE-532",
        masvs="MASVS-STORAGE-3",
    ),
    CodeRule(
        "MAVS-CODE-EXEC",
        "Runtime command execution",
        Severity.MEDIUM,
        ("Ljava/lang/Runtime;->exec", "Ljava/lang/ProcessBuilder;"),
        "The app can spawn OS commands. If any argument is attacker-influenced this is "
        "a command-injection risk.",
        cwe="CWE-78",
        masvs="MASVS-CODE-4",
    ),
    CodeRule(
        "MAVS-CODE-DYNLOAD",
        "Dynamic code loading",
        Severity.MEDIUM,
        (
            "Ldalvik/system/DexClassLoader;",
            "Ldalvik/system/PathClassLoader;",
            "Ldalvik/system/InMemoryDexClassLoader;",
        ),
        "The app loads code at runtime. Loaded code from an untrusted source can run "
        "arbitrary logic and evade static review.",
        cwe="CWE-494",
        masvs="MASVS-CODE-2",
    ),
    CodeRule(
        "MAVS-CODE-SQL",
        "Raw SQL query construction",
        Severity.LOW,
        ("rawQuery", "execSQL"),
        "Raw SQL is used. If queries interpolate untrusted input this is a SQL "
        "injection risk. Prefer parameterized queries.",
        cwe="CWE-89",
        masvs="MASVS-CODE-4",
    ),
    CodeRule(
        "MAVS-CODE-ROOTCHECK",
        "Root detection strings",
        Severity.INFO,
        ("/system/bin/su", "/system/xbin/su", "Superuser.apk", "test-keys", "eu.chainfire"),
        "The app appears to probe for root. This is a resilience control, not a "
        "vulnerability, and is easily bypassed.",
        masvs="MASVS-RESILIENCE-1",
    ),
    CodeRule(
        "MAVS-CODE-CLIPBOARD",
        "Clipboard access",
        Severity.INFO,
        ("Landroid/content/ClipboardManager;", "Landroid/text/ClipboardManager;"),
        "Clipboard is accessed. Sensitive values copied to the clipboard are readable "
        "by other apps.",
        cwe="CWE-200",
        masvs="MASVS-STORAGE-2",
    ),
    CodeRule(
        "MAVS-CODE-KEYSTORE",
        "AndroidKeyStore usage",
        Severity.INFO,
        ("AndroidKeyStore",),
        "The app uses the hardware-backed AndroidKeyStore. This is a good practice "
        "noted for context.",
        masvs="MASVS-CRYPTO-2",
    ),
    CodeRule(
        "MAVS-CODE-PINNING",
        "Certificate pinning present",
        Severity.INFO,
        ("Lokhttp3/CertificatePinner;", "CertificatePinner", "javax/net/ssl/PinningTrustManager"),
        "Certificate pinning is referenced. This is a good practice noted for context; "
        "confirm it is enforced on all endpoints.",
        masvs="MASVS-NETWORK-2",
    ),
)
