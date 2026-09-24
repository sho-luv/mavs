"""Unit tests for the mavs_scan static analysis engine.

These use crafted synthetic inputs only; no real application binaries or secret
values are included. DEX, ELF, ZIP, signing-block and certificate structures are
built in-memory to exercise the bounded parsers and analyzers deterministically.
Tests that require a real binary AndroidManifest.xml live in
``test_scan_integration.py`` and are gated on a sample directory.
"""

from __future__ import annotations

import io
import struct
import threading
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from datetime import UTC, datetime
from http.server import ThreadingHTTPServer
from pathlib import Path

import defusedxml.ElementTree as DET
import pytest
from asn1crypto import algos, keys, x509

from mavs_scan import dex, guidance
from mavs_scan.analyzers import (
    binary,
    certificate,
    code,
    framework,
    managed_keys,
    manifest,
    network,
    permissions,
    secrets,
    trackers,
)
from mavs_scan.analyzers.binary import _parse_elf
from mavs_scan.analyzers.certificate import _scheme_findings, _weak_signature
from mavs_scan.analyzers.permissions import requested_permissions
from mavs_scan.apk import (
    _V2_ID,
    LoadedApk,
    _central_dir_offset,
    _extract_certificates,
    _first_cert_from_v2v3,
    load,
)
from mavs_scan.context import ScanContext
from mavs_scan.engine import scan as engine_scan
from mavs_scan.model import AppInfo, Coverage, Finding, ScanReport, Severity
from mavs_scan.report import render as render_text
from mavs_scan.web import server as web_server
from mavs_scan.web.render import page
from mavs_scan.web.server import _Handler, _parse_multipart_file

ANDROID = "http://schemas.android.com/apk/res/android"
ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DLL = ROOT / "tests" / "fixtures" / "SyntheticFixture.dll"


# --- builders ----------------------------------------------------------------


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)


def build_dex(strings: list[str]) -> bytes:
    """Build a minimal valid-enough DEX exposing ``strings`` in the string pool."""
    header = bytearray(112)
    header[0:8] = b"dex\n035\x00"
    ids_off = 112
    data_off = ids_off + len(strings) * 4
    ids = bytearray()
    data = bytearray()
    for s in strings:
        ids += struct.pack("<I", data_off + len(data))
        data += _uleb(len(s)) + s.encode("utf-8") + b"\x00"
    struct.pack_into("<I", header, 56, len(strings))
    struct.pack_into("<I", header, 60, ids_off)
    return bytes(header) + bytes(ids) + bytes(data)


def build_zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


def empty_zip() -> bytes:
    return build_zip({})


def make_context(
    strings: list[str] | None = None,
    root: ET.Element | None = None,
    entries: dict[str, bytes] | None = None,
) -> ScanContext:
    raw = build_zip(entries) if entries is not None else empty_zip()
    loaded = LoadedApk(path="synthetic.apk", raw=raw, file_type="apk", manifest_root=root)
    ctx = ScanContext(apk=loaded, package="com.example.app", app_name="app")
    if strings is not None:
        ctx._strings = strings
    return ctx


def build_elf(*, exec_stack: bool, canary: bool, pie: bool = True, extra: bytes = b"") -> bytes:
    data = bytearray(120)
    data[0:4] = b"\x7fELF"
    data[4] = 2  # 64-bit
    data[5] = 1  # little endian
    struct.pack_into("<H", data, 16, 3 if pie else 2)  # e_type ET_DYN/ET_EXEC
    struct.pack_into("<Q", data, 32, 64)  # e_phoff
    struct.pack_into("<H", data, 54, 56)  # e_phentsize
    struct.pack_into("<H", data, 56, 1)  # e_phnum
    struct.pack_into("<I", data, 64, 0x6474E551)  # PT_GNU_STACK
    struct.pack_into("<I", data, 68, 0x7 if exec_stack else 0x6)  # p_flags
    payload = bytes(data)
    if canary:
        payload += b"__stack_chk_fail\x00"
    return payload + extra


def build_elf32_relro() -> bytes:
    data = bytearray(96)
    data[0:4] = b"\x7fELF"
    data[4] = 1  # 32-bit
    data[5] = 1  # little endian
    struct.pack_into("<H", data, 16, 3)  # e_type ET_DYN
    struct.pack_into("<I", data, 28, 52)  # e_phoff
    struct.pack_into("<H", data, 42, 32)  # e_phentsize
    struct.pack_into("<H", data, 44, 1)  # e_phnum
    struct.pack_into("<I", data, 52, 0x6474E552)  # PT_GNU_RELRO
    struct.pack_into("<I", data, 52 + 24, 0x4)  # p_flags (read-only)
    return bytes(data)


def _lp(b: bytes) -> bytes:
    return struct.pack("<I", len(b)) + b


def v2_value(cert_der: bytes) -> bytes:
    return _lp(_lp(_lp(_lp(b"digest") + _lp(_lp(cert_der)))))


def build_apk_with_v2(cert_der: bytes) -> bytes:
    value = v2_value(cert_der)
    pairs = struct.pack("<Q", len(value) + 4) + struct.pack("<I", _V2_ID) + value
    footer = 24 + len(pairs)
    prefix = b"\x00\x00\x00\x00"
    region = struct.pack("<Q", footer) + pairs + struct.pack("<Q", footer) + b"APK Sig Block 42"
    cd_offset = len(prefix) + len(region)
    eocd = b"PK\x05\x06" + b"\x00" * 12 + struct.pack("<I", cd_offset) + b"\x00\x00"
    return prefix + region + b"CDCD" + eocd


def make_cert(sig_algo: str = "md5_rsa") -> bytes:
    spki = keys.PublicKeyInfo(
        {
            "algorithm": keys.PublicKeyAlgorithm({"algorithm": "rsa"}),
            "public_key": keys.RSAPublicKey({"modulus": 0x1234567, "public_exponent": 65537}),
        }
    )
    name = x509.Name.build({"common_name": "MAVS Test"})
    tbs = x509.TbsCertificate(
        {
            "version": "v3",
            "serial_number": 1,
            "signature": algos.SignedDigestAlgorithm({"algorithm": sig_algo}),
            "issuer": name,
            "validity": x509.Validity(
                {
                    "not_before": x509.Time({"utc_time": datetime(2020, 1, 1, tzinfo=UTC)}),
                    "not_after": x509.Time({"utc_time": datetime(2030, 1, 1, tzinfo=UTC)}),
                }
            ),
            "subject": name,
            "subject_public_key_info": spki,
        }
    )
    cert = x509.Certificate(
        {
            "tbs_certificate": tbs,
            "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": sig_algo}),
            "signature_value": b"\x00" * 8,
        }
    )
    return cert.dump()


def _manifest(xml_body: str, attrs: str = "") -> ET.Element:
    doc = (
        f'<manifest xmlns:android="{ANDROID}" package="com.example.app" {attrs}>'
        f"{xml_body}</manifest>"
    )
    return DET.fromstring(doc)


# --- dex ---------------------------------------------------------------------


def test_dex_extract_strings_roundtrips_known_strings() -> None:
    blob = build_dex(["ALLOW_ALL_HOSTNAME_VERIFIER", "Ljava/util/Random;", "hello"])
    found = dex.extract_strings(blob)
    assert "ALLOW_ALL_HOSTNAME_VERIFIER" in found
    assert "Ljava/util/Random;" in found
    assert "hello" in found


def test_dex_extract_rejects_non_dex() -> None:
    assert dex.extract_strings(b"not a dex file at all") == []


def test_dex_truncated_ids_does_not_crash() -> None:
    blob = bytearray(build_dex(["a", "b"]))
    struct.pack_into("<I", blob, 56, 100000)  # claim far more strings than exist
    assert isinstance(dex.extract_strings(bytes(blob)), list)


def test_dex_multi_dex_dedup() -> None:
    a = build_dex(["shared", "onlyA"])
    b = build_dex(["shared", "onlyB"])
    combined = dex.extract_all_strings([("classes.dex", a), ("classes2.dex", b)])
    assert combined.count("shared") == 1
    assert "onlyA" in combined
    assert "onlyB" in combined


# --- code analyzer -----------------------------------------------------------


def test_code_analyzer_flags_hostname_and_attaches_exploit() -> None:
    ctx = make_context(["ALLOW_ALL_HOSTNAME_VERIFIER", "setJavaScriptEnabled"])
    findings = code.analyze(ctx)
    ids = {f.rule_id for f in findings}
    assert "MAVS-CODE-HOSTNAME" in ids
    assert "MAVS-CODE-WEBVIEW-JS" in ids
    hostname = next(f for f in findings if f.rule_id == "MAVS-CODE-HOSTNAME")
    assert hostname.severity is Severity.HIGH
    assert hostname.exploit is not None
    assert "Burp" in hostname.exploit


def test_code_analyzer_clean_pool_has_no_findings() -> None:
    assert code.analyze(make_context(["com/example/Harmless", "onCreate"])) == []


def test_code_analyzer_covers_crypto_exec_dynload_sql_worldperms() -> None:
    ctx = make_context(
        [
            "AES/ECB/PKCS5Padding",
            "Ljava/lang/Runtime;->exec",
            "Ldalvik/system/DexClassLoader;",
            "rawQuery",
            "MODE_WORLD_READABLE",
            "Landroid/util/Log;",
        ]
    )
    ids = {f.rule_id for f in code.analyze(ctx)}
    assert {
        "MAVS-CODE-CRYPTO-ECB",
        "MAVS-CODE-EXEC",
        "MAVS-CODE-DYNLOAD",
        "MAVS-CODE-SQL",
        "MAVS-CODE-WORLD-PERMS",
        "MAVS-CODE-LOG",
    } <= ids


def test_code_logging_attaches_exploit_guidance() -> None:
    logging = next(
        f
        for f in code.analyze(make_context(["Landroid/util/Log;"]))
        if f.rule_id == "MAVS-CODE-LOG"
    )
    assert logging.exploit is not None
    assert "logcat" in logging.exploit


def test_code_evidence_is_truncated() -> None:
    long_str = "setJavaScriptEnabled" + "X" * 500
    ctx = make_context([long_str])
    finding = next(f for f in code.analyze(ctx) if f.rule_id == "MAVS-CODE-WEBVIEW-JS")
    assert all(len(e) <= 160 for e in finding.evidence)


# --- trackers ----------------------------------------------------------------


def test_trackers_detected_from_descriptors() -> None:
    ctx = make_context(
        ["Lcom/google/firebase/analytics/FirebaseAnalytics;", "Lcom/facebook/ads/Ad;"],
    )
    findings = trackers.analyze(ctx)
    assert len(findings) == 1
    assert "Google Firebase Analytics" in findings[0].evidence
    assert "Facebook Login/Ads" in findings[0].evidence


def test_trackers_none_returns_empty() -> None:
    assert trackers.analyze(make_context(["com/example/App"])) == []


# --- network -----------------------------------------------------------------


def test_network_extracts_http_urls_and_emails() -> None:
    ctx = make_context(["http://insecure.example.com/api", "mailto contact@example.com here"])
    ids = {f.rule_id for f in network.analyze(ctx)}
    assert "MAVS-NET-HTTPURL" in ids
    assert "MAVS-NET-ENDPOINTS" in ids


def test_network_detects_firebase_endpoint() -> None:
    ctx = make_context(["https://demo-app.firebaseio.com/users.json"])
    ids = {f.rule_id for f in network.analyze(ctx)}
    assert "MAVS-NET-FIREBASE" in ids


def test_network_https_only_has_no_http_finding() -> None:
    ids = {f.rule_id for f in network.analyze(make_context(["https://secure.example.com/api"]))}
    assert "MAVS-NET-HTTPURL" not in ids


# --- secrets -----------------------------------------------------------------


def test_secrets_flags_embedded_aws_key() -> None:
    ids = {f.rule_id for f in secrets.analyze(make_context(["AKIAIOSFODNN7EXAMPLE"]))}
    assert "MAVS-SECRET-AWSACCESSKEY" in ids


def test_secrets_flags_private_key_and_other_patterns() -> None:
    ctx = make_context(
        [
            "-----BEGIN RSA PRIVATE KEY-----",
            "AIzaSyA1234567890123456789012345678901234",
            "sk_live_0123456789abcdef0123",
        ]
    )
    ids = {f.rule_id for f in secrets.analyze(ctx)}
    assert "MAVS-SECRET-PRIVATEKEY" in ids
    assert "MAVS-SECRET-GOOGLEAPIKEY" in ids
    assert "MAVS-SECRET-STRIPEKEY" in ids


def test_secrets_flags_bundled_key_file() -> None:
    ctx = make_context([], entries={"res/raw/server.pem": b"cert bytes"})
    finding = next(f for f in secrets.analyze(ctx) if f.rule_id == "MAVS-SECRET-KEYFILE")
    assert "res/raw/server.pem" in finding.evidence
    assert finding.exploit is not None


# --- binary / ELF ------------------------------------------------------------


def test_elf_parser_detects_executable_stack_and_canary() -> None:
    facts = _parse_elf(build_elf(exec_stack=True, canary=False))
    assert facts.is_elf is True
    assert facts.executable_stack is True
    assert facts.has_canary is False
    safe = _parse_elf(build_elf(exec_stack=False, canary=True))
    assert safe.executable_stack is False
    assert safe.has_canary is True


def test_elf_parser_rejects_non_elf() -> None:
    assert _parse_elf(b"not an elf").is_elf is False


def test_elf_parser_detects_relro_32bit() -> None:
    facts = _parse_elf(build_elf32_relro())
    assert facts.is_elf is True
    assert facts.has_relro is True


def test_binary_analyzer_reports_hardening_gaps() -> None:
    so = build_elf(exec_stack=True, canary=False, pie=False)
    ctx = make_context([], entries={"lib/arm64-v8a/libx.so": so})
    ids = {f.rule_id for f in binary.analyze(ctx)}
    assert {"MAVS-BIN-PIE", "MAVS-BIN-NX", "MAVS-BIN-CANARY"} <= ids


def test_binary_detects_outdated_libpng_banner() -> None:
    so = build_elf(exec_stack=False, canary=True, extra=b"libpng version 1.2.3\x00")
    ctx = make_context([], entries={"lib/x86/libpng.so": so})
    finding = next(f for f in binary.analyze(ctx) if f.rule_id == "MAVS-BIN-OUTDATED")
    assert any("libpng version 1.2.3" in e for e in finding.evidence)


# --- certificate -------------------------------------------------------------


def test_first_cert_from_v2v3_roundtrip() -> None:
    assert _first_cert_from_v2v3(v2_value(b"DERCERT")) == b"DERCERT"


def test_extract_certificates_from_v2_signing_block() -> None:
    certs, schemes = _extract_certificates(build_apk_with_v2(b"MYDERCERT"))
    assert "v2" in schemes
    assert b"MYDERCERT" in certs


def test_certificate_weak_signature_detected() -> None:
    ids = {f.rule_id for f in _weak_signature([make_cert("md5_rsa")])}
    assert "MAVS-CERT-WEAKSIG" in ids


def test_certificate_strong_signature_not_flagged() -> None:
    assert _weak_signature([make_cert("sha256_rsa")]) == []


def test_certificate_v1_only_flagged_but_multi_scheme_clean() -> None:
    assert [f.rule_id for f in _scheme_findings({"v1"})] == ["MAVS-CERT-V1ONLY"]
    assert _scheme_findings({"v1", "v2", "v3"}) == []


def test_certificate_analyze_no_cert_notes_partial() -> None:
    ctx = make_context([])
    assert certificate.analyze(ctx) == []
    assert any(c.stage == "certificate" and c.status == "partial" for c in ctx.coverage)


# --- permissions -------------------------------------------------------------


def test_permissions_maps_dangerous_and_drops_low() -> None:
    root = _manifest(
        '<uses-permission android:name="android.permission.READ_SMS"/>'
        '<uses-permission android:name="android.permission.CAMERA"/>'
        '<uses-permission android:name="android.permission.INTERNET"/>'
        '<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>',
    )
    findings = permissions.analyze(make_context([], root=root))
    evidence = {e for f in findings for e in f.evidence}
    assert "android.permission.READ_SMS" in evidence
    assert "android.permission.CAMERA" in evidence
    assert "android.permission.INTERNET" not in evidence
    assert "android.permission.RECEIVE_BOOT_COMPLETED" not in evidence


def test_requested_permissions_extracted_sorted() -> None:
    root = _manifest(
        '<uses-permission android:name="android.permission.CAMERA"/>'
        '<uses-permission-sdk-23 android:name="android.permission.READ_SMS"/>',
    )
    perms = requested_permissions(make_context([], root=root))
    assert perms == ("android.permission.CAMERA", "android.permission.READ_SMS")


# --- manifest ----------------------------------------------------------------


def test_manifest_flags_debuggable_and_backup() -> None:
    root = _manifest(
        '<uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>'
        '<application android:debuggable="true" android:allowBackup="true">'
        '<activity android:name=".Main" android:exported="true">'
        '<intent-filter><category android:name="android.intent.category.LAUNCHER"/>'
        "</intent-filter></activity></application>",
    )
    ids = {f.rule_id for f in manifest.analyze(make_context([], root=root))}
    assert "MAVS-MANIFEST-DEBUG" in ids
    assert "MAVS-MANIFEST-BACKUP" in ids


def test_manifest_launcher_activity_not_flagged_exported() -> None:
    root = _manifest(
        '<application android:allowBackup="false">'
        '<activity android:name=".Main" android:exported="true">'
        '<intent-filter><category android:name="android.intent.category.LAUNCHER"/>'
        "</intent-filter></activity></application>",
    )
    ids = {f.rule_id for f in manifest.analyze(make_context([], root=root))}
    assert not any(i.startswith("MAVS-MANIFEST-EXPORTED") for i in ids)


def test_manifest_flags_exported_component_without_permission() -> None:
    root = _manifest(
        '<application android:allowBackup="false">'
        '<service android:name=".Exposed" android:exported="true"/></application>',
    )
    findings = manifest.analyze(make_context([], root=root))
    assert any(f.rule_id.startswith("MAVS-MANIFEST-EXPORTED") for f in findings)


def test_manifest_permission_protected_component_skipped() -> None:
    root = _manifest(
        '<application android:allowBackup="false">'
        '<service android:name=".Guarded" android:exported="true" '
        'android:permission="com.example.PERM"/></application>',
    )
    ids = {f.rule_id for f in manifest.analyze(make_context([], root=root))}
    assert not any(i.startswith("MAVS-MANIFEST-EXPORTED") for i in ids)


def test_manifest_cleartext_calibration() -> None:
    def cleartext(app_attrs: str, target_sdk: int) -> Finding | None:
        root = _manifest(
            f'<uses-sdk android:targetSdkVersion="{target_sdk}"/>'
            f'<application android:allowBackup="false" {app_attrs}>'
            '<activity android:name=".A" android:excludeFromRecents="true"/></application>',
        )
        for f in manifest.analyze(make_context([], root=root)):
            if f.rule_id == "MAVS-MANIFEST-CLEARTEXT":
                return f
        return None

    explicit = cleartext('android:usesCleartextTraffic="true"', 33)
    assert explicit is not None
    assert explicit.severity is Severity.HIGH
    modern = cleartext("", 30)
    assert modern is not None
    assert modern.severity is Severity.INFO
    legacy = cleartext("", 21)
    assert legacy is not None
    assert legacy.severity is Severity.MEDIUM


def test_manifest_snapshot_suppressed_by_exclude_from_recents() -> None:
    root = _manifest(
        '<application android:allowBackup="false">'
        '<activity android:name=".A" android:excludeFromRecents="true"/></application>',
    )
    ids = {f.rule_id for f in manifest.analyze(make_context([], root=root))}
    assert "MAVS-MANIFEST-SNAPSHOT" not in ids


def test_manifest_snapshot_flagged_when_unprotected() -> None:
    root = _manifest('<application android:allowBackup="false"/>')
    ids = {f.rule_id for f in manifest.analyze(make_context([], root=root))}
    assert "MAVS-MANIFEST-SNAPSHOT" in ids


def test_manifest_min_sdk_thresholds() -> None:
    def min_sdk_finding(value: int) -> Finding | None:
        root = _manifest(
            f'<uses-sdk android:minSdkVersion="{value}" android:targetSdkVersion="33"/>'
            '<application android:allowBackup="false">'
            '<activity android:name=".A" android:excludeFromRecents="true"/></application>',
        )
        for f in manifest.analyze(make_context([], root=root)):
            if f.rule_id == "MAVS-MANIFEST-MINSDK":
                return f
        return None

    low = min_sdk_finding(19)
    assert low is not None
    assert low.severity is Severity.MEDIUM
    mid = min_sdk_finding(21)
    assert mid is not None
    assert mid.severity is Severity.LOW
    assert min_sdk_finding(24) is None


def test_manifest_not_decoded_returns_unsupported() -> None:
    ctx = make_context([], root=None)
    assert manifest.analyze(ctx) == []
    assert any(c.stage == "manifest-analysis" and c.status == "unsupported" for c in ctx.coverage)


# --- framework ---------------------------------------------------------------


def test_framework_detects_flutter_with_exploit() -> None:
    ctx = make_context([], entries={"lib/arm64-v8a/libflutter.so": b"\x00"})
    findings = framework.analyze(ctx)
    fw = next(f for f in findings if f.rule_id == "MAVS-FRAMEWORK")
    assert "Flutter" in fw.evidence
    assert fw.exploit is not None
    assert any(f.rule_id == "MAVS-STORAGE-MANUAL" for f in findings)


def test_framework_detects_xamarin_from_strings() -> None:
    ctx = make_context(["Mono.Android, Version=0.0.0.0"])
    fw = next(f for f in framework.analyze(ctx) if f.rule_id == "MAVS-FRAMEWORK")
    assert "Xamarin/.NET" in fw.evidence


def test_framework_storage_manual_always_present() -> None:
    findings = framework.analyze(make_context(["com/example/App"]))
    assert [f.rule_id for f in findings] == ["MAVS-STORAGE-MANUAL"]


# --- managed-keys adapter ----------------------------------------------------


def test_managed_keys_adapter_converts_findings(tmp_path: Path) -> None:
    if not FIXTURE_DLL.exists():
        return
    apk = tmp_path / "keys.apk"
    apk.write_bytes(build_zip({"assemblies/SyntheticFixture.dll": FIXTURE_DLL.read_bytes()}))
    loaded = load(apk)
    ctx = ScanContext(apk=loaded, package="com.example.app", app_name="app")
    findings = managed_keys.analyze(ctx)
    assert findings
    assert all(f.category == "managed-key" for f in findings)
    assert all(f.rule_id == "MAVS-KEY-001" for f in findings)
    assert all(f.severity in {Severity.HIGH, Severity.MEDIUM} for f in findings)
    assert any(c.stage == "managed-keys" for c in ctx.coverage)


# --- apk loader / containers -------------------------------------------------


def test_central_dir_offset_on_real_zip() -> None:
    offset = _central_dir_offset(build_zip({"a.txt": b"hello"}))
    assert offset is not None
    assert offset > 0


def test_xapk_container_extracts_base_apk(tmp_path: Path) -> None:
    inner = build_zip({"classes.dex": build_dex(["setJavaScriptEnabled"])})
    xapk = tmp_path / "app.xapk"
    xapk.write_bytes(build_zip({"manifest.json": b"{}", "com.example.base.apk": inner}))
    loaded = load(xapk)
    assert loaded.file_type == "xapk"
    assert loaded.dex_blobs()  # base apk was extracted and its dex is reachable


# --- engine orchestration ----------------------------------------------------


def test_engine_scan_orders_findings_and_skips_managed_keys(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(
        build_zip(
            {
                "classes.dex": build_dex(["ALLOW_ALL_HOSTNAME_VERIFIER", "http://x.example.com/a"]),
            }
        )
    )
    report = engine_scan(apk, managed_keys=False)
    assert report.file_type == "apk"
    ids = {f.rule_id for f in report.findings}
    assert "MAVS-CODE-HOSTNAME" in ids
    assert "MAVS-KEY-001" not in ids  # skipped
    severities = [int(f.severity) for f in report.findings]
    assert severities == sorted(severities, reverse=True)  # worst-first
    assert any(c.stage == "manifest" for c in report.coverage)


def test_engine_scan_unknown_type_for_non_apk(tmp_path: Path) -> None:
    blob = tmp_path / "mystery.bin"
    blob.write_bytes(b"this is not a zip")
    report = engine_scan(blob, managed_keys=False)
    assert report.file_type == "unknown"


# --- guidance ----------------------------------------------------------------


def test_guidance_fill_substitutes_placeholders() -> None:
    text = guidance.fill(guidance.DEBUG_EXPLOIT, package="com.x.y", app="y")
    assert text is not None
    assert "com.x.y" in text
    assert "{package}" not in text
    assert guidance.fill(None, package="p", app="a") is None


# --- text reporter -----------------------------------------------------------


def _report(findings: tuple[Finding, ...] = (), coverage: tuple[Coverage, ...] = ()) -> ScanReport:
    return ScanReport(
        target="x.apk",
        file_type="apk",
        sha256="0" * 64,
        size_bytes=10,
        app=AppInfo(package="com.example.app"),
        findings=findings,
        coverage=coverage,
    )


def test_text_report_verbose_and_exploit_and_strips_ansi() -> None:
    finding = Finding(
        rule_id="MAVS-CODE-LOG",
        category="code",
        title="Logging present",
        severity=Severity.LOW,
        description="logs",
        evidence=("Landroid/util/Log;",),
        verify="grep for Log",
        exploit="adb logcat -v time",
    )
    out = io.StringIO()
    render_text(_report((finding,)), verbose=True, exploit=True, color=False, out=out)
    text = out.getvalue()
    assert "Logging present" in text
    assert "Landroid/util/Log;" in text
    assert "adb logcat -v time" in text
    assert "\033[" not in text  # ANSI stripped when color disabled


def test_text_report_shows_coverage_notes() -> None:
    out = io.StringIO()
    cov = (Coverage(stage="manifest", status="error", detail="undecodable"),)
    render_text(_report((), cov), color=False, out=out)
    assert "Coverage notes" in out.getvalue()


# --- web server --------------------------------------------------------------


def _start_server() -> ThreadingHTTPServer:
    _Handler.state.report = None
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_web_server_serves_landing_and_json() -> None:
    srv = _start_server()
    try:
        port = srv.server_address[1]
        landing = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5).read()
        assert b"Upload" in landing
        payload = urllib.request.urlopen(f"http://127.0.0.1:{port}/report.json", timeout=5).read()
        assert payload == b"{}"
    finally:
        srv.shutdown()
        srv.server_close()


def test_web_server_post_without_file_is_400() -> None:
    srv = _start_server()
    try:
        port = srv.server_address[1]
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/scan",
            data=b"nope",
            headers={"Content-Type": "text/plain"},
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=5)
        assert exc_info.value.code == 400
    finally:
        srv.shutdown()
        srv.server_close()


def test_web_server_rejects_oversized_upload(monkeypatch) -> None:
    monkeypatch.setattr(web_server, "_MAX_UPLOAD", 4)
    srv = _start_server()
    try:
        port = srv.server_address[1]
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/scan",
            data=b"x" * 100,
            headers={"Content-Type": "multipart/form-data; boundary=b"},
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=5)
        assert exc_info.value.code == 413
    finally:
        srv.shutdown()
        srv.server_close()


def test_multipart_parser_extracts_file() -> None:
    boundary = "----X"
    body = (
        (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="app.apk"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        + b"PK\x03\x04payload"
        + f"\r\n--{boundary}--\r\n".encode()
    )
    parsed = _parse_multipart_file(body, f"multipart/form-data; boundary={boundary}")
    assert parsed is not None
    filename, data = parsed
    assert filename == "app.apk"
    assert data == b"PK\x03\x04payload"


def test_multipart_parser_without_boundary_returns_none() -> None:
    assert _parse_multipart_file(b"body", "text/plain") is None


# --- web render --------------------------------------------------------------


def test_render_page_handles_empty_and_populated() -> None:
    assert "Upload" in page(None)
    html = page(_report())
    assert "com.example.app" in html
    assert "A" in html  # grade for zero findings


# --- model scoring -----------------------------------------------------------


def test_risk_score_and_grade_monotonic() -> None:
    def finding(sev: Severity) -> Finding:
        return Finding(rule_id="X", category="code", title="t", severity=sev, description="d")

    low = _report((finding(Severity.LOW),))
    high = _report((finding(Severity.CRITICAL), finding(Severity.HIGH)))
    assert low.risk_score < high.risk_score
    assert low.grade in {"A", "B"}
    assert high.grade == "F"
    assert high.counts()["critical"] == 1
    assert _report().risk_score == 0
