# Managed authentication-key detection

## Scope
Add static detection of embedded authentication/cryptographic constants in Android Xamarin/.NET assemblies, including the KARR samples supplied outside this repository. Findings must provide evidence and redact values; static presence must not be presented as successful vehicle exploitation.

## Work plan
1. Completed: implement bounded APK/XAPK and Xamarin assembly-store reading plus managed-code findings.
2. Completed: integrate a keys-only CLI route and the existing MAVS scan, document setup and limits.
3. Completed: regression tests with synthetic constants and benign cases; real CLI runs against both KARR APKs and XAPKs; lint/type checks and evidence review.

## Baseline
- Fresh clone of sho-luv/mavs in the requested directory.
- Existing scanner is Bash; Go file manages Android devices and is unrelated to APK static analysis.
- Existing MAVS has no test suite or Python project. The user explicitly requested tests.
- Existing scan relies on apkinfo/dex2jar/apktool, and has no Xamarin assembly inspection.
- No APKs, real authentication values, or full decompiled application source will be added to this repository.


## Verification evidence
- Baseline regression failed at the public CLI before `-k` existed.
- Real APK testing exposed unusual UTF-16 strings; a compiled synthetic regression reproduced the failure before the parser fix.
- Independent review reproduced runtime-filled buffer and public PKCS#12 diversifier false positives; both now have negative controls.
- Malformed LZMA input reproduced an uncaught decoder error; specific boundary handling and LZMA/BZIP2 regressions pass.
- The final rule also finds a separate Syncfusion licensing XOR constant. Decompilation confirmed its use; integration expectations account for this medium-confidence candidate explicitly.
- Full suite: 24 passed, including four public CLI scans of the real packages. Each has 170 scanned assemblies, two high-confidence QTAuth fields and one medium-confidence licensing candidate.
- Ruff, formatting, strict basedpyright, programming-rule audit, Bash syntax and whitespace checks pass.
- Help, missing input, invalid JSON flag use, and relative paths with spaces exercised through the CLI.
- Redacted evidence is in `../analysis/MAVS-VERIFICATION.md` and per-input JSON reports. APKs and decompiled real code remain outside the repository.
- Legacy Java/manifest pipeline was not run end to end; it depends on separate Android tools. Keys-only integration is verified.

- Final rerun: 24 passed in 90.80 seconds; four distinct JSON artifacts verified and actual constant-value redaction checked.
- Independent final audit PASS: four input hashes match actual files and SHA256SUMS; 170 scanned assemblies each; two QTAuth findings plus licensing candidate; authentication fingerprints match across all inputs.

---

# MobSF-parity static analysis engine (mavs_scan)

## Scope
Add a unified Python static-analysis engine so MAVS covers the Android static
analysis MobSF performs, while preserving every existing MAVS check and its
verification/exploitation guidance. CLI-first for AI/automation, with an optional
zero-dependency web dashboard. Minimize dependencies.

## Design decisions (user-confirmed)
- Parsing engine: apkInspector (androguard 4's own zero-dependency parser backend)
  instead of full androguard. Measured androguard 4.1.4 pulled ~35 packages
  (IPython, SQLAlchemy, networkx, matplotlib) and a 427M venv; apkInspector +
  asn1crypto + defusedxml are all pure-Python with no transitive deps.
- Consolidate the Bash tool into Python. Legacy checks ported into analyzers;
  `-v`/`-e` guidance preserved verbatim in mavs_scan/guidance.py. Original
  mavs.sh kept as mavs-legacy.sh; new mavs.sh is a thin dispatcher.
- Android static first (phased). iOS and dynamic/Frida analysis deferred.
- Web interface uses only http.server (no framework).

## What was built
- mavs_scan package: apk loader (manifest via apkInspector, v1/v2/v3 signing-block
  cert extraction), bounded DEX string-pool parser, and analyzers for manifest,
  permissions, certificate, code (21 pattern rules), network, native ELF hardening,
  trackers, secrets, framework detection, and a managed-keys adapter over mavs_keys.
- Report model with severity, 0-100 risk score and A-F grade; text reporter with
  verbose/exploit modes; JSON output; stdlib web dashboard with upload + scan.
- Typer CLI (`scan`, `serve`) and `-F`/`-w`/`-p` flags in mavs.sh.

## Verification evidence
- End-to-end on the real KARR 0.80 APK: 25 findings across all categories,
  0 analyzer errors. Legacy checks reproduced (hostname-verifier disabled,
  trust-all TrustManager, backups allowed, cleartext, Xamarin framework) and the
  two QTAuth managed keys + Syncfusion licensing candidate still detected.
- Exploit guidance renders with the package substituted (adb backup+printf,
  logcat grep, run-as, data/data pull), confirming no `-e` content was lost.
- Fixed a mavs.sh bug: the `-k` branch wrapped `exec` in a subshell, so the script
  fell through to the full scan and returned its exit code. Now execs in the main
  shell. All 23 pre-existing managed-key tests pass again.
- New tests/test_scan_engine.py: 16 unit tests over crafted DEX/ELF/zip/manifest
  inputs (no real APKs committed). Full suite: 39 passed.
- Lint/type clean: ruff check + format and strict basedpyright pass on mavs_scan
  and tests; bash -n passes on all shell scripts.
- Performance: full scan ~76s on the Xamarin sample (managed-key parse dominates);
  `-F` fast mode ~1.9s.

## Deferred
- iOS (IPA/Mach-O/plist), Windows (APPX), and dynamic/Frida analysis.
- resources.arsc resolution (network security config is found by scanning res/xml).

## Test coverage expansion
Added tests/test_scan_engine.py (57 tests) and tests/test_scan_integration.py
(5 gated tests) covering the gaps identified in a coverage audit:
- P1: APK v2/v3 signing-block + certificate extraction, weak-signature and
  v1-only certificate findings, XAPK container extraction, and full engine.scan
  orchestration (worst-first sort, managed-keys skip, file-type detection).
- P2: permissions analyzer, manifest cleartext SDK calibration, snapshot
  suppression, min-SDK thresholds, launcher/permission-protected component logic,
  secrets (key files + private key + Google/Stripe patterns), framework detection.
- P3: more code rules (crypto/exec/dynload/SQL/world-perms), evidence truncation,
  DEX bounds/multi-dex de-dup, 32-bit ELF + RELRO + libpng banner, text reporter
  verbose/exploit + ANSI stripping + coverage notes, and web-server routing
  (landing, report.json, 400 no-file, 413 oversized).
Certificates and signing blocks are built in-memory with asn1crypto and struct;
no real APKs are committed. Real-manifest checks (network config, full scan,
managed keys end to end) live in the gated integration file.

Final: 80 passed, 6 skipped (gated) in ~2.8s; gated integration 5 passed in ~79s
against real KARR samples. ruff, ruff format, and strict basedpyright all pass.
