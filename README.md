<p align="center">
<img width="459" alt="notify" src="https://user-images.githubusercontent.com/1679089/83109222-deee5300-a075-11ea-890e-5588f347ce8d.png">

<h4 align="center">Mobile Application Vulnerability Scanner</h4>
<p align="center">
  <a href="https://twitter.com/sho_luv">
  <img src="https://img.shields.io/badge/Twitter-%40sho_luv-blue.svg">
  </a>
</p>


# mavs.sh

This tool performs static analysis on Android APKs and XAPK containers.
What makes this tool different from all the other tools that do this? My goal with this project is to actually exploit things.
Often you find static analysis tools point to things and say **VULNERABLE!** and the user is left to figure out why. Or worst its a
false positive.

MAVS now runs a single Python engine that covers the same static-analysis ground as
[MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) for Android, while
keeping what makes this tool different: exploitation and verification guidance for
every finding, and deep Xamarin/.NET embedded-key detection. It is CLI-first so AI
and automation can drive it, with an optional zero-dependency web dashboard.

  - `-v` verbose = Show me why you think its broken (evidence + how to verify), useful for fixing and reporting.
  - `-e` exploit = Show me how to exploit this so called broken thing, or how to manually confirm it. Commands are cut-and-paste ready.
  - `-j` json = Machine-readable report for AI tools and pipelines.

<p align="center">
  <img src="demo/mavs.gif" alt="MAVS scanning an APK: risk score, A-F grade, findings, and copy-paste exploit guidance" width="900">
</p>

## Required Dependencies

Only [uv](https://docs.astral.sh/uv/getting-started/installation/) and Python 3.12+.
No `apktool`, `dex2jar`, `apkinfo`, or Java are needed. The engine parses the APK in
process. Runtime Python dependencies are intentionally minimal and pinned in `uv.lock`:

```
apkInspector   # binary AndroidManifest.xml + DEX/ZIP parsing (zero transitive deps)
asn1crypto     # signing-certificate parsing
defusedxml     # safe XML parsing of app-supplied resources
dnfile, dncil  # Xamarin/.NET managed assembly parsing (managed-key check)
lz4            # XALZ/LZ4 assembly decompression
pydantic, typer
```

The first run creates a local `.venv` from the lockfile.

## Usage mavs.sh
```
./mavs.sh 

                                   ╓
                        ╕         ╒╣╕                     ╣╣╣─    ╦╣╣
                ╓      ║╬         ╣╣╣      ╒             ╣╣╣─  ╒╣╣╩╙╣╬║╣
                ╣╕     ╣╣        ╫╣ ╫╣     ╡  ╔         ╣╣╣   ╦╣╩   ║╣╬
               ╣╣╣    ║╣╣╬      ╔╣╩  ╫╣╖  ╞╬  ╣╣       ╣╣╣   ╣╣╬    ╞╩
             ╒╣╣╩╣╣╖ ╔╣╬╣╣╕    ╔╣╣╗╗╦╦╣╣╦╦╣╣  ╣╣╣     ╣╣╣     ╙╣╣╣╦╗╖
            ╔╣╣╜  ╝╣╣╣╜ ╙╣╣═╩╜║╣╣╜     ╫╣╖     ╣╣╣  ╒╣╣╣          ╠╜╝╣╣╣╣╗╖
          ╓╣╣╩           ╚╣╣ ╦╣╬        ╚╣╗     ╣╣╬╓╣╣╬      ╓╦╣╣╣╩      ╙╙╝╣╣╣╗╖
        ╒╣╣╬╗╗╗           ╚╣╣╖           ╙╣╣╗   ╙╣╣╣╣╩    ╓╣╣╩╙ ║╣             ╙╣╣╣╖
      ╓╣╣╝╜╙╙╙╙            ╚╣╣╖╦           ╙╝╣╗╖ ╫╣╣╬    ├╣╣╖    ╬           ╓╓╗╣╣╣╩
                       ║╣╣╣╣╣╣╣╣╣╖           ╓╣╣╣ ╣╬      ╙╙╝╣╣╣╣╣╣╣╣╣╣╣╣╣╣╣╝╝╜╙╙
                             └╙╙╨╝╝╝╝╝╝╝╝╝╨╜╜╙╙╙   ╣

		            Mobile Application Vulnerability Scanner | @sho_luv
 

Usage: mavs.sh [OPTIONS]

 Required:
  -f <apk>	Android APK or XAPK to run static analysis on

 Options:
  -v 		Verbose: show evidence and manual verification steps
  -e 		Exploit: show how to exploit / manually verify each finding
  -j 		JSON report (machine readable, for AI/automation)
  -k 		Managed authentication keys only (Xamarin/.NET), legacy fast mode
  -w 		Serve the result in a local web interface after scanning
  -F 		Fast: skip the slow Xamarin/.NET managed-key inspection
  -c 		Force ANSI color even when piped (e.g. into less -R or head)
  -p <port>	Web interface port (default 8000, implies -w)
  -h 		Show this help

```

Equivalent Python entry points (what `mavs.sh` calls):

```sh
uv run python -m mavs_scan scan -f app.apk -v -e     # full scan, evidence + exploit
uv run python -m mavs_scan scan -f app.apk -j        # JSON for automation
uv run python -m mavs_scan scan -f app.apk --web     # scan then open the dashboard
uv run python -m mavs_scan serve --port 8000         # dashboard, upload APKs in browser
```

## Web interface

`-w` (or `mavs_scan serve`) starts a local dashboard using only the Python standard
library. It binds to `127.0.0.1` by default, renders the report worst-first with
evidence and exploit guidance, and lets you upload another APK/XAPK to scan. Files
stay on the host and uploads are size limited.

## Current Security Checks

The engine reports findings across these categories, each with a severity, CWE,
OWASP MASVS reference, evidence, and verification/exploitation guidance. A 0-100 risk
score and A-F grade summarize the result.

**Manifest** — debuggable build, backups allowed, cleartext traffic (calibrated to
target SDK), screenshot/snapshot exposure (FLAG_SECURE / excludeFromRecents), low
minimum SDK, and exported activities/services/receivers/providers without a permission.

**Certificate** — v1-only signing (Janus, CVE-2017-13156) and weak signature
algorithms (MD5/SHA-1), parsed from v1 and v2/v3 signing blocks.

**Permissions** — dangerous requested permissions mapped to concrete risk.

**Code** (over the DEX string pool) — disabled hostname verification, trust-all
TrustManager, `canAuthenticateAgainstProtectionSpace`, WebView JavaScript / native
bridge / broad file access / ignored SSL errors, weak crypto (ECB, DES, RC4),
weak hashes, insecure `Random`, world-readable/writable storage, external storage,
logging, runtime `exec`, dynamic code loading, raw SQL, clipboard, root-detection,
AndroidKeyStore and certificate-pinning usage.

**Network** — network security config cleartext permits and user-CA trust, hardcoded
`http://` URLs, Firebase endpoints, and extracted URLs/emails for recon.

**Native binaries** — ELF hardening for bundled `.so` libraries (executable stack,
PIE, RELRO, stack canary) plus outdated library version banners (e.g. libpng).

**Trackers** — bundled analytics/ad SDKs detected from class descriptors.

**Secrets** — bundled key/certificate files (`.pem`, `.p12`, `.jks`, …) and embedded
private keys, AWS/Google/Stripe/Slack/GitHub credential patterns. Values are reported
by type and location, not printed.

**Framework** — Flutter, Xamarin/.NET, React Native, Cordova, Unity, Capacitor, with
framework-specific interception guidance and a manual device-data-storage checklist.

**Managed keys** — `MAVS-KEY-001` embedded Xamarin/.NET credential constants (below).


## Managed authentication-key inspection

`MAVS-KEY-001` detects embedded credentials in Xamarin/.NET Android code. It
recognizes direct static strings and compiler-emitted RVA byte-array initializers
(8–512 bytes), requires a
credential-like field name and a direct field read, and reports the assembly,
type, field, consuming methods, byte length and SHA-256 fingerprint. Raw constant
values are redacted. String lengths and fingerprints use UTF-8 bytes with lone
surrogates preserved. Authentication/cryptography-related method names increase
confidence; findings still require manual review.

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) and use Python
3.12 or later. Dependencies are pinned in `uv.lock`; the first run creates a local
`.venv`. Keys-only mode works independently of the legacy Android tools:

```sh
./mavs.sh -k -f app.apk -v
./mavs.sh -k -f app.xapk -j > report.json
```

A normal `./mavs.sh -f app.apk` runs this managed-key check as one analyzer inside the
full scan; `-k` runs it alone in the original fast keys-only mode. `-F` skips it when
you want a quick pass over the other checks (it is the slowest stage on Xamarin apps).
Exit status 0 means the supported patterns were inspected, including when findings
exist; status 2 means some coverage was incomplete or the input was invalid.
Automation should inspect `findings` and `coverage` in the JSON report.

Supported containers: ordinary embedded DLLs, Xamarin v1 XABA assembly stores,
XALZ/LZ4 compressed assemblies, and APKs nested one level inside an XAPK. Parsing
happens in memory without executing APK code or extracting archive paths. Input,
entry count, member and aggregate payload-byte limits reject oversized archives.
These are not CPU or peak-memory sandbox limits: ZIP and managed metadata incur
additional parser allocations.
Unsupported layouts and malformed inputs produce explicit coverage results.

Limitations: this is a heuristic managed-code check, not whole-app data flow or
an exploit test. Java/Kotlin DEX, native code, modern native MAUI stores,
obfuscated identifiers, computed or runtime-provisioned secrets, inlined const
strings, zero-initialized buffers, and local-variable keys are outside this rule. A scanned assembly can
still contain unsupported initialization patterns. No findings does not mean
an application is secure. A fingerprint match establishes identical bytes,
not that credentials work against a device.

### Verification

```sh
uv sync --locked
uv run pytest -q
uv run ruff check mavs_keys mavs_scan tests typings
uv run ruff format --check mavs_keys mavs_scan tests typings
uv run basedpyright
bash -n mavs.sh managed_keys.sh mavs-legacy.sh
```

`tests/test_scan_engine.py` covers the static engine with crafted synthetic inputs
only (in-memory DEX, ELF, ZIP, APK signing blocks, and certificates). It exercises
each analyzer, the manifest severity calibrations, the v1/v2/v3 certificate
extraction, framework and secret detection, native binary hardening, the full
`engine.scan` orchestration, the text reporter, and the web dashboard routes. The
managed-key tests package a compiled fixture with fabricated constants into APK,
XABA, XALZ and XAPK containers and check findings, benign/runtime-generated
exclusions, redaction, invalid inputs, and archive limits. Fixture source and
regeneration instructions are in `tests/fixtures/`. Real application binaries and
secret values are intentionally excluded from the repository.

To run the end-to-end scans that need a real binary manifest, point `MAVS_KARR_DIR`
at your separately obtained samples. `test_scan_integration.py` runs a full
`engine.scan` and asserts the expected findings, signing schemes, and XAPK handling;
`test_karr_samples.py` checks the managed-key detection in depth:

```sh
MAVS_KARR_DIR=/path/to/karr uv run pytest -q tests/test_scan_integration.py tests/test_karr_samples.py
```

It verifies 170 scanned assemblies per input, exactly two 16-byte fields in
`GridtraqPL.Objects.Units.QTAuth`, `GenerateHash` usage, and matching fingerprints
across versions and containers. It also checks the separate medium-confidence
Syncfusion licensing XOR-key candidate and rejects public PKCS#12 diversifiers.
The four package scans run concurrently. This optional test is skipped when the sample
directory is unset. It does not download, install or execute the applications.
