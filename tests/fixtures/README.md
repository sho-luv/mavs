# Synthetic managed fixture

`SyntheticFixture.dll` is compiled from the adjacent C# source. All byte arrays
are fabricated; this directory contains no real application secrets or binaries.
Two fixed authentication keys should be detected. The color table and the
runtime-generated keys should not be reported as embedded keys. `SessionKey`
is allocated as a zero-filled buffer and then populated with random bytes.
Unrelated strings contain a valid .NET lone UTF-16 surrogate, in both a static
initializer and an ordinary method, to guard against whole-assembly scan failure.
The explicitly initialized `keyDiversifier` is a public 64-byte algorithm
constant read by `DeriveKey`; it must not be classified as an embedded credential.

Regenerate using a .NET 8 SDK, from this directory:

```sh
dotnet build SyntheticFixture.csproj --configuration Release \
  --output /tmp/mavs-fixture-build \
  -p:BaseIntermediateOutputPath=/tmp/mavs-fixture-obj/
cp /tmp/mavs-fixture-build/SyntheticFixture.dll SyntheticFixture.dll
```

The initial fixture was built using .NET SDK 8.0.425 installed in
`/tmp/mavs-fixture-sdk` with the official `dotnet-install.sh` script. The SDK and
build intermediates are not part of the repository. Tests create APK/XAPK ZIP
containers, Xamarin v1 assembly stores, and raw LZ4 compressed assemblies in
temporary directories, so running the suite does not require the SDK.
