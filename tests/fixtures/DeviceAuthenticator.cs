using System.Security.Cryptography;

namespace SyntheticFixture;

public static class DeviceAuthenticator
{
    // Fabricated test bytes: these are not keys from any real application.
    public static readonly byte[] DealerKey = new byte[]
        { 0x11, 0x27, 0x39, 0x4b, 0x5d, 0x6f, 0x71, 0x83, 0x95, 0xa7, 0xb9, 0xcb, 0xdd, 0xef, 0xf1, 0x13 };
    public static readonly byte[] CustomerKey = new byte[]
        { 0x22, 0x34, 0x46, 0x58, 0x6a, 0x7c, 0x8e, 0x90, 0xa2, 0xb4, 0xc6, 0xd8, 0xea, 0xfc, 0x1e, 0x30 };
    public static readonly byte[] ColorTable = new byte[]
        { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    public static readonly byte[] SecretKey = RandomNumberGenerator.GetBytes(16);
    public static readonly byte[] SessionKey = new byte[16];
    public static readonly byte[] keyDiversifier = new byte[]
    {
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    };
    public static readonly string DisplayLabel = "\uD800";

    static DeviceAuthenticator() => RandomNumberGenerator.Fill(SessionKey);

    public static byte[] GenerateHash(byte[] challenge, bool dealer)
    {
        using var hmac = new HMACSHA256(dealer ? DealerKey : CustomerKey);
        return hmac.ComputeHash(challenge);
    }

    public static byte[] GenerateRuntimeHash(byte[] challenge)
    {
        using var hmac = new HMACSHA256(SecretKey);
        return hmac.ComputeHash(challenge);
    }

    public static string ReadUnrelatedUtf16Value() => "\uD800";

    public static byte[] DeriveKey() => keyDiversifier;

    public static byte[] GenerateSessionHash(byte[] challenge)
    {
        using var hmac = new HMACSHA256(SessionKey);
        return hmac.ComputeHash(challenge);
    }
}
