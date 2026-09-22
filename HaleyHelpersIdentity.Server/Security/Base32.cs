using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Haley.Abstractions;
using Haley.Models;
using Haley.Security;
using Microsoft.Extensions.Options;

namespace Haley.Security;
public static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    internal static string Encode(ReadOnlySpan<byte> data)
    {
        var output = new StringBuilder((data.Length * 8 + 4) / 5);
        var buffer = 0;
        var bits = 0;
        foreach (var value in data)
        {
            buffer = (buffer << 8) | value;
            bits += 8;
            while (bits >= 5)
            {
                output.Append(Alphabet[(buffer >> (bits -= 5)) & 31]);
            }
        }

        if (bits > 0)
            output.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        return output.ToString();
    }
}
