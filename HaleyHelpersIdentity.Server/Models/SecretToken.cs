namespace Haley.Models;

public sealed record SecretToken(string Value, byte[] Hash);
