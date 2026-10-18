using System.Text.Json.Serialization;

namespace Haley.Models;

/// <summary>Explicit administrative attestation or withdrawal of email ownership.</summary>
public sealed record AdminEmailVerificationAction([property: JsonRequired] bool IsVerified, string ReasonCode);
