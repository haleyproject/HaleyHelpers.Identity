using System.Text.Json.Serialization;

namespace Haley.Models;

/// <summary>Opaque tokens suit application-built links; numeric codes suit manual entry.</summary>
[JsonConverter(typeof(JsonNumberEnumConverter<VerificationProofKind>))]
public enum VerificationProofKind { OpaqueToken = 1, NumericCode = 2 }
