using System.Text.Json.Serialization;

namespace Haley.Models;

/// <summary>One intended action. Purposes cannot be combined or changed when completing a challenge.</summary>
[JsonConverter(typeof(JsonNumberEnumConverter<VerificationPurpose>))]
public enum VerificationPurpose { EmailVerification = 1, Onboarding = 2, PasswordReset = 4, PasswordlessLogin = 8 }
