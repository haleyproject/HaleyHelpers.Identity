namespace Haley.Exceptions;

/// <summary>An account changed state before its session transaction could commit.</summary>
public sealed class SessionRejectedException() : InvalidOperationException("The account is no longer active; the session was rejected.");
