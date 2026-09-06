namespace Snail.Toolkit.Authentication.JwtBearer;

/// <summary>
/// The verdict on a token, carrying why it was refused.
/// </summary>
/// <remarks>
/// Validation used to answer with a bare <c>bool</c>, so the caller could log that a request failed
/// but never that the token had merely expired — the one thing a client can act on. Validity is
/// derived from the refusal rather than stored beside it, so the two cannot disagree.
/// </remarks>
public sealed record TokenValidation(TokenRefusal Refusal, string? Fault)
{
    /// <summary>
    /// Whether the token passed every check.
    /// </summary>
    public bool IsValid => Refusal is TokenRefusal.None;

    /// <summary>
    /// The verdict of a token that passed every check.
    /// </summary>
    public static TokenValidation Valid { get; } = new(TokenRefusal.None, null);

    /// <summary>
    /// The verdict of a token that was refused, and why.
    /// </summary>
    public static TokenValidation Refused(TokenRefusal refusal, string fault) => new(refusal, fault);
}
