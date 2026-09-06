namespace Snail.Toolkit.Authentication.JwtBearer;

/// <summary>
/// Why a token was refused.
/// </summary>
/// <remarks>
/// Named rather than left as prose because the caller acts on the difference: an expired token asks
/// the client to refresh, a bad signature or a foreign issuer asks it to log in again, and only the
/// first of those is routine enough to leave out of an alert.
/// </remarks>
public enum TokenRefusal
{
    /// <summary>
    /// Nothing was wrong with the token.
    /// </summary>
    None = 0,

    /// <summary>
    /// The token is past its expiry.
    /// </summary>
    Expired,

    /// <summary>
    /// The token is not valid yet.
    /// </summary>
    NotYetValid,

    /// <summary>
    /// The signature does not match the key, or the algorithm is not the one this application signs with.
    /// </summary>
    Signature,

    /// <summary>
    /// The token was minted for another audience.
    /// </summary>
    Audience,

    /// <summary>
    /// The token was minted by another issuer.
    /// </summary>
    Issuer,

    /// <summary>
    /// The string is not a token this application can read at all.
    /// </summary>
    Malformed,

    /// <summary>
    /// Refused for a reason this package does not name.
    /// </summary>
    Other
}
