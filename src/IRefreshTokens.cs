namespace Snail.Toolkit.Authentication.JwtBearer;

/// <summary>
/// Mints the opaque secrets an application hands out alongside an access token.
/// </summary>
/// <remarks>
/// Separate from <see cref="ITokenProvider"/> because a refresh token is not a JWT: nothing here is
/// signed, parsed or validated, and none of the JWT settings apply. One registration serves every
/// issuer for the same reason — there is nothing to configure.
/// </remarks>
public interface IRefreshTokens
{
    /// <summary>
    /// Mints a refresh token of <paramref name="size"/> random bytes.
    /// </summary>
    /// <remarks>
    /// Encoded url-safe, so it survives a query string or a cookie unescaped. 32 bytes is 256 bits
    /// of entropy, which is what a bearer secret of this kind is expected to carry.
    /// </remarks>
    string Mint(int size = 32);
}
